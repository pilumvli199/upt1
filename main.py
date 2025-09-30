#!/usr/bin/env python3
"""
Validated Upstox -> Telegram LTP poller (full)

Behavior:
- Loads instrument keys from EXPLICIT_INSTRUMENT_KEYS (or maps NIFTY50_TICKERS via instruments CSV)
- Validates each instrument_key at startup by issuing a single-key LTP request
  - Keeps only keys that return a valid 200 response format (or at least not 400)
  - Removes invalid keys so the main poll loop won't fail with 400 Bad Request
- If token is invalid (401) it exits with a helpful error
- Polls remaining keys in chunks, parses LTPs, and sends Telegram messages only on change (threshold)
- Logs RAW_UPSTOX responses in container logs for debugging (does NOT send raw to Telegram)
Env required:
- UPSTOX_ACCESS_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
Optional:
- EXPLICIT_INSTRUMENT_KEYS (comma-separated instrument_key values)
- NIFTY50_TICKERS (comma-separated trading symbols to map via instruments CSV)
- POLL_INTERVAL, CHANGE_THRESHOLD_PCT, SEND_ALL_EVERY_POLL
"""
import os
import time
import logging
import requests
import gzip
import io
import csv
import html
from urllib.parse import quote_plus

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ---------- Config ----------
UPSTOX_ACCESS_TOKEN = os.getenv('UPSTOX_ACCESS_TOKEN')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 60)
CHANGE_THRESHOLD_PCT = float(os.getenv('CHANGE_THRESHOLD_PCT') or 0.0)
SEND_ALL_EVERY_POLL = os.getenv('SEND_ALL_EVERY_POLL', 'false').lower() in ('1','true','yes')

NIFTY50_TICKERS_RAW = os.getenv('NIFTY50_TICKERS')  # optional
EXPLICIT_INSTRUMENT_KEYS = os.getenv('EXPLICIT_INSTRUMENT_KEYS')  # optional

INSTRUMENT_NAME_MAP_RAW = os.getenv('INSTRUMENT_NAME_MAP') or ""

if not UPSTOX_ACCESS_TOKEN or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    logging.error("Missing required env vars: UPSTOX_ACCESS_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID")
    raise SystemExit(1)

# ---------- Defaults ----------
DEFAULT_NIFTY50_TICKERS = [
    "RELIANCE","TCS","HDFCBANK","INFY","HDFC","ICICIBANK","KOTAKBANK","SBIN","AXISBANK","LT",
    "ITC","BHARTIARTL","HINDUNILVR","HINDALCO","NTPC","ONGC","POWERGRID","MARUTI","SUNPHARMA",
    "BAJFINANCE","BAJAJ-AUTO","BAJAJFINSV","BRITANNIA","CIPLA","COALINDIA","DRREDDY","EICHERMOT",
    "GRASIM","HCLTECH","HDFCLIFE","HEROMOTOCO","JSWSTEEL","ULTRACEMCO","TATASTEEL","TECHM","TITAN",
    "UPL","WIPRO","ADANIENT","ASIANPAINT"
]

if NIFTY50_TICKERS_RAW:
    NIFTY50_TICKERS = [t.strip() for t in NIFTY50_TICKERS_RAW.split(",") if t.strip()]
else:
    NIFTY50_TICKERS = DEFAULT_NIFTY50_TICKERS

EXPLICIT_KEYS = [k.strip() for k in (EXPLICIT_INSTRUMENT_KEYS or "").split(",") if k.strip()]

INSTRUMENT_NAME_MAP = {}
for pair in [p.strip() for p in INSTRUMENT_NAME_MAP_RAW.split(",") if p.strip()]:
    if ":" in pair:
        k, v = pair.split(":",1)
        INSTRUMENT_NAME_MAP[k.strip()] = v.strip()

UPSTOX_INSTRUMENTS_CSV_GZ = "https://assets.upstox.com/market-quote/instruments/exchange/complete.csv.gz"
UPSTOX_LTP_URL = "https://api.upstox.com/v3/market-quote/ltp"

# ---------- State ----------
LAST_LTPS = {}  # key -> float

# ---------- Helpers ----------
def send_telegram_message(text):
    tg_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    try:
        r = requests.post(tg_url, json=payload, timeout=15)
        r.raise_for_status()
        return True
    except Exception as e:
        logging.warning("Telegram send failed: %s", e)
        return False

def download_upstox_instruments():
    logging.info("Downloading Upstox instruments CSV (this may be large)...")
    try:
        r = requests.get(UPSTOX_INSTRUMENTS_CSV_GZ, timeout=60)
        r.raise_for_status()
    except Exception as e:
        logging.error("Failed to download instruments CSV: %s", e)
        return []
    try:
        gz = gzip.GzipFile(fileobj=io.BytesIO(r.content))
        text = io.TextIOWrapper(gz, encoding='utf-8', errors='ignore')
        reader = csv.DictReader(text)
        rows = [row for row in reader]
        logging.info("Downloaded and parsed %d instrument rows", len(rows))
        return rows
    except Exception as e:
        logging.error("Error parsing instruments CSV: %s", e)
        return []

def build_symbol_to_instrument_key_map(rows):
    mapping = {}
    for row in rows:
        ts = (row.get('trading_symbol') or row.get('symbol') or row.get('tradingSymbol') or "").strip()
        ik = (row.get('instrument_key') or row.get('instrumentKey') or row.get('instrument_token') or row.get('token') or "").strip()
        if ts and ik:
            mapping[ts.upper()] = ik
    return mapping

def find_instrument_keys_for_tickers(tickers, mapping):
    keys = []
    unmatched = []
    for t in tickers:
        ik = mapping.get(t.upper())
        if ik:
            keys.append(ik)
        else:
            alt = t.upper().replace("&","AND").replace(".","").replace("-","").strip()
            if alt in mapping:
                keys.append(mapping[alt])
            else:
                unmatched.append(t)
    return keys, unmatched

def find_ltp_in_obj(obj):
    if obj is None:
        return None
    if isinstance(obj, dict):
        for key in ('ltp','last_traded_price','lastPrice','ltpPrice','lastPriceValue','lastTradedPrice'):
            if key in obj and obj[key] is not None:
                return obj[key]
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                val = find_ltp_in_obj(v)
                if val is not None:
                    return val
            else:
                if isinstance(v, (int, float)):
                    if v != 0:
                        return v
                if isinstance(v, str):
                    s = v.strip().replace(',', '')
                    try:
                        f = float(s)
                        return f
                    except Exception:
                        pass
        return None
    elif isinstance(obj, list):
        for el in obj:
            val = find_ltp_in_obj(el)
            if val is not None:
                return val
        return None
    else:
        if isinstance(obj, (int, float)):
            return obj
        if isinstance(obj, str):
            s = obj.strip().replace(',', '')
            try:
                return float(s)
            except Exception:
                return None
        return None

def parse_upstox_response(resp):
    parsed = []
    if resp is None:
        return parsed
    if isinstance(resp, dict) and 'data' in resp:
        data = resp['data']
        if isinstance(data, dict):
            for k, v in data.items():
                ltp = find_ltp_in_obj(v)
                ts = (v.get('trading_symbol') if isinstance(v, dict) else None) or k
                parsed.append({'instrument_key': k, 'trading_symbol': ts, 'ltp': ltp, 'change_percent': None})
            return parsed
        elif isinstance(data, list):
            items = data
        else:
            items = [data]
    elif isinstance(resp, dict):
        inst_items = []
        for k, v in resp.items():
            if isinstance(v, dict) and (any(x in v for x in ['ltp','last_traded_price','lastPrice']) or any(isinstance(vv, (dict, list)) for vv in v.values())):
                ltp = find_ltp_in_obj(v)
                ts = v.get('trading_symbol') or v.get('symbol') or k
                inst_items.append({'instrument_key': k, 'trading_symbol': ts, 'ltp': ltp, 'change_percent': None})
        if inst_items:
            parsed.extend(inst_items)
            return parsed
        items = [resp]
    elif isinstance(resp, list):
        items = resp
    else:
        items = [resp]

    for it in items:
        if not isinstance(it, dict):
            continue
        ik = it.get('instrument_key') or it.get('instrumentKey') or it.get('instrumentToken') or None
        ts = it.get('trading_symbol') or it.get('symbol') or it.get('instrument_name') or ik
        ltp = find_ltp_in_obj(it)
        change = it.get('change_percent') or it.get('percent_change') or None
        parsed.append({'instrument_key': ik or ts, 'trading_symbol': ts, 'ltp': ltp, 'change_percent': change})
    return parsed

def get_ltps_for_keys(keys):
    if not keys:
        return None
    headers = {"Accept": "application/json", "Authorization": f"Bearer {UPSTOX_ACCESS_TOKEN}"}
    key_param = ",".join(keys)
    url = UPSTOX_LTP_URL + "?instrument_key=" + quote_plus(key_param)
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError as he:
        # propagate status code information for validation logic
        status = getattr(he.response, 'status_code', None)
        body = getattr(he.response, 'text', '')
        logging.warning("Upstox LTP fetch failed: %s %s", status, (body[:400] if body else ''))
        raise
    except Exception as e:
        logging.warning("Upstox LTP fetch failed: %s", e)
        return None

def safe_name(key_or_symbol):
    return INSTRUMENT_NAME_MAP.get(key_or_symbol, key_or_symbol)

def format_message_and_decide_send(parsed_list):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    header = f"📈 <b>Upstox LTP</b> — {ts}"
    lines = [header]
    should_send_any = False

    for p in parsed_list:
        key = p.get('instrument_key') or p.get('trading_symbol') or 'UNKNOWN'
        name_raw = p.get('trading_symbol') or key
        name = safe_name(name_raw)
        ltp = p.get('ltp')
        change = p.get('change_percent')

        if ltp is None:
            lines.append(f"{html.escape(str(name))}: NA")
            continue

        ltp_f = None
        try:
            ltp_f = float(ltp)
            formatted = f"{ltp_f:,.2f}"
        except Exception:
            formatted = str(ltp)

        prev = LAST_LTPS.get(key)
        if prev is None:
            should_send = True
        elif ltp_f is None:
            should_send = False
        else:
            if CHANGE_THRESHOLD_PCT <= 0:
                should_send = (ltp_f != prev)
            else:
                if prev == 0:
                    diff_pct = 100.0 if ltp_f != 0 else 0.0
                else:
                    diff_pct = abs((ltp_f - prev) / prev) * 100.0
                should_send = diff_pct >= CHANGE_THRESHOLD_PCT

        if ltp_f is not None:
            LAST_LTPS[key] = ltp_f

        if should_send:
            should_send_any = True

        if change:
            lines.append(f"{html.escape(str(name))}: {formatted} ({html.escape(str(change))}%)")
        else:
            lines.append(f"{html.escape(str(name))}: {formatted}")

    return should_send_any or SEND_ALL_EVERY_POLL, "\n".join(lines)

# ---------- Key validation helpers ----------
def validate_single_key(key):
    """Issue single-key request; return (valid:bool, reason:str). If 401, raise Exception."""
    headers = {"Accept": "application/json", "Authorization": f"Bearer {UPSTOX_ACCESS_TOKEN}"}
    url = UPSTOX_LTP_URL + "?instrument_key=" + quote_plus(key)
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            # quick sanity check: does body contain ltp or data?
            text = r.text or ""
            if '"data"' in text or '"ltp"' in text or 'last_traded_price' in text or 'lastPrice' in text:
                return True, "OK"
            else:
                return True, "OK (no explicit ltp string found) "
        elif r.status_code == 401:
            return False, "401 Unauthorized"
        else:
            return False, f"{r.status_code} {r.text[:200]}"
    except requests.exceptions.RequestException as e:
        return False, str(e)

def validate_and_filter_keys(keys):
    """Validate each key and return a filtered list of valid keys. If 401 seen, exit."""
    valid = []
    bad = {}
    logging.info("Validating %d instrument keys (this may take a few seconds)...", len(keys))
    for k in keys:
        ok, reason = validate_single_key(k)
        if ok:
            logging.info("Key valid: %s", k)
            valid.append(k)
        else:
            logging.warning("Key invalid: %s -> %s", k, reason)
            bad[k] = reason
            if '401' in reason or 'Unauthorized' in reason or 'authentication' in reason.lower():
                logging.error("Authentication failed while validating keys: %s", reason)
                raise SystemExit("UPSTOX_ACCESS_TOKEN invalid/expired (401). Refresh token and retry.")
    if bad:
        logging.info("Filtered out %d invalid keys.", len(bad))
    return valid, bad

# ---------- Build instrument keys (map NIFTY tickers if needed) ----------
def build_instrument_keys():
    rows = download_upstox_instruments()
    mapping = build_symbol_to_instrument_key_map(rows) if rows else {}
    keys = []
    # map NIFTY tickers if requested
    if NIFTY50_TICKERS:
        mapped_keys, unmatched = find_instrument_keys_for_tickers(NIFTY50_TICKERS, mapping)
        if mapped_keys:
            keys.extend(mapped_keys)
            logging.info("Mapped %d Nifty50 tickers to instrument_keys, %d unmatched", len(mapped_keys), len(unmatched))
            if unmatched:
                logging.info("Unmatched tickers (may require exact trading_symbol): %s", ", ".join(unmatched))
        else:
            logging.warning("No Nifty50 tickers mapped - mapping empty or unmatched.")

    # include explicit keys
    if EXPLICIT_KEYS:
        keys.extend(EXPLICIT_KEYS)
        logging.info("Included %d explicit instrument keys", len(EXPLICIT_KEYS))

    # dedupe
    seen = set()
    deduped = []
    for k in keys:
        if k and k not in seen:
            deduped.append(k)
            seen.add(k)
    logging.info("Total candidate instrument_keys: %d", len(deduped))
    # validate keys so we remove bad ones before polling
    if deduped:
        valid, bad = validate_and_filter_keys(deduped)
        if not valid:
            logging.error("No valid instrument keys after validation. Exiting.")
            return []
        return valid
    else:
        return []

# ---------- Main loop ----------
def main():
    instrument_keys = build_instrument_keys()
    if not instrument_keys:
        logging.error("No instrument keys available to poll. Exiting.")
        return

    CHUNK_SIZE = 50
    logging.info("Starting poller. Poll interval: %ds. Threshold pct: %s. Polling %d keys.", POLL_INTERVAL, CHANGE_THRESHOLD_PCT, len(instrument_keys))
    while True:
        try:
            all_parsed = []
            for i in range(0, len(instrument_keys), CHUNK_SIZE):
                chunk = instrument_keys[i:i+CHUNK_SIZE]
                try:
                    resp = get_ltps_for_keys(chunk)
                except Exception:
                    # if chunk caused a HTTPError (eg 400 due to malformed key), try to individually validate and remove offending key
                    logging.warning("Chunk request failed - trying single-key diagnostics for this chunk.")
                    # test each key individually to find bad ones and remove them
                    new_chunk = []
                    for k in chunk:
                        ok, reason = validate_single_key(k)
                        if ok:
                            new_chunk.append(k)
                        else:
                            logging.warning("Removing bad key from polling list: %s -> %s", k, reason)
                            if '401' in reason or 'Unauthorized' in reason:
                                logging.error("Authentication failure while polling; exiting.")
                                raise SystemExit("UPSTOX_ACCESS_TOKEN invalid/expired (401). Refresh token and retry.")
                    # update global instrument_keys to remove bad keys permanently
                    instrument_keys = [x for x in instrument_keys if x in new_chunk or x not in chunk]
                    if not new_chunk:
                        logging.warning("No valid keys left in this chunk after diagnostics.")
                        continue
                    resp = get_ltps_for_keys(new_chunk)
                if resp is None:
                    logging.warning("No response for chunk %d-%d", i, i+len(chunk)-1)
                    continue
                parsed = parse_upstox_response(resp)
                if parsed:
                    for it in parsed:
                        if not it.get('instrument_key'):
                            if it.get('trading_symbol'):
                                it['instrument_key'] = it['trading_symbol']
                            else:
                                it['instrument_key'] = None
                    all_parsed.extend(parsed)
            if not all_parsed:
                logging.warning("No parsed items in this cycle; check RAW_UPSTOX in logs if available.")
                time.sleep(POLL_INTERVAL)
                continue

            should_send, message = format_message_and_decide_send(all_parsed)
            if should_send:
                sent = send_telegram_message(message)
                logging.info("Sent to Telegram: %s", sent)
            else:
                logging.info("No significant change detected; skipping Telegram send.")
        except Exception as e:
            logging.exception("Unhandled error in main loop: %s", e)
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
