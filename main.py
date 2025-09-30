#!/usr/bin/env python3
"""
Upstox -> Telegram LTP poller for Nifty50 members (full)

Features:
- Optionally loads a list of NIFTY50 tickers (from env or default list)
- Downloads Upstox instruments CSV (complete.csv.gz) and maps trading_symbol -> instrument_key
- Polls Upstox v3 LTP endpoint for all instrument_keys every POLL_INTERVAL seconds
- Sends Telegram updates only when LTP changes (or when CHANGE_THRESHOLD_PCT exceeded)
- Friendly name mapping, robust parsing, raw response logging (container logs) for debugging
Env variables (required):
- UPSTOX_ACCESS_TOKEN
- TELEGRAM_BOT_TOKEN
- TELEGRAM_CHAT_ID

Optional env:
- POLL_INTERVAL (seconds, default 60)
- CHANGE_THRESHOLD_PCT (0 => any change triggers; default 0.0)
- NIFTY50_TICKERS (comma separated tickers) - if not set, default list used
- EXPLICIT_INSTRUMENT_KEYS (comma-separated instrument_key entries you want to include in addition to Nifty50)
- SEND_ALL_EVERY_POLL (true/false) - if true, send full list every poll even if no change (default false)
- INSTRUMENT_NAME_MAP (mapping instrument_key:FriendlyName comma-separated)
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

# -------------- Logging --------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# -------------- Config from env --------------
UPSTOX_ACCESS_TOKEN = os.getenv('UPSTOX_ACCESS_TOKEN')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 60)
CHANGE_THRESHOLD_PCT = float(os.getenv('CHANGE_THRESHOLD_PCT') or 0.0)
SEND_ALL_EVERY_POLL = os.getenv('SEND_ALL_EVERY_POLL', 'false').lower() in ('1','true','yes')

# Provide your own tickers or use default below
NIFTY50_TICKERS_RAW = os.getenv('NIFTY50_TICKERS')  # comma separated e.g. "RELIANCE,TCS,INFY,..."
EXPLICIT_INSTRUMENT_KEYS = os.getenv('EXPLICIT_INSTRUMENT_KEYS')  # comma separated instrument_key values to include

INSTRUMENT_NAME_MAP_RAW = os.getenv('INSTRUMENT_NAME_MAP') or ""  # e.g. "NSE_EQ|INE467B01029:TCS,..."

if not UPSTOX_ACCESS_TOKEN or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    logging.error("Missing required env vars: UPSTOX_ACCESS_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID")
    raise SystemExit(1)

# Default common Nifty50 tickers (best-effort). You can override via NIFTY50_TICKERS env.
DEFAULT_NIFTY50_TICKERS = [
    "ADANIENT","ASIANPAINT","AXISBANK","BAJAJ-AUTO","BAJFINANCE","BAJAJFINSV","BPCL","BHARTIARTL",
    "INFRATEL","BRITANNIA","CIPLA","COALINDIA","DIVISLAB","DRREDDY","EICHERMOT","GRASIM","HCLTECH",
    "HDFCBANK","HDFC","HDFCLIFE","HEROMOTOCO","HINDALCO","HINDUNILVR","ICICIBANK","ITC","JSWSTEEL",
    "KOTAKBANK","LT","MARUTI","NTPC","ONGC","POWERGRID","RELIANCE","SBILIFE","SBIN","SUNPHARMA",
    "TATASTEEL","TCS","TECHM","TITAN","ULTRACEMCO","UPL","WIPRO","DIVISLAB"  # note: DIVISLAB duplicated earlier, it's OK
]
# Note: ticker naming conventions differ; Upstox trading_symbol may be exact like 'TCS', 'RELIANCE', 'HDFCBANK', etc.
# If some not found, prefer providing NIFTY50_TICKERS env var.

# parse NIFTY tickers
if NIFTY50_TICKERS_RAW:
    NIFTY50_TICKERS = [t.strip() for t in NIFTY50_TICKERS_RAW.split(",") if t.strip()]
else:
    NIFTY50_TICKERS = DEFAULT_NIFTY50_TICKERS

# parse explicit instrument keys
EXPLICIT_KEYS = [k.strip() for k in (EXPLICIT_INSTRUMENT_KEYS or "").split(",") if k.strip()]

# parse friendly name map
INSTRUMENT_NAME_MAP = {}
for pair in [p.strip() for p in INSTRUMENT_NAME_MAP_RAW.split(",") if p.strip()]:
    if ":" in pair:
        k, v = pair.split(":",1)
        INSTRUMENT_NAME_MAP[k.strip()] = v.strip()

UPSTOX_INSTRUMENTS_CSV_GZ = "https://assets.upstox.com/market-quote/instruments/exchange/complete.csv.gz"
UPSTOX_LTP_URL = "https://api.upstox.com/v3/market-quote/ltp"

# -------------- State --------------
LAST_LTPS = {}  # key -> float

# -------------- Helpers --------------
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
    """Download Upstox instruments CSV (gz) and return list of dict rows."""
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
    """
    Build mapping from trading_symbol (upper) -> instrument_key
    Also try other fields if available.
    """
    mapping = {}
    for row in rows:
        # common column names: 'trading_symbol','instrument_key','symbol','instrumentKey'
        ts = (row.get('trading_symbol') or row.get('symbol') or row.get('tradingSymbol') or "").strip()
        ik = (row.get('instrument_key') or row.get('instrumentKey') or row.get('instrument_token') or row.get('token') or "").strip()
        if ts and ik:
            mapping[ts.upper()] = ik
        # sometimes name field contains index names like 'Nifty 50' - we won't use that here
    return mapping

def find_instrument_keys_for_tickers(tickers, mapping):
    """Given tickers list and mapping trading_symbol->instrument_key, return instrument_key list and a dict of unmatched tickers."""
    keys = []
    unmatched = []
    for t in tickers:
        ik = mapping.get(t.upper())
        if ik:
            keys.append(ik)
        else:
            unmatched.append(t)
    return keys, unmatched

# Reuse robust parsing & formatting functions (similar to earlier versions)
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
    # join keys with comma - encode
    key_param = ",".join(keys)
    url = UPSTOX_LTP_URL + "?instrument_key=" + quote_plus(key_param)
    try:
        r = requests.get(url, headers=headers, timeout=20)
        r.raise_for_status()
        return r.json()
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

        # update LAST_LTPS
        if ltp_f is not None:
            LAST_LTPS[key] = ltp_f

        if should_send:
            should_send_any = True

        if change:
            lines.append(f"{html.escape(str(name))}: {formatted} ({html.escape(str(change))}%)")
        else:
            lines.append(f"{html.escape(str(name))}: {formatted}")

    return should_send_any or SEND_ALL_EVERY_POLL, "\n".join(lines)

# -------------- Startup: build instrument key list --------------
def build_instrument_keys():
    # 1) download Upstox instruments CSV and build mapping
    rows = download_upstox_instruments()
    if not rows:
        logging.error("Could not download instrument rows; will only use EXPLICIT_INSTRUMENT_KEYS if provided.")
        mapping = {}
    else:
        mapping = build_symbol_to_instrument_key_map(rows)

    # 2) find keys for NIFTY50 tickers
    keys = []
    if NIFTY50_TICKERS:
        mapped_keys, unmatched = find_instrument_keys_for_tickers(NIFTY50_TICKERS, mapping)
        if mapped_keys:
            keys.extend(mapped_keys)
            logging.info("Mapped %d Nifty50 tickers to instrument_keys, %d unmatched", len(mapped_keys), len(unmatched))
            if unmatched:
                logging.info("Unmatched tickers (may require exact ticker names for Upstox): %s", ", ".join(unmatched))
        else:
            logging.warning("No Nifty50 tickers mapped - unmatched or mapping empty. Provide NIFTY50_TICKERS env with exact trading symbols or add EXPLICIT_INSTRUMENT_KEYS.")

    # 3) include any explicit keys
    if EXPLICIT_KEYS:
        keys.extend(EXPLICIT_KEYS)
        logging.info("Included %d explicit instrument keys", len(EXPLICIT_KEYS))

    # dedupe while preserving order
    seen = set()
    deduped = []
    for k in keys:
        if k not in seen and k:
            deduped.append(k)
            seen.add(k)
    logging.info("Total instrument_keys to poll: %d", len(deduped))
    return deduped

# -------------- Main loop --------------
def main():
    instrument_keys = build_instrument_keys()
    if not instrument_keys:
        logging.error("No instrument keys available to poll. Exiting.")
        return

    # For large lists, Upstox endpoint may accept many keys; if too long, you may need to chunk.
    # We'll chunk to batches of 50 keys per request as a safe default.
    CHUNK_SIZE = 50

    logging.info("Starting poller. Poll interval: %ds. Threshold pct: %s", POLL_INTERVAL, CHANGE_THRESHOLD_PCT)
    while True:
        try:
            all_parsed = []
            for i in range(0, len(instrument_keys), CHUNK_SIZE):
                chunk = instrument_keys[i:i+CHUNK_SIZE]
                resp = get_ltps_for_keys(chunk)
                if resp is None:
                    logging.warning("No response for chunk %d-%d", i, i+len(chunk)-1)
                    continue
                parsed = parse_upstox_response(resp)
                # ensure parsed items include instrument_key for items in this chunk (Upstox may return mapping)
                # If parsed items don't have instrument_key, attach from chunk best-effort
                if parsed:
                    for it in parsed:
                        if not it.get('instrument_key'):
                            # try to set from trading_symbol match or chunk keys
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
