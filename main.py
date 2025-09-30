#!/usr/bin/env python3
"""
Upstox -> Telegram LTP poller (full)
Features:
- Robustly parses many Upstox response shapes (list, dict with 'data', mapping instrument_key->payload, nested)
- Pretty Telegram message formatting
- Sends updates only when LTP changes (or when change % threshold exceeded)
- Friendly name mapping via INSTRUMENT_NAME_MAP env var
- Logs raw Upstox response to container logs when parsing fails (NOT to Telegram)
Env variables:
- UPSTOX_ACCESS_TOKEN (required)
- TELEGRAM_BOT_TOKEN (required)
- TELEGRAM_CHAT_ID (required)
- INSTRUMENT_KEYS  OR (NIFTY_INSTRUMENT_KEY and/or TCS_INSTRUMENT_KEY)
- INSTRUMENT_NAME_MAP (optional): e.g. NSE_INDEX|Nifty 50:Nifty 50,NSE_EQ|INE467B01029:TCS
- POLL_INTERVAL (optional, default 60)
- CHANGE_THRESHOLD_PCT (optional, default 0.0) # percent change required to trigger message (0 = any change)
"""
import os
import time
import logging
import requests
import html
from urllib.parse import quote_plus

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- Env / config ---
UPSTOX_ACCESS_TOKEN = os.getenv('UPSTOX_ACCESS_TOKEN')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

INSTRUMENT_KEYS = os.getenv('INSTRUMENT_KEYS') or ",".join(filter(None, [
    os.getenv('NIFTY_INSTRUMENT_KEY'),
    os.getenv('TCS_INSTRUMENT_KEY'),
]))

INSTRUMENT_NAME_MAP_RAW = os.getenv('INSTRUMENT_NAME_MAP') or ""
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 60)
CHANGE_THRESHOLD_PCT = float(os.getenv('CHANGE_THRESHOLD_PCT') or 0.0)  # 0 => any change triggers

if not UPSTOX_ACCESS_TOKEN or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not INSTRUMENT_KEYS:
    logging.error("Missing required env vars. Need UPSTOX_ACCESS_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID and INSTRUMENT_KEYS (or NIFTY_INSTRUMENT_KEY/TCS_INSTRUMENT_KEY).")
    raise SystemExit(1)

# parse mapping like "NSE_INDEX|Nifty 50:Nifty 50,NSE_EQ|INE467B01029:TCS"
INSTRUMENT_NAME_MAP = {}
for pair in [p.strip() for p in INSTRUMENT_NAME_MAP_RAW.split(",") if p.strip()]:
    if ":" in pair:
        k, v = pair.split(":", 1)
        INSTRUMENT_NAME_MAP[k.strip()] = v.strip()

UPSTOX_LTP_URL = "https://api.upstox.com/v3/market-quote/ltp"

# --- In-memory last values to suppress unchanged updates ---
LAST_LTPS = {}  # key -> float

# --- HTTP helpers ---
def get_ltps(instrument_keys):
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {UPSTOX_ACCESS_TOKEN}"
    }
    url = UPSTOX_LTP_URL + "?instrument_key=" + quote_plus(instrument_keys)
    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.warning("Upstox request failed: %s", e)
        return None

def send_telegram_message(text):
    tg_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    try:
        r = requests.post(tg_url, json=payload, timeout=10)
        r.raise_for_status()
        return True
    except Exception as e:
        logging.warning("Telegram send failed: %s", e)
        return False

# --- Utilities ---
def safe_name(key_or_symbol):
    return INSTRUMENT_NAME_MAP.get(key_or_symbol, key_or_symbol)

def find_ltp_in_obj(obj):
    """
    Recursively search obj (dict/list/scalar) for an LTP-like value.
    Keys checked: 'ltp','last_traded_price','lastPrice','ltpPrice','lastTradedPrice'
    Also tries to coerce numeric-like scalars.
    Returns first found value (as float or original type) or None.
    """
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
    """
    Return list of parsed dicts: {'instrument_key', 'trading_symbol', 'ltp', 'change_percent'}
    Attempts to handle:
      - {'data': {...}} where data is dict/list
      - mapping instrument_key -> payload
      - list of payloads
      - single payload
    """
    parsed = []
    if resp is None:
        return parsed

    # case: {'data': ...}
    if isinstance(resp, dict) and 'data' in resp:
        data = resp['data']
        if isinstance(data, dict):
            # treat each key->payload within data as instrument items
            for k, v in data.items():
                ltp = find_ltp_in_obj(v)
                ts = v.get('trading_symbol') if isinstance(v, dict) else None
                parsed.append({'instrument_key': k, 'trading_symbol': ts or k, 'ltp': ltp, 'change_percent': None})
            return parsed
        elif isinstance(data, list):
            items = data
        else:
            items = [data]
    elif isinstance(resp, dict):
        # maybe mapping instrument_key -> payload
        instrument_items = []
        for k, v in resp.items():
            # if v looks like payload or nested structure
            if isinstance(v, dict) and (any(x in v for x in ['ltp','last_traded_price','lastPrice']) or any(isinstance(vv, (dict, list)) for vv in v.values())):
                ltp = find_ltp_in_obj(v)
                ts = v.get('trading_symbol') if isinstance(v, dict) else None
                instrument_items.append({'instrument_key': k, 'trading_symbol': ts or k, 'ltp': ltp, 'change_percent': None})
        if instrument_items:
            parsed.extend(instrument_items)
            return parsed
        # else treat resp as a single payload
        items = [resp]
    elif isinstance(resp, list):
        items = resp
    else:
        items = [resp]

    # normalize items
    for it in items:
        if not isinstance(it, dict):
            continue
        ik = it.get('instrument_key') or it.get('instrumentKey') or it.get('instrumentToken') or None
        ts = it.get('trading_symbol') or it.get('symbol') or it.get('instrument_name') or None
        ltp = find_ltp_in_obj(it)
        change = it.get('change_percent') or it.get('percent_change') or None
        parsed.append({
            'instrument_key': ik or ts or None,
            'trading_symbol': ts or ik or None,
            'ltp': ltp,
            'change_percent': change
        })
    return parsed

def format_pretty(parsed_list):
    """
    Build a pretty Telegram message from parsed list.
    Returns (send_any: bool, message_text: str)
    send_any indicates whether we should send based on thresholds and last values.
    """
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    header = f"📈 <b>Upstox LTP</b> — {ts}"
    lines = [header]
    send_any = False

    for p in parsed_list:
        key = p.get('instrument_key') or p.get('trading_symbol') or 'UNKNOWN'
        raw_name = p.get('trading_symbol') or key
        name = safe_name(raw_name)
        ltp = p.get('ltp')
        change = p.get('change_percent')

        if ltp is None:
            val_str = "NA"
            lines.append(f"{html.escape(str(name))}: {val_str}")
            continue

        # coerce to float if possible for comparisons & formatting
        ltp_f = None
        try:
            ltp_f = float(ltp)
            val_str = f"{ltp_f:,.2f}"
        except Exception:
            val_str = str(ltp)

        prev = LAST_LTPS.get(key)

        # determine if send based on CHANGE_THRESHOLD_PCT
        if prev is None:
            # first seen -> send
            should_send = True
        elif ltp_f is None:
            should_send = False
        else:
            if CHANGE_THRESHOLD_PCT <= 0:
                should_send = (ltp_f != prev)
            else:
                # avoid division by zero
                if prev == 0:
                    diff_pct = 100.0 if ltp_f != 0 else 0.0
                else:
                    diff_pct = abs((ltp_f - prev) / prev) * 100.0
                should_send = diff_pct >= CHANGE_THRESHOLD_PCT

        # update stored value regardless
        if ltp_f is not None:
            LAST_LTPS[key] = ltp_f

        if should_send:
            send_any = True

        if change:
            lines.append(f"{html.escape(str(name))}: {val_str} ({html.escape(str(change))}%)")
        else:
            lines.append(f"{html.escape(str(name))}: {val_str}")

    text = "\n".join(lines)
    return send_any, text

# --- Main loop ---
def main():
    logging.info("Starting poller. Instruments: %s", INSTRUMENT_KEYS)
    while True:
        resp = get_ltps(INSTRUMENT_KEYS)
        if resp is None:
            logging.warning("No response from Upstox this cycle.")
            time.sleep(POLL_INTERVAL)
            continue

        parsed = parse_upstox_response(resp)
        # if parsed empty or all ltp missing, log raw response for debugging (container logs only)
        if not parsed or all(p.get('ltp') is None for p in parsed):
            logging.warning("Parsed list empty or no LTP found — logging raw response for debugging.")
            try:
                logging.info("RAW_UPSTOX: %s", str(resp)[:4000])
            except Exception:
                logging.info("RAW_UPSTOX: (failed to stringify)")
            # still allow updating LAST_LTPS if any numeric values found (best-effort)
            # but do not spam telegram with raw content
            time.sleep(POLL_INTERVAL)
            continue

        send_any, message = format_pretty(parsed)
        if send_any:
            sent = send_telegram_message(message)
            logging.info("Sent to Telegram: %s", sent)
        else:
            logging.info("No significant change — skipping Telegram.")
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
