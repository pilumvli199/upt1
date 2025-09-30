#!/usr/bin/env python3
"""
More-robust Upstox -> Telegram LTP poller
- Aggressively searches nested responses to find LTP values
- Handles mapping instrument_key -> payload, list payloads, 'data' shapes, etc.
- Logs raw Upstox response to container logs when parsing fails (NOT to Telegram)
"""
import os
import time
import logging
import requests
import html
from urllib.parse import quote_plus

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

UPSTOX_ACCESS_TOKEN = os.getenv('UPSTOX_ACCESS_TOKEN')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

INSTRUMENT_KEYS = os.getenv('INSTRUMENT_KEYS') or ",".join(filter(None, [
    os.getenv('NIFTY_INSTRUMENT_KEY'),
    os.getenv('TCS_INSTRUMENT_KEY'),
]))

INSTRUMENT_NAME_MAP_RAW = os.getenv('INSTRUMENT_NAME_MAP') or ""
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 60)

if not UPSTOX_ACCESS_TOKEN or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not INSTRUMENT_KEYS:
    logging.error("Missing required env vars. Need UPSTOX_ACCESS_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID and INSTRUMENT_KEYS (or NIFTY_INSTRUMENT_KEY/TCS_INSTRUMENT_KEY).")
    raise SystemExit(1)

INSTRUMENT_NAME_MAP = {}
for pair in [p.strip() for p in INSTRUMENT_NAME_MAP_RAW.split(",") if p.strip()]:
    if ":" in pair:
        k, v = pair.split(":", 1)
        INSTRUMENT_NAME_MAP[k.strip()] = v.strip()

UPSTOX_LTP_URL = "https://api.upstox.com/v3/market-quote/ltp"

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

def safe_name(key_or_symbol):
    return INSTRUMENT_NAME_MAP.get(key_or_symbol, key_or_symbol)

def find_ltp_in_obj(obj):
    """
    Recursively search obj (dict/list/scalar) for an LTP-like value.
    Returns the first found value (as-is) or None.
    Keys considered: 'ltp','last_traded_price','lastPrice','ltpPrice','lastPriceValue'
    """
    if obj is None:
        return None
    # if it's a dict, look for direct keys first
    if isinstance(obj, dict):
        for key in ('ltp','last_traded_price','lastPrice','ltpPrice','lastPriceValue','lastTradedPrice'):
            if key in obj and obj[key] is not None:
                return obj[key]
        # try numeric-looking keys or nested fields
        for k, v in obj.items():
            # skip if k looks like metadata
            if isinstance(v, (dict, list)):
                val = find_ltp_in_obj(v)
                if val is not None:
                    return val
            else:
                # if value is numeric-like (int/float/str of digits with dot)
                if isinstance(v, (int, float)):
                    # heuristics: value likely > 1 and reasonable
                    if v != 0:
                        return v
                if isinstance(v, str):
                    s = v.strip().replace(',', '')
                    # simple float test
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
        # scalar
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
    Aggressively handle: {'data':...}, list, mapping instrument_key->payload, nested shapes.
    """
    parsed = []

    if resp is None:
        return parsed

    # If resp has top-level 'data'
    if isinstance(resp, dict) and 'data' in resp:
        data = resp['data']
        # if data itself is mapping instrument_key->payload
        if isinstance(data, dict):
            # iterate keys
            for k, v in data.items():
                ltp = find_ltp_in_obj(v)
                # try to find trading symbol within v
                ts = None
                if isinstance(v, dict):
                    ts = v.get('trading_symbol') or v.get('symbol') or v.get('instrument_name') or None
                parsed.append({'instrument_key': k, 'trading_symbol': ts or k, 'ltp': ltp, 'change_percent': None})
            return parsed
        elif isinstance(data, list):
            items = data
        else:
            items = [data]
    elif isinstance(resp, dict):
        # maybe mapping instrument_key -> payload at top level
        instrument_like_items = []
        for k, v in resp.items():
            if isinstance(v, dict) and any(x in v for x in ['ltp','last_traded_price','lastPrice']) or isinstance(v, (dict, list)):
                # treat as payload for k
                ltp = find_ltp_in_obj(v)
                ts = v.get('trading_symbol') if isinstance(v, dict) else None
                instrument_like_items.append({'instrument_key': k, 'trading_symbol': ts or k, 'ltp': ltp, 'change_percent': None})
        if instrument_like_items:
            parsed.extend(instrument_like_items)
            return parsed
        # else maybe resp itself is a single payload with ltp fields
        items = [resp]
    elif isinstance(resp, list):
        items = resp
    else:
        items = [resp]

    # normalize items (list of dicts)
    for it in items:
        if not isinstance(it, dict):
            # if scalar or unknown, skip
            continue
        ik = it.get('instrument_key') or it.get('instrumentKey') or None
        # if ik not present, maybe key present inside object under some known key
        ts = (it.get('trading_symbol') or it.get('symbol') or it.get('instrument_name') or None)
        ltp = find_ltp_in_obj(it)
        change = it.get('change_percent') or it.get('percent_change') or None
        parsed.append({
            'instrument_key': ik or ts or None,
            'trading_symbol': ts or ik or None,
            'ltp': ltp,
            'change_percent': change
        })
    return parsed

def format_message(parsed_list, raw_resp=None):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    lines = [f"<b>Upstox LTP Update</b> — {ts}"]
    if not parsed_list:
        lines.append("No LTPs parsed from response. Check container logs (RAW_UPSTOX).")
        return "\n".join(lines)
    for p in parsed_list:
        name = p.get('trading_symbol') or p.get('instrument_key') or 'UNKNOWN'
        name = safe_name(name)
        ltp = p.get('ltp')
        change = p.get('change_percent')
        if ltp is None:
            line = f"{html.escape(str(name))}: NA"
        else:
            ltp_s = html.escape(str(ltp))
            if change:
                line = f"{html.escape(str(name))}: {ltp_s} ({html.escape(str(change))}%)"
            else:
                line = f"{html.escape(str(name))}: {ltp_s}"
        lines.append(line)
    return "\n".join(lines)

def main():
    logging.info("Starting poller. Instruments: %s", INSTRUMENT_KEYS)
    while True:
        resp = get_ltps(INSTRUMENT_KEYS)
        if resp is None:
            logging.warning("No response from Upstox this cycle.")
            msg = format_message([], raw_resp=None)
            send_telegram_message(msg)
            time.sleep(POLL_INTERVAL)
            continue

        parsed = parse_upstox_response(resp)
        if not parsed or all(p.get('ltp') is None for p in parsed):
            logging.warning("Parsed list empty or LTP missing — logging raw response for debugging.")
            # log raw response to container logs (not to telegram)
            try:
                logging.info("RAW_UPSTOX: %s", str(resp)[:4000])
            except Exception:
                logging.info("RAW_UPSTOX: (failed to stringify)")
            msg = format_message(parsed, raw_resp=None)
            send_telegram_message(msg)
        else:
            msg = format_message(parsed, raw_resp=None)
            sent = send_telegram_message(msg)
            logging.info("Sent to Telegram: %s", sent)
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
