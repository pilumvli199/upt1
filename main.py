#!/usr/bin/env python3
"""
Robust Upstox -> Telegram LTP poller (fixed logging)
- Handles multiple Upstox response shapes
- Proper logging format & datefmt to avoid ValueError
"""
import os
import time
import logging
import requests
import html
from urllib.parse import quote_plus

# Correct logging setup: use %(asctime)s in format and datefmt for datetime formatting.
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

def parse_upstox_response(resp):
    items = []
    if resp is None:
        return items
    if isinstance(resp, dict) and 'data' in resp:
        data = resp['data']
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = [data]
    elif isinstance(resp, list):
        items = resp
    elif isinstance(resp, dict):
        for k, v in resp.items():
            if isinstance(v, dict) and any(x in v for x in ['ltp', 'last_traded_price', 'lastPrice']):
                payload = dict(v)
                payload.setdefault('instrument_key', k)
                items.append(payload)
        if not items and any(x in resp for x in ['ltp', 'last_traded_price', 'lastPrice']):
            items = [resp]
    parsed = []
    for it in items:
        if not isinstance(it, dict):
            continue
        ik = it.get('instrument_key') or it.get('instrumentKey') or it.get('instrumentToken') or it.get('token') or it.get('symbol')
        ts = (it.get('trading_symbol') or it.get('symbol') or ik or "").strip()
        ltp = it.get('ltp') or it.get('last_traded_price') or it.get('lastPrice') or it.get('ltpPrice') or None
        change = it.get('change_percent') or it.get('percent_change') or it.get('change') or None
        parsed.append({
            'instrument_key': ik or ts,
            'trading_symbol': ts or ik,
            'ltp': ltp,
            'change_percent': change
        })
    return parsed

def format_message(parsed_list, raw_resp=None):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    lines = [f"<b>Upstox LTP Update</b> — {ts}"]
    if not parsed_list:
        lines.append("No LTPs parsed from response. Raw response logged on server.")
        if raw_resp is not None:
            snippet = html.escape(str(raw_resp))[:600]
            lines.append(f"<pre>{snippet}</pre>")
        return "\n".join(lines)
    for p in parsed_list:
        name = p.get('trading_symbol') or p.get('instrument_key') or 'UNKNOWN'
        name = safe_name(name)
        ltp = p.get('ltp')
        change = p.get('change_percent')
        if ltp is None:
            line = f"{html.escape(name)}: NA"
        else:
            ltp_s = html.escape(str(ltp))
            if change:
                line = f"{html.escape(name)}: {ltp_s} ({html.escape(str(change))}%)"
            else:
                line = f"{html.escape(name)}: {ltp_s}"
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
        if not parsed:
            logging.warning("Parsed list empty — logging raw response for debugging.")
            logging.info("RAW_UPSTOX: %s", str(resp)[:2000])
            msg = format_message([], raw_resp=resp)
            send_telegram_message(msg)
        else:
            msg = format_message(parsed, raw_resp=None)
            sent = send_telegram_message(msg)
            logging.info("Sent to Telegram: %s", sent)
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
