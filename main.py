#!/usr/bin/env python3
"""
Upstox -> Telegram LTP poller
- Railway compatible (reads env vars)
- Polls every 60s for NIFTY 50 and TCS LTP via Upstox v3 market-quote LTP endpoint
Environment variables:
- UPSTOX_ACCESS_TOKEN (required) : Upstox user access token (Bearer)
- TELEGRAM_BOT_TOKEN (required)
- TELEGRAM_CHAT_ID (required)
- TCS_INSTRUMENT_KEY (optional) : if you already have it (e.g., NSE_EQ|INE467B01029)
- POLL_INTERVAL (optional) : seconds, default 60
"""
import os
import time
import logging
import requests
from urllib.parse import quote_plus

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

UPSTOX_ACCESS_TOKEN = os.getenv('UPSTOX_ACCESS_TOKEN')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
TCS_INSTRUMENT_KEY = os.getenv('TCS_INSTRUMENT_KEY')  # optional
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL') or 60)

if not UPSTOX_ACCESS_TOKEN or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    logging.error("Missing required environment variables. See README and .env.example")
    raise SystemExit(1)

UPSTOX_LTP_URL = "https://api.upstox.com/v3/market-quote/ltp"
INSTRUMENTS_CSV_GZ = "https://assets.upstox.com/market-quote/instruments/exchange/complete.csv.gz"

def fetch_tcs_instrument_key():
    """Download instruments CSV gz and search for trading symbol 'TCS' (case-insensitive).
    Returns instrument_key or None."""
    try:
        logging.info("Downloading instruments CSV (may be ~10-20MB gz)...")
        r = requests.get(INSTRUMENTS_CSV_GZ, timeout=30)
        r.raise_for_status()
    except Exception as e:
        logging.warning("Failed to download instruments file: %s", e)
        return None

    import gzip, io, csv
    try:
        gz = gzip.GzipFile(fileobj=io.BytesIO(r.content))
        text = io.TextIOWrapper(gz, encoding='utf-8')
        reader = csv.DictReader(text)
        for row in reader:
            # fields may include 'trading_symbol' and 'instrument_key'
            ts = row.get('trading_symbol') or row.get('symbol') or ''
            if ts and ts.strip().upper() == 'TCS':
                ik = row.get('instrument_key') or row.get('instrumentKey') or None
                if ik:
                    logging.info("Found TCS instrument_key: %s", ik)
                    return ik
        logging.warning("TCS not found in instruments CSV.")
    except Exception as e:
        logging.warning("Error parsing instruments CSV: %s", e)
    return None

def get_ltps(instrument_keys):
    """Call Upstox v3 LTP endpoint with comma-separated instrument_key list."""
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
        logging.warning("Upstox LTP request failed: %s", e)
        return None

def send_telegram_message(text):
    tg_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
    try:
        r = requests.post(tg_url, json=payload, timeout=10)
        r.raise_for_status()
        return True
    except Exception as e:
        logging.warning("Telegram send failed: %s", e)
        return False

def format_message(data):
    # data is expected per Upstox response structure. We'll be defensive.
    lines = []
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    lines.append(f"<b>Upstox LTP Update</b> — {ts}")
    items = []
    # Upstox returns list or dict with 'data' etc. normalize:
    if isinstance(data, dict):
        if 'data' in data and isinstance(data['data'], list):
            items = data['data']
        elif 'data' in data and isinstance(data['data'], dict):
            items = [data['data']]
        elif 'results' in data:
            items = data['results']
        else:
            for v in data.values():
                if isinstance(v, dict) and 'ltp' in v:
                    items.append(v)
    elif isinstance(data, list):
        items = data
    for it in items:
        try:
            name = it.get('trading_symbol') or it.get('instrument_key') or it.get('symbol') or 'UNKNOWN'
            ltp = it.get('ltp') or it.get('last_traded_price') or it.get('lastPrice') or 'NA'
            change = it.get('change_percent') or it.get('percent_change') or ''
            lines.append(f"{name}: {ltp} {('('+str(change)+'%)') if change else ''}")
        except Exception:
            lines.append(str(it))
    return "\n".join(lines)

def main():
    global TCS_INSTRUMENT_KEY
    if not TCS_INSTRUMENT_KEY:
        TCS_INSTRUMENT_KEY = fetch_tcs_instrument_key()
        if not TCS_INSTRUMENT_KEY:
            logging.warning("TCS instrument key not found automatically. Set TCS_INSTRUMENT_KEY env var to include it.")
    # NIFTY 50 instrument key (per Upstox docs)
    NIFTY_KEY = "NSE_INDEX|Nifty 50"
    keys = [NIFTY_KEY]
    if TCS_INSTRUMENT_KEY:
        keys.append(TCS_INSTRUMENT_KEY)
    instrument_keys = ",".join(keys)
    logging.info("Starting poller. Instruments: %s", instrument_keys)
    while True:
        data = get_ltps(instrument_keys)
        if data:
            msg = format_message(data)
            sent = send_telegram_message(msg)
            logging.info("Sent to Telegram: %s", sent)
        else:
            logging.warning("No data received from Upstox this cycle.")
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
