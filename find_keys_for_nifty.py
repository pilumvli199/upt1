# find_keys_for_nifty.py
# Usage:
# - set NIFTY50_TICKERS env or edit TICKERS list below
# - python find_keys_for_nifty.py
import gzip, io, csv, requests, os

CSV_URL = "https://assets.upstox.com/market-quote/instruments/exchange/complete.csv.gz"

TICKERS_RAW = os.getenv('NIFTY50_TICKERS') or "RELIANCE,TCS,INFY,HDFCBANK,HDFC,ICICIBANK,KOTAKBANK,SBIN,AXISBANK,LT,ITC,BHARTIARTL,HINDUNILVR,HINDALCO,NTPC,ONGC,POWERGRID,MARUTI,SUNPHARMA,BAJFINANCE,BAJAJ-AUTO,BAJAJFINSV,BRITANNIA,CIPLA,COALINDIA,DRREDDY,EICHERMOT,GRASIM,HCLTECH,HDFCLIFE,HEROMOTOCO,JSWSTEEL,ULTRACEMCO,TATASTEEL,TECHM,TITAN,UPL,WIPRO,ADANIENT,ASIANPAINT"
TICKERS = [t.strip() for t in TICKERS_RAW.split(",") if t.strip()]

def download_rows():
    print("Downloading instruments CSV ...")
    r = requests.get(CSV_URL, timeout=60)
    r.raise_for_status()
    gz = gzip.GzipFile(fileobj=io.BytesIO(r.content))
    text = io.TextIOWrapper(gz, encoding='utf-8', errors='ignore')
    reader = csv.DictReader(text)
    rows = [row for row in reader]
    print("Rows loaded:", len(rows))
    return rows

def build_map(rows):
    m = {}
    for row in rows:
        ts = (row.get('trading_symbol') or row.get('symbol') or row.get('tradingSymbol') or "").strip()
        ik = (row.get('instrument_key') or row.get('instrumentKey') or row.get('instrument_token') or row.get('token') or "").strip()
        name = (row.get('name') or row.get('instrument_name') or "").strip()
        if ts and ik:
            m[ts.upper()] = (ik, name)
    return m

def main():
    rows = download_rows()
    m = build_map(rows)
    found = []
    unmatched = []
    for t in TICKERS:
        key = t.upper()
        if key in m:
            ik, name = m[key]
            print(f"{t} -> {ik}   ({name})")
            found.append(ik)
        else:
            alt = key.replace("&","AND").replace(".","").replace("-","").strip()
            if alt in m:
                ik, name = m[alt]
                print(f"{t} -> {ik}   ({name})  [matched via alt '{alt}']")
                found.append(ik)
            else:
                unmatched.append(t)
    print("\n--- Summary ---")
    print("Found instrument_keys (comma separated):")
    print(",".join(found))
    if unmatched:
        print("\nUnmatched tickers (need exact trading_symbol used by Upstox):")
        print(",".join(unmatched))
    else:
        print("\nAll tickers matched.")

if __name__ == '__main__':
    main()
