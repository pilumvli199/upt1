# Upstox -> Telegram LTP Poller (Railway compatible)

What this does
- Polls Upstox v3 LTP endpoint every `POLL_INTERVAL` seconds for **Nifty 50** and **TCS**.
- Posts the LTP summary to a Telegram chat/channel.

Files
- `main.py` - the poller
- `requirements.txt` - Python dependencies
- `.env.example` - example env vars
- `Procfile` - Railway start command
- `start.sh` - wrapper to run

Railway setup
1. Create a new service and upload these files (or connect a repo).
2. Add environment variables in Railway: `UPSTOX_ACCESS_TOKEN`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`. Optionally `TCS_INSTRUMENT_KEY`.
3. Deploy. Start command is handled by `Procfile` (`web: python main.py`).

Notes & troubleshooting
- Upstox access tokens typically expire daily — refresh as needed.
- If `TCS_INSTRUMENT_KEY` isn't set, the script tries to download Upstox instruments CSV and find TCS.
- If Telegram messages fail, check bot token and chat id (for channels the bot must be admin).
