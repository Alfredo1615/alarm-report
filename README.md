# CPC Alarm Center Pro - FSD Direct Edition

This build adds:

- direct FSD/TCP client mode (the app connects to the CPC/E2)
- optional listener mode (the app waits for inbound TCP on your own server)
- raw frame capture with HEX + printable ASCII extraction
- heuristic alarm extraction from binary/text frames
- Twilio SMS per user
- custom app icons and PWA manifest

## Important note

FSD is a proprietary Emerson/Copeland protocol. This app now captures and stores raw frames directly, but exact decoding can still require site-specific tuning or a known startup/heartbeat frame.

## Render

- Works well for the web app and outbound client mode.
- Listener mode with a custom inbound port is better on a VPS or local server.

## Environment variables

- `SECRET_KEY`
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_FROM_NUMBER`
- `VAPID_PUBLIC_KEY`
- `VAPID_PRIVATE_KEY`
- `VAPID_CLAIMS_EMAIL`

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

## Render start command

```bash
gunicorn app:app
```
