# ScamShield - AI Scam Message & Link Detector

**HackNowa Global Hackathon 2026** | Track: Digital Safety & Cybersecurity

Online scams in India (UPI fraud, fake KYC, fake jobs, "digital arrest", investment fraud) cost people
thousands of crores every year, and victims are often ordinary people who cannot tell a real message from a fake one.

**ScamShield** lets anyone paste a suspicious SMS / WhatsApp / email / link and instantly get:

- a 0-100 risk score and verdict (Scam / Suspicious / Likely Safe)
- the exact red-flag phrases highlighted in the message
- plain-language reasons and what to do next (1930 helpline, cybercrime.gov.in)
- an AI explanation in the same language as the message (Hindi / Hinglish / English)

## How it works

1. **Rule engine**: 13 scam-pattern detectors (OTP/PIN requests, fake urgency, account-block threats, UPI collect tricks,
   fake jobs, upfront fees, remote-access apps, police/CBI impersonation, investment bait...).
2. **Link analyzer**: flags raw IPs, URL shorteners, cheap TLDs, `@` tricks, punycode, non-HTTPS and
   look-alike bank domains (e.g. `sbi-kyc-update.xyz`).
3. **Claude AI layer** (optional): gives a second opinion and a simple explanation. Final score blends 40% rules + 60% AI.
   Works fully offline with rules only if no API key is set.
4. **Privacy**: message text is never stored. Only an anonymous verdict counter is kept.

## Tech stack

FastAPI (Python) | SQLite | Vanilla HTML/CSS/JS | Anthropic Claude API

## Run locally (VS Code)

```bash
python -m venv venv
venv\Scripts\activate          # Windows   (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env         # Mac/Linux: cp .env.example .env   (optional: add ANTHROPIC_API_KEY)
uvicorn app:app --reload
```

Open http://127.0.0.1:8000

## API

`POST /api/analyze` with `{"text": "..."}` returns score, verdict, reasons, highlights, actions.
`GET /api/stats` and `GET /api/health`.

## Future scope

Browser extension, WhatsApp bot, voice-call scam detection, more Indian languages, crowd-sourced scam number database.
