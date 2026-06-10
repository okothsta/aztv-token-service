# AZTV Token Service

Auto-mints `cdnedgch2.azamtvltd.co.tz` path-tokens from a single AzamMax
subscription and serves them to API-key holders. Runs on Render free tier.

**What it does:**
1. You paste your AzamMax credentials into the admin panel ONCE.
2. Every 10 hours, the service mints a fresh ~12h `cdnedgch2` token via the
   two-hop dance: `api.aztv.videoready.tv/authToken` → `cdnblncr` 302 → extract
   the path-token from the redirect Location.
3. Customers (your friends, your own apps) hit `GET /api/token` with their
   API key and get the current token.

**What it does NOT do:**
- It does NOT generate Bearer tokens. Bearer tokens come from your AzamMax
  web/app login session and last ~1 month. When yours expires, log into
  web.azamtvmax.com again, copy the new headers + payload, paste into the
  admin panel. Five minutes of manual work, every month or so.

---

## Deploy on Render (free tier)

1. **Push this folder to a NEW GitHub repo.** Don't put it in your existing
   `web_app` repo — it should be deployable independently.
2. Go to [render.com](https://render.com) → New → Web Service.
3. Connect your repo. Select the `aztv-token-service` folder if you put it
   inside a monorepo.
4. Settings:
   - Environment: **Node**
   - Build command: `npm install`
   - Start command: `npm start`
   - Plan: **Free** (or paid if you want no cold starts)
5. **Environment variables** (Settings → Environment):
   - `ADMIN_PASSWORD` — pick a long random string. THIS IS YOUR LOGIN.
   - `SESSION_SECRET` — another random 32+ char string.
   - `FIREBASE_SERVICE_ACCOUNT_JSON` — paste the full contents of your
     `firebase-service-account.json` file (single line). If you reuse
     the Firebase project from your streaming app, this is the same JSON.
6. Deploy. Wait for the green check.

### Keep-alive ping (free tier sleeps after 15 min idle)

The free tier sleeps if no requests come in for 15 min, then takes ~30 sec
to wake. To keep it warm, set up a free uptime monitor that pings
`https://YOUR-SERVICE.onrender.com/healthz` every 5 minutes. Options:
- [UptimeRobot](https://uptimerobot.com/) — free, unlimited 5-min checks.
- [Cronitor](https://cronitor.io/) — free tier.
- A GitHub Action with `schedule: cron("*/10 * * * *")` calling curl.

The mint loop runs every 10 HOURS so even if the service sleeps a few times
a day it'll still refresh the token in time.

---

## First-time setup (after deploy)

1. Go to `https://YOUR-SERVICE.onrender.com/admin/login`.
2. Sign in with the password you set in `ADMIN_PASSWORD`.
3. **Capture credentials from web.azamtvmax.com:**
   - Open https://web.azamtvmax.com in a browser. Sign in. Play any channel.
   - Press F12 → Network tab. Filter by `authToken`.
   - Click the `authToken` POST request.
   - Copy the entire **Request Headers** block. Paste it into "Request Headers".
   - Click the **Payload** tab → **view source**. Copy the JSON. Paste it into "Payload".
   - Click **Save and validate**.
4. The service will parse, validate by minting one real token, and start the
   auto-refresh loop. You should see the token info appear in the Status section.

---

## Add API keys for customers

In the admin panel:
1. Type a label (e.g. "Friend John", "MyApp staging").
2. Click **Generate new API key**.
3. The plaintext key shows up ONCE in green — copy it now and send to the
   customer. The service only stores its SHA-256 hash; if you lose the
   plaintext you have to generate a new one.

You can disable or delete keys any time without affecting others.

---

## Customer integration

```http
GET https://YOUR-SERVICE.onrender.com/api/token
Headers: X-Api-Key: <key>

Response:
{
  "token": "eyJhbGciOiJIUzUxMiI...",
  "exp": 1781999999,
  "cdnHost": "https://cdnedgch2.azamtvltd.co.tz"
}
```

Build the play URL:
```
https://cdnedgch2.azamtvltd.co.tz/tok_<token>/live/eds/<Channel>/DASH/<Channel>.mpd
```

Or the helper that returns a ready-to-play URL:
```http
GET /api/play/AzamOne
Headers: X-Api-Key: <key>

Response:
{
  "url": "https://cdnedgch2.azamtvltd.co.tz/tok_eyJ.../live/eds/AzamOne/DASH/AzamOne.mpd",
  "exp": 1781999999
}
```

Customers should cache the token until ~30 minutes before `exp`, then re-fetch.
A simple per-page fetch on player open is also fine.

---

## Security notes

- Bearer + subscriptionDtl + contentDtl never leave the server. They live in
  Firestore (encrypted at rest by Google), accessed only by the service
  account on this Render service.
- API keys are stored as SHA-256 hashes only.
- Admin login uses an HMAC-signed cookie with 24h TTL.
- Admin login is rate-limited (10 attempts / 5 min / IP).
- Customer endpoints are rate-limited (60 req/min / IP).
- Disable any leaked key from the admin panel — instant.

---

## Local dev

```bash
cd aztv-token-service
npm install
# put firebase-service-account.json here, set env vars in a .env file you load
ADMIN_PASSWORD=test1234 SESSION_SECRET=somelongrandomstring node server.js
```

Then open http://localhost:3000/admin/login.
