# AZTV Token Relay

Tiny script that runs on a residential IP (your laptop, an old Android phone
with Termux, a Tanzanian VPS) and pushes fresh magic JWTs to your Render
AZTV Token Service every 10 hours.

## Why

cdnblncr blocks cloud datacenter IPs. The token service on Render can store
tokens fine, but it can't MINT them — that has to come from a residential
ISP IP. This relay lives on such an IP and does the minting.

## One-time setup

### 1. On Render: add the push secret

Go to your `aztv-token-service` Render dashboard → Environment tab → add:

- **Key:** `PUSH_SECRET`
- **Value:** any long random string, 32+ chars. (`openssl rand -base64 48`
  gives a good one. Or use https://1password.com/password-generator/.)

Save. Render redeploys.

### 2. On the relay box (your laptop / phone / friend's PC)

Open a terminal in this folder, then:

```
copy .env.example .env       # Windows cmd
# OR
cp .env.example .env         # macOS/Linux/Termux
```

Edit `.env` and fill in **five values**:

| Field | Where to get it |
|---|---|
| `SERVICE_URL` | Your Render URL, e.g. `https://aztv-token-service.onrender.com` |
| `PUSH_SECRET` | The same string you set on Render in step 1 |
| `BEARER` | From web.azamtvmax.com DevTools → Network → authToken request → Headers tab → `authorization: Bearer eyJ...` (just the JWT, no "Bearer " prefix) |
| `SUBSCRIPTION_DTL` | From the same request → Payload tab → view source → the `subscriptionDtl` value |
| `CONTENT_DTL` | Same request → Payload → view source → the `contentDtl` value |

### 3. Run it

```
node relay.js
```

You should see output like:

```
AZTV Relay starting. Service=https://aztv-token-service.onrender.com  Refresh=10h
[2026-...] ✓ Minted magic JWT (lifespan 720m). Pushing to service…
[2026-...] ✓ Service accepted token. Customers will stream until 2026-06-11T05:33:36.000Z.
```

Leave the terminal open. The relay runs forever, minting every 10 hours.

## Running it on different devices

### On your laptop (Windows)

```
cd path\to\aztv-token-service\relay
copy .env.example .env
notepad .env                  # fill in the values
node relay.js
```

When you close the cmd window, the relay stops. Reopen it any time and run
`node relay.js` again. The current token in Render's Firestore lasts 12h,
so even if your laptop is off overnight, channels keep working until that
window closes.

To make it auto-start when you boot Windows: search "Task Scheduler" →
Create Basic Task → Trigger "When I log on" → Action "Start a program" →
program `node`, arguments `relay.js`, start-in your relay folder. Or just
run `node relay.js` in a saved batch file.

### On Android (Termux)

1. Install Termux from F-Droid (https://f-droid.org/en/packages/com.termux/)
   — NOT from Play Store; Play Store version is broken.
2. Open Termux, install Node:
   ```
   pkg update && pkg install -y nodejs git
   ```
3. Get the relay onto the phone. Easiest way: clone your repo:
   ```
   git clone https://github.com/okothsta/aztv-token-service.git
   cd aztv-token-service/relay
   ```
4. Create `.env`:
   ```
   cp .env.example .env
   nano .env             # paste your values, Ctrl+O save, Ctrl+X quit
   ```
5. Disable Termux battery optimization:
   - Android Settings → Apps → Termux → Battery → Unrestricted.
6. Acquire wake-lock so Android doesn't kill the script:
   ```
   termux-wake-lock
   node relay.js
   ```
7. To run in the background even when you close Termux, install
   `termux-services` and run as a service, OR just use `nohup`:
   ```
   nohup node relay.js > relay.log 2>&1 &
   ```

The phone needs to stay charged and on WiFi or mobile data. WiFi is
preferable so the IP stays stable.

### On a Tanzanian VPS

Any Linux VPS in Tanzania (Liquid Telecom, ZulkaHost, AfricanLion). Install
Node 18+, clone the repo, set up `.env`, run with `pm2` or `systemd`.

```
sudo npm install -g pm2
cd aztv-token-service/relay
pm2 start relay.js --name aztv-relay
pm2 save
pm2 startup    # follow the printed command to install boot script
```

## When does the Bearer expire?

The Bearer (the long string in `.env`) is your AzamMax web session token.
Lifespan ~30 days. When it expires, the relay logs:

```
✗ Attempt 1/4 failed: BEARER is expired — re-capture from web.azamtvmax.com and update .env
```

Refresh it: log into web.azamtvmax.com again, capture the new
authorization header from DevTools, paste into `.env`, restart the relay.

`SUBSCRIPTION_DTL` and `CONTENT_DTL` change less often — usually just when
your subscription renews or AzamTV updates their backend. Capture all
three together when refreshing.

## Troubleshooting

- **"BEARER is expired"** → re-capture from web.azamtvmax.com.
- **"cdnblncr did not redirect (HTTP 403)"** → this box's IP is on the
  blocklist. Try a different residential IP, or check if you have a VPN
  on (turn it off).
- **"push HTTP 403: bad push secret"** → `PUSH_SECRET` in `.env` doesn't
  match the env var on Render. Fix one or the other.
- **"push HTTP ... fetch error"** → the service may be sleeping (free
  tier idle). Wait 30s and the next retry should wake it.

## Security notes

- `.env` contains your AzamMax credentials. Never commit it.
- `PUSH_SECRET` is the only thing protecting Render's push endpoint —
  pick a strong random value.
- The magic JWT itself is only useful for ~12h and only for streaming —
  it cannot be used to access your AzamMax account.
