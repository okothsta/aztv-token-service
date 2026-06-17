// AZTV Token Service — single-tenant, API-key gated cdnedgch2 token vendor.
//
// Endpoints:
//   GET  /                       redirects to /admin/
//   GET  /healthz                liveness probe (used by Render keep-alive ping)
//
//   GET  /api/token              CUSTOMER endpoint — current cdnedgch2 path-token
//   GET  /api/play/:channel      CUSTOMER endpoint — full URL + DRM keys helper
//
//   GET  /admin/login            ADMIN login page
//   POST /admin/login            ADMIN login submit
//   POST /admin/logout           ADMIN logout
//   GET  /admin/                 ADMIN dashboard (status + paste forms + key list)
//   POST /admin/api/credentials  ADMIN save Bearer + payload (parses messy text)
//   POST /admin/api/refresh      ADMIN trigger immediate token mint
//   GET  /admin/api/status       ADMIN status JSON (token, creds, keys)
//   POST /admin/api/keys         ADMIN create new API key (returns plaintext ONCE)
//   POST /admin/api/keys/:id     ADMIN toggle disable
//   DELETE /admin/api/keys/:id   ADMIN delete key

const express = require('express');
const path    = require('path');
const rateLimit = require('express-rate-limit');

const store  = require('./src/store');
const auth   = require('./src/auth');
const parse  = require('./src/parse');
const minter = require('./src/minter');

const PORT = parseInt(process.env.PORT, 10) || 3000;
const REFRESH_HOURS = parseInt(process.env.TOKEN_REFRESH_HOURS, 10) || 10;
const REFRESH_INTERVAL_MS = REFRESH_HOURS * 60 * 60 * 1000;

const app = express();
app.disable('x-powered-by');
// Render terminates TLS at its proxy; trust X-Forwarded-* so rate-limit + Secure cookies behave.
app.set('trust proxy', 1);

// ─────────── Security headers (applied to every response) ───────────
// No external dependency (helmet) needed — these are the high-value ones.
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');      // stop MIME sniffing
    res.setHeader('X-Frame-Options', 'DENY');                // block clickjacking of the admin panel
    res.setHeader('Referrer-Policy', 'no-referrer');         // don't leak the admin URL
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    // Strict transport security only matters over HTTPS (Render serves TLS).
    if (process.env.NODE_ENV === 'production' || process.env.RENDER) {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    // CSP for the admin HTML pages. The dashboard uses one inline <script> and
    // inline styles, so we allow 'unsafe-inline' for those but lock everything
    // else down to same-origin. This blocks injected external scripts.
    if (req.path === '/admin/' || req.path === '/admin/login') {
        res.setHeader('Content-Security-Policy',
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    }
    next();
});

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// Try to init Firestore eagerly so we fail fast on misconfig.
try { store.initFirestore(); console.log('🔥 Firestore initialized'); }
catch (e) { console.error('❌ Firestore init failed:', e.message); }

// ─────────── Background mint loop ───────────
let _mintInFlight = null;
let _lastMintAt = 0;
let _lastMintError = null;

async function mintAndStore(source) {
    if (_mintInFlight) return _mintInFlight;
    _mintInFlight = (async () => {
        try {
            const creds = await store.getCredentials();
            if (!creds || !creds.bearer) {
                throw new Error('No credentials saved yet — admin must paste them.');
            }
            const result = await minter.mintToken(creds);
            await store.setCurrentToken(result.jwt, result.exp, source || 'auto');
            _lastMintAt = Date.now();
            _lastMintError = null;
            const remaining = result.exp - Math.floor(Date.now() / 1000);
            console.log(`✅ Minted token (source=${source || 'auto'}). Lifespan ${Math.round(remaining/60)}m. exp=${new Date(result.exp*1000).toISOString()}`);
            return result;
        } catch (e) {
            _lastMintError = { at: Date.now(), message: e.message };
            console.error('❌ Mint failed:', e.message);
            throw e;
        }
    })().finally(() => { _mintInFlight = null; });
    return _mintInFlight;
}

async function startMintLoop() {
    // Immediate mint on startup (best-effort).
    try { await mintAndStore('startup'); }
    catch (_) { /* keep going; admin may need to paste creds */ }

    // Schedule recurring refresh.
    setInterval(() => {
        mintAndStore('scheduled').catch(() => {});
    }, REFRESH_INTERVAL_MS);
    console.log(`🔁 Auto-mint loop running every ${REFRESH_HOURS}h`);
}

// ─────────── Healthz ───────────
app.get('/healthz', (_req, res) => {
    res.json({ ok: true, ts: Date.now() });
});

// ─────────── Static admin assets ───────────
app.use('/admin/static', express.static(path.join(__dirname, 'public')));

// ─────────── Push endpoint for the residential relay ───────────
// This route is mounted BEFORE the admin gate so the relay (which
// authenticates with PUSH_SECRET, not the admin login) can reach it.
// A small script runs on a residential ISP (laptop / phone with Termux /
// Tanzanian VPS) and POSTs freshly-minted magic JWTs here. Authenticated by
// PUSH_SECRET — totally separate from ADMIN_PASSWORD so the relay is unattended.
const PUSH_SECRET = process.env.PUSH_SECRET || '';
if (!PUSH_SECRET || PUSH_SECRET.length < 16) {
    console.warn('⚠️  PUSH_SECRET is missing or too short. /api/push-token will refuse all pushes.');
}
const pushTokenHandler = async (req, res) => {
    // Shared-secret auth (header preferred, body fallback for tooling)
    const presented = req.get('x-push-secret') || (req.body && req.body.secret) || '';
    const a = Buffer.from(String(presented), 'utf8');
    const b = Buffer.from(String(PUSH_SECRET), 'utf8');
    if (!PUSH_SECRET || a.length !== b.length || !require('crypto').timingSafeEqual(a, b)) {
        return res.status(403).json({ ok: false, error: 'bad push secret' });
    }
    const jwt = (req.body && req.body.jwt) ? String(req.body.jwt).trim() : '';
    if (!jwt || !jwt.startsWith('eyJ')) {
        return res.status(400).json({ ok: false, error: 'missing or invalid jwt field' });
    }
    // Decode exp from payload
    let exp = 0;
    try {
        const b64 = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        const payload = JSON.parse(Buffer.from(b64 + '='.repeat((4 - b64.length % 4) % 4), 'base64').toString('utf8'));
        exp = parseInt(payload.exp, 10) || 0;
    } catch (_) {}
    if (!exp) return res.status(400).json({ ok: false, error: 'jwt has no parseable exp' });
    if (exp * 1000 < Date.now()) return res.status(400).json({ ok: false, error: 'jwt is already expired' });

    await store.setCurrentToken(jwt, exp, 'relay');
    _lastMintAt = Date.now();
    _lastMintError = null;
    const remaining = exp - Math.floor(Date.now() / 1000);
    console.log(`📥 Token pushed by relay. Lifespan ${Math.round(remaining/60)}m. exp=${new Date(exp*1000).toISOString()}`);
    res.json({ ok: true, exp, lifespanMinutes: Math.round(remaining/60) });
};
// Mount on both the new clean path AND the legacy path so existing relays
// configured with the old URL keep working.
app.post('/api/push-token', pushTokenHandler);
app.post('/admin/api/push-token-legacy', pushTokenHandler);  // not under requireAdmin gate

// ─────────── Customer API (rate-limited + key-gated) ───────────
const customerLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,                  // 60 req/min per IP — prevents abuse
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Rate limit exceeded' }
});

app.get('/api/token', customerLimiter, auth.requireApiKey, async (_req, res) => {
    const t = await store.getCurrentToken();
    if (!t || !t.jwt) return res.status(503).json({ error: 'No token available yet' });
    res.set('Cache-Control', 'no-store');
    res.json({
        token: t.jwt,
        exp: t.exp,
        cdnHost: 'https://cdnedgch2.azamtvltd.co.tz'
    });
});

app.get('/api/play/:channel', customerLimiter, auth.requireApiKey, async (req, res) => {
    const t = await store.getCurrentToken();
    if (!t || !t.jwt) return res.status(503).json({ error: 'No token available yet' });
    const ch = String(req.params.channel || '').replace(/[^A-Za-z0-9_]/g, '');
    if (!ch) return res.status(400).json({ error: 'Invalid channel name' });
    res.set('Cache-Control', 'no-store');
    res.json({
        url: `https://cdnedgch2.azamtvltd.co.tz/tok_${t.jwt}/live/eds/${ch}/DASH/${ch}.mpd`,
        exp: t.exp
    });
});

// ─────────── Admin auth pages ───────────
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many login attempts. Wait 5 minutes.'
});

app.get('/admin/login', (_req, res) => {
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(loginHtml(''));
});

app.post('/admin/login', loginLimiter, (req, res) => {
    const { password } = req.body || {};
    if (!auth.passwordMatches(password)) {
        res.set('Content-Type', 'text/html; charset=utf-8');
        return res.status(401).send(loginHtml('Wrong password.'));
    }
    auth.issueSessionCookie(res);
    res.redirect('/admin/');
});

app.post('/admin/logout', (_req, res) => {
    auth.clearSessionCookie(res);
    res.redirect('/admin/login');
});

// ─────────── Admin protected ───────────
app.use('/admin', auth.requireAdmin);

app.get('/admin/', (_req, res) => {
    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(dashboardHtml());
});

app.get('/admin/api/status', async (_req, res) => {
    const [creds, token, keys] = await Promise.all([
        store.getCredentials(), store.getCurrentToken(), store.listApiKeys()
    ]);
    const credsSafe = creds ? {
        hasBearer:        !!creds.bearer,
        bearerExp:        creds.bearerExp || null,
        bearerIss:        creds.bearerIss || '',
        bearerIp:         creds.bearerIp || '',
        deviceId:         creds.deviceId || '',
        subscriptionDtlPreview: creds.subscriptionDtl ? creds.subscriptionDtl.substring(0, 24) + '...' : '',
        contentDtlPreview:      creds.contentDtl      ? creds.contentDtl.substring(0, 24) + '...'      : '',
        updatedAt:        creds.updatedAt || null
    } : null;
    const keysSafe = keys.map(k => ({
        id: k.id, label: k.label || '',
        disabled: !!k.disabled,
        expiresAt: k.expiresAt || null,
        requestCount: k.requestCount || 0,
        createdAt: k.createdAt || null,
        lastUsedAt: k.lastUsedAt || null
    }));
    res.json({
        credentials: credsSafe,
        token: token ? { exp: token.exp, source: token.source, mintedAt: token.mintedAt, hasJwt: !!token.jwt } : null,
        lastMintAt: _lastMintAt || null,
        lastMintError: _lastMintError,
        serverNow: Date.now(),
        keys: keysSafe
    });
});

app.post('/admin/api/credentials', async (req, res) => {
    const { headers, payload } = req.body || {};
    try {
        const parsed = parse.parsePastedCredentials(headers || '', payload || '');
        // ALWAYS save the credentials first — even if the mint test fails. This
        // way the auto-mint loop can keep retrying from Render's actual IP, and
        // logs will show the real failure reason. Trying to validate before
        // saving created a bootstrap loop where bad-mint blocked saving.
        await store.setCredentials(parsed);

        // Optional best-effort mint to give immediate feedback. Failure here
        // does NOT undo the save — admin can see the error and let the loop
        // try again on schedule.
        let result = null, mintError = null;
        try {
            result = await minter.mintToken(parsed);
            await store.setCurrentToken(result.jwt, result.exp, 'manual');
            _lastMintAt = Date.now();
            _lastMintError = null;
        } catch (e) {
            mintError = e.message || String(e);
            _lastMintError = { at: Date.now(), message: mintError };
        }

        if (result) {
            return res.json({
                ok: true,
                saved: true,
                bearerExp: parsed.bearerExp,
                tokenExp: result.exp,
                lifespanMinutes: Math.round((result.exp - Math.floor(Date.now()/1000)) / 60)
            });
        }
        // Saved but mint failed — return ok so admin sees creds are stored, but
        // include the mint error so they know the upstream is rejecting us.
        return res.json({
            ok: true,
            saved: true,
            mintWarning: mintError,
            bearerExp: parsed.bearerExp
        });
    } catch (e) {
        return res.status(400).json({ ok: false, error: e.message });
    }
});

// Build a ready-to-paste Termux relay config from a messy DevTools blob.
// The admin pastes ONE blob (payload + headers together, however messy). The
// server parses out BEARER / SUBSCRIPTION_DTL / CONTENT_DTL, and injects the
// server-known PUSH_SECRET + SERVICE_URL so the generated .env is ALWAYS
// correct — no more "bad push secret" mismatches.
app.post('/admin/api/relay-config', (req, res) => {
    try {
        const blob = (req.body && (req.body.blob || req.body.text)) || '';
        const headers = (req.body && req.body.headers) || blob;
        const payload = (req.body && req.body.payload) || blob;
        if (!String(headers).trim() && !String(payload).trim()) {
            return res.status(400).json({ ok: false, error: 'Paste the DevTools capture first.' });
        }
        // Reuse the same tolerant parser the credentials box uses. Passing the
        // same blob to both args works because extractBearer scans anywhere and
        // extractPayloadFields grabs the first {...} block.
        const parsed = parse.parsePastedCredentials(headers, payload);

        const refreshHours = parseInt(process.env.TOKEN_REFRESH_HOURS, 10) || 10;
        const pushSecret = PUSH_SECRET || '';
        // Prefer an explicit SERVICE_URL env, else derive from the request host.
        const host = req.get('x-forwarded-host') || req.get('host') || 'aztv-token-service.onrender.com';
        const proto = (req.get('x-forwarded-proto') || req.protocol || 'https').split(',')[0];
        const serviceUrl = (process.env.SERVICE_URL || `${proto}://${host}`).replace(/\/+$/, '');

        // ── Multi-phone redundancy ──────────────────────────────────────
        // Several phones can run the relay at once so that if some go offline,
        // others keep the token fresh. To avoid all phones minting at the same
        // instant, we stagger them: phone N waits (REFRESH_HOURS * (N-1)/TOTAL)
        // hours before its first mint, then mints every REFRESH_HOURS like the
        // rest. Pushes are idempotent (the service just keeps the newest token),
        // so overlap is harmless — it's pure safety margin.
        let relayNumber = parseInt(req.body && req.body.relayNumber, 10);
        let totalRelays = parseInt(req.body && req.body.totalRelays, 10);
        if (!Number.isFinite(relayNumber) || relayNumber < 1) relayNumber = 1;
        if (!Number.isFinite(totalRelays) || totalRelays < 1) totalRelays = 1;
        if (relayNumber > totalRelays) relayNumber = totalRelays;
        const offsetHours = totalRelays > 1
            ? Math.round((refreshHours * (relayNumber - 1) / totalRelays) * 100) / 100
            : 0;

        // profileId appears in the headers blob as e.g. "profileid24338457" or
        // "profileId: 24338457". Extract it so the relay's API calls match the
        // account; default to the known web profile if not found.
        let profileId = '24338457';
        const pidMatch = String(headers).match(/profile[_-]?id["':\s]*([0-9]{4,})/i);
        if (pidMatch) profileId = pidMatch[1];

        const envLines = [
            `SERVICE_URL=${serviceUrl}`,
            `PUSH_SECRET=${pushSecret}`,
            `BEARER=${parsed.bearer}`,
            // subscriptionDtl is auto-refreshed every cycle from currentSubscription
            // (it expires ~12h). Kept here only as a fallback if that fetch fails.
            `SUBSCRIPTION_DTL=${parsed.subscriptionDtl}`,
            `CONTENT_DTL=${parsed.contentDtl}`,
            `PROFILE_ID=${profileId}`,
            `REFRESH_HOURS=${refreshHours}`
        ];
        if (offsetHours > 0) envLines.push(`MINT_OFFSET_HOURS=${offsetHours}`);
        const envText = envLines.join('\n');

        // One-paste UPDATE script: for a phone that already has the relay
        // installed. cd, pull latest code (so it gets the auto-refresh relay),
        // stop old relay, write .env, start, tail log.
        const script =
`cd ~/aztv-token-service
git pull 2>/dev/null || echo "(git pull skipped)"
cd ~/aztv-token-service/relay
pkill -f "node relay.js"; sleep 2
cat > .env <<'AZTVCONFIG'
${envText}
AZTVCONFIG
termux-wake-lock 2>/dev/null
nohup node relay.js > relay.log 2>&1 &
sleep 1
tail -f relay.log`;

        // FIRST-TIME script: for a brand-new phone with nothing installed yet.
        // Installs Node + git, clones the repo, writes .env, starts the relay.
        const firstTimeScript =
`pkg update -y && pkg install -y nodejs git
cd ~
git clone https://github.com/okothsta/aztv-token-service.git 2>/dev/null || echo "already cloned, continuing"
cd ~/aztv-token-service/relay
cat > .env <<'AZTVCONFIG'
${envText}
AZTVCONFIG
termux-wake-lock 2>/dev/null
nohup node relay.js > relay.log 2>&1 &
sleep 1
tail -f relay.log`;

        res.json({
            ok: true,
            env: envText,
            script,
            firstTimeScript,
            relayNumber,
            totalRelays,
            offsetHours,
            refreshHours,
            bearerExp: parsed.bearerExp,
            bearerIp: parsed.bearerIp,
            pushSecretMissing: !pushSecret || pushSecret.length < 16,
            serviceUrl
        });
    } catch (e) {
        res.status(400).json({ ok: false, error: e.message });
    }
});

app.post('/admin/api/refresh', async (_req, res) => {
    try {
        const r = await mintAndStore('manual');
        res.json({ ok: true, exp: r.exp });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

app.post('/admin/api/keys', async (req, res) => {
    const label = (req.body && req.body.label) ? String(req.body.label).slice(0, 80) : '';
    const plaintext = auth.generateApiKey();
    const hash = auth.hashKey(plaintext);
    const id = require('crypto').randomBytes(8).toString('hex');
    await store.saveApiKey(id, hash, label);
    // The plaintext key is shown ONCE here. Never stored, never shown again.
    res.json({ ok: true, id, key: plaintext, label });
});

app.post('/admin/api/keys/:id', async (req, res) => {
    const { disabled } = req.body || {};
    await store.setApiKeyDisabled(req.params.id, !!disabled);
    res.json({ ok: true });
});

// Set/extend/clear a key's access deadline.
//   body { addMs }       -> add this many ms to the current deadline
//                           (or to "now" if no deadline / already expired)
//   body { setAt }       -> set the deadline to an absolute unix-ms time
//   body { clear: true } -> remove the deadline (unlimited again)
app.post('/admin/api/keys/:id/expiry', async (req, res) => {
    try {
        const body = req.body || {};
        if (body.clear) {
            await store.setApiKeyExpiry(req.params.id, null);
            return res.json({ ok: true, expiresAt: null });
        }
        if (Number.isFinite(Number(body.setAt))) {
            const at = Number(body.setAt);
            await store.setApiKeyExpiry(req.params.id, at);
            return res.json({ ok: true, expiresAt: at });
        }
        const addMs = Number(body.addMs);
        if (!Number.isFinite(addMs) || addMs <= 0) {
            return res.status(400).json({ ok: false, error: 'Provide addMs (>0), setAt, or clear:true' });
        }
        // Base the addition on the existing future deadline, else on now.
        const keys = await store.listApiKeys();
        const k = keys.find(x => x.id === req.params.id);
        if (!k) return res.status(404).json({ ok: false, error: 'Key not found' });
        const base = (k.expiresAt && Number(k.expiresAt) > Date.now()) ? Number(k.expiresAt) : Date.now();
        const next = base + addMs;
        await store.setApiKeyExpiry(req.params.id, next);
        res.json({ ok: true, expiresAt: next });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

app.delete('/admin/api/keys/:id', async (req, res) => {
    await store.deleteApiKey(req.params.id);
    res.json({ ok: true });
});

// ─────────── Root redirect ───────────
app.get('/', (_req, res) => res.redirect('/admin/'));

// ─────────── HTML templates (inline so we have one deployable folder) ───────────
function loginHtml(errMsg) {
    return `<!doctype html><html><head><meta charset="utf-8"><title>AZTV Token Service — Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>${BASE_CSS}</style></head><body class="centered">
<form method="post" action="/admin/login" class="card">
<h1>AZTV Token Service</h1>
<p class="muted">Admin login</p>
<input type="password" name="password" placeholder="Admin password" required autofocus>
<button type="submit">Sign in</button>
${errMsg ? `<p class="err">${escapeHtml(errMsg)}</p>` : ''}
</form></body></html>`;
}

function dashboardHtml() {
    return `<!doctype html><html><head><meta charset="utf-8"><title>AZTV Token Service — Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>${BASE_CSS}</style></head><body>
<header><h1>AZTV Token Service</h1>
<form method="post" action="/admin/logout" style="margin:0"><button class="ghost" type="submit">Logout</button></form>
</header>
<main>
  <div id="alert-banner"></div>
  <section class="card" id="status-card"><h2>Status</h2><div id="health-badges" class="badges"></div><div id="status">loading…</div>
    <div class="row"><button id="refresh-btn">Mint new token now</button></div>
  </section>

  <section class="card"><h2>1. Paste credentials from web.azamtvmax.com</h2>
    <p class="muted">Open <code>web.azamtvmax.com</code>, sign in, play any channel. Then in DevTools Network tab, click the <code>authToken</code> request. Copy the <b>Request Headers</b> raw text into box 1 and the <b>Payload (view source)</b> raw text into box 2. Click Save.</p>
    <label>Request Headers (paste raw)</label>
    <textarea id="headers" rows="8" placeholder=":authority: api.aztv.videoready.tv\nauthorization: Bearer eyJ..."></textarea>
    <label>Payload — view source (paste raw)</label>
    <textarea id="payload" rows="6" placeholder='{"offlineDownload":false,"subscriptionDtl":"...","contentDtl":"...","deviceId":"..."}'></textarea>
    <div class="row"><button id="save-creds-btn">Save and validate</button><span id="save-status" class="muted"></span></div>
  </section>

  <section class="card"><h2>1b. Termux relay setup (one-paste generator)</h2>
    <p class="muted">If this server's host is geo-blocked, the relay must run on a residential IP (an Android phone with Termux). Paste the <b>same DevTools capture</b> below (the whole messy blob — payload and headers together, however you copied it). The server cleans it up and fills in the push secret + service URL automatically, so it's always correct. The relay then auto-refreshes the subscription detail every cycle, so it runs hands-off until the Bearer expires (~monthly).</p>
    <label>Paste DevTools capture (payload + headers, any mess)</label>
    <textarea id="relay-blob" rows="6" placeholder='Paste everything you copied from the authToken request here — payload JSON and request headers together is fine.'></textarea>
    <p class="muted" style="margin-top:14px"><b>Running several phones for backup?</b> So the relay never goes down, you can run it on several phones at once. If one phone dies, the others keep the token fresh. Tell each phone its number so they take turns minting (no clashes).</p>
    <div class="row">
      <label style="margin:0">This phone is number
        <input id="relay-number" type="number" min="1" value="1" style="width:70px;display:inline-block">
      </label>
      <label style="margin:0">out of total phones
        <input id="relay-total" type="number" min="1" value="1" style="width:70px;display:inline-block">
      </label>
    </div>
    <p class="muted">Example: 4 phones → phone 1 = (1, 4), phone 2 = (2, 4), phone 3 = (3, 4), phone 4 = (4, 4). Generate once per phone, changing only "this phone is number".</p>
    <div class="row"><button id="gen-relay-btn">Generate Termux commands</button><span id="relay-status" class="muted"></span></div>
    <div id="relay-out"></div>
  </section>

  <section class="card"><h2>2. API keys for customers</h2>
    <p class="muted">Each customer gets one key. Send it to them as <code>X-Api-Key: &lt;key&gt;</code> header (or <code>?key=&lt;key&gt;</code> query). The plaintext is shown <b>once</b> on creation — store it safely.</p>
    <div class="row"><input id="key-label" placeholder="Label (e.g. Friend John, MyApp staging)"><button id="create-key-btn">Generate new API key</button></div>
    <div id="new-key-out"></div>
    <table id="keys-table"><thead><tr><th>Label</th><th>Requests</th><th>Last used</th><th>Access expires</th><th>State</th><th></th></tr></thead><tbody></tbody></table>
  </section>

  <section class="card"><h2>How to integrate</h2>
    <pre>GET https://${''}YOUR-SERVICE-URL/api/token
Headers: X-Api-Key: &lt;your-key&gt;

Response:
{
  "token": "eyJhbGciOiJIUzUxMiI...",
  "exp": 1781999999,
  "cdnHost": "https://cdnedgch2.azamtvltd.co.tz"
}

Build the play URL:
  https://cdnedgch2.azamtvltd.co.tz/tok_&lt;token&gt;/live/eds/&lt;Channel&gt;/DASH/&lt;Channel&gt;.mpd

Or use the helper endpoint:
  GET /api/play/:channel    (returns the full URL ready-to-play)</pre>
  </section>
</main>
<script>${DASHBOARD_JS}</script>
</body></html>`;
}

const BASE_CSS = `
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; background:#0a0a0a; color:#eee; font-family:system-ui,-apple-system,Segoe UI,sans-serif; line-height:1.5; }
body.centered { display:flex; align-items:center; justify-content:center; min-height:100vh; padding:24px; }
header { display:flex; align-items:center; justify-content:space-between; padding:16px 24px; border-bottom:1px solid #222; }
header h1 { font-size:18px; margin:0; }
main { max-width:920px; margin:0 auto; padding:24px; display:grid; gap:20px; }
.card { background:#141414; border:1px solid #222; border-radius:10px; padding:20px; }
.card h2 { margin-top:0; font-size:16px; }
.muted { color:#888; font-size:13px; }
input, textarea, button { font:inherit; }
input[type=text], input[type=password], input:not([type]), textarea {
  width:100%; background:#0a0a0a; color:#eee; border:1px solid #2a2a2a; border-radius:6px; padding:10px 12px; margin-top:4px; }
textarea { font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; resize:vertical; }
label { display:block; font-size:12px; color:#aaa; margin-top:10px; }
button { background:#2c7be5; color:#fff; border:0; border-radius:6px; padding:10px 16px; cursor:pointer; }
button:hover { background:#1f5fb5; }
button.ghost { background:transparent; border:1px solid #333; color:#ccc; }
button.danger { background:#9b1c1c; }
.row { display:flex; gap:8px; align-items:center; margin-top:12px; flex-wrap:wrap; }
.err { color:#ff6b6b; }
.ok { color:#5cf09a; }
.warn { color:#ffb74d; }
table { width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }
th, td { text-align:left; padding:8px 6px; border-bottom:1px solid #222; }
th { color:#aaa; font-weight:500; }
code, pre { font-family: ui-monospace,SFMono-Regular,Menlo,monospace; }
pre { background:#0a0a0a; border:1px solid #222; border-radius:6px; padding:12px; font-size:12px; overflow:auto; }
.kv { display:grid; grid-template-columns:max-content 1fr; gap:6px 16px; font-size:13px; margin-top:8px; }
.kv b { color:#aaa; font-weight:500; }
.new-key { background:#1a2f1a; border:1px solid #2c5c2c; padding:12px; border-radius:6px; margin-top:12px; font-family:ui-monospace,monospace; word-break:break-all; }
.keydetail { background:#0d0d0d; border:1px solid #222; border-radius:6px; padding:14px; }
.badges { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px; }
.badge { font-size:12px; padding:4px 10px; border-radius:999px; border:1px solid #333; display:inline-flex; align-items:center; gap:6px; }
.badge.good { background:#10240f; border-color:#2c5c2c; color:#5cf09a; }
.badge.bad  { background:#2a0f0f; border-color:#6b1c1c; color:#ff8a8a; }
.badge.warn { background:#2a230f; border-color:#6b561c; color:#ffce6b; }
.banner { padding:14px 16px; border-radius:8px; margin-bottom:16px; font-size:14px; }
.banner.bad  { background:#2a0f0f; border:1px solid #6b1c1c; color:#ff8a8a; }
.banner.warn { background:#2a230f; border:1px solid #6b561c; color:#ffce6b; }
`;

const DASHBOARD_JS = `
async function jget(u){const r=await fetch(u);if(!r.ok)throw new Error(r.status);return r.json();}
async function jpost(u,b){const r=await fetch(u,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b||{})});return r.json();}
async function jdel(u){const r=await fetch(u,{method:'DELETE'});return r.json();}
function fmtTs(t){if(!t)return '—';if(typeof t==='object'&&t._seconds)t=t._seconds*1000;return new Date(t).toLocaleString();}
function tsToMs(t){if(!t)return 0;if(typeof t==='object'&&t._seconds)return t._seconds*1000;var n=Number(t);return isNaN(n)?0:n;}
function fmtAgo(ms){if(!ms)return '—';var d=Date.now()-ms;if(d<0)d=0;return fmtDuration(d)+' ago';}
function fmtExp(s){if(!s)return '—';const r=parseInt(s,10)-Math.floor(Date.now()/1000);return new Date(parseInt(s,10)*1000).toLocaleString()+' ('+(r>0?Math.round(r/60)+'m left':'EXPIRED')+')';}
function fmtDuration(ms){if(ms<=0)return '0s';var s=Math.floor(ms/1000);var d=Math.floor(s/86400);s-=d*86400;var h=Math.floor(s/3600);s-=h*3600;var m=Math.floor(s/60);s-=m*60;var parts=[];if(d)parts.push(d+'d');if(h)parts.push(h+'h');if(m)parts.push(m+'m');parts.push(s+'s');return parts.slice(0,3).join(' ');}
function fmtAccess(expiresAt){
  if(!expiresAt)return '<span class="muted">unlimited</span>';
  var at=Number(expiresAt);var rem=at-Date.now();
  if(rem<=0)return '<span class="err" data-exp="'+at+'">ENDED '+new Date(at).toLocaleString()+'</span>';
  var cls=rem<3600000?'warn':'ok';
  return '<span class="'+cls+'" data-exp="'+at+'">'+fmtDuration(rem)+' left<br><small class="muted">'+new Date(at).toLocaleString()+'</small></span>';
}
function copyText(txt, btn, label){
  function done(){const o=btn.textContent;btn.textContent='✓ Copied';setTimeout(function(){btn.textContent=label||o;},1500);}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done,function(){fallback();});}
  else fallback();
  function fallback(){const ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');}catch(e){}document.body.removeChild(ta);done();}
}

async function refreshStatus(){
  const s=await jget('/admin/api/status');
  const c=s.credentials, t=s.token;
  let html='';
  if(!c){html+='<p class="warn">No credentials saved yet. Paste them below.</p>';}
  else{html+='<div class="kv">';
    html+='<b>Bearer expires:</b><span>'+fmtExp(c.bearerExp)+'</span>';
    html+='<b>Bearer ipAddress:</b><span>'+c.bearerIp+'</span>';
    html+='<b>Bearer iss:</b><span>'+c.bearerIss+'</span>';
    html+='<b>deviceId:</b><span>'+(c.deviceId||'—')+'</span>';
    html+='<b>subscriptionDtl:</b><span><code>'+c.subscriptionDtlPreview+'</code></span>';
    html+='<b>contentDtl:</b><span><code>'+c.contentDtlPreview+'</code></span>';
    html+='<b>creds saved at:</b><span>'+fmtTs(c.updatedAt)+'</span>';
  html+='</div>';}
  if(t){html+='<div class="kv" style="margin-top:14px">';
    html+='<b>Current token exp:</b><span>'+fmtExp(t.exp)+'</span>';
    html+='<b>Source:</b><span>'+t.source+'</span>';
    html+='<b>Minted at:</b><span>'+fmtTs(t.mintedAt)+'</span>';
  html+='</div>';}
  if(s.lastMintError){html+='<p class="err">Last mint error: '+s.lastMintError.message+'</p>';}
  document.getElementById('status').innerHTML=html;

  // ── Health badges + alert banners ──
  var badges=[]; var banners=[];
  var nowMs=s.serverNow||Date.now();
  // Token health
  if(t && t.exp){var tRem=parseInt(t.exp,10)*1000-nowMs;
    if(tRem>0)badges.push('<span class="badge good">● Token valid '+fmtDuration(tRem)+'</span>');
    else badges.push('<span class="badge bad">● Token EXPIRED</span>');
  } else badges.push('<span class="badge bad">● No token</span>');
  // Relay health (last push/mint time)
  if(s.lastMintAt){var rAgo=nowMs-s.lastMintAt;
    if(rAgo<13*3600000)badges.push('<span class="badge good">● Relay pushed '+fmtDuration(rAgo)+' ago</span>');
    else badges.push('<span class="badge bad">● Relay silent '+fmtDuration(rAgo)+'</span>');
    if(rAgo>=13*3600000)banners.push(['bad','⚠ No fresh token in '+fmtDuration(rAgo)+'. All relay phones may be offline — customers will stop streaming soon. Check the Termux phones.']);
  } else badges.push('<span class="badge warn">● Relay never pushed</span>');
  // Bearer expiry
  if(c && c.bearerExp){var bRem=parseInt(c.bearerExp,10)*1000-nowMs;
    if(bRem<=0){badges.push('<span class="badge bad">● Bearer EXPIRED</span>');banners.push(['bad','⛔ The Bearer has EXPIRED. Minting is dead until you recapture it from web.azamtvmax.com and paste it above.']);}
    else if(bRem<3*86400000){badges.push('<span class="badge warn">● Bearer expires in '+fmtDuration(bRem)+'</span>');banners.push(['warn','⚠ Bearer expires in '+fmtDuration(bRem)+'. Recapture it from web.azamtvmax.com soon, or the whole system stops when it lapses.']);}
    else badges.push('<span class="badge good">● Bearer valid '+fmtDuration(bRem)+'</span>');
  }
  document.getElementById('health-badges').innerHTML=badges.join('');
  document.getElementById('alert-banner').innerHTML=banners.map(function(b){return '<div class="banner '+b[0]+'">'+b[1]+'</div>';}).join('');

  // keys
  const tb=document.querySelector('#keys-table tbody'); tb.innerHTML='';
  window.__keys = s.keys;
  s.keys.forEach(k=>{
    const tr=document.createElement('tr');
    var lastMs=tsToMs(k.lastUsedAt);
    tr.innerHTML='<td>'+(k.label||'(no label)')+'<br><small class="muted">'+k.id+'</small></td>'+
      '<td>'+(k.requestCount||0)+'</td>'+
      '<td>'+(lastMs?('<span data-ago="'+lastMs+'">'+fmtAgo(lastMs)+'</span><br><small class="muted">'+new Date(lastMs).toLocaleString()+'</small>'):'<span class="muted">never</span>')+'</td>'+
      '<td>'+fmtAccess(k.expiresAt)+'</td>'+
      '<td>'+(k.disabled?'<span class="warn">disabled</span>':'<span class="ok">active</span>')+'</td>'+
      '<td><button class="ghost" data-eye="'+k.id+'">👁</button> '+
          '<button class="ghost" data-toggle="'+k.id+'" data-disabled="'+(!!k.disabled)+'">'+(k.disabled?'Enable':'Disable')+'</button> '+
          '<button class="danger" data-delete="'+k.id+'">Delete</button></td>';
    tb.appendChild(tr);
    // hidden detail/expiry row
    var createdMs=tsToMs(k.createdAt);
    var reqCount=k.requestCount||0;
    var ageMs=createdMs?(Date.now()-createdMs):0;
    var ageDays=ageMs/86400000;
    var perDay=ageDays>=0.5?(reqCount/ageDays):reqCount;
    var perHour=ageMs>=3600000?(reqCount/(ageMs/3600000)):reqCount;
    var dr=document.createElement('tr');
    dr.id='detail-'+k.id; dr.style.display='none';
    dr.innerHTML='<td colspan="6"><div class="keydetail">'+
      '<div class="kv">'+
        '<b>Key ID:</b><span>'+k.id+'</span>'+
        '<b>Label:</b><span>'+(k.label||'(no label)')+'</span>'+
        '<b>Created:</b><span>'+fmtTs(k.createdAt)+(createdMs?(' <small class="muted">('+fmtAgo(createdMs)+')</small>'):'')+'</span>'+
        '<b>Last used:</b><span>'+(lastMs?('<span data-ago="'+lastMs+'">'+fmtAgo(lastMs)+'</span> <small class="muted">('+new Date(lastMs).toLocaleString()+')</small>'):'never')+'</span>'+
        '<b>Total requests:</b><span>'+reqCount+'</span>'+
        '<b>Avg per day:</b><span>'+(createdMs?perDay.toFixed(1):'—')+'</span>'+
        '<b>Avg per hour:</b><span>'+(createdMs?perHour.toFixed(2):'—')+'</span>'+
        '<b>Active for:</b><span>'+(createdMs?fmtDuration(ageMs):'—')+'</span>'+
        '<b>State:</b><span>'+(k.disabled?'disabled':'active')+'</span>'+
        '<b>Access expires:</b><span>'+fmtAccess(k.expiresAt)+'</span>'+
        '<b>Secret key:</b><span class="muted">hidden (stored hashed — not recoverable)</span>'+
      '</div>'+
      '<div class="row" style="margin-top:10px"><b style="font-size:12px;color:#aaa">Add access time:</b>'+
        '<button class="ghost" data-add="'+k.id+'" data-ms="'+(60*60*1000)+'">+1 hour</button>'+
        '<button class="ghost" data-add="'+k.id+'" data-ms="'+(24*60*60*1000)+'">+1 day</button>'+
        '<button class="ghost" data-add="'+k.id+'" data-ms="'+(7*24*60*60*1000)+'">+7 days</button>'+
        '<button class="ghost" data-add="'+k.id+'" data-ms="'+(30*24*60*60*1000)+'">+30 days</button>'+
        '<button class="danger" data-clear="'+k.id+'">Remove deadline (unlimited)</button>'+
      '</div></div></td>';
    tb.appendChild(dr);
  });
}

document.addEventListener('click', async (e)=>{
  const t=e.target;
  if(t.id==='refresh-btn'){t.disabled=true;t.textContent='Minting…';
    const r=await jpost('/admin/api/refresh');t.disabled=false;t.textContent='Mint new token now';
    if(!r.ok)alert('Refresh failed: '+r.error); refreshStatus();}
  else if(t.id==='save-creds-btn'){const headers=document.getElementById('headers').value;const payload=document.getElementById('payload').value;
    const st=document.getElementById('save-status');st.textContent='Validating…';st.className='muted';
    t.disabled=true; const r=await jpost('/admin/api/credentials',{headers,payload}); t.disabled=false;
    if(r.ok && r.lifespanMinutes){st.textContent='✓ Saved. Token lifespan: '+r.lifespanMinutes+' min.';st.className='ok';refreshStatus();}
    else if(r.ok && r.mintWarning){st.textContent='⚠ Credentials saved but mint failed: '+r.mintWarning+' — see logs / status panel for next steps.';st.className='warn';refreshStatus();}
    else if(r.ok){st.textContent='✓ Saved. (No mint result yet, see status panel.)';st.className='ok';refreshStatus();}
    else{st.textContent='✗ '+r.error;st.className='err';}}
  else if(t.id==='create-key-btn'){const label=document.getElementById('key-label').value;
    const r=await jpost('/admin/api/keys',{label});
    if(r.ok){
      const out=document.getElementById('new-key-out');
      out.innerHTML='<div class="new-key"><b>NEW API KEY (shown ONCE — copy now):</b><br><span id="newkey-val">'+r.key+'</span><br><button class="ghost" id="copy-newkey-btn" style="margin-top:8px">Copy key</button></div>';
      window.__newKey=r.key;
      document.getElementById('key-label').value=''; refreshStatus();
    } else alert('Failed: '+(r.error||'unknown'));}
  else if(t.id==='copy-newkey-btn'){copyText(window.__newKey, t, 'Copy key');}
  else if(t.id==='gen-relay-btn'){const blob=document.getElementById('relay-blob').value;
    const relayNumber=parseInt(document.getElementById('relay-number').value,10)||1;
    const totalRelays=parseInt(document.getElementById('relay-total').value,10)||1;
    const st=document.getElementById('relay-status');st.textContent='Parsing…';st.className='muted';
    t.disabled=true; const r=await jpost('/admin/api/relay-config',{blob,relayNumber,totalRelays}); t.disabled=false;
    const out=document.getElementById('relay-out');
    if(!r.ok){st.textContent='✗ '+r.error;st.className='err';out.innerHTML='';return;}
    st.textContent='✓ Generated for phone '+r.relayNumber+' of '+r.totalRelays+'. Copy a command below into Termux.';st.className='ok';
    var warn = r.pushSecretMissing ? '<p class="err">⚠ PUSH_SECRET is not set on this server. Set the PUSH_SECRET env var on Render (16+ chars) and regenerate, or pushes will be rejected.</p>' : '';
    var expTxt = r.bearerExp ? fmtExp(r.bearerExp) : '—';
    var staggerTxt = r.offsetHours>0 ? ('Phone '+r.relayNumber+' of '+r.totalRelays+' — waits '+r.offsetHours+'h before its first mint, then every '+(r.refreshHours||10)+'h. This staggers the phones so they take turns.') : 'Single phone — mints immediately, then every cycle.';
    out.innerHTML =
      warn +
      '<div class="kv" style="margin-top:12px"><b>This phone:</b><span>number '+r.relayNumber+' of '+r.totalRelays+'</span>'+
      '<b>Schedule:</b><span>'+staggerTxt+'</span>'+
      '<b>Service URL:</b><span>'+r.serviceUrl+'</span>'+
      '<b>Bearer expires:</b><span>'+expTxt+'</span>'+
      '<b>Relay IP (from Bearer):</b><span>'+(r.bearerIp||'—')+'</span></div>'+
      '<h3 style="margin:18px 0 4px;font-size:14px">▶ Brand-new phone (nothing installed yet)</h3>'+
      '<p class="muted">Install Termux from F-Droid first (not Play Store). Open it, then paste this ONE block. It installs everything, downloads the relay, and starts it.</p>'+
      '<pre id="relay-firstscript"></pre>'+
      '<div class="row"><button id="copy-first-btn">Copy first-time setup command</button></div>'+
      '<h3 style="margin:22px 0 4px;font-size:14px">▶ Phone that already has the relay (just updating tokens)</h3>'+
      '<p class="muted">If this phone already ran the relay before, paste this shorter block instead. It refreshes the tokens and restarts.</p>'+
      '<pre id="relay-script"></pre>'+
      '<div class="row"><button id="copy-script-btn">Copy update command</button>'+
      '<button class="ghost" id="copy-env-btn">Copy .env only</button></div>'+
      '<h3 style="margin:22px 0 4px;font-size:14px">After pasting</h3>'+
      '<p class="muted">You should see <span class="ok">↻ Refreshed subscriptionDtl</span>, then <span class="ok">✓ Minted magic JWT</span>, then <span class="ok">✓ Service accepted token</span>. That phone is now live and keeps itself fresh automatically — it re-fetches the subscription detail every cycle, so you only need to come back here when the Bearer expires (about once a month). Press Ctrl+C to stop watching the log — the relay keeps running in the background. To keep it alive: Android Settings → Apps → Termux → Battery → Unrestricted.</p>';
    document.getElementById('relay-firstscript').textContent = r.firstTimeScript;
    document.getElementById('relay-script').textContent = r.script;
    window.__relayScript = r.script; window.__relayEnv = r.env; window.__relayFirst = r.firstTimeScript;
  }
  else if(t.id==='copy-first-btn'){copyText(window.__relayFirst, t, 'Copy first-time setup command');}
  else if(t.id==='copy-script-btn'){copyText(window.__relayScript, t, 'Copy update command');}
  else if(t.id==='copy-env-btn'){copyText(window.__relayEnv, t, 'Copy .env only');}
  else if(t.dataset.eye){const id=t.dataset.eye;const dr=document.getElementById('detail-'+id);
    if(dr)dr.style.display=(dr.style.display==='none'?'table-row':'none');}
  else if(t.dataset.add){const id=t.dataset.add;const ms=parseInt(t.dataset.ms,10);
    t.disabled=true;const r=await jpost('/admin/api/keys/'+id+'/expiry',{addMs:ms});t.disabled=false;
    if(!r.ok)alert('Failed: '+r.error);else refreshStatus();}
  else if(t.dataset.clear){const id=t.dataset.clear;if(!confirm('Remove the access deadline? This key will work with no time limit.'))return;
    const r=await jpost('/admin/api/keys/'+id+'/expiry',{clear:true});
    if(!r.ok)alert('Failed: '+r.error);else refreshStatus();}
  else if(t.dataset.toggle){const id=t.dataset.toggle;const wasDisabled=t.dataset.disabled==='true';
    await jpost('/admin/api/keys/'+id,{disabled:!wasDisabled}); refreshStatus();}
  else if(t.dataset.delete){const id=t.dataset.delete;if(!confirm('Delete this key permanently?'))return;
    await jdel('/admin/api/keys/'+id); refreshStatus();}
});

refreshStatus();
setInterval(refreshStatus, 15000);
// Live countdown + last-used stopwatch: update every second without refetching.
setInterval(function(){
  document.querySelectorAll('[data-exp]').forEach(function(el){
    var at=Number(el.getAttribute('data-exp'));var rem=at-Date.now();
    if(rem<=0){el.className='err';el.innerHTML='ENDED '+new Date(at).toLocaleString();}
    else{el.className=rem<3600000?'warn':'ok';el.innerHTML=fmtDuration(rem)+' left<br><small class="muted">'+new Date(at).toLocaleString()+'</small>';}
  });
  document.querySelectorAll('[data-ago]').forEach(function(el){
    var ms=Number(el.getAttribute('data-ago'));
    el.textContent=fmtAgo(ms);
  });
}, 1000);
`;

function escapeHtml(s){return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

// ─────────── Boot ───────────
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 AZTV Token Service listening on :${PORT}`);
    startMintLoop();
});
