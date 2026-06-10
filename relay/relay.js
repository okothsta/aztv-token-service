#!/usr/bin/env node
/**
 * AZTV Token Relay
 * ----------------
 * A tiny script that runs on a RESIDENTIAL IP (your laptop, an Android phone
 * with Termux, a friend's home computer, a Tanzanian VPS). It mints a fresh
 * magic cdnedgch2 JWT every N hours and pushes it to your Render-hosted
 * AZTV Token Service.
 *
 * Why this exists:
 *   cdnblncr.azamtvltd.co.tz blocks cloud datacenter IPs (Render, GCP,
 *   Cloudflare, etc.). Residential ISP IPs are accepted. Since the token
 *   service must run on a public host but minting requires a residential IP,
 *   we split: the service stores + serves tokens, this relay supplies them.
 *
 * Setup:
 *   1. Copy .env.example to .env in this folder and fill in:
 *        SERVICE_URL    -> https://your-aztv.onrender.com
 *        PUSH_SECRET    -> the secret you set on the service (matches PUSH_SECRET env var on Render)
 *        BEARER         -> Bearer JWT from web.azamtvmax.com DevTools
 *        SUBSCRIPTION_DTL -> from the same Payload
 *        CONTENT_DTL      -> from the same Payload
 *   2. node relay.js
 *
 * Output: a log line every mint+push cycle. Stop with Ctrl+C.
 */

const https = require('https');
const fs    = require('fs');
const path  = require('path');

// ─── Config ─────────────────────────────────────────────────────────────
loadDotEnvIfPresent();

const SERVICE_URL    = required('SERVICE_URL');     // https://aztv-token-service.onrender.com
const PUSH_SECRET    = required('PUSH_SECRET');
const BEARER         = required('BEARER');
const SUBSCRIPTION_DTL = required('SUBSCRIPTION_DTL');
const CONTENT_DTL    = required('CONTENT_DTL');

// How often to mint. The magic JWT lives ~12h; we refresh well before expiry.
const REFRESH_HOURS = parseFloat(process.env.REFRESH_HOURS || '10');
const REFRESH_MS    = REFRESH_HOURS * 60 * 60 * 1000;

// Retry behaviour on failure (e.g. transient network or upstream hiccup).
const RETRY_ATTEMPTS = parseInt(process.env.RETRY_ATTEMPTS || '4', 10);
const RETRY_BACKOFF_MS = parseInt(process.env.RETRY_BACKOFF_MS || '60000', 10); // 1 min

// ─── Helpers ────────────────────────────────────────────────────────────
function loadDotEnvIfPresent() {
    const p = path.join(__dirname, '.env');
    if (!fs.existsSync(p)) return;
    const text = fs.readFileSync(p, 'utf8');
    for (const line of text.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith('#')) continue;
        const eq = t.indexOf('=');
        if (eq < 0) continue;
        const k = t.slice(0, eq).trim();
        let v = t.slice(eq + 1).trim();
        if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
            v = v.slice(1, -1);
        }
        if (!process.env[k]) process.env[k] = v;
    }
}

function required(name) {
    const v = process.env[name];
    if (!v) {
        console.error(`❌ Missing required env var: ${name}. See .env.example.`);
        process.exit(1);
    }
    return v;
}

function ts() { return new Date().toISOString(); }

function _request(opts, body) {
    return new Promise((resolve, reject) => {
        const req = https.request(opts, (res) => {
            let buf = '';
            res.on('data', c => buf += c);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: buf }));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(new Error('upstream timeout')); });
        if (body) req.write(body);
        req.end();
    });
}

function decodeJwtPayload(jwt) {
    try {
        const b64 = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
        return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    } catch (_) { return null; }
}

// ─── Mint flow ──────────────────────────────────────────────────────────
async function callAuthApi() {
    const body = JSON.stringify({
        offlineDownload: false,
        subscriptionDtl: SUBSCRIPTION_DTL,
        contentDtl:      CONTENT_DTL
    });
    const opts = {
        method: 'POST',
        hostname: 'api.aztv.videoready.tv',
        path: '/drm-auth-integration/v1/drm/authToken',
        headers: {
            'authorization':     'Bearer ' + BEARER,
            'content-type':      'application/json',
            'content-length':    Buffer.byteLength(body),
            'accept':            'application/json',
            'origin':            'https://web.azamtvmax.com',
            'referer':           'https://web.azamtvmax.com/',
            'platform':          'WEB',
            'tenant_identifier': 'master',
            'user-agent':        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/148.0.0.0 Safari/537.36'
        },
        timeout: 15000
    };
    const r = await _request(opts, body);
    if (r.status !== 200) throw new Error(`authToken HTTP ${r.status}: ${(r.body||'').substring(0,180)}`);
    const j = JSON.parse(r.body);
    if (!j.data || !j.data.cdnToken) throw new Error('authToken response had no data.cdnToken');
    return j.data.cdnToken;
}

function extractInnerJwt(rawCdnToken) {
    let s = String(rawCdnToken || '').trim();
    if (s.startsWith('?cdntoken=')) s = s.slice('?cdntoken='.length);
    else if (s.startsWith('cdntoken=')) s = s.slice('cdntoken='.length);
    s = s.split('&')[0].replace(/=+$/, '');
    return s;
}

async function followCdnRedirect(userJwt) {
    const opts = {
        method: 'GET',
        hostname: 'cdnblncr.azamtvltd.co.tz',
        path: `/live/eds/AzamOne/DASH/AzamOne.mpd?cdntoken=${userJwt}`,
        headers: { 'user-agent': 'Mozilla/5.0', 'accept': '*/*' },
        timeout: 15000
    };
    const r = await _request(opts, null);
    if (r.status !== 302 || !(r.headers && r.headers.location)) {
        throw new Error(`cdnblncr did not redirect (HTTP ${r.status}). This box's IP is on the blocklist.`);
    }
    const m = r.headers.location.match(/\/tok_([^/]+)\//);
    if (!m) throw new Error('redirect did not contain /tok_<JWT>/');
    return m[1];
}

async function mintMagicToken() {
    // Bearer expiry sanity check
    const bp = decodeJwtPayload(BEARER);
    if (bp && bp.exp && bp.exp * 1000 < Date.now()) {
        throw new Error('BEARER is expired — re-capture from web.azamtvmax.com and update .env');
    }
    const raw = await callAuthApi();
    const userJwt = extractInnerJwt(raw);
    if (!userJwt.startsWith('eyJ')) throw new Error('could not extract user JWT from authToken response');
    const magic = await followCdnRedirect(userJwt);
    const p = decodeJwtPayload(magic);
    if (!p || !p.exp) throw new Error('magic JWT has no exp');
    return { jwt: magic, exp: parseInt(p.exp, 10) };
}

// ─── Push to service ────────────────────────────────────────────────────
async function pushToService(magic) {
    const u = new URL('/api/push-token', SERVICE_URL);
    const body = JSON.stringify({ jwt: magic.jwt });
    const opts = {
        method: 'POST',
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname,
        headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(body),
            'x-push-secret': PUSH_SECRET,
            'user-agent': 'aztv-relay/1.0'
        },
        timeout: 15000
    };
    const r = await _request(opts, body);
    if (r.status !== 200) throw new Error(`push HTTP ${r.status}: ${(r.body||'').substring(0,180)}`);
    return JSON.parse(r.body);
}

// ─── Cycle ─────────────────────────────────────────────────────────────
async function cycle() {
    let lastErr;
    for (let attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++) {
        try {
            const magic = await mintMagicToken();
            const remainingMin = Math.round((magic.exp - Math.floor(Date.now()/1000)) / 60);
            console.log(`[${ts()}] ✓ Minted magic JWT (lifespan ${remainingMin}m). Pushing to service…`);
            const r = await pushToService(magic);
            console.log(`[${ts()}] ✓ Service accepted token. Customers will stream until ${new Date(magic.exp*1000).toISOString()}.`);
            return;
        } catch (e) {
            lastErr = e;
            const wait = RETRY_BACKOFF_MS * attempt;
            console.error(`[${ts()}] ✗ Attempt ${attempt}/${RETRY_ATTEMPTS} failed: ${e.message}`);
            if (attempt < RETRY_ATTEMPTS) {
                console.error(`[${ts()}]   retrying in ${wait/1000}s…`);
                await new Promise(r => setTimeout(r, wait));
            }
        }
    }
    console.error(`[${ts()}] ✗ All retry attempts exhausted. Will try again in ${REFRESH_HOURS}h.`);
}

// ─── Boot ──────────────────────────────────────────────────────────────
console.log(`AZTV Relay starting. Service=${SERVICE_URL}  Refresh=${REFRESH_HOURS}h`);
cycle();
setInterval(cycle, REFRESH_MS);
