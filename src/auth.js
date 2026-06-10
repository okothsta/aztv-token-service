// Auth helpers: API-key gate for customers, admin session for the panel.
//
// API keys: 32-byte base64url. We store only the SHA-256 hash, never the
// plaintext. When a customer presents a key, we hash it and look up the doc
// by hash. This way even the Firestore data leaking would not expose live keys.
//
// Admin session: a signed cookie containing {iat,exp}. We use crypto.timingSafeEqual
// to compare the password and HMAC-sign the cookie with SESSION_SECRET. No user
// table — there's exactly one admin and the password is in env.

const crypto = require('crypto');
const { findApiKeyByHash, bumpApiKeyUsage } = require('./store');

const ADMIN_PASSWORD  = process.env.ADMIN_PASSWORD  || '';
const SESSION_SECRET  = process.env.SESSION_SECRET  || '';
const SESSION_COOKIE  = 'aztv_admin';
const SESSION_TTL_MS  = 24 * 60 * 60 * 1000; // 24 hours

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
    console.warn('⚠️  ADMIN_PASSWORD is missing or too short. Admin panel will refuse all logins.');
}
if (!SESSION_SECRET || SESSION_SECRET.length < 16) {
    console.warn('⚠️  SESSION_SECRET is missing or too short. Sessions will not validate.');
}

// ─────────── API key helpers ───────────
function generateApiKey() {
    return crypto.randomBytes(32).toString('base64url'); // ~43 char URL-safe
}
function hashKey(plaintext) {
    return crypto.createHash('sha256').update(String(plaintext), 'utf8').digest('hex');
}

/**
 * Express middleware: gate /api/* customer endpoints behind an API key.
 * Looks for X-Api-Key header first, then ?key= query, then ?api_key= query.
 * Sets req.apiKey = { id, label } on success.
 */
async function requireApiKey(req, res, next) {
    const presented = req.get('x-api-key') || req.query.key || req.query.api_key;
    if (!presented) return res.status(401).json({ error: 'Missing API key' });
    const hash = hashKey(presented);
    const found = await findApiKeyByHash(hash);
    if (!found) return res.status(403).json({ error: 'Invalid API key' });
    if (found.disabled) return res.status(403).json({ error: 'API key disabled' });
    req.apiKey = { id: found.id, label: found.label || '' };
    bumpApiKeyUsage(found.id).catch(() => {});
    next();
}

// ─────────── Admin session helpers ───────────
function passwordMatches(presented) {
    if (!ADMIN_PASSWORD || !presented) return false;
    const a = Buffer.from(String(presented), 'utf8');
    const b = Buffer.from(String(ADMIN_PASSWORD), 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function signSession(payload) {
    const data = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig  = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
    return `${data}.${sig}`;
}

function verifySession(cookie) {
    if (!cookie || typeof cookie !== 'string' || !cookie.includes('.')) return null;
    const [data, sig] = cookie.split('.', 2);
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
    const a = Buffer.from(sig); const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
        const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
        if (!payload || !payload.exp || payload.exp < Date.now()) return null;
        return payload;
    } catch (_) { return null; }
}

/**
 * Read the session cookie from a request. Returns the parsed payload or null.
 */
function readSession(req) {
    const raw = req.headers.cookie || '';
    const parts = raw.split(';').map(s => s.trim()).filter(Boolean);
    for (const p of parts) {
        const eq = p.indexOf('=');
        if (eq < 0) continue;
        if (p.slice(0, eq) === SESSION_COOKIE) return verifySession(decodeURIComponent(p.slice(eq + 1)));
    }
    return null;
}

function issueSessionCookie(res) {
    const payload = { iat: Date.now(), exp: Date.now() + SESSION_TTL_MS };
    const value = signSession(payload);
    const flags = [
        `${SESSION_COOKIE}=${encodeURIComponent(value)}`,
        'HttpOnly',
        'Path=/',
        `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
        'SameSite=Lax'
    ];
    if (process.env.NODE_ENV === 'production' || process.env.RENDER) flags.push('Secure');
    res.setHeader('Set-Cookie', flags.join('; '));
}

function clearSessionCookie(res) {
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}

/**
 * Express middleware: require admin login for /admin/* protected pages and APIs.
 * Returns JSON 401 for /admin/api/*, otherwise redirects to /admin/login.
 */
function requireAdmin(req, res, next) {
    const sess = readSession(req);
    if (sess) { req.admin = sess; return next(); }
    if (req.path.startsWith('/admin/api/')) return res.status(401).json({ error: 'Not logged in' });
    return res.redirect('/admin/login');
}

module.exports = {
    generateApiKey, hashKey,
    requireApiKey,
    passwordMatches, issueSessionCookie, clearSessionCookie,
    readSession, requireAdmin,
    SESSION_COOKIE
};
