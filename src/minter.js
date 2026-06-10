// The two-hop mint flow:
//   1) POST api.aztv.videoready.tv/drm-auth-integration/v1/drm/authToken
//      with { offlineDownload:false, subscriptionDtl, contentDtl }
//      and the user's Bearer in the Authorization header.
//      Response includes data.cdnToken which is the SHORT-LIVED IP-bound JWT.
//
//   2) GET cdnblncr.azamtvltd.co.tz/.../*.mpd?cdntoken=<JWT>
//      cdnblncr returns 302 with Location pointing to
//      cdnedgch2.azamtvltd.co.tz/tok_<BIG-JWT>/.../*.mpd
//      That BIG-JWT is the 12h, sip:"", max_sessions:0 token we want.

const https = require('https');
const { decodeJwtPayload } = require('./parse');

// AzamMax sample channel we use for the redirect probe. Any DRM channel works;
// AzamOne is reliable.
const PROBE_PATH = '/live/eds/AzamOne/DASH/AzamOne.mpd';

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

/**
 * Hop 1: ask api.aztv for a per-user cdnToken.
 * @param {object} creds  { bearer, subscriptionDtl, contentDtl }
 * @returns {string} raw cdnToken value as the API returned it (may include "?cdntoken=..&hdnts=..")
 */
async function callAuthApi(creds) {
    const body = JSON.stringify({
        offlineDownload: false,
        subscriptionDtl: creds.subscriptionDtl,
        contentDtl:      creds.contentDtl
    });
    const opts = {
        method: 'POST',
        hostname: 'api.aztv.videoready.tv',
        path: '/drm-auth-integration/v1/drm/authToken',
        headers: {
            'authorization':     'Bearer ' + creds.bearer,
            'content-type':      'application/json',
            'content-length':    Buffer.byteLength(body),
            'accept':            'application/json',
            'origin':            'https://web.azamtvmax.com',
            'referer':           'https://web.azamtvmax.com/',
            'platform':          'WEB',
            'language':          'en',
            'languagecode':      'en',
            'tenant_identifier': 'master',
            'user-agent':        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36'
        },
        timeout: 15000
    };
    const r = await _request(opts, body);
    if (r.status !== 200) {
        throw new Error(`authToken HTTP ${r.status}: ${(r.body || '').substring(0, 180)}`);
    }
    let json;
    try { json = JSON.parse(r.body); } catch (e) { throw new Error('authToken response not JSON'); }
    if (!json.data || !json.data.cdnToken) {
        throw new Error('authToken response had no data.cdnToken: ' + JSON.stringify(json).substring(0, 180));
    }
    return json.data.cdnToken;  // e.g. "?cdntoken=eyJ...&hdnts=exp=...~hmac=..."
}

/**
 * From the raw cdnToken value the API returned, extract just the JWT (drop
 * "?cdntoken=" prefix and "&hdnts=..." suffix).
 */
function extractInnerJwt(rawCdnToken) {
    let s = String(rawCdnToken || '').trim();
    if (s.startsWith('?cdntoken=')) s = s.slice('?cdntoken='.length);
    else if (s.startsWith('cdntoken=')) s = s.slice('cdntoken='.length);
    s = s.split('&')[0];
    s = s.replace(/=+$/, '');
    return s;
}

/**
 * Hop 2: ask cdnblncr for a manifest, capture the 302 Location, extract the
 * cdnedgch2 path-token JWT.
 * @param {string} userJwt  the JWT from hop 1
 * @returns {{jwt: string, exp: number, raw: string}} the long-lived path-token + decoded exp
 */
async function followCdnRedirect(userJwt) {
    const opts = {
        method: 'GET',
        hostname: 'cdnblncr.azamtvltd.co.tz',
        path: `${PROBE_PATH}?cdntoken=${userJwt}`,
        headers: { 'user-agent': 'Mozilla/5.0', 'accept': '*/*' },
        timeout: 15000
    };
    const r = await _request(opts, null);
    if (r.status !== 302 || !r.headers.location) {
        throw new Error(`cdnblncr did not redirect (HTTP ${r.status})`);
    }
    const loc = r.headers.location;
    const m = loc.match(/\/tok_([^/]+)\//);
    if (!m) throw new Error('redirect did not contain /tok_<JWT>/ : ' + loc.substring(0, 180));
    const pathJwt = m[1];

    const payload = decodeJwtPayload(pathJwt);
    if (!payload) throw new Error('extracted path-token JWT did not decode');
    const exp = parseInt(payload.exp, 10) || 0;
    if (!exp) throw new Error('extracted path-token JWT had no exp');

    return { jwt: pathJwt, exp, raw: loc };
}

/**
 * Run the full mint and return the long-lived cdnedgch2 path-token.
 * Throws on any failure with a useful message.
 */
async function mintToken(creds) {
    if (!creds || !creds.bearer || !creds.subscriptionDtl || !creds.contentDtl) {
        throw new Error('missing credentials (need bearer, subscriptionDtl, contentDtl)');
    }
    // Bearer expiry sanity check.
    const bp = decodeJwtPayload(creds.bearer);
    if (bp && bp.exp && bp.exp * 1000 < Date.now()) {
        throw new Error('Bearer token is expired — admin must paste a fresh one');
    }

    const rawCdnToken = await callAuthApi(creds);
    const userJwt = extractInnerJwt(rawCdnToken);
    if (!userJwt || !userJwt.startsWith('eyJ')) {
        throw new Error('could not extract inner JWT from authToken response');
    }
    const result = await followCdnRedirect(userJwt);
    return result;
}

module.exports = { mintToken, callAuthApi, extractInnerJwt, followCdnRedirect };
