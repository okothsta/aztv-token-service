// Tolerant parsers for the messy text the admin pastes from DevTools.
// Goal: take ANY of the formats Chrome/Edge/Firefox produce and pull out
// the four values we need: bearer, subscriptionDtl, contentDtl, deviceId.

/**
 * Parse a Bearer token out of free-form "request headers" text.
 * Accepts:
 *   - lines like "authorization: Bearer eyJ..."
 *   - lines like ":authority: api.aztv...\nauthorization: Bearer eyJ..."
 *   - lone "Bearer eyJ..." strings
 *   - lone "eyJ..." JWT strings
 * Returns the JWT (without the "Bearer " prefix) or null.
 */
function extractBearer(raw) {
    if (!raw || typeof raw !== 'string') return null;
    const text = raw.trim();
    if (!text) return null;

    // 1. Look for "authorization: Bearer ..." line (case-insensitive).
    const m1 = text.match(/^[ \t]*authorization[ \t]*:?[ \t]*Bearer[ \t]+([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/im);
    if (m1) return m1[1];

    // 2. Look for any "Bearer eyJ..." anywhere.
    const m2 = text.match(/Bearer[ \t]+([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/i);
    if (m2) return m2[1];

    // 3. Lone JWT (3 dot-separated base64url segments).
    const m3 = text.match(/(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/);
    if (m3) return m3[1];

    return null;
}

/**
 * Decode a JWT payload without verifying signature.
 * Returns the parsed payload object, or null on any failure.
 */
function decodeJwtPayload(jwt) {
    try {
        const parts = jwt.split('.');
        if (parts.length !== 3) return null;
        const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
        return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
    } catch (_) { return null; }
}

/**
 * Parse the request payload (JSON the page POSTs to /authToken) out of
 * free-form text the admin pastes. Tolerates:
 *   - clean JSON
 *   - JSON with extra whitespace / line breaks
 *   - "view source" raw text from DevTools
 *   - text with the JSON embedded in a larger blob (we extract the first {...} block)
 *
 * Returns { subscriptionDtl, contentDtl, deviceId } or throws Error with reason.
 */
function extractPayloadFields(raw) {
    if (!raw || typeof raw !== 'string') throw new Error('Empty payload');
    let text = raw.trim();

    // If it's not pure JSON, try to extract the first balanced {...} block.
    let parsed = null;
    try { parsed = JSON.parse(text); } catch (_) {}
    if (!parsed) {
        const firstBrace = text.indexOf('{');
        const lastBrace = text.lastIndexOf('}');
        if (firstBrace >= 0 && lastBrace > firstBrace) {
            try { parsed = JSON.parse(text.slice(firstBrace, lastBrace + 1)); } catch (_) {}
        }
    }
    if (!parsed || typeof parsed !== 'object') {
        throw new Error('Could not parse JSON from the pasted payload');
    }

    // Look for the values, allowing both spellings AzamMax has used historically.
    const subscriptionDtl = parsed.subscriptionDtl || parsed.subscriberDtl || null;
    const contentDtl      = parsed.contentDtl      || null;
    const deviceId        = parsed.deviceId        || parsed.device_id || null;

    if (!subscriptionDtl) throw new Error('Missing subscriptionDtl in payload');
    if (!contentDtl)      throw new Error('Missing contentDtl in payload');
    // deviceId is optional — many AzamMax web requests omit it; the API still works.

    return {
        subscriptionDtl: String(subscriptionDtl).trim(),
        contentDtl:      String(contentDtl).trim(),
        deviceId:        deviceId ? String(deviceId).trim() : null
    };
}

/**
 * Parse all four credentials in one go from the admin's two paste boxes.
 * @param {string} headersText  - raw "Request Headers" paste
 * @param {string} payloadText  - raw "Payload (view source)" paste
 * @returns {object}            - { bearer, subscriptionDtl, contentDtl, deviceId, bearerExp }
 */
function parsePastedCredentials(headersText, payloadText) {
    const bearer = extractBearer(headersText);
    if (!bearer) throw new Error('Could not find a Bearer JWT in the headers paste');

    const payload = decodeJwtPayload(bearer);
    if (!payload) throw new Error('Bearer token is not a valid JWT');
    if (!payload.exp) throw new Error('Bearer JWT has no exp claim');
    if (payload.exp * 1000 < Date.now()) throw new Error('Bearer JWT is already expired');

    const fields = extractPayloadFields(payloadText);

    // The deviceId from the JWT (after the underscore in `iss`) is canonical
    // if the payload didn't carry one explicitly.
    let deviceId = fields.deviceId;
    if (!deviceId && typeof payload.iss === 'string' && payload.iss.includes('_')) {
        deviceId = payload.iss.split('_').slice(1).join('_');
    }

    return {
        bearer,
        subscriptionDtl: fields.subscriptionDtl,
        contentDtl:      fields.contentDtl,
        deviceId:        deviceId || '',
        bearerExp:       payload.exp,
        bearerIss:       payload.iss || '',
        bearerIp:        payload.ipAddress || ''
    };
}

module.exports = { extractBearer, decodeJwtPayload, extractPayloadFields, parsePastedCredentials };
