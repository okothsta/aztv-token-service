// Firestore store for credentials, current token, and API keys.
//
// Layout (all under one root collection so it doesn't collide with any
// existing app data on the same Firestore project):
//
//   aztvToken/
//     credentials             { bearer, subscriptionDtl, contentDtl, deviceId,
//                               bearerExp, bearerIss, bearerIp, updatedAt }
//     currentToken            { jwt, exp, mintedAt, source: 'auto'|'manual' }
//     apiKeys/<keyId>         { hash, label, createdAt, lastUsedAt, requestCount,
//                               disabled?, monthlyQuota? }
//
// Service-account credential is supplied EITHER via the
// FIREBASE_SERVICE_ACCOUNT_JSON env var (single-line JSON) OR by placing
// firebase-service-account.json in the project root for local dev.

const admin = require('firebase-admin');
const fs    = require('fs');
const path  = require('path');

let _db = null;

function initFirestore() {
    if (_db) return _db;
    if (admin.apps.length === 0) {
        let serviceAccount = null;
        if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
            try { serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON); }
            catch (e) { throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON is set but not valid JSON: ' + e.message); }
        } else {
            const localPath = path.join(__dirname, '..', 'firebase-service-account.json');
            if (fs.existsSync(localPath)) {
                serviceAccount = JSON.parse(fs.readFileSync(localPath, 'utf8'));
            }
        }
        if (!serviceAccount) {
            throw new Error('No Firebase credentials. Set FIREBASE_SERVICE_ACCOUNT_JSON env var or place firebase-service-account.json in project root.');
        }
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    }
    _db = admin.firestore();
    return _db;
}

const ROOT = 'aztvToken';
const CREDS_DOC      = () => initFirestore().collection(ROOT).doc('credentials');
const TOKEN_DOC      = () => initFirestore().collection(ROOT).doc('currentToken');
const API_KEYS_COL   = () => initFirestore().collection(ROOT).doc('credentials').collection('keys');

async function getCredentials() {
    const doc = await CREDS_DOC().get();
    return doc.exists ? doc.data() : null;
}

async function setCredentials(creds) {
    await CREDS_DOC().set({
        ...creds,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
}

async function getCurrentToken() {
    const doc = await TOKEN_DOC().get();
    return doc.exists ? doc.data() : null;
}

async function setCurrentToken(jwt, exp, source) {
    await TOKEN_DOC().set({
        jwt,
        exp,
        source: source || 'auto',
        mintedAt: admin.firestore.FieldValue.serverTimestamp()
    });
}

async function listApiKeys() {
    const snap = await API_KEYS_COL().get();
    return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}

async function saveApiKey(keyId, hash, label) {
    await API_KEYS_COL().doc(keyId).set({
        hash,
        label: label || '',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        requestCount: 0,
        disabled: false
    });
}

async function findApiKeyByHash(hash) {
    const snap = await API_KEYS_COL().where('hash', '==', hash).limit(1).get();
    if (snap.empty) return null;
    const doc = snap.docs[0];
    return { id: doc.id, ...doc.data() };
}

async function bumpApiKeyUsage(keyId) {
    try {
        await API_KEYS_COL().doc(keyId).update({
            lastUsedAt: admin.firestore.FieldValue.serverTimestamp(),
            requestCount: admin.firestore.FieldValue.increment(1)
        });
    } catch (_) { /* non-fatal */ }
}

async function deleteApiKey(keyId) {
    await API_KEYS_COL().doc(keyId).delete();
}

async function setApiKeyDisabled(keyId, disabled) {
    await API_KEYS_COL().doc(keyId).update({ disabled: !!disabled });
}

module.exports = {
    initFirestore,
    getCredentials, setCredentials,
    getCurrentToken, setCurrentToken,
    listApiKeys, saveApiKey, findApiKeyByHash, bumpApiKeyUsage,
    deleteApiKey, setApiKeyDisabled
};
