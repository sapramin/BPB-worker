import assert from 'node:assert/strict';
import { createHmac, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Load the actual Worker without Cloudflare's sockets module. Networking is
// deliberately unavailable: these tests exercise only sessions and passwords.
const source = readFileSync(new URL('../_worker.js', import.meta.url), 'utf8');
const script = source
    .replace("import { connect } from 'cloudflare:sockets';", '')
    .replace('export default {', 'const worker = {')
    + '\nglobalThis.authTest = { worker, Authenticate, generateJWTToken };';
const context = {
    crypto: webcrypto, TextEncoder, TextDecoder, Request, Response, URL,
    URLSearchParams, Headers, atob, btoa,
    console: { log() {}, error() {} },
    fetch() { throw new Error('Unexpected network access'); }
};
vm.runInNewContext(script, context, { filename: '_worker.js' });
const { worker, Authenticate, generateJWTToken } = context.authTest;
const initialSecret = 'synthetic-session-secret-for-unit-tests';
const initialPassword = 'InitialPassword9';

function fixture() {
    const data = new Map([['secretKey', initialSecret], ['sessionSigningKey', initialSecret], ['pwd', initialPassword]]);
    const writes = [];
    const env = { bpb: {
        async get(key) { return data.get(key) ?? null; },
        async put(key, value) { writes.push(key); data.set(key, value); }
    } };
    return { data, writes, env };
}

function request(path, token, method = 'GET', body) {
    const headers = token ? { Cookie: `other=value; jwtToken=${token}` } : {};
    return new Request(`https://worker.test${path}`, { method, headers, body });
}

function signedToken(payload, secret = initialSecret, header = { alg: 'HS256', typ: 'JWT' }) {
    const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    const input = `${encode(header)}.${encode(payload)}`;
    return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

function cookieToken(response) {
    const cookie = response.headers.get('Set-Cookie');
    assert.ok(cookie?.startsWith('jwtToken=Bearer '));
    return cookie.slice('jwtToken='.length).split(';')[0];
}

test('login issues an independently verifiable HS256 session without credentials', async () => {
    const { env } = fixture();
    const response = await worker.fetch(request('/login', null, 'POST', initialPassword), env, {});
    assert.equal(response.status, 200);
    const token = cookieToken(response);
    const [header, payload, signature] = token.slice(7).split('.');
    assert.match(header, /^[A-Za-z0-9_-]+$/);
    assert.match(payload, /^[A-Za-z0-9_-]+$/);
    assert.equal(signature, createHmac('sha256', initialSecret).update(`${header}.${payload}`).digest('base64url'));
    const claims = JSON.parse(Buffer.from(payload, 'base64url'));
    assert.ok(Number.isSafeInteger(claims.exp));
    assert.ok(claims.exp > Date.now() / 1000);
    assert.equal(JSON.stringify(claims).includes(initialSecret), false);
    assert.equal(JSON.stringify(claims).includes(initialPassword), false);
    assert.equal(await Authenticate(request('/panel', token), env), true);
    assert.match(response.headers.get('Set-Cookie'), /HttpOnly; Secure;/);
});

test('incorrect login credentials do not issue a session', async () => {
    const { env, writes } = fixture();
    const response = await worker.fetch(request('/login', null, 'POST', 'IncorrectPassword9'), env, {});
    assert.equal(response.ok, false);
    assert.equal(response.headers.get('Set-Cookie'), null);
    assert.deepEqual(writes, []);
});

test('payload changes and a different signing key invalidate the session', async () => {
    const { env } = fixture();
    const token = await generateJWTToken(initialSecret);
    const parts = token.slice(7).split('.');
    parts[1] = Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, altered: true })).toString('base64url');
    assert.equal(await Authenticate(request('/panel', parts.join('.')), env), false);
    assert.equal(await Authenticate(request('/panel', signedToken({ exp: Math.floor(Date.now() / 1000) + 3600 }, 'different-key')), env), false);
});

test('expiry is required, numeric, integral, and strictly in the future', async () => {
    const { env } = fixture();
    const now = Math.floor(Date.now() / 1000);
    for (const claims of [{}, { exp: `${now + 3600}` }, { exp: null }, { exp: now }, { exp: now - 1 }, { exp: now + 0.5 }, null]) {
        assert.equal(await Authenticate(request('/panel', signedToken(claims)), env), false);
    }
    assert.equal(await Authenticate(request('/panel', signedToken({ exp: now + 3600 })), env), true);
});

test('unexpected algorithms and malformed cookies fail closed without throwing', async () => {
    const { env } = fixture();
    const exp = Math.floor(Date.now() / 1000) + 3600;
    for (const header of [{ alg: 'none', typ: 'JWT' }, { alg: 'HS512', typ: 'JWT' }, { alg: 'HS256', typ: 'other' }, null]) {
        assert.equal(await Authenticate(request('/panel', signedToken({ exp }, initialSecret, header)), env), false);
    }
    for (const token of [undefined, 'not-a-token', 'a.b.c', 'Bearer a..b', 'a.b.c.d', '%.%.%']) {
        assert.equal(await Authenticate(request('/panel', token), env), false);
    }
    const response = await worker.fetch(request('/panel', 'a.b.c', 'POST', 'ignored'), env, {});
    assert.equal(response.status, 401);
});

test('sessions require a configured signing secret', async () => {
    const { env, data } = fixture();
    const token = await generateJWTToken(initialSecret);
    data.delete('sessionSigningKey');
    assert.equal(await Authenticate(request('/panel', token), env), false);
});

test('password changes reject GET, unauthenticated POST, and weak passwords without writes', async () => {
    const { env, writes, data } = fixture();
    const token = await generateJWTToken(initialSecret);
    const getResponse = await worker.fetch(request('/panel/password', token), env, {});
    assert.equal(getResponse.status, 405);
    assert.equal(getResponse.headers.get('Allow'), 'POST');
    const unauthorized = await worker.fetch(request('/panel/password', null, 'POST', 'ReplacementPassword9'), env, {});
    assert.equal(unauthorized.status, 401);
    for (const password of ['', 'shortA9', 'lowercase9', 'UppercaseOnly', initialPassword]) {
        const response = await worker.fetch(request('/panel/password', token, 'POST', password), env, {});
        assert.equal(response.status, 400);
    }
    assert.deepEqual(writes, []);
    assert.equal(data.get('pwd'), initialPassword);
    assert.equal(data.get('sessionSigningKey'), initialSecret);
});

test('a valid password change revokes old sessions and permits login with the new password', async () => {
    const { env, data } = fixture();
    const oldToken = await generateJWTToken(initialSecret);
    const response = await worker.fetch(request('/panel/password', oldToken, 'POST', 'ReplacementPassword9'), env, {});
    assert.equal(response.status, 200);
    assert.equal(data.get('pwd'), 'ReplacementPassword9');
    assert.notEqual(data.get('sessionSigningKey'), initialSecret);
    assert.equal(await Authenticate(request('/panel', oldToken), env), false);
    const login = await worker.fetch(request('/login', null, 'POST', 'ReplacementPassword9'), env, {});
    assert.equal(login.status, 200);
    assert.equal(await Authenticate(request('/panel', cookieToken(login)), env), true);
});

test('legacy deployments get a fresh session key on login', async () => {
    const { env, data } = fixture();
    data.delete('sessionSigningKey');
    const oldKeyToken = signedToken({ exp: Math.floor(Date.now() / 1000) + 3600 });
    assert.equal(await Authenticate(request('/panel', oldKeyToken), env), false);
    const login = await worker.fetch(request('/login', null, 'POST', initialPassword), env, {});
    assert.equal(login.status, 200);
    assert.ok(data.get('sessionSigningKey'));
    assert.notEqual(data.get('sessionSigningKey'), initialSecret);
    assert.equal(await Authenticate(request('/panel', oldKeyToken), env), false);
    assert.equal(await Authenticate(request('/panel', cookieToken(login)), env), true);
});
