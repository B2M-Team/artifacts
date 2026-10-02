import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { oidcConfigFromEnv, verifyIdToken, hasRequiredRole, principalName, createPasswordSignIn, createCodeFlow, pkceChallenge } from '../oidc.js';

function b64url(x) {
  return Buffer.from(x).toString('base64url');
}

function makeIdToken({ privateKey, kid, claims, alg = 'RS256' }) {
  const h = b64url(JSON.stringify({ alg, kid, typ: 'JWT' }));
  const p = b64url(JSON.stringify(claims));
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${p}`), privateKey);
  return `${h}.${p}.${b64url(sig)}`;
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { get: async (kid) => (kid === 'k1' ? publicKey : null) };
const now = Math.floor(Date.now() / 1000);
const base = { iss: 'https://sso.example/realms/r', aud: 'artifacts', exp: now + 300, nonce: 'n1', preferred_username: 'tuna' };

test('config is null without OIDC_ISSUER and throws when the client is half-configured', () => {
  assert.equal(oidcConfigFromEnv({}), null);
  assert.throws(() => oidcConfigFromEnv({ OIDC_ISSUER: 'https://sso.example/realms/r' }), /OIDC_CLIENT_ID/);
  const cfg = oidcConfigFromEnv({ OIDC_ISSUER: 'https://sso.example/realms/r/', OIDC_CLIENT_ID: 'a', OIDC_CLIENT_SECRET: 's' });
  assert.equal(cfg.issuer, 'https://sso.example/realms/r');
  assert.equal(cfg.internalIssuer, cfg.issuer);
  assert.equal(cfg.only, true, 'OIDC_ONLY defaults to true');
  assert.equal(cfg.signinTitle, 'Sign in with your company account');
  assert.equal(oidcConfigFromEnv({ ...process.env, OIDC_ISSUER: 'x', OIDC_CLIENT_ID: 'a', OIDC_CLIENT_SECRET: 's', OIDC_ONLY: 'false' }).only, false);
});

test('a well-formed id_token verifies and yields the username', async () => {
  const token = makeIdToken({ privateKey, kid: 'k1', claims: base });
  const claims = await verifyIdToken(token, { jwks, issuerClaim: base.iss, clientId: 'artifacts', nonce: 'n1' });
  assert.equal(principalName(claims), 'tuna');
});

test('signature, issuer, audience, expiry and nonce are each enforced', async () => {
  const opts = { jwks, issuerClaim: base.iss, clientId: 'artifacts', nonce: 'n1' };
  const good = makeIdToken({ privateKey, kid: 'k1', claims: base });
  const [h, p] = good.split('.');
  await assert.rejects(verifyIdToken(`${h}.${p}.${b64url('nope')}`, opts), /bad signature/);
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  await assert.rejects(verifyIdToken(makeIdToken({ privateKey: other, kid: 'k1', claims: base }), opts), /bad signature/);
  await assert.rejects(verifyIdToken(makeIdToken({ privateKey, kid: 'k9', claims: base }), opts), /unknown signing key/);
  await assert.rejects(verifyIdToken(makeIdToken({ privateKey, kid: 'k1', claims: { ...base, iss: 'https://evil' } }), opts), /wrong issuer/);
  await assert.rejects(verifyIdToken(makeIdToken({ privateKey, kid: 'k1', claims: { ...base, aud: 'other' } }), opts), /wrong audience/);
  // An access token is signed by the same issuer but addressed to the resource server; the
  // role fallback verifies it with the audience check off.
  const at = await verifyIdToken(makeIdToken({ privateKey, kid: 'k1', claims: { ...base, aud: 'account', realm_access: { roles: ['reports-admin'] } } }), { ...opts, requireAudience: false });
  assert.equal(hasRequiredRole(at, 'reports-admin'), true);
  await assert.rejects(verifyIdToken(makeIdToken({ privateKey, kid: 'k1', claims: { ...base, exp: now - 600 } }), opts), /expired/);
  await assert.rejects(verifyIdToken(makeIdToken({ privateKey, kid: 'k1', claims: { ...base, nonce: 'zz' } }), opts), /nonce mismatch/);
  await assert.rejects(verifyIdToken(makeIdToken({ privateKey, kid: 'k1', claims: base, alg: 'none' }), opts), /unsupported alg/);
});

test('required role is looked up in realm, top-level and client roles', () => {
  assert.equal(hasRequiredRole({}, ''), true, 'no role required → everyone');
  assert.equal(hasRequiredRole({}, 'reports-admin'), false);
  assert.equal(hasRequiredRole({ realm_access: { roles: ['reports-admin'] } }, 'reports-admin'), true);
  assert.equal(hasRequiredRole({ roles: ['reports-admin'] }, 'reports-admin'), true);
  assert.equal(hasRequiredRole({ resource_access: { artifacts: { roles: ['reports-admin'] } } }, 'reports-admin'), true);
});

// The password grant end to end against a stub IdP: token endpoint + JWKS on a local server.
test('createPasswordSignIn exchanges credentials with the IdP and enforces the role', async () => {
  const jwk = publicKey.export({ format: 'jwk' });
  const answers = {
    'good:pw': { id: { ...base, aud: 'artifacts', preferred_username: 'good' }, at: { ...base, aud: 'account', realm_access: { roles: ['reports-admin'] } } },
    'norole:pw': { id: { ...base, aud: 'artifacts', preferred_username: 'norole' }, at: { ...base, aud: 'account', realm_access: { roles: [] } } },
  };
  const srv = http.createServer(async (req, res) => {
    if (req.url === '/certs') return res.end(JSON.stringify({ keys: [{ ...jwk, kid: 'k1', use: 'sig' }] }));
    let body = ''; for await (const c of req) body += c;
    const f = new URLSearchParams(body);
    const a = answers[`${f.get('username')}:${f.get('password')}`];
    if (f.get('grant_type') !== 'password' || !a) { res.statusCode = 401; return res.end(JSON.stringify({ error: 'invalid_grant' })); }
    res.end(JSON.stringify({
      id_token: makeIdToken({ privateKey, kid: 'k1', claims: { ...a.id, nonce: undefined } }),
      access_token: makeIdToken({ privateKey, kid: 'k1', claims: a.at }),
    }));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const log = [];
  try {
    const cfg = { clientId: 'artifacts', clientSecret: 's', scopes: 'openid', requiredRole: 'reports-admin', only: true };
    const disc = { tokenEndpoint: `http://127.0.0.1:${port}/token`, jwksUri: `http://127.0.0.1:${port}/certs`, issuerClaim: base.iss };
    const signIn = createPasswordSignIn(cfg, disc, { logAuth: (e, f) => log.push(f.outcome) });
    assert.equal(await signIn('good', 'pw'), 'good');
    await assert.rejects(signIn('good', 'wrong'), (e) => e.status === 401);
    await assert.rejects(signIn('norole', 'pw'), (e) => e.status === 403 && /reports-admin/.test(e.message));
    assert.deepEqual(log, ['ok', 'refused', 'forbidden']);
    const open = createPasswordSignIn({ ...cfg, requiredRole: '' }, disc, { logAuth: () => {} });
    assert.equal(await open('norole', 'pw'), 'norole', 'no required role → any IdP account');
  } finally {
    srv.close();
  }
});

test('an IdP that is down is a 502, not a 401', async () => {
  const signIn = createPasswordSignIn({ clientId: 'a', clientSecret: 's', scopes: 'openid' }, { tokenEndpoint: 'http://127.0.0.1:1/token', jwksUri: 'http://127.0.0.1:1/certs', issuerClaim: 'x' }, { logAuth: () => {} });
  await assert.rejects(signIn('u', 'p'), (e) => e.status === 502);
});

// ---- authorization-code flow --------------------------------------------------------------

const REDIRECT = 'https://host.example/api/auth/oidc/callback';
const AUTHORIZE = 'https://sso.example/realms/r/protocol/openid-connect/auth';

// A stub token endpoint that records what it was sent and answers like Keycloak would. `idRoles` /
// `atRoles` decide where the required role lives, which is the whole point of the fallback test.
async function stubIdp({ idRoles = [], atRoles = [], nonce } = {}) {
  const jwk = publicKey.export({ format: 'jwk' });
  const seen = [];
  const srv = http.createServer(async (req, res) => {
    if (req.url === '/certs') return res.end(JSON.stringify({ keys: [{ ...jwk, kid: 'k1', use: 'sig' }] }));
    let body = ''; for await (const c of req) body += c;
    const f = new URLSearchParams(body);
    seen.push(Object.fromEntries(f));
    if (f.get('grant_type') !== 'authorization_code' || f.get('code') !== 'good-code') { res.statusCode = 400; return res.end(JSON.stringify({ error: 'invalid_grant' })); }
    res.end(JSON.stringify({
      id_token: makeIdToken({ privateKey, kid: 'k1', claims: { ...base, aud: 'artifacts', nonce, realm_access: { roles: idRoles } } }),
      access_token: makeIdToken({ privateKey, kid: 'k1', claims: { ...base, aud: 'account', realm_access: { roles: atRoles } } }),
    }));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const disc = { tokenEndpoint: `http://127.0.0.1:${port}/token`, jwksUri: `http://127.0.0.1:${port}/certs`, authorizationEndpoint: AUTHORIZE, issuerClaim: base.iss };
  return { srv, seen, disc };
}
const cfg = { clientId: 'artifacts', clientSecret: 's', scopes: 'openid profile', requiredRole: 'reports-admin', only: true };

test('start() sends the browser to the IdP with PKCE, state and nonce, and keeps the verifier server-side', () => {
  const flow = createCodeFlow(cfg, { authorizationEndpoint: AUTHORIZE, tokenEndpoint: 'x', jwksUri: 'x', issuerClaim: base.iss }, { logAuth: () => {} });
  const { url, flow: kept } = flow.start(REDIRECT);
  const u = new URL(url);
  assert.equal(`${u.origin}${u.pathname}`, AUTHORIZE);
  assert.equal(u.searchParams.get('response_type'), 'code');
  assert.equal(u.searchParams.get('client_id'), 'artifacts');
  assert.equal(u.searchParams.get('redirect_uri'), REDIRECT);
  assert.equal(u.searchParams.get('state'), kept.s);
  assert.equal(u.searchParams.get('nonce'), kept.n);
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(u.searchParams.get('code_challenge'), pkceChallenge(kept.v));
  assert.ok(!url.includes(kept.v), 'the verifier never appears in the URL');
  assert.notEqual(flow.start(REDIRECT).flow.s, kept.s, 'every attempt gets fresh values');
});

test('finish() redeems the code with the verifier and returns the principal', async () => {
  const { srv, seen, disc } = await stubIdp({ idRoles: ['reports-admin'], nonce: 'N' });
  try {
    const flow = createCodeFlow(cfg, disc, { logAuth: () => {} });
    const name = await flow.finish({ code: 'good-code', state: 'S' }, { s: 'S', n: 'N', v: 'VERIFIER', exp: Date.now() + 60_000 }, REDIRECT);
    assert.equal(name, 'tuna');
    assert.equal(seen[0].code_verifier, 'VERIFIER');
    assert.equal(seen[0].redirect_uri, REDIRECT, 'byte-identical to the one sent to the authorize endpoint');
    assert.equal(seen[0].client_secret, 's');
  } finally { srv.close(); }
});

test('the required role is also found in the access token when the id_token lacks it (Keycloak default)', async () => {
  const { srv, disc } = await stubIdp({ idRoles: [], atRoles: ['reports-admin'], nonce: 'N' });
  try {
    const flow = createCodeFlow(cfg, disc, { logAuth: () => {} });
    assert.equal(await flow.finish({ code: 'good-code', state: 'S' }, { s: 'S', n: 'N', v: 'V', exp: Date.now() + 60_000 }, REDIRECT), 'tuna');
  } finally { srv.close(); }
});

test('an account without the role is refused with 403 even though the IdP signed it in', async () => {
  const { srv, disc } = await stubIdp({ idRoles: [], atRoles: [], nonce: 'N' });
  try {
    const flow = createCodeFlow(cfg, disc, { logAuth: () => {} });
    await assert.rejects(flow.finish({ code: 'good-code', state: 'S' }, { s: 'S', n: 'N', v: 'V', exp: Date.now() + 60_000 }, REDIRECT), (e) => e.status === 403);
  } finally { srv.close(); }
});

test('state, expiry, nonce and a refused code are each rejected', async () => {
  const { srv, disc } = await stubIdp({ idRoles: ['reports-admin'], nonce: 'N' });
  try {
    const flow = createCodeFlow(cfg, disc, { logAuth: () => {} });
    const live = { s: 'S', n: 'N', v: 'V', exp: Date.now() + 60_000 };
    await assert.rejects(flow.finish({ code: 'good-code', state: 'other' }, live, REDIRECT), (e) => e.status === 400, 'state mismatch');
    await assert.rejects(flow.finish({ code: 'good-code', state: 'S'.repeat(500) }, live, REDIRECT), (e) => e.status === 400, 'a very long state is a 400, not a throw');
    await assert.rejects(flow.finish({ code: 'good-code', state: 'S' }, null, REDIRECT), (e) => e.status === 400, 'no flow cookie');
    await assert.rejects(flow.finish({ code: 'good-code', state: 'S' }, { ...live, exp: Date.now() - 1 }, REDIRECT), (e) => e.status === 400, 'expired flow');
    await assert.rejects(flow.finish({ code: 'good-code', state: 'S' }, { ...live, n: 'different' }, REDIRECT), /nonce mismatch/);
    await assert.rejects(flow.finish({ code: 'bad-code', state: 'S' }, live, REDIRECT), (e) => e.status === 401);
    await assert.rejects(flow.finish({ code: undefined, state: 'S' }, live, REDIRECT), (e) => e.status === 400);
  } finally { srv.close(); }
});

test('the new switches default to the safe, compatible values', () => {
  const c = oidcConfigFromEnv({ OIDC_ISSUER: 'https://sso.example/realms/r', OIDC_CLIENT_ID: 'a', OIDC_CLIENT_SECRET: 's' });
  assert.equal(c.passwordForm, true);
  assert.equal(c.ssoButton, 'Sign in with SSO');
  assert.equal(c.returnPath, '/');
  const d = oidcConfigFromEnv({ OIDC_ISSUER: 'https://sso.example/realms/r', OIDC_CLIENT_ID: 'a', OIDC_CLIENT_SECRET: 's', OIDC_PASSWORD_FORM: 'false', OIDC_RETURN_PATH: '/reports/' });
  assert.equal(d.passwordForm, false);
  assert.equal(d.returnPath, '/reports/');
});
