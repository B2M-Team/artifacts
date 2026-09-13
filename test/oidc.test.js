import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { oidcConfigFromEnv, verifyIdToken, hasRequiredRole, principalName, createPasswordSignIn } from '../oidc.js';

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
