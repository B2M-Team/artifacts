import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { oidcConfigFromEnv, verifyIdToken, hasRequiredRole, principalName } from '../oidc.js';

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
