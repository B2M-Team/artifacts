// Company sign-in for the dashboard through an OpenID Connect provider, WITHOUT
// leaving the app: the dashboard keeps its own username/password form and this
// module exchanges those credentials with the IdP's token endpoint (resource
// owner password grant — "direct access grant" in Keycloak). No redirect to the
// IdP's pages, no callback URL, no second password. Dependency-free: the id_token
// is verified with node:crypto against the issuer's JWKS (RS*/ES*).
//
// Env:
//   OIDC_ISSUER           public issuer, e.g. https://sso.example.com/auth/realms/main (enables OIDC)
//   OIDC_CLIENT_ID        confidential client id
//   OIDC_CLIENT_SECRET    its secret
//   OIDC_INTERNAL_ISSUER  optional: issuer URL reachable from this server (in-cluster), used for
//                         the token and JWKS calls. The browser still goes to OIDC_ISSUER.
//   OIDC_REQUIRED_ROLE    optional: a realm/app role the id_token must carry (realm_access.roles
//                         or roles claim). Empty = every authenticated user is an admin.
//   OIDC_ONLY             "true" (default) — the form only accepts IdP accounts. "false" — when the
//                         IdP refuses, the local admin account is tried as a break-glass fallback.
//   OIDC_SCOPES           default "openid profile email"
//   OIDC_SIGNIN_TITLE     text over the form, default "Sign in with your company account"
import crypto from 'node:crypto';

export function oidcConfigFromEnv(env = process.env) {
  const issuer = (env.OIDC_ISSUER || '').replace(/\/$/, '');
  if (!issuer) return null;
  const clientId = env.OIDC_CLIENT_ID;
  const clientSecret = env.OIDC_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error('OIDC_ISSUER is set but OIDC_CLIENT_ID / OIDC_CLIENT_SECRET are missing');
  }
  const only = env.OIDC_ONLY === undefined ? true : /^(1|true)$/i.test(env.OIDC_ONLY);
  return {
    issuer,
    internalIssuer: (env.OIDC_INTERNAL_ISSUER || issuer).replace(/\/$/, ''),
    clientId,
    clientSecret,
    requiredRole: env.OIDC_REQUIRED_ROLE || '',
    only,
    scopes: env.OIDC_SCOPES || 'openid profile email',
    signinTitle: env.OIDC_SIGNIN_TITLE || 'Sign in with your company account',
  };
}

// Discovery is fetched once per process from the internal issuer, but the endpoints the
// BROWSER is sent to are rebuilt on the public issuer: a Keycloak behind a private hostname
// answers discovery with whatever frontend URL it was told, which is not always the one the
// operator's users can reach.
export async function loadDiscovery(cfg) {
  const res = await fetch(`${cfg.internalIssuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`oidc discovery ${res.status} from ${cfg.internalIssuer}`);
  const d = await res.json();
  // Keycloak answers discovery with whatever hostname it was configured with. The only
  // endpoints used (token, jwks) are called by THIS SERVER, so they are rebuilt on the
  // internal origin: sign-in never depends on egress to the public ingress. Only the
  // origin is swapped, the path is the IdP's own.
  const onOrigin = (url, base) => {
    if (!url) return url;
    const b = new URL(base);
    const u = new URL(url);
    u.protocol = b.protocol;
    u.host = b.host;
    return u.toString();
  };
  if (!(d.grant_types_supported || ['password']).includes('password')) {
    throw new Error('the IdP does not advertise the password grant; enable direct access grants on the client');
  }
  return {
    tokenEndpoint: onOrigin(d.token_endpoint, cfg.internalIssuer),
    jwksUri: onOrigin(d.jwks_uri, cfg.internalIssuer),
    // Tokens carry the public issuer in `iss` (Keycloak's frontend URL), not the internal
    // hostname discovery may have been fetched from.
    issuerClaim: cfg.issuer,
  };
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function decodeSegment(seg) {
  return JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
}

const SIG_ALGS = {
  RS256: { hash: 'sha256' },
  RS384: { hash: 'sha384' },
  RS512: { hash: 'sha512' },
  ES256: { hash: 'sha256', dsa: 'ieee-p1363' },
  ES384: { hash: 'sha384', dsa: 'ieee-p1363' },
  ES512: { hash: 'sha512', dsa: 'ieee-p1363' },
};

// JWKS is cached and refreshed once on an unknown kid (key rotation), never more often
// than every 60s so a flood of bad tokens cannot hammer the IdP.
export function createJwks(jwksUri) {
  let keys = new Map();
  let lastFetch = 0;
  async function refresh() {
    const res = await fetch(jwksUri);
    if (!res.ok) throw new Error(`jwks ${res.status}`);
    const { keys: list } = await res.json();
    keys = new Map(list.filter((k) => k.use !== 'enc').map((k) => [k.kid, crypto.createPublicKey({ key: k, format: 'jwk' })]));
    lastFetch = Date.now();
  }
  return {
    async get(kid) {
      if (!keys.has(kid) && Date.now() - lastFetch > 60_000) await refresh();
      return keys.get(kid) || null;
    },
  };
}

export async function verifyIdToken(token, { jwks, issuerClaim, clientId, nonce, requireAudience = true }) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('id_token: malformed');
  const [h, p, s] = parts;
  const header = decodeSegment(h);
  const alg = SIG_ALGS[header.alg];
  if (!alg) throw new Error(`id_token: unsupported alg ${header.alg}`);
  const key = await jwks.get(header.kid);
  if (!key) throw new Error('id_token: unknown signing key');
  const ok = crypto.verify(alg.hash, Buffer.from(`${h}.${p}`), { key, dsaEncoding: alg.dsa }, Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('id_token: bad signature');
  const claims = decodeSegment(p);
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== issuerClaim) throw new Error('id_token: wrong issuer');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (requireAudience && !aud.includes(clientId)) throw new Error('id_token: wrong audience');
  if (typeof claims.exp !== 'number' || claims.exp <= now - 30) throw new Error('id_token: expired');
  if (nonce && claims.nonce !== nonce) throw new Error('id_token: nonce mismatch');
  return claims;
}

export function hasRequiredRole(claims, role) {
  if (!role) return true;
  const roles = new Set([
    ...(claims.realm_access?.roles || []),
    ...(Array.isArray(claims.roles) ? claims.roles : []),
    ...Object.values(claims.resource_access || {}).flatMap((r) => r.roles || []),
  ]);
  return roles.has(role);
}

export function principalName(claims) {
  return claims.preferred_username || claims.email || claims.sub;
}

// Exchanges a username/password with the IdP (resource owner password grant) and returns
// the signed-in principal's name. Throws { status, message } the way ApiError is shaped:
// 401 for a refused credential, 403 for a missing role, 502 when the IdP misbehaves.
export function createPasswordSignIn(cfg, discovery, deps) {
  const jwks = createJwks(discovery.jwksUri);
  const fail = (status, message) => Object.assign(new Error(message), { status });
  return async function signIn(username, password) {
    const body = new URLSearchParams({
      grant_type: 'password',
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      username,
      password,
      scope: cfg.scopes,
    });
    let tr;
    try {
      tr = await fetch(discovery.tokenEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    } catch (e) {
      deps.logAuth('oidc', { username, outcome: 'idp_unreachable', error: e.message });
      throw fail(502, 'the identity provider is unreachable');
    }
    if (tr.status === 400 || tr.status === 401) {
      // invalid_grant covers a wrong password, a disabled user, a required action (e.g.
      // "verify profile") and a user the client may not see. All of them are "no" here;
      // the IdP's own reason goes to the log, not to the login form.
      const detail = await tr.json().catch(() => ({}));
      deps.logAuth('oidc', { username, outcome: 'refused', error: detail.error_description || detail.error });
      throw fail(401, 'invalid credentials');
    }
    if (!tr.ok) {
      deps.logAuth('oidc', { username, outcome: 'idp_error', status: tr.status });
      throw fail(502, 'the identity provider answered with an error');
    }
    const tokens = await tr.json();
    const claims = await verifyIdToken(tokens.id_token, { jwks, issuerClaim: discovery.issuerClaim, clientId: cfg.clientId });
    const name = principalName(claims);
    // Keycloak puts realm/client roles in the ACCESS token by default and only adds them to
    // the id_token when the operator flips a mapper. When the id_token has no such role,
    // look in the access token too — after checking it is a JWT this issuer signed (its
    // audience is the resource server's, not ours, so that check is skipped).
    let roleClaims = claims;
    if (cfg.requiredRole && !hasRequiredRole(claims, cfg.requiredRole) && typeof tokens.access_token === 'string' && tokens.access_token.split('.').length === 3) {
      try {
        roleClaims = await verifyIdToken(tokens.access_token, { jwks, issuerClaim: discovery.issuerClaim, clientId: cfg.clientId, requireAudience: false });
      } catch (e) {
        deps.logAuth('oidc', { username: name, outcome: 'access_token_unverified', error: e.message });
      }
    }
    if (!hasRequiredRole(roleClaims, cfg.requiredRole)) {
      deps.logAuth('oidc', { username: name, outcome: 'forbidden' });
      throw fail(403, `signed in as ${name}, but this account has no "${cfg.requiredRole}" role — ask an administrator`);
    }
    deps.logAuth('oidc', { username: name, outcome: 'ok' });
    return name;
  };
}
