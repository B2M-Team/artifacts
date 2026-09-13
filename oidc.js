// OpenID Connect sign-in for the dashboard (authorization code + PKCE), so an
// operator with a company IdP (Keycloak, Entra, Okta, …) does not run a second
// password just for this app. Dependency-free: the id_token is verified with
// node:crypto against the issuer's JWKS (RS256/RS384/RS512, ES256/384/512).
//
// Env:
//   OIDC_ISSUER           public issuer, e.g. https://sso.example.com/auth/realms/main (enables OIDC)
//   OIDC_CLIENT_ID        confidential client id
//   OIDC_CLIENT_SECRET    its secret
//   OIDC_INTERNAL_ISSUER  optional: issuer URL reachable from this server (in-cluster), used for
//                         the token and JWKS calls. The browser still goes to OIDC_ISSUER.
//   OIDC_REQUIRED_ROLE    optional: a realm/app role the id_token must carry (realm_access.roles
//                         or roles claim). Empty = every authenticated user is an admin.
//   OIDC_ONLY             "true" (default when OIDC is on) hides the local username/password form.
//   OIDC_RETURN_PATH      where the browser lands after sign-in/sign-out, default "/"
//   OIDC_SCOPES           default "openid profile email"
import crypto from 'node:crypto';

const OIDC_COOKIE = 'artifacts_oidc';
const FLOW_TTL_MS = 10 * 60 * 1000;

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
    returnPath: env.OIDC_RETURN_PATH || '/',
    scopes: env.OIDC_SCOPES || 'openid profile email',
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
  // Keycloak answers discovery with whatever hostname it was configured with. Endpoints the
  // BROWSER visits are rebuilt on the public issuer's origin; endpoints THIS SERVER calls
  // (token, jwks) on the internal one, so sign-in never depends on egress to the public
  // ingress. Only the origin is swapped, the path is the IdP's own.
  const onOrigin = (url, base) => {
    if (!url) return url;
    const b = new URL(base);
    const u = new URL(url);
    u.protocol = b.protocol;
    u.host = b.host;
    return u.toString();
  };
  return {
    authorizationEndpoint: onOrigin(d.authorization_endpoint, cfg.issuer),
    endSessionEndpoint: d.end_session_endpoint ? onOrigin(d.end_session_endpoint, cfg.issuer) : null,
    tokenEndpoint: onOrigin(d.token_endpoint, cfg.internalIssuer),
    jwksUri: onOrigin(d.jwks_uri, cfg.internalIssuer),
    // The id_token is minted for a browser that came in through the public issuer, so
    // that is the `iss` it carries — not the internal hostname discovery may report.
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

// Mounts /api/auth/oidc/{login,callback,logout}. `deps` supplies what the host app owns:
//   signSession/verifySession(payload|token, secret), ensureSessionSecret(), issueSession(res, name, extra),
//   readCookie(req, name), baseUrl, logAuth(event, fields)
export function mountOidc(app, cfg, discovery, deps) {
  const jwks = createJwks(discovery.jwksUri);
  const callbackUrl = `${deps.baseUrl}/api/auth/oidc/callback`;
  const secure = deps.baseUrl.startsWith('https');

  app.get('/api/auth/oidc/login', async (req, res, next) => {
    try {
      const secret = await deps.ensureSessionSecret();
      const state = b64url(crypto.randomBytes(24));
      const nonce = b64url(crypto.randomBytes(24));
      const verifier = b64url(crypto.randomBytes(48));
      const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
      const flow = deps.signSession({ state, nonce, verifier, exp: Date.now() + FLOW_TTL_MS }, secret);
      res.cookie(OIDC_COOKIE, flow, { httpOnly: true, secure, sameSite: 'lax', maxAge: FLOW_TTL_MS, path: '/api/auth/oidc' });
      const u = new URL(discovery.authorizationEndpoint);
      u.searchParams.set('client_id', cfg.clientId);
      u.searchParams.set('response_type', 'code');
      u.searchParams.set('scope', cfg.scopes);
      u.searchParams.set('redirect_uri', callbackUrl);
      u.searchParams.set('state', state);
      u.searchParams.set('nonce', nonce);
      u.searchParams.set('code_challenge', challenge);
      u.searchParams.set('code_challenge_method', 'S256');
      res.redirect(302, u.toString());
    } catch (err) {
      next(err);
    }
  });

  app.get('/api/auth/oidc/callback', async (req, res, next) => {
    try {
      const secret = await deps.ensureSessionSecret();
      const flow = deps.verifySession(deps.readCookie(req, OIDC_COOKIE), secret);
      res.clearCookie(OIDC_COOKIE, { path: '/api/auth/oidc' });
      const { code, state, error, error_description: desc } = req.query;
      if (error) return res.status(401).type('text/plain').send(`sign-in refused by the identity provider: ${desc || error}`);
      if (!flow || flow.exp < Date.now() || !state || state !== flow.state) {
        return res.status(400).type('text/plain').send('sign-in flow expired or state mismatch — start again from the dashboard');
      }
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: callbackUrl,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        code_verifier: flow.verifier,
      });
      const tr = await fetch(discovery.tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
      if (!tr.ok) {
        deps.logAuth('oidc', { outcome: 'token_error', status: tr.status });
        return res.status(502).type('text/plain').send('could not exchange the sign-in code with the identity provider');
      }
      const tokens = await tr.json();
      const claims = await verifyIdToken(tokens.id_token, {
        jwks,
        issuerClaim: discovery.issuerClaim,
        clientId: cfg.clientId,
        nonce: flow.nonce,
      });
      const name = principalName(claims);
      // Keycloak puts realm/client roles in the ACCESS token by default and only adds them to
      // the id_token when the operator flips a mapper. So when the id_token has no such role,
      // look in the access token too — but only after checking it is a JWT this issuer signed
      // (its audience is the resource server's, not ours, so that check is skipped).
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
        return res.status(403).type('text/plain').send(`signed in as ${name}, but this account has no "${cfg.requiredRole}" role — ask an administrator`);
      }
      await deps.issueSession(res, name, { oidc: true });
      deps.logAuth('oidc', { username: name, outcome: 'ok' });
      res.redirect(302, cfg.returnPath);
    } catch (err) {
      deps.logAuth('oidc', { outcome: 'error', error: err.message });
      next(err);
    }
  });

  // Ends the local session AND the IdP session, otherwise an OIDC-only dashboard signs the
  // user straight back in on the next load.
  app.get('/api/auth/oidc/logout', (req, res) => {
    res.clearCookie(deps.sessionCookie, { path: '/' });
    if (!discovery.endSessionEndpoint) return res.redirect(302, cfg.returnPath);
    const u = new URL(discovery.endSessionEndpoint);
    u.searchParams.set('client_id', cfg.clientId);
    u.searchParams.set('post_logout_redirect_uri', `${deps.baseUrl}${cfg.returnPath}`);
    res.redirect(302, u.toString());
  });
}
