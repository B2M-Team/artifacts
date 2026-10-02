// Owner-based access to artifacts.
//
// Off by default (OWNER_SCOPING unset): every principal sees and edits every artifact, as before.
// On, a principal is either
//   * unscoped — the bootstrap key, a managed key with no `owner`, a local-admin session, or a
//     company sign-in session holding OIDC_ADMIN_ROLE: sees and edits everything; or
//   * scoped to one owner — a company sign-in session without that role (owner = its username) or a
//     managed key minted with an `owner`: sees, edits and deletes only artifacts whose
//     `meta.owner` is that name. An artifact with no owner (published before scoping) belongs to
//     nobody, so only unscoped principals reach it.
//
// The owner of a new artifact comes from the AUTHENTICATED principal, never from the request body:
// a scoped principal owns what it publishes; an unscoped one (a trusted service holding the
// bootstrap key, e.g. the Shahin MCP) may name the owner with the X-Artifacts-Owner header.
// Nothing a caller puts in `project`, `tags` or any other field changes ownership.

export const OWNER_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/;

export function ownerScopingEnabled(env = process.env) {
  return /^(1|true)$/i.test(env.OWNER_SCOPING || '');
}

const norm = (s) => String(s).trim().toLowerCase();

// -> { scoped: false } | { scoped: true, owner }
export function scopeOf(principal, enabled) {
  if (!enabled || !principal) return { scoped: false };
  if (principal.super) return { scoped: false };
  // A company sign-in session without the admin role is scoped to its own username.
  if (principal.session && principal.oidc) {
    return typeof principal.username === 'string' && principal.username
      ? { scoped: true, owner: norm(principal.username) }
      : { scoped: true, owner: null }; // no usable name: matches nothing
  }
  // A managed key minted with an owner is scoped to it; one without (and the bootstrap key) is not.
  if (principal.key && typeof principal.key.owner === 'string' && principal.key.owner) {
    return { scoped: true, owner: norm(principal.key.owner) };
  }
  return { scoped: false };
}

export function canAccess(scope, meta) {
  if (!scope.scoped) return true;
  if (!scope.owner || !meta || typeof meta.owner !== 'string' || !meta.owner) return false;
  return norm(meta.owner) === scope.owner;
}

// The owner to stamp on a NEW artifact, or undefined for "leave it unowned".
export function ownerForNew(scope, headerValue) {
  if (scope.scoped) return scope.owner || undefined;
  if (typeof headerValue === 'string' && OWNER_RE.test(headerValue.trim())) return headerValue.trim();
  return undefined;
}

// Validates an owner a super-admin assigns (key owner, backfill). Returns the cleaned name or throws.
export function cleanOwner(value) {
  const v = typeof value === 'string' ? value.trim() : '';
  if (!OWNER_RE.test(v)) throw Object.assign(new Error('owner must be 1-64 chars of letters, digits, . _ @ -'), { status: 400 });
  return v;
}

// ---- the guard table ------------------------------------------------------------------------
// Every route under these prefixes and every MCP tool must be classified here. test/ownership-guard.test.js
// scans server.js and fails on one that is missing, so an upstream merge that adds a route or a tool cannot
// silently ship it unchecked (the MCP wrapper in server.js also refuses to register an unclassified tool).
//   slug    — acts on one existing artifact: a scoped caller gets 404 unless it owns it
//   create  — makes an artifact: the owner is stamped from the principal (or the trusted header)
//   list    — returns artifacts: filtered to the caller's own
//   super   — unscoped principals only (403 for a scoped one)
//   open    — carries no artifact data
export const GUARDED_PREFIXES = ['/api/artifacts', '/api/keys', '/api/config', '/api/owners'];
export const ROUTE_GUARDS = {
  'POST /api/artifacts': 'create',
  'POST /api/artifacts/zip': 'create',
  'PUT /api/artifacts/:slug': 'slug',
  'PATCH /api/artifacts/:slug': 'slug',
  'DELETE /api/artifacts/:slug': 'slug',
  'GET /api/artifacts/:slug/link': 'slug',
  'GET /api/artifacts/:slug/qr': 'slug',
  'POST /api/artifacts/:slug/duplicate': 'slug',
  'GET /api/artifacts': 'list',
  'GET /api/config': 'open',
  'PUT /api/config': 'super',
  'GET /api/keys': 'super',
  'POST /api/keys': 'super',
  'PATCH /api/keys/:id': 'super',
  'DELETE /api/keys/:id': 'super',
  'POST /api/owners/backfill': 'super',
};
export const MCP_TOOL_GUARDS = {
  publish_artifact: 'create',
  list_artifacts: 'list',
  update_artifact: 'slug',
  rename_artifact: 'slug',
  set_artifact_expiry: 'slug',
  set_artifact_tags: 'slug',
  set_artifact_project: 'slug',
  set_artifact_visibility: 'slug',
  disable_artifact: 'slug',
  enable_artifact: 'slug',
  set_artifact_frame: 'slug',
  delete_artifact: 'slug',
};
