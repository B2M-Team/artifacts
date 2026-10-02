# Owner-based access

Off by default. With `OWNER_SCOPING=true` an artifact has an **owner** and most people only see and change
their own.

| Principal | Scope |
|---|---|
| Company sign-in session holding `OIDC_ADMIN_ROLE` | everything |
| Company sign-in session without it | only artifacts whose owner is its username |
| Local-admin session (`/api/auth/setup`) | everything (break-glass) |
| Bootstrap key (`ARTIFACTS_API_KEY`) | everything |
| Managed key **with** an `owner` | only that owner's artifacts |
| Managed key **without** an owner | everything (how every key worked before) |

A not-owned artifact answers **404** on every route and MCP tool (`list` filters it out, `link`, `qr`, `PATCH`,
`PUT`, `DELETE`, `duplicate` refuse it), the way a private artifact hides from the public. Artifacts with no owner
(published before scoping) belong to nobody: only unscoped principals reach them. `/a/<slug>` (the public
viewer) is unchanged; visibility still means who can open the link.

## Who becomes the owner

Only the authenticated principal decides, never the request body:

* a scoped principal owns what it publishes (a `copy` is owned by whoever made it; a replace keeps the owner);
* an **unscoped** principal may name the owner with the `X-Artifacts-Owner` header on create (`POST
  /api/artifacts`, `/zip`, `duplicate`, MCP `publish_artifact`). That is for a trusted service holding the
  bootstrap key (the Shahin MCP). Anyone with that key can already read everything, so the header is a
  statement by someone entitled to make it. A scoped caller's header is ignored.

`project`, `tags` and every other field are labels; changing them never changes ownership.

## Keys, config, backfill

`/api/keys*`, `PUT /api/config` and `/api/owners/backfill` are for unscoped principals only; a scoped one gets 403
(otherwise it could mint an owner-less key, which is unscoped). `POST /api/keys` and `PATCH /api/keys/:id` take
`owner` (a name, or `null` to unscope).

`POST /api/owners/backfill` assigns owners to artifacts that have none. It is a **dry run** unless
`{"dryRun": false}`. `assign` (`{slug: owner}`) wins; otherwise an unowned artifact whose `project` label is a
valid owner name takes it (`fromProject`, default true). Owned artifacts are never reassigned.

## Sessions

Signing out of a company session revokes **that user's** earlier sessions (`revoked` in `auth.json`); it no
longer rotates the secret that signs everyone's cookies. The local admin still rotates it.

## Config

```
OWNER_SCOPING=true
OIDC_ADMIN_ROLE=platform-admin   # a role in the id/access token; holders see everything
```

`test/ownership-guard.test.js` fails when a route under `/api/artifacts`, `/api/keys`, `/api/config` or
`/api/owners`, or an MCP tool, is missing from the table in `lib/ownership.js`; the MCP server refuses to
register an unclassified tool.
