# Coolify + SeaweedFS (durable storage without AWS)

Run artifacts on [Coolify](https://coolify.io) with [SeaweedFS](https://github.com/seaweedfs/seaweedfs)
as the durable object store. SeaweedFS speaks the S3 API, so this is the `s3` backend pointed at
your own box instead of AWS — every artifact lives in SeaweedFS, and the app container holds no
state. ([← back to README](../README.md))

Reach for this when the app host wipes local disk on redeploy, when you want your data on
hardware you control, or when you already run Coolify and would rather not depend on a cloud
bucket. For the AWS/R2/B2 version of the same backend, see [S3](deploy.md#s3-and-s3-compatible-r2-b2-seaweedfs-spaces-wasabi-gcs-interop).

## The shape

Two Coolify resources on one project, talking over the internal Docker network:

```
SeaweedFS  (chrislusf/seaweedfs)  ── volume /data  ← the durable store, back this up
  ▲  S3 API :8333 (internal)
  │
artifacts  (this repo) ── STORAGE_BACKEND=s3 → SeaweedFS ── no volume, stateless
  ▲  :3000 → your reverse proxy → https://artifacts.example.com
```

Because artifacts state (every artifact **and** the reserved `auth.json` — admin account,
both HMAC secrets, managed keys) all go through the storage backend, once the backend is
SeaweedFS the app container is throwaway. Back up SeaweedFS's volume and you have backed up
everything.

## Why SeaweedFS "just works" here

The `s3` backend addresses objects **path-style** (`ENDPOINT/BUCKET/key`), not virtual-hosted
(`BUCKET.ENDPOINT/key`). SeaweedFS's S3 gateway serves path-style requests, so `S3_ENDPOINT` is
just the SeaweedFS host and S3 port with **no bucket in the hostname** and no wildcard DNS to set
up. Requests are signed SigV4 via `aws4fetch`, which ships in the Docker image
(`npm ci --omit=dev` keeps optional deps), so there is nothing extra to install. CI runs the full
smoke suite and a restart-durability check against a real SeaweedFS container on every push.

## Step 1 — SeaweedFS on Coolify

SeaweedFS reads its S3 users and their permissions from an **identity file** passed with
`-s3.config`. Write that file first. One identity for you (to create the bucket), one scoped
identity for the app:

```json
{
  "identities": [
    {
      "name": "admin",
      "credentials": [{ "accessKey": "<admin-access-key>", "secretKey": "<strong-admin-secret>" }],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    },
    {
      "name": "artifacts-app",
      "credentials": [{ "accessKey": "<app-access-key>", "secretKey": "<strong-app-secret>" }],
      "actions": ["Read:artifacts", "Write:artifacts", "List:artifacts"]
    }
  ]
}
```

The `:artifacts` suffix scopes an action to that one bucket, so the app key can read and write
its bucket and nothing else (it cannot create or delete buckets). **Never start SeaweedFS without
`-s3.config`**: with no identities configured its S3 gateway accepts anonymous requests, which
would make every artifact, and `auth.json`, readable and writable by anyone who can reach port
8333.

Then add a Docker-image resource for SeaweedFS:

- **Image:** `chrislusf/seaweedfs:4.47` (pin a version; upgrade on purpose, not on redeploy)
- **Command:** `server -s3 -s3.config=/etc/seaweedfs/s3.json -dir=/data` — one process runs the
  master, a volume server, the filer and the S3 gateway.
- **Volume:** persistent volume mounted at **`/data`** — this is the real durable store (object
  data and the filer's metadata), so put it on disk you back up.
- **File mount:** the identity file above at **`/etc/seaweedfs/s3.json`** (Coolify: Persistent
  Storage → add a file mount and paste the content). Treat it as a secret.
- **Ports:** S3 API `8333`. It can stay internal — see step 3. Do **not** expose the master
  (`9333`), volume (`8080`) or filer (`8888`) ports; they have no authentication.

Bring it up, then create the bucket with the **admin** identity, using any S3 client that can
reach the S3 port — for example the AWS CLI:

```bash
AWS_ACCESS_KEY_ID=<admin-access-key> AWS_SECRET_ACCESS_KEY=<strong-admin-secret> \
AWS_DEFAULT_REGION=us-east-1 AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
  aws --endpoint-url http://<seaweedfs-service>:8333 s3api create-bucket --bucket artifacts
```

(Alternative without an S3 client, from Coolify's terminal on the SeaweedFS container:
`echo "s3.bucket.create -name artifacts" | weed shell`.)

Leave the bucket **private** — do not add an `anonymous` identity or any public-read action.
Artifacts are only ever served back *through* the app so their `noindex`, expiry, disable, and
visibility checks apply; a public bucket bypasses all of it.

## Step 2 — artifacts on Coolify

Add a second resource for this app:

- **Source:** this repo with Build Pack **Dockerfile**, or the prebuilt image
  `ghcr.io/anvilnine/artifacts:latest`.
- **Port:** `3000`. Point a domain at it (`https://artifacts.example.com`) through Coolify's proxy.
- **No `/data` volume needed** — state lives in SeaweedFS. (A volume does no harm, it just goes
  unused.)
- **Healthcheck:** leave Coolify's container healthcheck **disabled**. `node:22-slim` has no
  `curl`/`wget`, so an enabled healthcheck marks the container unhealthy and blocks routing. Point
  an external monitor at `GET /healthz` instead.
- **Env vars:**

  ```
  ARTIFACTS_API_KEY=<openssl rand -hex 32>     # bootstrap admin bearer, required
  BASE_URL=https://artifacts.example.com        # public origin in returned URLs

  STORAGE_BACKEND=s3
  S3_ENDPOINT=http://<seaweedfs-service>:8333   # SeaweedFS S3 API, internal (see step 3)
  S3_BUCKET=artifacts
  S3_ACCESS_KEY_ID=<app-access-key from step 1>
  S3_SECRET_ACCESS_KEY=<strong-app-secret from step 1>
  S3_REGION=us-east-1                           # SeaweedFS ignores it; any value, keep the default
  # S3_PREFIX=artifacts/                        # optional, if the bucket is shared
  ```

  Full meaning of every var is in [deploy.md](deploy.md#configuration) and
  [the S3 table](deploy.md#s3-and-s3-compatible-r2-b2-seaweedfs-spaces-wasabi-gcs-interop).

## Step 3 — keep S3 traffic on the internal network

Point `S3_ENDPOINT` at SeaweedFS's **internal** address so object bytes never leave the Docker
host: put both resources in the **same Coolify project/network** and use the SeaweedFS service's
internal hostname (`http://<seaweedfs-service>:8333`). Internal `http` between the two containers
is fine — it's a private hop, and it dodges TLS-cert hassles on the S3 leg.

Only expose the SeaweedFS **S3 API** publicly if a machine outside the host must reach it. If you
do, put it behind the proxy with `https://` and a **real certificate** — `aws4fetch` uses `fetch`,
which rejects a self-signed cert, so a bad cert makes the app fail its boot probe. Even then,
keep the **bucket private**; the public S3 endpoint is not a public artifact endpoint.

## Bring up and verify

Deploy SeaweedFS first, create the bucket, then deploy artifacts. On boot the app runs a
**write/delete probe** against the bucket and **refuses to start** if SeaweedFS is unreachable or
the creds/bucket are wrong — so a misconfig fails loudly in the deploy log, it never comes up
serving empty. If it crashes at boot, read the log:

- `S3 boot probe rejected (403)` → bad access key/secret, or the identity lacks `Write:artifacts`.
- `S3 boot probe rejected (404)` → `S3_BUCKET` does not exist (create it in step 1).
- `unreachable after retries` → `S3_ENDPOINT` wrong (port is `8333`), or the two resources aren't
  on one network.

Once green, publish a test artifact and confirm it survives a redeploy:

```bash
curl -s -X POST https://artifacts.example.com/api/artifacts \
  -H "Authorization: Bearer $ARTIFACTS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content":"<h1>seaweedfs ok</h1>","type":"html","slug":"seaweedfs-ok","visibility":"public"}'

# Redeploy the artifacts app in Coolify, then:
curl -sS -o /dev/null -w '%{http_code}\n' https://artifacts.example.com/a/seaweedfs-ok   # still 200
```

The artifact surviving a redeploy of the **app** (which has no volume) is the whole point — the
bytes were in SeaweedFS the entire time.

## SeaweedFS notes

| Topic | Detail |
|---|---|
| Addressing | Path-style — the backend builds `ENDPOINT/BUCKET/key`. Served by the S3 gateway on `8333`; no wildcard DNS. |
| Region | SeaweedFS ignores `S3_REGION`; SigV4 still needs *a* value. Keep `us-east-1`. |
| Rename | Uses server-side `CopyObject` (`x-amz-copy-source`), which SeaweedFS supports. |
| Credentials | Use the bucket-scoped app identity, never the admin one. Rotate by editing the identity file and restarting SeaweedFS. |
| Bucket policy | Private, always. No `anonymous` identity; serving happens through the app, not the bucket. |
| Durability | SeaweedFS's `/data` volume is the source of truth — back it up (or run a multi-node cluster with replication). |
| Prefix | Set `S3_PREFIX=artifacts/` if the bucket holds other things; keys stay namespaced. |

## Behind Cloudflare or a reverse proxy

The app rate-limits its two unauthenticated routes (login, unlock) per client IP. Behind a proxy
that number is only right if you tell it where the real client IP comes from — set `TRUST_PROXY`
(`cloudflare` or `xff`) as covered in [rate limiting and the edge](deploy.md#rate-limiting-and-the-edge).

If Coolify sits behind a **Cloudflare tunnel** that terminates TLS, set the app's FQDN in Coolify
as `http://` (not `https://`) — the tunnel already did TLS, and a second TLS attempt at the proxy
gives `SSL_ERROR_RX_RECORD_TOO_LONG`. This is about the app's public FQDN, separate from the
internal `S3_ENDPOINT` in step 3.

## Security follow-ups

- **Rotate `ARTIFACTS_API_KEY` and the SeaweedFS app key** after setup if either transited a chat,
  a paste, or a shared terminal. Day-to-day, hand CLI/MCP clients scoped [managed keys](auth.md),
  not the bootstrap key.
- **Keep the bucket private and the S3 endpoint internal.** The only public surface should be the
  artifacts app's own origin.
- Serve artifacts from a **dedicated origin** that hosts nothing else — see the
  [deployment rule](deploy.md#deployment-rule-security) and [SECURITY.md](../SECURITY.md).
