// Boots a real server with OWNER_SCOPING=true and drives every artifact surface with owner-scoped keys.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BOOT = 'boot-key-for-ownership-test';
let proc, base, dir, A, B, C; // A: owner alice, B: owner bob, C: key with no owner (unscoped)

const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
async function call(method, path, { key = BOOT, body, headers = {} } = {}) {
  const r = await fetch(base + path, { method, headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  return { status: r.status, body: json };
}
const slugs = (r) => r.body.map((a) => a.slug).sort();

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'own-'));
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  proc = spawn('node', ['server.js'], { cwd: ROOT, env: { PATH: process.env.PATH, PORT: String(port), DATA_DIR: dir, ARTIFACTS_API_KEY: BOOT, BASE_URL: base, OWNER_SCOPING: 'true' }, stdio: 'ignore' });
  for (let i = 0; i < 60; i++) { try { if ((await fetch(base + '/healthz')).ok) break; } catch {} await new Promise((r) => setTimeout(r, 250)); }
  // keys are minted with the bootstrap key (the only thing that may mint)
  const mint = async (name, owner) => (await call('POST', '/api/keys', { body: { name, scopes: ['full'], ...(owner ? { owner } : {}) } })).body.key;
  A = await mint('alice-key', 'alice'); B = await mint('bob-key', 'bob'); C = await mint('service-key');
  const pub = (key, slug, extra = {}, headers = {}) => call('POST', '/api/artifacts', { key, body: { slug, content: `<h1>${slug}</h1>`, visibility: 'public', ...extra }, headers });
  assert.equal((await pub(A, 'alice-one')).status, 201);
  assert.equal((await pub(B, 'bob-one')).status, 201);
  assert.equal((await pub(BOOT, 'legacy-one', { project: 'carol' })).status, 201); // unowned
  assert.equal((await pub(C, 'for-alice', {}, { 'X-Artifacts-Owner': 'alice' })).status, 201); // a trusted service names the owner
});
after(() => { proc?.kill(); if (dir) rmSync(dir, { recursive: true, force: true }); });

test('each owner lists only their own; unscoped principals list all', async () => {
  assert.deepEqual(slugs(await call('GET', '/api/artifacts', { key: A })), ['alice-one', 'for-alice']);
  assert.deepEqual(slugs(await call('GET', '/api/artifacts', { key: B })), ['bob-one']);
  assert.deepEqual(slugs(await call('GET', '/api/artifacts', { key: C })), ['alice-one', 'bob-one', 'for-alice', 'legacy-one']);
  assert.deepEqual(slugs(await call('GET', '/api/artifacts')), ['alice-one', 'bob-one', 'for-alice', 'legacy-one']);
  const own = (await call('GET', '/api/artifacts', { key: A })).body.find((a) => a.slug === 'for-alice');
  assert.equal(own.owner, 'alice');
});

test('every slug route is a 404 for a non-owner and works for the owner', async () => {
  const table = [
    ['GET', '/api/artifacts/bob-one/link'],
    ['GET', '/api/artifacts/bob-one/qr'],
    ['PATCH', '/api/artifacts/bob-one', { title: 'hijack' }],
    ['PUT', '/api/artifacts/bob-one', { content: '<p>x</p>' }],
    ['POST', '/api/artifacts/bob-one/duplicate', { slug: 'stolen-copy' }],
    ['DELETE', '/api/artifacts/bob-one'],
    ['GET', '/api/artifacts/legacy-one/link'], // unowned: not alice's either
    ['DELETE', '/api/artifacts/legacy-one'],
  ];
  for (const [m, p, body] of table) assert.equal((await call(m, p, { key: A, body })).status, 404, `${m} ${p} as alice`);
  assert.equal((await call('GET', '/api/artifacts/alice-one/link', { key: A })).status, 200);
  assert.equal((await call('PATCH', '/api/artifacts/alice-one', { key: A, body: { title: 'mine' } })).status, 200);
  assert.equal((await call('POST', '/api/artifacts/alice-one/duplicate', { key: A, body: { slug: 'alice-copy' } })).status, 201);
  assert.equal((await call('GET', '/api/artifacts', { key: A })).body.find((a) => a.slug === 'alice-copy').owner, 'alice', 'a copy is owned by whoever made it');
  assert.equal((await call('DELETE', '/api/artifacts/alice-copy', { key: A })).status, 200);
  // bob's artifact is untouched by all of the above
  const bob = (await call('GET', '/api/artifacts', { key: B })).body.find((a) => a.slug === 'bob-one');
  assert.notEqual(bob.title, 'hijack');
});

test('the owner cannot be chosen by a scoped caller: not by header, not by body, not by patch', async () => {
  const r = await call('POST', '/api/artifacts', { key: A, headers: { 'X-Artifacts-Owner': 'bob' }, body: { slug: 'alice-sneaky', content: '<p>x</p>', owner: 'bob', project: 'bob', visibility: 'public' } });
  assert.equal(r.status, 201);
  const made = (await call('GET', '/api/artifacts', { key: A })).body.find((a) => a.slug === 'alice-sneaky');
  assert.equal(made.owner, 'alice');
  await call('PATCH', '/api/artifacts/alice-sneaky', { key: A, body: { owner: 'bob', project: 'bob' } });
  assert.equal((await call('GET', '/api/artifacts', { key: A })).body.find((a) => a.slug === 'alice-sneaky').owner, 'alice');
  assert.ok(!(await call('GET', '/api/artifacts', { key: B })).body.some((a) => a.slug === 'alice-sneaky'), 'bob never sees it, whatever its project label says');
  // replacing keeps the owner
  await call('PUT', '/api/artifacts/alice-sneaky', { key: A, body: { content: '<p>y</p>' } });
  assert.equal((await call('GET', '/api/artifacts', { key: A })).body.find((a) => a.slug === 'alice-sneaky').owner, 'alice');
});

test('a scoped key cannot reach keys, config or the backfill (the way to mint an unscoped key)', async () => {
  for (const [m, p, body] of [['GET', '/api/keys'], ['POST', '/api/keys', { name: 'x' }], ['PATCH', '/api/keys/abc', { owner: null }], ['DELETE', '/api/keys/abc'], ['PUT', '/api/config', { branding: {} }], ['POST', '/api/owners/backfill', { dryRun: false }]]) {
    const r = await call(m, p, { key: A, body });
    assert.ok(r.status === 401 || r.status === 403, `${m} ${p} → ${r.status}`);
  }
  // an unowned managed key is unscoped but is not an administrator of keys either
  assert.equal((await call('POST', '/api/keys', { key: C, body: { name: 'x' } })).status, 401);
});

test('zip uploads are stamped with the uploader', async () => {
  const { default: AdmZip } = await import('adm-zip');
  const z = new AdmZip(); z.addFile('index.html', Buffer.from('<h1>z</h1>'));
  const r = await fetch(`${base}/api/artifacts/zip?slug=alice-zip&visibility=public`, { method: 'POST', headers: { Authorization: `Bearer ${A}`, 'Content-Type': 'application/zip' }, body: z.toBuffer() });
  assert.equal(r.status, 201);
  assert.equal((await call('GET', '/api/artifacts', { key: A })).body.find((a) => a.slug === 'alice-zip').owner, 'alice');
  assert.ok(!(await call('GET', '/api/artifacts', { key: B })).body.some((a) => a.slug === 'alice-zip'));
});

async function mcp(key, name, args) {
  const r = await fetch(base + '/mcp', { method: 'POST', headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }) });
  const text = await r.text();
  const data = text.split('\n').find((l) => l.startsWith('data:'));
  return JSON.parse(data ? data.slice(5) : text).result;
}

test('MCP tools are scoped too: list is filtered, slug tools refuse a non-owner, publish stamps the owner', async () => {
  const listed = JSON.parse((await mcp(B, 'list_artifacts', {})).content[0].text).map((a) => a.slug);
  assert.deepEqual(listed, ['bob-one']);
  for (const [tool, args] of [['delete_artifact', { slug: 'alice-one' }], ['set_artifact_tags', { slug: 'alice-one', tags: ['x'] }], ['rename_artifact', { slug: 'alice-one', newSlug: 'bob-took-it' }], ['set_artifact_visibility', { slug: 'alice-one', visibility: 'private' }]]) {
    const r = await mcp(B, tool, args);
    assert.equal(r.isError, true, `${tool} as bob`);
  }
  assert.equal((await call('GET', '/api/artifacts', { key: A })).body.some((a) => a.slug === 'alice-one'), true, 'alice-one survived');
  await mcp(B, 'publish_artifact', { slug: 'bob-mcp', content: '<p>m</p>', visibility: 'public' });
  assert.equal((await call('GET', '/api/artifacts', { key: B })).body.find((a) => a.slug === 'bob-mcp').owner, 'bob');
});

test('backfill: dry run by default, assign beats project, unowned stay super-only, then it applies once', async () => {
  const dry = await call('POST', '/api/owners/backfill', { body: {} });
  assert.equal(dry.status, 200);
  assert.equal(dry.body.dryRun, true);
  const row = dry.body.rows.find((r) => r.slug === 'legacy-one');
  assert.deepEqual([row.owner, row.proposedOwner, row.applied], [null, 'carol', false]);
  assert.equal((await call('GET', '/api/artifacts', { key: A })).body.some((a) => a.slug === 'legacy-one'), false, 'a dry run changes nothing');
  const bad = await call('POST', '/api/owners/backfill', { body: { assign: { 'legacy-one': 'a b' } } });
  assert.equal(bad.status, 400);
  const done = await call('POST', '/api/owners/backfill', { body: { dryRun: false, assign: { 'legacy-one': 'alice' } } });
  assert.equal(done.body.rows.find((r) => r.slug === 'legacy-one').applied, true);
  assert.equal((await call('GET', '/api/artifacts', { key: A })).body.some((a) => a.slug === 'legacy-one'), true, 'now alice\'s');
  const again = await call('POST', '/api/owners/backfill', { body: { dryRun: false } });
  assert.equal(again.body.rows.filter((r) => r.applied).length, 0, 'owned artifacts are never reassigned');
});
