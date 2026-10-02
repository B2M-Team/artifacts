// Fails when a route or MCP tool that touches artifacts is not classified in lib/ownership.js, so an upstream
// merge cannot add an unchecked surface without a red test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { GUARDED_PREFIXES, ROUTE_GUARDS, MCP_TOOL_GUARDS } from '../lib/ownership.js';

const SERVER = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'server.js'), 'utf8');

test('every route under a guarded prefix is classified, and nothing classified has gone missing', () => {
  const found = new Set();
  for (const m of SERVER.matchAll(/app\.(get|post|put|patch|delete)\('(\/[^']*)'/g)) {
    if (GUARDED_PREFIXES.some((p) => m[2] === p || m[2].startsWith(p + '/'))) found.add(`${m[1].toUpperCase()} ${m[2]}`);
  }
  assert.deepEqual([...found].sort(), Object.keys(ROUTE_GUARDS).sort());
});

test('every MCP tool is classified, and nothing classified has gone missing', () => {
  const tools = [...SERVER.matchAll(/registerTool\(\s*'([a-z_]+)'/g)].map((m) => m[1]);
  assert.ok(tools.length >= 12, 'the scan found the tools');
  assert.deepEqual(tools.sort(), Object.keys(MCP_TOOL_GUARDS).sort());
});

test('routes classified super carry requireUnscoped; slug routes call the ownership check', () => {
  for (const [route, kind] of Object.entries(ROUTE_GUARDS)) {
    const [method, path] = route.split(' ');
    const start = SERVER.indexOf(`app.${method.toLowerCase()}('${path}'`);
    assert.ok(start >= 0, route);
    const block = SERVER.slice(start, SERVER.indexOf('\n});', start));
    if (kind === 'super') assert.match(block, /requireUnscoped/, route);
    if (kind === 'slug') assert.match(block, /assertOwned|canAccess\(scopeFor/, route);
    if (kind === 'create') assert.match(block, /newOwner\(/, route);
    if (kind === 'list') assert.match(block, /scopeFor\(/, route);
  }
});
