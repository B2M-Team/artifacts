import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scopeOf, canAccess, ownerForNew, cleanOwner, ownerScopingEnabled, OWNER_RE } from '../lib/ownership.js';

const session = (over = {}) => ({ admin: true, session: true, oidc: true, username: 'Vijay.Sharma', super: false, ...over });
const key = (owner) => ({ admin: false, scopes: ['full'], keyId: 'k1', key: { id: 'k1', owner } });
const BOOT = { admin: true, scopes: ['full'], keyId: null, key: null };

test('scoping is off unless OWNER_SCOPING is true/1', () => {
  assert.equal(ownerScopingEnabled({}), false);
  assert.equal(ownerScopingEnabled({ OWNER_SCOPING: 'false' }), false);
  assert.equal(ownerScopingEnabled({ OWNER_SCOPING: 'true' }), true);
  assert.equal(ownerScopingEnabled({ OWNER_SCOPING: '1' }), true);
});

test('with scoping off nobody is scoped', () => {
  for (const p of [session(), key('a'), BOOT]) assert.deepEqual(scopeOf(p, false), { scoped: false });
});

test('who is scoped when it is on', () => {
  assert.deepEqual(scopeOf(session(), true), { scoped: true, owner: 'vijay.sharma' });
  assert.deepEqual(scopeOf(session({ super: true }), true), { scoped: false }, 'the admin role lifts it');
  assert.deepEqual(scopeOf({ admin: true, session: true, username: 'admin' }, true), { scoped: false }, 'local admin is break-glass');
  assert.deepEqual(scopeOf(key('Hassan.Munir'), true), { scoped: true, owner: 'hassan.munir' });
  assert.deepEqual(scopeOf(key(undefined), true), { scoped: false }, 'a legacy key without owner stays unscoped');
  assert.deepEqual(scopeOf(BOOT, true), { scoped: false });
  assert.deepEqual(scopeOf(session({ username: '' }), true), { scoped: true, owner: null }, 'no usable name matches nothing');
});

test('a scoped principal reaches only its own artifacts; unowned ones are for unscoped principals', () => {
  const s = scopeOf(session(), true);
  assert.equal(canAccess(s, { owner: 'vijay.sharma' }), true);
  assert.equal(canAccess(s, { owner: 'VIJAY.SHARMA' }), true, 'case-insensitive');
  assert.equal(canAccess(s, { owner: 'hassan.munir' }), false);
  assert.equal(canAccess(s, {}), false, 'unowned');
  assert.equal(canAccess(s, null), false);
  assert.equal(canAccess(scopeOf(session({ username: '' }), true), { owner: '' }), false);
  assert.equal(canAccess({ scoped: false }, {}), true);
});

test('the owner of a new artifact is the principal, or the header only for unscoped callers', () => {
  const scoped = scopeOf(session(), true);
  assert.equal(ownerForNew(scoped, 'someone.else'), 'vijay.sharma', 'a scoped caller cannot name another owner');
  assert.equal(ownerForNew({ scoped: false }, 'vijay.sharma'), 'vijay.sharma');
  assert.equal(ownerForNew({ scoped: false }, '  vijay.sharma '), 'vijay.sharma');
  assert.equal(ownerForNew({ scoped: false }, undefined), undefined);
  assert.equal(ownerForNew({ scoped: false }, 'a b'), undefined, 'an invalid header value is ignored');
  assert.equal(ownerForNew({ scoped: false }, '../x'), undefined);
});

test('owner names are validated', () => {
  assert.equal(cleanOwner(' vijay.sharma '), 'vijay.sharma');
  assert.equal(cleanOwner('a@b.c'), 'a@b.c');
  for (const bad of ['', ' ', '-x', 'a b', 'x'.repeat(65), null, undefined, 5]) assert.throws(() => cleanOwner(bad), /owner must be/);
  assert.ok(OWNER_RE.test('shahin-mcp'));
});
