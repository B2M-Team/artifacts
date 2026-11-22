// PLATFORM-834: a project label is the owner's user name (Shahin's report_publish sends `project=<username>`), and some
// sites sign people in with an e-mail as the user name (gcc-telco: gt.owner@gcc-telco.example). Plain names keep the
// old rule; an e-mail is the one extra shape, so nothing else that was refused before is let in.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError } from '../lib/errors.js';
import { parseProject } from '../lib/project.js';

test('plain names are taken exactly as before', () => {
  assert.equal(parseProject('tuna.lab'), 'tuna.lab');
  assert.equal(parseProject('  retail   owner '), 'retail owner');
  assert.equal(parseProject('Ünal_2026-q4'), 'Ünal_2026-q4');
  assert.equal(parseProject(''), '');
  assert.equal(parseProject(null), '');
});

test('an e-mail user name is a project label', () => {
  assert.equal(parseProject('gt.owner@gcc-telco.example'), 'gt.owner@gcc-telco.example');
  assert.equal(parseProject('a+b@x.co'), 'a+b@x.co');
  const long = `${'a'.repeat(64)}@${'b'.repeat(180)}.example`;
  assert.equal(parseProject(long), long, 'an e-mail may be longer than a plain name, as the owner rule allows');
});

test('what was refused stays refused, and a broken e-mail is refused too', () => {
  for (const bad of ['-lead', '.hidden', 'a/b', 'x'.repeat(65), 'a%b', 'a#b', 'a?b',
    '@x.co', 'a@', 'a@@b.co', 'a@b@c.co', 'a..b@x.co', 'a@x..co', '.a@x.co', 'a.@x.co', 'a b@x.co',
    'a@x.co/..', `${'a'.repeat(250)}@x.co`]) {
    assert.throws(() => parseProject(bad), (e) => e instanceof ApiError && e.status === 400, bad);
  }
  assert.throws(() => parseProject(5), (e) => e instanceof ApiError && e.message === 'project must be a string');
});
