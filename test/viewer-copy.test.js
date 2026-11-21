// The word a viewer reads on the pages they land on.
//
// Someone who opens a shared link is reading a page, not an "artifact": that is the publisher's
// word for what they stored. So every string these screens show a viewer says "page", and this
// test fails the day one of them says "artifact" again. Storage keys, element ids and comments
// keep the old word: nobody reads them, and renaming a localStorage key forgets every viewer's
// saved theme.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { fillShell } from '../lib/shells.js';
import { jsxBrandSlots, notFoundBrandSlots, passwordBrandSlots } from '../lib/branding.js';
import { EXPIRED_COPY, NOT_FOUND_COPY } from '../lib/status-page.js';

const here = dirname(fileURLToPath(import.meta.url));
const shell = (name) => readFileSync(join(here, '..', 'shells', `${name}.html`), 'utf8');
const NONE = { productName: '', logoUrl: '', faviconUrl: '', accentColor: '', footerText: '' };

// What a person can read: the text between tags, plus the attributes a browser shows
// (title, aria-label, placeholder, alt). Scripts, styles and comments are dropped first.
function visibleText(html) {
  const stripped = html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');
  const attrs = [...stripped.matchAll(/\s(?:title|aria-label|placeholder|alt)="([^"]*)"/gi)].map((m) => m[1]);
  const text = stripped.replace(/<[^>]+>/g, ' ');
  return `${text} ${attrs.join(' ')}`;
}

test('the password page calls it a protected page', () => {
  const html = fillShell(shell('password'), passwordBrandSlots(NONE));
  assert.match(html, /<title>Protected page<\/title>/);
  assert.match(html, /<h1>Protected page<\/h1>/);
  assert.match(html, /<p>This page is password protected\.<\/p>/);
  assert.doesNotMatch(visibleText(html), /artifact/i);
});

test('the 404 and 410 cards say page, not artifact', () => {
  for (const copy of [NOT_FOUND_COPY, EXPIRED_COPY]) {
    const html = fillShell(shell('not-found'), { ...notFoundBrandSlots(NONE), ...copy });
    assert.doesNotMatch(visibleText(html), /artifact/i, copy.HEADING);
  }
  assert.equal(NOT_FOUND_COPY.HEADING, 'Page unavailable');
  assert.equal(EXPIRED_COPY.HEADING, 'Page expired');
});

test('the frame bar tooltip says page', () => {
  assert.doesNotMatch(visibleText(shell('frame')), /artifact/i);
});

test('a jsx page that throws does not show the word artifact', () => {
  // The label prefixes the error readout, and Babel puts data-filename into every syntax error.
  assert.doesNotMatch(jsxBrandSlots(NONE).ERROR_LABEL, /artifact/i);
  assert.doesNotMatch(shell('jsx'), /data-filename="[^"]*artifact/i);
});

test('the 404 footer line sits apart from the message', () => {
  // The shell styles its last paragraph with `p:last-child` (0,1,1), and the footer is that last
  // paragraph, so a bare `.brandfooter` (0,1,0) lost: no gap, message-sized text, and the footer
  // read as the end of the sentence above it.
  const html = fillShell(shell('not-found'), {
    ...notFoundBrandSlots({ ...NONE, footerText: 'Published with Shahin' }),
    ...NOT_FOUND_COPY,
  });
  assert.match(html, /main > p\.brandfooter \{ margin: 20px 0 0; font-size: 12px;/);
});

test('a wrong password reads as an error, in the error color', () => {
  // `#card p` (1,0,1) outranked `#error` (1,0,0), so "Incorrect password" came out muted grey
  // with the paragraph's margins and looked like help text under the button.
  assert.match(shell('password'), /#card #error \{ min-height: 18px; margin: 10px 0 0; font-size: 13px; color: var\(--error\); \}/);
});

test('the gate footer line keeps its own gap', () => {
  // Same fight on the gate: `#card p` (1,0,1) outranked `.brandfooter` (0,1,0), so the footer
  // lost its top margin and sat flush under "Incorrect password".
  const slots = passwordBrandSlots({ ...NONE, footerText: 'Published with Shahin' });
  assert.match(slots.BRAND_STYLE, /#card \.brandfooter \{ margin: 14px 0 0; font-size: 12px;/);
});
