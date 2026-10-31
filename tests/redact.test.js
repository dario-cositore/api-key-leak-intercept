'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const D = require('../extension/detect.js');

const FREE = { enabled: true, categories: { apiKeys: true, pii: false, network: false }, isPro: false };
const FULL = { enabled: true, categories: { apiKeys: true, pii: true, network: true }, isPro: true };

test('every pattern declares a confidence of high or low', () => {
  for (const p of D.PATTERNS) {
    assert.ok(p.confidence === 'high' || p.confidence === 'low', p.name);
  }
});

test('redact replaces secrets with numbered placeholders', () => {
  const text = 'key sk-proj-abcdefghijklmnopqrstuvwxyz123456 and sk-proj-abcdefghijklmnopqrstuvwxyz123456';
  const r = D.redact(text, FREE);
  assert.match(r.text, /\[API_KEY_1\]/);
  // same value -> same number
  const count = (r.text.match(/\[API_KEY_1\]/g) || []).length;
  assert.equal(count, 2);
  assert.equal(r.count, 2);
});

test('redact uses different numbers for different values', () => {
  const text = 'a sk-proj-abcdefghijklmnopqrstuvwxyz123456 b sk-proj-zyxwvutsrqponmlkjihgfedcba987654';
  const r = D.redact(text, FREE);
  assert.match(r.text, /\[API_KEY_1\]/);
  assert.match(r.text, /\[API_KEY_2\]/);
});

test('redact highOnly skips low-confidence findings', () => {
  const text = 'password: Tr0ub4dor and sk-proj-abcdefghijklmnopqrstuvwxyz123456';
  const r = D.redact(text, FREE, { highOnly: true });
  // low-confidence password should remain
  assert.ok(r.text.includes('Tr0ub4dor'));
  assert.match(r.text, /\[API_KEY_1\]/);
});

test('redact handles email and IP placeholders', () => {
  const text = 'email foo@bar.com ip 1.2.3.4';
  const r = D.redact(text, FULL);
  assert.match(r.text, /\[EMAIL_1\]/);
  assert.match(r.text, /\[IP_1\]/);
});
