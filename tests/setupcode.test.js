'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  globalThis.crypto = require('node:crypto').webcrypto;
}
const S = require('../extension/setupcode.js');

const VALID = {
  orgId: 'org_abc12345',
  orgToken: 'tok_1234567890abcdef',
  userEmail: 'employee@example.com',
  universalMode: true,
  extraSites: ['intranet.example.com'],
  heartbeat: true,
  blockSendAnyway: true,
  autoRedact: false,
};

test('setup code round-trips through format and parse', async () => {
  const f = await S.format(VALID);
  assert.equal(f.ok, true);
  assert.ok(f.code.startsWith('SGSETUP1.'));
  const p = await S.parse(f.code);
  assert.equal(p.ok, true);
  assert.deepEqual(p.data, VALID);
});

test('plain base64 without the SGSETUP1 prefix is rejected', async () => {
  const p = await S.parse(Buffer.from(JSON.stringify(VALID)).toString('base64'));
  assert.equal(p.ok, false);
  assert.match(p.error, /Unsupported setup code version/);
});

test('a damaged checksum is rejected', async () => {
  const f = await S.format(VALID);
  const broken = f.code.slice(0, -1) + (f.code.endsWith('0') ? '1' : '0');
  const p = await S.parse(broken);
  assert.equal(p.ok, false);
  assert.match(p.error, /damaged/);
});

test('codes above the size limit are rejected', async () => {
  const p = await S.parse('SGSETUP1.' + 'a'.repeat(S.MAX_CODE_CHARS));
  assert.equal(p.ok, false);
  assert.match(p.error, /too large/);
});

test('a code carrying alertEndpoint is rejected outright', async () => {
  const payload = Buffer.from(JSON.stringify({ ...VALID, alertEndpoint: 'https://evil.example.com' })).toString('base64url');
  const code = 'SGSETUP1.' + payload + '.' + (await S.checksumOf(payload));
  const p = await S.parse(code);
  assert.equal(p.ok, false);
  assert.match(p.error, /alert endpoint/);
});

test('field types are validated strictly', async () => {
  const cases = [
    [{ ...VALID, orgId: 'nope' }, /org ID/],
    [{ ...VALID, orgToken: 'has spaces here' }, /org token/],
    [{ ...VALID, userEmail: 'not-an-email' }, /email/],
    [{ ...VALID, universalMode: 'yes' }, /universalMode/],
    [{ ...VALID, extraSites: ['good.example.com', 'bad site'] }, /site list/],
    [{ ...VALID, extraSites: 'good.example.com' }, /site list/],
  ];
  for (const [data, re] of cases) {
    const f = await S.format(data);
    assert.equal(f.ok, false, JSON.stringify(data));
    assert.match(f.error, re);
    const payload = Buffer.from(JSON.stringify(data)).toString('base64url');
    const code = 'SGSETUP1.' + payload + '.' + (await S.checksumOf(payload));
    const p = await S.parse(code);
    assert.equal(p.ok, false, JSON.stringify(data));
    assert.match(p.error, re);
  }
});

test('unknown fields are dropped, never applied', async () => {
  const payload = Buffer.from(JSON.stringify({ ...VALID, evil: 'x', categories: { pii: true } })).toString('base64url');
  const code = 'SGSETUP1.' + payload + '.' + (await S.checksumOf(payload));
  const p = await S.parse(code);
  assert.equal(p.ok, true);
  assert.deepEqual(p.data, VALID);
});

test('org ID is required', async () => {
  const f = await S.format({ userEmail: 'a@b.co' });
  assert.equal(f.ok, false);
  assert.match(f.error, /org ID/);
});
