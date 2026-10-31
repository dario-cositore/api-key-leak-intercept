'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { webcrypto } = require('node:crypto');

const V = require('../extension/configverify.js');

const DATA = { aiSites: ['chatgpt.com'], excludedSites: [], extraPatterns: ['TCK-[0-9]{6}'] };

async function makeKey() {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = Buffer.from(await webcrypto.subtle.exportKey('spki', pair.publicKey)).toString('base64');
  const pkcs8 = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', pair.privateKey));
  const pem = '-----BEGIN PRIVATE KEY-----\n' + pkcs8.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END PRIVATE KEY-----\n';
  return { pair, spki, pem };
}

async function signEnvelope(pair, env) {
  const payload = JSON.stringify({ schemaVersion: 1, kid: env.kid, seq: env.seq, exp: env.exp, data: env.data });
  const sig = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(payload));
  return { schemaVersion: 1, kid: env.kid, seq: env.seq, exp: env.exp, data: env.data, signature: Buffer.from(sig).toString('base64') };
}

const NOW = 1700000000000;
const FUTURE = Math.floor(NOW / 1000) + 86400;

test('the offline signing script produces envelopes the extension accepts', () => {
  return makeKey().then(({ pair, spki, pem }) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sgcfg-'));
    const dataFile = path.join(dir, 'data.json');
    const keyFile = path.join(dir, 'k1.pem');
    fs.writeFileSync(dataFile, JSON.stringify(DATA));
    fs.writeFileSync(keyFile, pem);
    const out = execFileSync(process.execPath, [
      path.join(__dirname, '..', 'scripts', 'sign-config.mjs'), dataFile, 'k1', keyFile, '7', String(FUTURE),
    ], { encoding: 'utf8' });
    const env = JSON.parse(out);
    assert.equal(env.kid, 'k1');
    assert.equal(env.seq, 7);
    return V.verifyEnvelope(env, NOW, { k1: spki }).then((res) => {
      assert.equal(res.ok, true);
      assert.deepEqual(res.data, DATA);
      assert.equal(res.seq, 7);
    });
  });
});

test('a tampered payload fails the signature check', async () => {
  const { pair, spki } = await makeKey();
  const env = await signEnvelope(pair, { kid: 'k1', seq: 3, exp: FUTURE, data: DATA });
  env.data = { ...DATA, excludedSites: ['chatgpt.com'] };
  const res = await V.verifyEnvelope(env, NOW, { k1: spki });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'bad signature');
});

test('unknown kids, bad seq, and bad exp are rejected', async () => {
  const { pair, spki } = await makeKey();
  const env = await signEnvelope(pair, { kid: 'k1', seq: 3, exp: FUTURE, data: DATA });

  assert.equal((await V.verifyEnvelope({ ...env, kid: 'k9' }, NOW, { k1: spki })).error, 'kid');
  assert.equal((await V.verifyEnvelope({ ...env, seq: 0 }, NOW, { k1: spki })).error, 'seq');
  assert.equal((await V.verifyEnvelope({ ...env, seq: 1.5 }, NOW, { k1: spki })).error, 'seq');
  assert.equal((await V.verifyEnvelope({ ...env, exp: Math.floor(NOW / 1000) - 1 }, NOW, { k1: spki })).error, 'expired');
  assert.equal((await V.verifyEnvelope({ ...env, exp: Math.floor(NOW / 1000) + 365 * 86400 }, NOW, { k1: spki })).error, 'exp too far');
});

test('expired configs are rejected even with a valid signature', async () => {
  const { pair, spki } = await makeKey();
  const env = await signEnvelope(pair, { kid: 'k1', seq: 3, exp: Math.floor(NOW / 1000) - 10, data: DATA });
  const res = await V.verifyEnvelope(env, NOW, { k1: spki });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'expired');
});

test('replayed older configs are rejected against the accepted seq', async () => {
  const { pair, spki } = await makeKey();
  const env = await signEnvelope(pair, { kid: 'k1', seq: 3, exp: FUTURE, data: DATA });
  // a validly signed envelope with seq 3 loses against an already accepted seq 5
  const res = await V.verifyEnvelope(env, NOW, { k1: spki }, 5);
  assert.equal(res.ok, false);
  assert.equal(res.error, 'stale');
  // same envelope is accepted when nothing newer was seen
  const fresh = await V.verifyEnvelope(env, NOW, { k1: spki }, 0);
  assert.equal(fresh.ok, true);
});

test('data is sanitized before it is trusted', async () => {
  assert.equal(V.sanitizeConfigData(null), null);
  assert.equal(V.sanitizeConfigData([1]), null);
  assert.equal(V.sanitizeConfigData({ extraPatterns: ['('] }), null, 'uncompilable pattern');
  assert.equal(V.sanitizeConfigData({ extraPatterns: ['a'.repeat(257)] }), null, 'pattern too long');
  assert.equal(V.sanitizeConfigData({ extraPatterns: new Array(33).fill('x') }), null, 'too many patterns');
  assert.equal(V.sanitizeConfigData({ aiSites: ['good.example.com', 'bad site'] }), null, 'bad hostname');
  assert.equal(V.sanitizeConfigData({ aiSites: new Array(201).fill('x.com') }), null, 'too many sites');
  const ok = V.sanitizeConfigData({ aiSites: ['ChatGPT.com'], extraPatterns: ['TCK-[0-9]{6}'] });
  assert.deepEqual(ok, { aiSites: ['ChatGPT.com'], excludedSites: [], extraPatterns: ['TCK-[0-9]{6}'] });
});

test('embedded keys: both k1 and k2 are valid SPKI for P-256', async () => {
  for (const spki of Object.values(V.CONFIG_KEYS)) {
    const key = await webcrypto.subtle.importKey('spki', V.base64ToBuffer(spki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    assert.equal(key.type, 'public');
  }
});
