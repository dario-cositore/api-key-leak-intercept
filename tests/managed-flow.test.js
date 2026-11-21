'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const backgroundSrc = fs.readFileSync(path.join(__dirname, '..', 'extension', 'background.js'), 'utf8');
const Detect = require('../extension/detect.js');
const Ent = require('../extension/entitlement-state.js');

const POLICY = {
  orgId: 'org_abc123def456',
  orgToken: 'tok_policycafed00d',
  userEmail: 'employee@example.com',
};

function loadBackground({ policy = POLICY, responders = {} } = {}) {
  const store = {}; // chrome.storage.local backing store
  const fetchLog = [];
  const listeners = { onInstalled: [], onStartup: [], onMessage: [], onAlarm: [], onChanged: [] };

  const chromeStub = {
    runtime: {
      getManifest: () => ({ version: '1.1.0' }),
      getURL: (p) => p,
      setUninstallURL() {},
      onInstalled: { addListener: (fn) => listeners.onInstalled.push(fn) },
      onStartup: { addListener: (fn) => listeners.onStartup.push(fn) },
      onMessage: { addListener: (fn) => listeners.onMessage.push(fn) },
    },
    alarms: {
      create() {},
      onAlarm: { addListener: (fn) => listeners.onAlarm.push(fn) },
    },
    action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
    tabs: { create() {}, query(_q, cb) { cb([]); }, sendMessage() { return Promise.resolve(); } },
    management: { getSelf(cb) { cb({ installType: 'admin' }); } },
    storage: {
      onChanged: { addListener: (fn) => listeners.onChanged.push(fn) },
      local: {
        get(keys, cb) {
          const out = {};
          for (const k of (Array.isArray(keys) ? keys : [keys])) out[k] = store[k];
          cb(out);
        },
        set(obj, cb) {
          Object.assign(store, obj);
          if (cb) cb();
        },
      },
      managed: { get(_keys, cb) { cb(policy || {}); } },
    },
  };

  const fetchImpl = async (url, opts) => {
    fetchLog.push({
      url: String(url),
      method: (opts && opts.method) || 'GET',
      body: opts && opts.body ? JSON.parse(opts.body) : null,
    });
    for (const [suffix, resp] of Object.entries(responders)) {
      if (String(url).endsWith(suffix)) {
        return { ok: true, status: 200, json: async () => resp, text: async () => JSON.stringify(resp) };
      }
    }
    return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
  };

  const sandbox = {
    console,
    URL,
    fetch: fetchImpl,
    setTimeout,
    clearTimeout,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    TextEncoder,
    crypto: require('node:crypto').webcrypto,
    chrome: chromeStub,
    importScripts() {
      sandbox.SGConfigVerify = require('../extension/configverify.js');
      sandbox.SGEntitlement = require('../extension/entitlement-state.js');
    },
  };
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(backgroundSrc, sandbox, { filename: 'background.js' });

  return { sandbox, store, fetchLog, listeners };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 30));

function findFetch(log, suffix) {
  return log.find((e) => e.url.endsWith(suffix));
}

test('policy-only managed install: entitlement is fetched and heartbeat is sent', async () => {
  const env = loadBackground({
    responders: { '/api/entitlement': { ok: true, pro: true, plan: 'paid' } },
  });
  for (const fn of env.listeners.onStartup) fn();
  await tick();

  const ent = findFetch(env.fetchLog, '/api/entitlement');
  assert.ok(ent, 'entitlement endpoint must be called');
  assert.equal(ent.method, 'POST');
  assert.equal(ent.body.orgId, POLICY.orgId);
  assert.equal(ent.body.orgToken, POLICY.orgToken, 'policy token must reach the server');

  const hb = findFetch(env.fetchLog, '/api/heartbeat');
  assert.ok(hb, 'heartbeat must be sent for a policy-only managed install');
  assert.equal(hb.body.orgId, POLICY.orgId);
  assert.equal(hb.body.userEmail, POLICY.userEmail);
});

test('a paid org unlocks Pro capabilities from the cached entitlement', async () => {
  const env = loadBackground({
    responders: { '/api/entitlement': { ok: true, pro: true, plan: 'paid' } },
  });
  for (const fn of env.listeners.onStartup) fn();
  await tick();

  const ent = env.store.sg_entitlement;
  assert.ok(ent, 'entitlement answer must be cached');
  assert.equal(ent.pro, true);
  assert.equal(ent.orgId, POLICY.orgId);
  assert.equal(Ent.entitledFrom(ent, POLICY.orgId), true);

  const pii = Detect.PATTERNS.find((p) => p.name === 'Email address');
  const opts = {
    enabled: true,
    categories: { apiKeys: true, pii: true, network: true },
    isPro: false,
    entitled: Ent.entitledFrom(ent, POLICY.orgId),
  };
  assert.equal(Detect.categoryAllowed(pii, opts), true, 'paid org gets PII detection');
  assert.equal(Detect.customPatternsAllowed(opts), true);
});

test('a free org stays free and revokes immediately', async () => {
  const env = loadBackground({
    responders: { '/api/entitlement': { ok: true, pro: false, plan: 'free' } },
  });
  for (const fn of env.listeners.onStartup) fn();
  await tick();

  const ent = env.store.sg_entitlement;
  assert.ok(ent, 'even a negative answer is cached');
  assert.equal(ent.pro, false);
  assert.equal(Ent.entitledFrom(ent, POLICY.orgId), false);

  const pii = Detect.PATTERNS.find((p) => p.name === 'Email address');
  const opts = {
    enabled: true,
    categories: { apiKeys: true, pii: true, network: true },
    isPro: false,
    entitled: Ent.entitledFrom(ent, POLICY.orgId),
  };
  assert.equal(Detect.categoryAllowed(pii, opts), false, 'free org never gets PII detection');
  assert.equal(Detect.customPatternsAllowed(opts), false);
});

test('getSettings reports the policy-merged org and entitlement', async () => {
  const env = loadBackground({
    responders: { '/api/entitlement': { ok: true, pro: true, plan: 'paid' } },
  });
  for (const fn of env.listeners.onStartup) fn();
  await tick();

  let response = null;
  for (const fn of env.listeners.onMessage) {
    fn({ type: 'getSettings' }, {}, (r) => { response = r; });
  }
  await tick();
  assert.ok(response, 'getSettings must answer');
  assert.equal(response.org.orgId, POLICY.orgId);
  assert.equal(response.org.teamMode, true, 'policy orgId turns team mode on');
  assert.equal(response.org.orgToken, POLICY.orgToken);
  assert.equal(response.entitled, true);
});

test('policy heartbeat:false overrides the managed default', async () => {
  const env = loadBackground({
    policy: { ...POLICY, heartbeat: false },
    responders: { '/api/entitlement': { ok: true, pro: true, plan: 'paid' } },
  });
  for (const fn of env.listeners.onStartup) fn();
  await tick();
  assert.equal(findFetch(env.fetchLog, '/api/heartbeat'), undefined, 'heartbeat must not be sent');
  assert.ok(findFetch(env.fetchLog, '/api/entitlement'), 'entitlement is still fetched');
});
