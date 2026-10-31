'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'extension', 'content.js'), 'utf8');

class StubElement {
  constructor(tagName, registry) {
    this.tagName = (tagName || 'div').toUpperCase();
    this.id = '';
    this.className = '';
    this._innerHTML = '';
    this.textContent = '';
    this.disabled = false;
    this.style = {};
    this.type = 'text';
    this.parentElement = null;
    this._value = '';
    this._registry = registry;
    this._listeners = {};
    this.classList = { add() {}, remove() {}, toggle() {}, contains() { return false; } };
  }
  get value() { return this._value; }
  set value(v) { this._value = String(v); }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(html) {
    this._innerHTML = String(html);
    if (!this._registry) return;
    for (const m of this._innerHTML.matchAll(/id="([^"]+)"/g)) {
      if (!this._registry.has(m[1])) {
        const el = new StubElement('div', this._registry);
        el.id = m[1];
        this._registry.set(m[1], el);
      }
    }
  }
  addEventListener(type, fn) { (this._listeners[type] = this._listeners[type] || []).push(fn); }
  removeEventListener() {}
  dispatchEvent() { return true; }
  focus() {}
  blur() {}
  setAttribute() {}
  getAttribute() { return null; }
  removeAttribute() {}
  querySelector(sel) {
    if (!this._registry) return null;
    const key = this.id + '>' + sel;
    if (!this._registry.has(key)) {
      const el = new StubElement('div', this._registry);
      this._registry.set(key, el);
    }
    return this._registry.get(key);
  }
  querySelectorAll() { return []; }
  closest() { return null; }
  contains() { return false; }
  getBoundingClientRect() { return { top: 0, left: 0, right: 0, bottom: 0 }; }
  appendChild(child) { return child; }
  remove() { this.removed = true; }
}

function loadContentScript(opts) {
  opts = opts || {};
  const storageRes = opts.storageRes || {};
  const listeners = {};
  const appended = [];
  const registry = new Map();

  const documentStub = {
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    removeEventListener() {},
    getElementById(id) {
      if (registry.has(id)) return registry.get(id);
      return appended.find((el) => el.id === id) || null;
    },
    createElement: (t) => new StubElement(t, registry),
    querySelector: () => null,
    querySelectorAll: () => [],
    body: {
      appendChild(el) { appended.push(el); return el; },
      contains: () => false,
      querySelector: () => null,
      querySelectorAll: () => [],
    },
    execCommand: () => true,
    createRange: () => ({ selectNodeContents() {}, cloneRange() { return this; } }),
  };

  const chromeStub = {
    runtime: {
      getManifest: () => ({ version: '0.0.0-test' }),
      getURL: (p) => 'chrome-extension://test/' + p,
      id: 'test',
      lastError: undefined,
      onMessage: { addListener() {} },
      sendMessage(msg, cb) {
        if (msg && msg.type === 'getManagedState') {
          if (cb) cb({ managed: !!opts.managed });
        } else if (cb) {
          cb({});
        }
        return undefined;
      },
    },
    storage: {
      local: {
        get(keys, cb) { cb(storageRes); },
        set() {},
      },
    },
  };

  const host = opts.hostname || 'chatgpt.com';
  const sandbox = {
    console,
    location: { protocol: 'https:', hostname: host, pathname: '/', origin: 'https://' + host },
    document: documentStub,
    chrome: chromeStub,
    setTimeout: () => 0,
    clearTimeout: () => {},
    URL,
    FileReader: class {
      readAsText(file) {
        this.result = (file && file.__text) || '';
        if (this.onload) this.onload();
      }
    },
    HTMLTextAreaElement: StubElement,
    HTMLInputElement: StubElement,
    Event: class { constructor(type, opts) { this.type = type; Object.assign(this, opts || {}); } },
    InputEvent: class { constructor(type, opts) { this.type = type; Object.assign(this, opts || {}); } },
    KeyboardEvent: class { constructor(type, opts) { this.type = type; Object.assign(this, opts || {}); } },
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.SGDetect = require('../extension/detect.js');
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: 'content.js' });

  return { sandbox, listeners, appended, registry };
}

function keydownEvent(target, text) {
  target.value = text;
  return {
    key: 'Enter',
    shiftKey: false,
    isComposing: false,
    target,
    prevented: false,
    preventDefault() { this.prevented = true; },
    stopPropagation() {},
    stopImmediatePropagation() {},
  };
}

function dropEvent(text) {
  return {
    target: new StubElement('div', new Map()),
    dataTransfer: { files: [], getData: () => text },
    prevented: false,
    preventDefault() { this.prevented = true; },
    stopPropagation() {},
    stopImmediatePropagation() {},
  };
}

function fileDropEvent(file) {
  return {
    target: new StubElement('div', new Map()),
    dataTransfer: {
      files: [file],
      getData: () => '',
      items: { add() {} },
    },
    prevented: false,
    preventDefault() { this.prevented = true; },
    stopPropagation() {},
    stopImmediatePropagation() {},
  };
}

const SECRET = 'my key is sk-proj-abcdefghijklmnopqrstuvwxyz123456';

test('enter with a secret blocks the send and renders the warning modal', () => {
  const env = loadContentScript();
  const event = keydownEvent(new StubElement('textarea', new Map()), SECRET);
  for (const fn of env.listeners.keydown) fn(event);

  assert.equal(event.prevented, true, 'send must be blocked');
  const overlay = env.appended.find((el) => el.id === 'sg-overlay');
  assert.ok(overlay, 'warning modal must be appended to the page');
  assert.match(overlay.innerHTML, /sg-modal/);
  assert.match(overlay.innerHTML, /OpenAI API key/);
  assert.match(overlay.innerHTML, /leaks stopped this month/);
});

test('clean message passes through untouched', () => {
  const env = loadContentScript();
  const event = keydownEvent(new StubElement('textarea', new Map()), 'hello, how are you?');
  for (const fn of env.listeners.keydown) fn(event);

  assert.equal(event.prevented, false, 'clean sends must not be intercepted');
  assert.equal(env.appended.find((el) => el.id === 'sg-overlay'), undefined);
});

test('blockSendAnyway hides the send button even without enforceJustification', () => {
  const env = loadContentScript({
    storageRes: {
      sg_org: {
        teamMode: true,
        orgId: 'org_abc12345',
        blockSendAnyway: true,
      },
    },
  });
  const event = keydownEvent(new StubElement('textarea', new Map()), SECRET);
  for (const fn of env.listeners.keydown) fn(event);

  const overlay = env.appended.find((el) => el.id === 'sg-overlay');
  assert.ok(overlay, 'modal must render');
  const sendBtn = env.registry.get('sg-send');
  assert.ok(sendBtn, 'send button must exist in the modal');
  assert.equal(sendBtn.style.display, 'none', 'send anyway must be hidden');
  assert.equal(env.registry.get('sg-reason'), undefined, 'no reason field without enforceJustification');
});

test('text drop with a secret uses the paste redaction path', () => {
  const env = loadContentScript();
  const event = dropEvent(SECRET);
  for (const fn of env.listeners.drop) fn(event);

  assert.equal(event.prevented, true, 'drop must be parked behind the modal');
  const overlay = env.appended.find((el) => el.id === 'sg-overlay');
  assert.ok(overlay, 'text drop with a secret must open the modal');
  assert.match(overlay.innerHTML, /Redact and paste/, 'text drops reuse the paste redaction path');
});

test('file attachments get no redact button', async () => {
  const env = loadContentScript();
  const event = fileDropEvent({ name: 'notes.txt', size: 10, __text: SECRET });
  for (const fn of env.listeners.drop) fn(event);
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(event.prevented, true, 'file drop must be parked behind the modal');
  const overlay = env.appended.find((el) => el.id === 'sg-overlay');
  assert.ok(overlay, 'file with a secret must open the modal');
  assert.match(overlay.innerHTML, /Attach anyway/);
  assert.doesNotMatch(overlay.innerHTML, /id="sg-redact"/, 'no redact button for attachments');
  assert.doesNotMatch(overlay.innerHTML, /id="sg-redact-locked"/, 'no locked redact button for attachments');
});

/* ------------------------------------------------------------------ */
/* Write-back honesty: a claim of redaction must match the editor      */
/* ------------------------------------------------------------------ */
// Pro reads as Pro only with a stored license key: the flag alone is forgeable
// local state, the key is proof a verification happened.
const PRO_AUTO = {
  sg_isPro: true,
  sg_license_key: 'SG-AABBCCDDEEFF0011',
  sg_settings: { enabled: true, categories: { apiKeys: true, pii: false, network: false }, autoRedact: true },
};
const PRO_MANUAL = {
  sg_isPro: true,
  sg_license_key: 'SG-AABBCCDDEEFF0011',
  sg_settings: { enabled: true, categories: { apiKeys: true, pii: false, network: false }, autoRedact: false },
};

// an editor that accepts writes but never changes, like a framework editor
// that ignores execCommand (this is what ChatGPT did)
function stuckTextarea() {
  const ta = new StubElement('textarea', new Map());
  Object.defineProperty(ta, 'value', { get: () => SECRET, set() {}, configurable: true });
  return ta;
}

test('auto-redact writes verified: secret gone, message sends, no modal', () => {
  const env = loadContentScript({ storageRes: PRO_AUTO });
  const ta = new StubElement('textarea', new Map());
  const event = keydownEvent(ta, SECRET);
  for (const fn of env.listeners.keydown) fn(event);

  assert.equal(event.prevented, true);
  assert.ok(!ta.value.includes('sk-proj'), 'editor must hold the redacted text');
  assert.ok(ta.value.includes('[API_KEY'), 'placeholder must be written');
  assert.equal(env.appended.find((el) => el.id === 'sg-overlay'), undefined, 'no modal when auto-redact worked');
  assert.equal(env.appended.find((el) => el.id === 'sg-toast'), undefined, 'auto-redact is silent: no toast, just the inline placeholder');
});

test('auto-redact with a flaky read-back never sends: the modal appears instead', () => {
  const env = loadContentScript({ storageRes: PRO_AUTO });
  const ta = new StubElement('textarea', new Map());
  // the scan can read the secret, but every later read (the write
  // verification) reports nothing: an empty read-back must never count as
  // clean or the secret is auto-sent untouched
  let reads = 0;
  Object.defineProperty(ta, 'value', { get: () => (++reads === 1 ? SECRET : ''), set() {}, configurable: true });
  const event = keydownEvent(ta, SECRET);
  for (const fn of env.listeners.keydown) fn(event);

  assert.equal(event.prevented, true, 'the send must be parked');
  assert.ok(env.appended.find((el) => el.id === 'sg-overlay'), 'the modal must appear');
  assert.equal(env.appended.find((el) => el.id === 'sg-toast'), undefined, 'no redaction claim');
});

test('auto-redact on a stuck editor never sends: the modal appears instead', () => {
  const env = loadContentScript({ storageRes: PRO_AUTO });
  const ta = stuckTextarea();
  const event = keydownEvent(ta, SECRET);
  for (const fn of env.listeners.keydown) fn(event);

  assert.equal(event.prevented, true, 'the send must be parked');
  assert.ok(env.appended.find((el) => el.id === 'sg-overlay'), 'fallback modal must appear');
  assert.ok(ta.value.includes('sk-proj'), 'editor still holds the secret, so it must not be sent');
  assert.equal(env.appended.find((el) => el.id === 'sg-toast'), undefined, 'no false redaction claim');
});

test('manual redact on a stuck editor keeps the modal open and warns', () => {
  const env = loadContentScript({ storageRes: PRO_MANUAL });
  const ta = stuckTextarea();
  for (const fn of env.listeners.keydown) fn(keydownEvent(ta, SECRET));

  const overlay = env.appended.find((el) => el.id === 'sg-overlay');
  assert.ok(overlay, 'modal must be open');
  const redactBtn = env.registry.get('sg-redact');
  assert.ok(redactBtn, 'redact button must exist for Pro');
  redactBtn._listeners.click[0]();

  assert.ok(!overlay.removed, 'modal must stay open so Cancel still works');
  const warn = env.appended.find((el) => el.id === 'sg-toast' && /could not be written/.test(el.textContent));
  assert.ok(warn, 'the warning must say the write failed');
});

test('manual redact on a working editor closes the modal and redacts', () => {
  const env = loadContentScript({ storageRes: PRO_MANUAL });
  const ta = new StubElement('textarea', new Map());
  for (const fn of env.listeners.keydown) fn(keydownEvent(ta, SECRET));

  const overlay = env.appended.find((el) => el.id === 'sg-overlay');
  assert.ok(overlay);
  env.registry.get('sg-redact')._listeners.click[0]();

  assert.ok(overlay.removed, 'modal closes on success');
  assert.ok(!ta.value.includes('sk-proj'), 'secret replaced');
  assert.ok(ta.value.includes('[API_KEY'), 'placeholder written');
});
