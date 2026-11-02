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
  // An empty store is not the normal case: a real user has a sg_settings record
  // because the welcome page wrote one after they accepted. Default to that so
  // these tests exercise interception rather than the consent gate. Pass
  // storageRes: {} explicitly to model "no record yet".
  const storageRes = opts.storageRes !== undefined ? opts.storageRes : {
    sg_settings: { enabled: true, categories: { apiKeys: true, pii: false, network: false } },
  };
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
      onChanged: {
        addListener(fn) { (listeners.storageChanged = listeners.storageChanged || []).push(fn); },
      },
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
      sg_settings: { enabled: true, categories: { apiKeys: true, pii: false, network: false } },
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

test('paste mode prints no fragment of the secret into the page DOM', () => {
  // In paste and attach modes the content never reached the page. Printing
  // any part of the preview would put it there anyway, in the DOM of the very
  // site the user is declining to hand it to, so those modes name the type
  // and the severity and nothing else.
  const env = loadContentScript();
  const event = dropEvent(SECRET);
  for (const fn of env.listeners.drop) fn(event);

  const overlay = env.appended.find((el) => el.id === 'sg-overlay');
  assert.ok(overlay, 'the modal must appear');
  assert.ok(!overlay.innerHTML.includes('sk-proj'), 'no fragment of the secret in the DOM');
  assert.ok(overlay.innerHTML.includes('OpenAI API key'), 'the type is still named');
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

test('auto-redact never sends on a framework editor that only took the DOM write', () => {
  // Lexical and ProseMirror submit their model, not their markup. execCommand
  // is ignored there, so setText forces textContent: the box LOOKS redacted
  // while the text that goes out is still the original. A verified DOM
  // read-back is not proof of a verified write, so this must fall to the modal.
  const env = loadContentScript({ storageRes: PRO_AUTO });
  const el = new StubElement('div', new Map());
  el.isContentEditable = true;
  el.textContent = SECRET;
  const event = keydownEvent(el, SECRET);
  for (const fn of env.listeners.keydown) fn(event);

  assert.equal(event.prevented, true, 'the send must be parked');
  assert.ok(el.textContent.includes('[API_KEY'), 'the DOM does show the redaction');
  assert.ok(
    env.appended.find((e2) => e2.id === 'sg-overlay'),
    'the modal must appear because the editor state was never reached'
  );
  assert.equal(env.appended.find((e2) => e2.id === 'sg-toast'), undefined, 'no redaction claim');
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

// ---------------------------------------------------------------------------
// Click-path send controls.
//
// StubElement.closest() returns null, which is exactly how the click path
// shipped broken: isSendButton matched `button, [role="button"]` while the
// handler re-derived the button with `closest('button')` and bailed on every
// role="button" control. The elements below evaluate the selector for real,
// so that shape of bug fails here instead of reaching the store.
// ---------------------------------------------------------------------------

function sendableMatches(el, sel) {
  const tag = (el.tagName || '').toLowerCase();
  const role = el.getAttribute('role');
  const type = (el.getAttribute('type') || el.type || '').toLowerCase();
  return String(sel).split(',').some((raw) => {
    const p = raw.trim();
    if (p === 'button') return tag === 'button';
    if (p === '[role="button"]') return role === 'button';
    if (p === 'input[type="submit"]') return tag === 'input' && type === 'submit';
    if (p === 'input[type="image"]') return tag === 'input' && type === 'image';
    return false;
  });
}

// A send control that really evaluates SENDABLE, paired with the composer it
// would send, so findInputEl can reach it through querySelector. `type` is set
// as a property as well as an attribute: isEditable reads el.type, and the
// stub's constructor default of 'text' would otherwise make a submit input
// look like the composer.
function sendControl(tagName, attrs, text) {
  const el = new StubElement(tagName, new Map());
  el._attrs = Object.assign({}, attrs);
  el.getAttribute = (k) => (k in el._attrs ? el._attrs[k] : null);
  if ('type' in el._attrs) el.type = el._attrs.type;
  el.closest = (sel) => (sendableMatches(el, sel) ? el : null);
  el.click = () => { el.clicked = true; };
  const ta = new StubElement('textarea', new Map());
  ta.value = text || SECRET;
  el.querySelector = () => ta;
  el._composer = ta;
  return el;
}

function clickEvent(target) {
  return {
    target,
    prevented: false,
    preventDefault() { this.prevented = true; },
    stopPropagation() {},
    stopImmediatePropagation() {},
  };
}

test('click on a role="button" send control is intercepted', () => {
  const env = loadContentScript();
  const event = clickEvent(sendControl('div', { role: 'button', 'aria-label': 'Send message' }));
  for (const fn of env.listeners.click) fn(event);

  assert.equal(event.prevented, true, 'a role="button" send must be intercepted');
  assert.ok(env.appended.find((el) => el.id === 'sg-overlay'), 'warning modal must appear');
});

test('click on a submit input is intercepted', () => {
  const env = loadContentScript();
  const event = clickEvent(sendControl('input', { type: 'submit', value: 'Send' }));
  for (const fn of env.listeners.click) fn(event);

  assert.equal(event.prevented, true, 'a submit input must be intercepted');
  assert.ok(env.appended.find((el) => el.id === 'sg-overlay'), 'warning modal must appear');
});

test('click on an ordinary button is intercepted too', () => {
  const env = loadContentScript();
  const event = clickEvent(sendControl('button', { 'aria-label': 'Send' }));
  for (const fn of env.listeners.click) fn(event);

  assert.equal(event.prevented, true, 'a plain button send must be intercepted');
});

test('form submit is stopped even with no click on a send control', () => {
  const env = loadContentScript();
  const el = sendControl('div', {});
  const form = new StubElement('form', new Map());
  form.querySelector = () => el._composer;
  const event = {
    target: form,
    prevented: false,
    preventDefault() { this.prevented = true; },
    stopPropagation() {},
    stopImmediatePropagation() {},
  };
  for (const fn of env.listeners.submit) fn(event);

  assert.equal(event.prevented, true, 'a form carrying a secret must be stopped');
  assert.ok(env.appended.find((el2) => el2.id === 'sg-overlay'), 'warning modal must appear');
});

test('a non-send control is never intercepted', () => {
  const env = loadContentScript();
  const event = clickEvent(sendControl('button', { 'aria-label': 'Bold' }, 'hello there'));
  for (const fn of env.listeners.click) fn(event);

  assert.equal(event.prevented, false, 'ordinary buttons must pass through');
});

test('revoking the licence reaches an already-open tab', () => {
  // loadSettings must derive isPro fresh on every run. It used to set the flag
  // true and never clear it, so after a sign-out or a revocation open tabs kept
  // running PII, custom patterns and redaction while the popup already said
  // Free. Reproducing it needs one settings object and two loads: the flag has
  // to have been true before it can go stale.
  const storageRes = {
    sg_isPro: true,
    sg_license_key: 'SG-AABBCCDDEEFF0011',
    sg_settings: { enabled: true, categories: { apiKeys: true, pii: false, network: false }, autoRedact: true },
  };
  const env = loadContentScript({ storageRes });

  // Build the event once. There is more than one keydown listener, and
  // keydownEvent rewrites target.value each time it is called, so calling it
  // per handler would put the secret back after the first handler redacted it.
  const ta = new StubElement('textarea', new Map());
  const first = keydownEvent(ta, SECRET);
  for (const fn of env.listeners.keydown) fn(first);
  assert.ok(ta.value.includes('[API_KEY'), 'auto-redact runs while the licence is valid');

  // The licence is revoked underneath the open tab. The harness does not run
  // setTimeout callbacks, so clear the send-through latch by hand first.
  delete storageRes.sg_isPro;
  delete storageRes.sg_license_key;
  for (const fn of (env.listeners.storageChanged || [])) fn({ sg_isPro: {} }, 'local');
  env.sandbox.__sgBypass = false;

  const ta2 = new StubElement('textarea', new Map());
  const ev2 = keydownEvent(ta2, SECRET);
  for (const fn of env.listeners.keydown) fn(ev2);
  assert.ok(ta2.value.includes('sk-proj'), 'the revoked tab must no longer auto-redact');
  assert.ok(env.appended.find((el) => el.id === 'sg-overlay'), 'it must fall back to the modal');
});

test('both Pro flags together do unlock auto-redact', () => {
  const env = loadContentScript({ storageRes: PRO_AUTO });
  const ta = new StubElement('textarea', new Map());
  const event = keydownEvent(ta, SECRET);
  for (const fn of env.listeners.keydown) fn(event);

  assert.equal(event.prevented, true);
  assert.ok(!ta.value.includes('sk-proj'), 'auto-redact runs when both flags are set');
  assert.ok(ta.value.includes('[API_KEY'), 'placeholder written');
});

test('protection stays off until a settings record says it is on', () => {
  // The welcome page is where protection is accepted. A content script that
  // injects before onInstalled has written the defaults, or when storage is
  // briefly empty, must not start scanning: the initial enabled flag used to
  // be true, which ran detection before any consent at all.
  const env = loadContentScript({ storageRes: {} });
  const ta = new StubElement('textarea', new Map());
  const event = keydownEvent(ta, SECRET);
  for (const fn of env.listeners.keydown) fn(event);

  assert.equal(event.prevented, false, 'nothing may be intercepted before consent');
  assert.equal(env.appended.find((el) => el.id === 'sg-overlay'), undefined, 'no modal');
});
