/**
 * API Key Leak Intercept: setup code codec
 *
 * Format: SGSETUP1.<base64url(JSON)>.<8-hex sha256 of the base64url payload>
 * Pure functions: no DOM, no storage, no network. Loaded by popup.html
 * (exposes globalThis.SGSetup) and required by the Node test suite.
 */
(function (root) {
  'use strict';

  const PREFIX = 'SGSETUP1.';
  const MAX_CODE_CHARS = 2048;
  const MAX_JSON_BYTES = 1500;
  const HOSTNAME_RE = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i;
  const ORG_ID_RE = /^org_[a-z0-9]{6,}$/i;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  const PRINTABLE_RE = /^[\x21-\x7E]+$/;
  const BOOLEAN_FIELDS = ['universalMode', 'heartbeat', 'blockSendAnyway', 'autoRedact'];

  function b64urlEncode(str) {
    const bin = btoa(unescape(encodeURIComponent(str)));
    return bin.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlDecode(s) {
    const bin = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = bin.length % 4 === 0 ? '' : '='.repeat(4 - (bin.length % 4));
    return decodeURIComponent(escape(atob(bin + pad)));
  }

  async function checksumOf(payload) {
    const bytes = new TextEncoder().encode(payload);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    return hex.slice(0, 8);
  }

  // Only these fields ever leave the codec. Everything else is dropped.
  function pickValid(data) {
    const out = {};
    if (typeof data.orgId === 'string' && ORG_ID_RE.test(data.orgId)) out.orgId = data.orgId;
    else if (data.orgId !== undefined) return { error: 'Setup code has an invalid org ID.' };
    if (typeof data.orgToken === 'string') {
      if (!data.orgToken || data.orgToken.length > 128 || !PRINTABLE_RE.test(data.orgToken)) {
        return { error: 'Setup code has an invalid org token.' };
      }
      out.orgToken = data.orgToken;
    }
    if (typeof data.userEmail === 'string') {
      if (!data.userEmail || data.userEmail.length > 254 || !EMAIL_RE.test(data.userEmail)) {
        return { error: 'Setup code has an invalid email address.' };
      }
      out.userEmail = data.userEmail;
    }
    for (const f of BOOLEAN_FIELDS) {
      if (data[f] !== undefined) {
        if (typeof data[f] !== 'boolean') return { error: 'Setup code has an invalid ' + f + ' flag.' };
        out[f] = data[f];
      }
    }
    if (data.extraSites !== undefined) {
      if (!Array.isArray(data.extraSites) || data.extraSites.length > 50) {
        return { error: 'Setup code has an invalid site list.' };
      }
      for (const s of data.extraSites) {
        if (typeof s !== 'string' || !s || s.length > 253 || !HOSTNAME_RE.test(s)) {
          return { error: 'Setup code has an invalid site list.' };
        }
      }
      out.extraSites = data.extraSites.map(s => s.toLowerCase());
    }
    return { value: out };
  }

  async function format(data) {
    const picked = pickValid(data || {});
    if (picked.error) return { ok: false, error: picked.error };
    if (!picked.value.orgId) return { ok: false, error: 'Setup code needs an org ID.' };
    const json = JSON.stringify(picked.value);
    if (json.length > MAX_JSON_BYTES) return { ok: false, error: 'Setup code is too large.' };
    const payload = b64urlEncode(json);
    const code = PREFIX + payload + '.' + (await checksumOf(payload));
    if (code.length > MAX_CODE_CHARS) return { ok: false, error: 'Setup code is too large.' };
    return { ok: true, code };
  }

  async function parse(code) {
    const raw = String(code || '').trim();
    if (!raw) return { ok: false, error: 'Paste a setup code first.' };
    if (raw.length > MAX_CODE_CHARS) return { ok: false, error: 'Setup code is too large.' };
    if (!raw.startsWith(PREFIX)) return { ok: false, error: 'Unsupported setup code version.' };
    const rest = raw.slice(PREFIX.length);
    const dot = rest.lastIndexOf('.');
    if (dot <= 0) return { ok: false, error: 'Setup code is damaged. Ask your IT admin for a new one.' };
    const payload = rest.slice(0, dot);
    const sum = rest.slice(dot + 1);
    if (sum !== (await checksumOf(payload))) {
      return { ok: false, error: 'Setup code is damaged. Ask your IT admin for a new one.' };
    }
    let data;
    try {
      const json = b64urlDecode(payload);
      if (json.length > MAX_JSON_BYTES) return { ok: false, error: 'Setup code is too large.' };
      data = JSON.parse(json);
    } catch (e) {
      return { ok: false, error: 'Setup code is damaged. Ask your IT admin for a new one.' };
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      return { ok: false, error: 'Setup code is damaged. Ask your IT admin for a new one.' };
    }
    // The alert endpoint is enterprise policy only. A pasted code can never
    // point alerts, the org token, or the user's email at another server.
    if (data.alertEndpoint !== undefined) {
      return { ok: false, error: 'This setup code is not allowed to set an alert endpoint.' };
    }
    const picked = pickValid(data);
    if (picked.error) return { ok: false, error: picked.error };
    if (!picked.value.orgId) return { ok: false, error: 'Setup code needs an org ID.' };
    return { ok: true, data: picked.value };
  }

  const api = { PREFIX, MAX_CODE_CHARS, MAX_JSON_BYTES, format, parse, checksumOf };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.SGSetup = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
