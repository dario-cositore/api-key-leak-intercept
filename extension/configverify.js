/**
 * API Key Leak Intercept: signed config envelope verification
 *
 * Pure functions: no DOM, no storage, no network. Loaded by the service
 * worker (importScripts, exposes globalThis.SGConfigVerify) and required
 * by the Node test suite.
 *
 * Envelope: { schemaVersion: 1, kid, seq, exp, data, signature }
 * Signed bytes: UTF-8 of JSON.stringify({ schemaVersion: 1, kid, seq, exp, data })
 * with keys in exactly that order. signature is raw ECDSA P-256 r||s, base64.
 */
(function (root) {
  'use strict';

  // Config signing keys (SPKI, base64), selected by the envelope's kid. The
  // private keys live offline only; rotate by signing with the other kid.
  const CONFIG_KEYS = {
    k1: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES52xQYKV7WndaQkvNa9AqH06ZQsUmZ/z8fIY4GRqoJnJYizeqP4BDLMnpyWJl3OaB2eXlhd3sAYfbHxLHIjXpw==',
    k2: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkvJBW/Qm3sCmGqBGoOPGg/wunMbjEqf3bqzcW3nziBwlkV7tydMG1aywSPh3Cs0PJcLuwFnuFWgP083PpgPREA==',
  };
  const CONFIG_MAX_EXP_DAYS = 180;
  const HOSTNAME_RE = /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i;

  function base64ToBuffer(b64) {
    const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  // Data payloads are strictly typed and size-capped before they are trusted
  function sanitizeConfigData(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
    const strList = (v, maxItems) => {
      if (v === undefined) return [];
      if (!Array.isArray(v) || v.length > maxItems) return null;
      const out = [];
      for (const s of v) {
        if (typeof s !== 'string' || !s || s.length > 253 || !HOSTNAME_RE.test(s)) return null;
        out.push(s);
      }
      return out;
    };
    const out = {
      aiSites: strList(data.aiSites, 200),
      excludedSites: strList(data.excludedSites, 200),
      extraPatterns: [],
    };
    if (out.aiSites === null || out.excludedSites === null) return null;
    if (data.extraPatterns !== undefined) {
      if (!Array.isArray(data.extraPatterns) || data.extraPatterns.length > 32) return null;
      for (const p of data.extraPatterns) {
        if (typeof p !== 'string' || !p || p.length > 256) return null;
        try { new RegExp(p); } catch (e) { return null; }
        out.extraPatterns.push(p);
      }
    }
    return out;
  }

  // Verifies one envelope against the embedded keys and the replay window.
  // Returns { ok: true, seq, exp, data } or { ok: false, error }. The key
  // table is injectable for tests only; minSeq is the highest seq already
  // accepted, so older (replayed) configs are rejected.
  async function verifyEnvelope(cfg, nowMs, keys, minSeq) {
    const now = typeof nowMs === 'number' ? nowMs : Date.now();
    const table = keys || CONFIG_KEYS;
    try {
      if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return { ok: false, error: 'schema' };
      if (typeof cfg.schemaVersion !== 'number' || cfg.schemaVersion !== 1) return { ok: false, error: 'schema' };
      if (!cfg.data || typeof cfg.data !== 'object') return { ok: false, error: 'data' };
      if (typeof cfg.kid !== 'string' || !table[cfg.kid]) return { ok: false, error: 'kid' };
      if (!Number.isInteger(cfg.seq) || cfg.seq < 1) return { ok: false, error: 'seq' };
      if (typeof minSeq === 'number' && cfg.seq <= minSeq) return { ok: false, error: 'stale' };
      if (typeof cfg.exp !== 'number' || !isFinite(cfg.exp)) return { ok: false, error: 'exp' };
      if (cfg.exp * 1000 <= now) return { ok: false, error: 'expired' };
      if (cfg.exp * 1000 > now + CONFIG_MAX_EXP_DAYS * 86400000) return { ok: false, error: 'exp too far' };
      if (typeof cfg.signature !== 'string' || !cfg.signature) return { ok: false, error: 'no signature' };
      const key = await crypto.subtle.importKey('spki', base64ToBuffer(table[cfg.kid]), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const signedBytes = new TextEncoder().encode(JSON.stringify({ schemaVersion: 1, kid: cfg.kid, seq: cfg.seq, exp: cfg.exp, data: cfg.data }));
      const sigBytes = base64ToBuffer(cfg.signature);
      const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sigBytes, signedBytes);
      if (!ok) return { ok: false, error: 'bad signature' };
      const clean = sanitizeConfigData(cfg.data);
      if (!clean) return { ok: false, error: 'bad data' };
      return { ok: true, seq: cfg.seq, exp: cfg.exp, data: clean };
    } catch (e) {
      return { ok: false, error: 'malformed' };
    }
  }

  const api = { CONFIG_KEYS, CONFIG_MAX_EXP_DAYS, sanitizeConfigData, verifyEnvelope, base64ToBuffer };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.SGConfigVerify = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
