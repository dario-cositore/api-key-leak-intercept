/**
 * API Key Leak Intercept: detection engine
 *
 * Pure functions: no DOM, no storage, no network. Loaded as a content script
 * (exposes globalThis.SGDetect) and required by the Node test suite.
 */
(function (root) {
  'use strict';

  const MAX_SCAN_CHARS = 200000;
  const MAX_SCAN_TOTAL = 1024 * 1024;
  const WINDOW_OVERLAP = 4096;
  const MAX_FINDINGS = 20;
  // Bits per character. Chosen from data (see tests/fixtures/entropy-notes.md):
  // true-positive fixtures run 4.96 to 5.03, benign tokens that pass the
  // structural filters top out at 4.63 apart from two random-looking strings.
  const ENTROPY_MIN = 4.5;
  const DEFAULT_OPTS = {
    enabled: true,
    categories: { apiKeys: true, pii: false, network: false },
    isPro: false,
    entitled: false,
    customPatterns: [],
  };

  /* ------------------------------------------------------------------ */
  /* Detection patterns                                                  */
  /* ------------------------------------------------------------------ */
  // Each: { name, sev: 'high'|'med'|'low', cat: 'api'|'pii'|'net', re, valid? }
  // cat drives the plan gate: 'api' is free, 'pii' and 'net' are Pro.
  // valid(raw) is an optional checksum that a regex match must also pass.
  const PATTERNS = [
    // --- API keys / tokens (free) ---
    // Patterns are case-insensitive: hand-typed or case-mangled keys must not
    // slip through (regression: "akiaiosfodnn7example" passed while the
    // uppercase form was caught).
    { name: 'OpenAI API key', sev: 'high', cat: 'api', confidence: 'high', re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/i },
    { name: 'Anthropic API key', sev: 'high', cat: 'api', confidence: 'high', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/i },
    { name: 'AWS Access Key ID', sev: 'high', cat: 'api', confidence: 'high', re: /\bAKIA[0-9A-Z]{16}\b/i },
    // 40-char run, but not a plain hex string (git SHA-1 / hashes are hex)
    { name: 'AWS Secret Access Key', sev: 'high', cat: 'api', confidence: 'low', re: /\b(?![0-9a-fA-F]{40}\b)[A-Za-z0-9/+=]{40}\b/, valid: (raw) => hasMixedClasses(raw) && shannon(raw) >= ENTROPY_MIN },
    { name: 'GitHub token', sev: 'high', cat: 'api', confidence: 'high', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/i },
    { name: 'Stripe secret key', sev: 'high', cat: 'api', confidence: 'high', re: /\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b/i },
    { name: 'Stripe restricted key', sev: 'high', cat: 'api', confidence: 'high', re: /\brk_(?:live|test)_[A-Za-z0-9]{24,}\b/i },
    { name: 'Google API key', sev: 'high', cat: 'api', confidence: 'high', re: /\bAIza[0-9A-Za-z_-]{35}\b/i },
    { name: 'Slack token', sev: 'high', cat: 'api', confidence: 'high', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/i },
    { name: 'Slack webhook URL', sev: 'high', cat: 'api', confidence: 'high', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/i },
    { name: 'Discord webhook URL', sev: 'high', cat: 'api', confidence: 'high', re: /https:\/\/(?:(?:ptb|canary)\.)?discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/\d{17,20}\/[A-Za-z0-9_-]{20,}/i },
    { name: 'Telegram bot token', sev: 'high', cat: 'api', confidence: 'high', re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/ },
    { name: 'Hugging Face token', sev: 'high', cat: 'api', confidence: 'high', re: /\bhf_[A-Za-z0-9]{30,}\b/i },
    { name: 'Groq API key', sev: 'high', cat: 'api', confidence: 'high', re: /\bgsk_[A-Za-z0-9]{40,}\b/i },
    { name: 'npm token', sev: 'high', cat: 'api', confidence: 'high', re: /\bnpm_[A-Za-z0-9]{36}\b/i },
    { name: 'GitLab token', sev: 'high', cat: 'api', confidence: 'high', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/i },
    { name: 'SendGrid API key', sev: 'high', cat: 'api', confidence: 'high', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/i },
    { name: 'Twilio API key', sev: 'high', cat: 'api', confidence: 'high', re: /\bSK[0-9a-fA-F]{32}\b/i },
    { name: 'JWT', sev: 'high', cat: 'api', confidence: 'high', re: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/ },
    { name: 'Private key (PEM)', sev: 'high', cat: 'api', confidence: 'high', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/i },
    { name: 'Bearer token', sev: 'high', cat: 'api', confidence: 'high', re: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/i },
    { name: 'Database connection string', sev: 'high', cat: 'api', confidence: 'high', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s:\/@]*:[^\s@]+@[^\s'"<>]+/i },
    { name: '.env file block', sev: 'high', cat: 'api', confidence: 'high', re: /(?<![^\n])[ \t]*[A-Z][A-Z0-9_]*=(?:"[^"\n]*"|'[^'\n]*'|[^\s,;()'"]+)[ \t]*\r?(?=\n|$)(?:\n[ \t]*[A-Z][A-Z0-9_]*=(?:"[^"\n]*"|'[^'\n]*'|[^\s,;()'"]+)[ \t]*\r?(?=\n|$)){2,}/ },
    { name: 'Password assignment', sev: 'med', cat: 'api', confidence: 'low', re: /(?<![A-Za-z0-9])(?:password|passwd|pwd|secret)[ \t]*(?:=[ \t]*(?:"[^"'\r\n]{6,}"|'[^'"\r\n]{6,}'|(?![^\s"'`]*[.(\[])[^\s"'`]{6,})|:[ \t]*(?:"[^"'\r\n]{6,}"|'[^'"\r\n]{6,}'|(?![^\s"'`]*[.(\[])(?=[^\s"'`]*[0-9@#$%^&*+=\-/\\|~])[^\s"'`]{6,}))/i },
    { name: 'Generic secret assignment', sev: 'med', cat: 'api', confidence: 'low', re: /\b(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*["']?[A-Za-z0-9_\-/+=]{16,}["']?/i },
    // --- PII (Pro) ---
    { name: 'Email address', sev: 'med', cat: 'pii', confidence: 'high', re: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
    { name: 'US SSN', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{3}-\d{2}-\d{4}\b/ },
    { name: 'Credit card number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b(?:\d[ -]*?){14,19}\b/, valid: (raw) => {
      const digits = raw.replace(/\D/g, '');
      return digits.length >= 13 && digits.length <= 19 && !/^(\d)\1+$/.test(digits) && luhn(digits);
    } },
    { name: 'US phone number', sev: 'med', cat: 'pii', confidence: 'high', re: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/ },
    { name: 'EU phone number', sev: 'med', cat: 'pii', confidence: 'high', re: /\+(?:39|44|49|33|34)(?:[ .()-]{0,2}\d){6,12}(?!\d)/ },
    { name: 'IBAN', sev: 'high', cat: 'pii', confidence: 'high', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b/, valid: validIban },
    { name: 'Italian codice fiscale', sev: 'med', cat: 'pii', confidence: 'high', re: /\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b/, valid: validCodiceFiscale },
    { name: 'Italian partita IVA', sev: 'med', cat: 'pii', confidence: 'high', re: /\b(?:p\.?\s?iva|partita\s+iva|vat)[\s:#.-]*(?:IT\s?)?\d{11}\b/i, valid: validPartitaIva },
    // --- National identity numbers (Pro) ---
    { name: 'Indian Aadhaar number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/, valid: validVerhoeff },
    { name: 'Chinese resident ID', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b/, valid: validCnId },
    { name: 'Brazilian CPF', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/, valid: validCpf },
    { name: 'Canadian SIN / Australian TFN', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{3}[ -]?\d{3}[ -]?\d{3}\b/, valid: (raw) => luhn(raw.replace(/\D/g, '')) || validTfn(raw) },
    { name: 'NZ IRD number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b(?:\d{3}-\d{3}-\d{3}|\d{2}-\d{3}-\d{3}|\d{8,9})\b/, valid: validIrd },
    { name: 'German tax ID (Steuer-ID)', sev: 'high', cat: 'pii', confidence: 'high', re: /\b[1-9]\d{10}\b/, valid: validSteuerId },
    { name: 'German VAT ID', sev: 'med', cat: 'pii', confidence: 'high', re: /\bDE ?[1-9]\d{8}\b/i, valid: validUstId },
    { name: 'French NIR (social security)', sev: 'high', cat: 'pii', confidence: 'high', re: /\b[123478]\s?\d{2}\s?(?:0[1-9]|1[0-2]|20)\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b/, valid: validNir },
    { name: 'Spanish NIF/NIE', sev: 'high', cat: 'pii', confidence: 'high', re: /\b(?:\d{8}|[XYZ]\d{7})[ -]?[A-Z]\b/, valid: validNifEs },
    { name: 'Argentine CUIL', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{2}[ -]\d{8}[ -]\d\b/, valid: validCuil },
    { name: 'Chilean RUT', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Kk]\b/, valid: validRut },
    { name: 'South African ID number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{13}\b/, valid: (raw) => luhn(raw) },
    { name: 'Russian SNILS', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{3}-?\d{3}-?\d{3}[ -]?\d{2}\b/, valid: validSnils },
    { name: 'Turkish ID number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b[1-9]\d{10}\b/, valid: validKimlik },
    { name: 'South Korean resident number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{6}-?[1-4]\d{5}[0-9]\b/, valid: validRrn },
    { name: 'Japanese My Number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{12}\b/, valid: validMyNumber },
    { name: 'Dutch BSN', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{9}\b/, valid: validBsn },
    { name: 'Polish PESEL', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{11}\b/, valid: validPesel },
    { name: 'Swedish personnummer', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{6}[+-]?\d{4}\b/, valid: validPersonnummer },
    { name: 'Danish CPR number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{6}-?\d{4}\b/, valid: validCpr },
    { name: 'Norwegian fødselsnummer', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{6}[ -]?\d{5}\b/, valid: validFodselsnummer },
    { name: 'Finnish hetu', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{6}[-+A]\d{3}[0-9A-Y]\b/, valid: validHetu },
    { name: 'Irish PPS number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{7}[A-W][A-I]?\b/, valid: validPps },
    { name: 'Portuguese NIF', sev: 'high', cat: 'pii', confidence: 'high', re: /\b\d{9}\b/, valid: validNifPt },
    { name: 'UK National Insurance number', sev: 'high', cat: 'pii', confidence: 'high', re: /\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b/ },
    { name: 'Indian PAN card', sev: 'med', cat: 'pii', confidence: 'high', re: /\b[A-Z]{5}\d{4}[A-Z]\b/ },
    { name: 'Mexican CURP', sev: 'high', cat: 'pii', confidence: 'high', re: /\b[A-Z]{4}\d{6}[HMX][A-Z]{5}[0-9A-Z]\d\b/i, valid: validCurp },
    { name: 'Mexican RFC', sev: 'high', cat: 'pii', confidence: 'high', re: /\b[A-Z]{3,4}\d{6}[A-Z0-9&]{2}[0-9A]\b/i, valid: validRfc },
    { name: 'Singapore NRIC / FIN', sev: 'high', cat: 'pii', confidence: 'high', re: /\b[STFG]\d{7}[A-Z]\b/i, valid: validNric },
    { name: 'Indonesian NIK', sev: 'high', cat: 'pii', confidence: 'low', re: /\b\d{16}\b/, valid: validNik },
    // --- Network (Pro) ---
    { name: 'IPv4 address', sev: 'low', cat: 'net', confidence: 'high', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/, valid: (raw) => !/^(?:0\.0\.0\.0|127\.)/.test(raw) },
  ];

  /* ------------------------------------------------------------------ */
  /* Randomness checks                                                   */
  /* ------------------------------------------------------------------ */
  // Shannon entropy in bits per character
  function shannon(s) {
    const counts = new Map();
    for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
    let h = 0;
    for (const n of counts.values()) {
      const p = n / s.length;
      h -= p * Math.log2(p);
    }
    return h;
  }

  function hasMixedClasses(s) {
    return /[a-z]/.test(s) && /[A-Z]/.test(s) && /\d/.test(s);
  }

  /* ------------------------------------------------------------------ */
  /* Checksums                                                           */
  /* ------------------------------------------------------------------ */
  function luhn(num) {
    let sum = 0, alt = false;
    for (let i = num.length - 1; i >= 0; i--) {
      let n = parseInt(num[i], 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }

  // ISO 13616 mod-97 check (letters A=10 ... Z=35)
  function validIban(raw) {
    const s = raw.replace(/ /g, '');
    const rearranged = s.slice(4) + s.slice(0, 4);
    let r = 0;
    for (const ch of rearranged) {
      const digits = /[A-Z]/.test(ch) ? String(ch.charCodeAt(0) - 55) : ch;
      for (const d of digits) r = (r * 10 + Number(d)) % 97;
    }
    return r === 1;
  }

  const CF_ODD = {
    '0': 1, '1': 0, '2': 5, '3': 7, '4': 9, '5': 13, '6': 15, '7': 17, '8': 19, '9': 21,
    A: 1, B: 0, C: 5, D: 7, E: 9, F: 13, G: 15, H: 17, I: 19, J: 21, K: 2, L: 4, M: 18,
    N: 20, O: 11, P: 3, Q: 6, R: 8, S: 12, T: 14, U: 16, V: 10, W: 22, X: 25, Y: 24, Z: 23,
  };
  function validCodiceFiscale(raw) {
    const s = raw.toUpperCase();
    let sum = 0;
    for (let i = 0; i < 15; i++) {
      const c = s[i];
      if (i % 2 === 0) sum += CF_ODD[c];
      else sum += /\d/.test(c) ? Number(c) : c.charCodeAt(0) - 65;
    }
    return String.fromCharCode(65 + (sum % 26)) === s[15];
  }

  // Italian partita IVA: 11 digits, Luhn-style check on the last digit
  function validPartitaIva(raw) {
    const m = raw.match(/\d{11}$/);
    if (!m) return false;
    const s = m[0];
    let sum = 0;
    for (let i = 0; i < 10; i++) {
      let n = Number(s[i]);
      if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    return (10 - (sum % 10)) % 10 === Number(s[10]);
  }

  /* ------------------------------------------------------------------ */
  /* Global identity numbers (checksummed where the scheme has one)      */
  /* ------------------------------------------------------------------ */
  // ISO 7064 MOD 11,10 (German Steuer-ID and USt-IdNr)
  function iso7064Mod1110(digits) {
    let produkt = 10;
    for (const ch of digits) {
      let summe = (Number(ch) + produkt) % 10;
      if (summe === 0) summe = 10;
      produkt = (summe * 2) % 11;
    }
    const pruef = 11 - produkt;
    return pruef === 10 ? 0 : pruef;
  }
  function validSteuerId(raw) {
    const s = raw.replace(/\D/g, '');
    return s.length === 11 && s[0] !== '0' && iso7064Mod1110(s.slice(0, 10)) === Number(s[10]);
  }
  function validUstId(raw) {
    const s = raw.replace(/\D/g, '');
    return s.length === 9 && s[0] !== '0' && iso7064Mod1110(s.slice(0, 8)) === Number(s[8]);
  }

  // Verhoeff dihedral check (Indian Aadhaar)
  const VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
  ];
  const VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
  ];
  function validVerhoeff(raw) {
    const digits = raw.replace(/\D/g, '');
    let c = 0;
    for (let i = 0; i < digits.length; i++) {
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][Number(digits[digits.length - 1 - i])]];
    }
    return c === 0;
  }

  // China resident ID: ISO 7064 MOD 11-2 over the first 17 digits
  function validCnId(raw) {
    const s = raw.toUpperCase();
    if (!/^\d{17}[0-9X]$/.test(s)) return false;
    const w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let sum = 0;
    for (let i = 0; i < 17; i++) sum += Number(s[i]) * w[i];
    return '10X98765432'[sum % 11] === s[17];
  }

  // Brazil CPF: two mod-11 check digits
  function validCpf(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 11 || /^(\d)\1{10}$/.test(s)) return false;
    const calc = (len) => {
      let sum = 0;
      for (let i = 0; i < len; i++) sum += Number(s[i]) * (len + 1 - i);
      const r = (sum * 10) % 11;
      return r === 10 ? 0 : r;
    };
    return calc(9) === Number(s[9]) && calc(10) === Number(s[10]);
  }

  // Australia TFN: weighted mod 11
  function validTfn(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 9) return false;
    const w = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum = 0;
    for (let i = 0; i < 9; i++) sum += Number(s[i]) * w[i];
    return sum % 11 === 0;
  }

  // Argentina CUIL/CUIT: weighted mod 11
  function validCuil(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 11) return false;
    const w = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let sum = 0;
    for (let i = 0; i < 10; i++) sum += Number(s[i]) * w[i];
    let c = 11 - (sum % 11);
    if (c === 11) c = 0;
    if (c === 10) c = 9;
    return c === Number(s[10]);
  }

  // Chile RUT: mod 11 check digit (0-9 or K)
  function validRut(raw) {
    const s = raw.replace(/[.\-\s]/g, '').toUpperCase();
    const body = s.slice(0, -1);
    const dv = s.slice(-1);
    if (!/^\d{7,8}$/.test(body)) return false;
    let sum = 0;
    let mul = 2;
    for (let i = body.length - 1; i >= 0; i--) {
      sum += Number(body[i]) * mul;
      mul = mul === 7 ? 2 : mul + 1;
    }
    const c = 11 - (sum % 11);
    return (c === 11 ? '0' : c === 10 ? 'K' : String(c)) === dv;
  }

  // Spain NIF / NIE: mod 23 letter
  function validNifEs(raw) {
    const s = raw.replace(/[.\-\s]/g, '').toUpperCase();
    const letters = 'TRWAGMYFPDXBNJZSQVHLCKE';
    let m = s.match(/^(\d{8})([A-Z])$/);
    if (m) return letters[Number(m[1]) % 23] === m[2];
    m = s.match(/^([XYZ])(\d{7})([A-Z])$/);
    if (m) return letters[Number({ X: '0', Y: '1', Z: '2' }[m[1]] + m[2]) % 23] === m[3];
    return false;
  }

  // Portugal NIF: mod 11
  function validNifPt(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 9) return false;
    const w = [9, 8, 7, 6, 5, 4, 3, 2];
    let sum = 0;
    for (let i = 0; i < 8; i++) sum += Number(s[i]) * w[i];
    let c = 11 - (sum % 11);
    if (c >= 10) c = 0;
    return c === Number(s[8]);
  }

  // Ireland PPS number: mod 23 letter check
  function validPps(raw) {
    const s = raw.replace(/[\s-]/g, '').toUpperCase();
    const m = s.match(/^(\d{7})([A-W])([A-I]?)$/);
    if (!m) return false;
    const w = [8, 7, 6, 5, 4, 3, 2];
    let sum = 0;
    for (let i = 0; i < 7; i++) sum += Number(m[1][i]) * w[i];
    sum += (m[2].charCodeAt(0) - 64) * 9;
    return sum % 23 === 0;
  }

  // Netherlands BSN: mod 11
  function validBsn(raw) {
    const s = raw.replace(/\D/g, '');
    if (!/^\d{8,9}$/.test(s)) return false;
    const t = s.length === 8 ? '0' + s : s;
    let sum = 0;
    for (let i = 0; i < 8; i++) sum += Number(t[i]) * (9 - i);
    sum -= Number(t[8]);
    return sum !== 0 && sum % 11 === 0;
  }

  // Poland PESEL: weighted mod 10
  function validPesel(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 11) return false;
    const w = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum = 0;
    for (let i = 0; i < 10; i++) sum += Number(s[i]) * w[i];
    return (10 - (sum % 10)) % 10 === Number(s[10]);
  }

  // Denmark CPR: weighted mod 11
  function validCpr(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 10) return false;
    const w = [4, 3, 2, 7, 6, 5, 4, 3, 2, 1];
    let sum = 0;
    for (let i = 0; i < 10; i++) sum += Number(s[i]) * w[i];
    return sum % 11 === 0;
  }

  // Norway fødselsnummer: two mod 11 check digits
  function validFodselsnummer(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 11) return false;
    const d = s.split('').map(Number);
    const w1 = [3, 7, 6, 1, 8, 9, 4, 5, 2];
    let s1 = 0;
    for (let i = 0; i < 9; i++) s1 += d[i] * w1[i];
    let k1 = 11 - (s1 % 11);
    if (k1 === 11) k1 = 0;
    if (k1 === 10 || k1 !== d[9]) return false;
    const w2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let s2 = 0;
    for (let i = 0; i < 10; i++) s2 += d[i] * w2[i];
    let k2 = 11 - (s2 % 11);
    if (k2 === 11) k2 = 0;
    return k2 !== 10 && k2 === d[10];
  }

  // Sweden personnummer: Luhn over the ten core digits
  function validPersonnummer(raw) {
    const s = raw.replace(/[+\-\s]/g, '');
    const t = s.length === 12 ? s.slice(2) : s;
    return /^\d{10}$/.test(t) && luhn(t);
  }

  // Finland hetu: mod 31 check character
  function validHetu(raw) {
    const m = raw.replace(/\s/g, '').toUpperCase().match(/^(\d{6})([-+A])(\d{3})([0-9A-Y])$/);
    if (!m) return false;
    const map = '0123456789ABCDEFHJKLMNPRSTUVWXY';
    return map[Number(m[1] + m[3]) % 31] === m[4];
  }

  // Russia SNILS: mod 101 over the first nine digits
  function validSnils(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 11 || /^(\d)\1{10}$/.test(s)) return false;
    let sum = 0;
    for (let i = 0; i < 9; i++) sum += Number(s[i]) * (9 - i);
    let c;
    if (sum < 100) c = sum;
    else if (sum <= 101) c = 0;
    else c = sum % 101;
    return c === Number(s.slice(9));
  }

  // Turkey T.C. kimlik: two mod 10 check digits
  function validKimlik(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 11 || s[0] === '0') return false;
    const d = s.split('').map(Number);
    const odd = d[0] + d[2] + d[4] + d[6] + d[8];
    const even = d[1] + d[3] + d[5] + d[7];
    if (((odd * 7 - even) % 10 + 10) % 10 !== d[9]) return false;
    const sum10 = d.slice(0, 10).reduce((a, b) => a + b, 0);
    return sum10 % 10 === d[10];
  }

  // South Korea resident registration number: mod 11
  function validRrn(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 13) return false;
    const w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum = 0;
    for (let i = 0; i < 12; i++) sum += Number(s[i]) * w[i];
    return (11 - (sum % 11)) % 10 === Number(s[12]);
  }

  // Japan My Number: mod 11
  function validMyNumber(raw) {
    const s = raw.replace(/\D/g, '');
    if (s.length !== 12) return false;
    const w = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let sum = 0;
    for (let i = 0; i < 11; i++) sum += Number(s[i]) * w[i];
    let c = (11 - (sum % 11)) % 11;
    if (c === 10) c = 0;
    return c === Number(s[11]);
  }

  // France NIR: mod 97 over the first thirteen digits
  function validNir(raw) {
    const s = raw.replace(/[\s.]/g, '');
    if (!/^[123478]\d{2}(?:0[1-9]|1[0-2]|20)\d{10}$/.test(s)) return false;
    return 97 - (Number(s.slice(0, 13)) % 97) === Number(s.slice(13));
  }

  // Mexico CURP: mod 11 with weights 17..1 (values A=10..Z=35)
  function validCurp(raw) {
    const s = raw.replace(/[\s-]/g, '').toUpperCase();
    if (!/^[A-Z]{4}\d{6}[HMX][A-Z]{5}[0-9A-Z]\d$/.test(s)) return false;
    let sum = 0;
    for (let i = 0; i < 17; i++) {
      const c = s[i];
      sum += (c >= '0' && c <= '9' ? Number(c) : c.charCodeAt(0) - 55) * (17 - i);
    }
    const d = 10 - (sum % 11);
    return String(d === 10 ? 0 : d) === s[17];
  }

  // Mexico RFC: mod 11 with weights 13..2 (Anexo III values, & = 24, O = 25..Z = 36)
  function validRfc(raw) {
    const s = raw.replace(/[\s-]/g, '').toUpperCase();
    if (!/^[A-Z]{3,4}\d{6}[A-Z0-9&]{2}[0-9A]$/.test(s)) return false;
    let sum = 0;
    for (let i = 0; i < s.length - 1; i++) {
      const c = s[i];
      let v;
      if (c >= '0' && c <= '9') v = Number(c);
      else if (c === '&') v = 24;
      else if (c <= 'N') v = c.charCodeAt(0) - 55;
      else v = c.charCodeAt(0) - 54;
      sum += v * (13 - i);
    }
    const r = sum % 11;
    return (r === 0 ? '0' : 11 - r === 10 ? 'A' : String(11 - r)) === s[s.length - 1];
  }

  // Singapore NRIC / FIN: weighted mod 11, offset 4 for T/G, check-letter tables
  function validNric(raw) {
    const m = raw.replace(/[\s-]/g, '').toUpperCase().match(/^([STFG])(\d{7})([A-Z])$/);
    if (!m) return false;
    const w = [2, 7, 6, 5, 4, 3, 2];
    let sum = 0;
    for (let i = 0; i < 7; i++) sum += Number(m[2][i]) * w[i];
    const d = (sum + (m[1] === 'T' || m[1] === 'G' ? 4 : 0)) % 11;
    const table = m[1] === 'S' || m[1] === 'T' ? 'JZIHGFEDCBA' : 'XWUTRQPNMLK';
    return table[d] === m[3];
  }

  // New Zealand IRD: mod 11 with a second weight set when the first yields 10
  function validIrd(raw) {
    const s = raw.replace(/[\s-]/g, '');
    if (!/^\d{8,9}$/.test(s)) return false;
    const n = Number(s);
    if (n < 10000000 || n > 200000000) return false;
    const base = s.slice(0, -1).padStart(8, '0');
    const check = Number(s[s.length - 1]);
    for (const w of [[3, 2, 7, 6, 5, 4, 3, 2], [7, 4, 3, 2, 5, 2, 7, 6]]) {
      let sum = 0;
      for (let i = 0; i < 8; i++) sum += Number(base[i]) * w[i];
      const r = sum % 11;
      const c = r === 0 ? 0 : 11 - r;
      if (c === 10) continue;
      return c === check;
    }
    return false;
  }

  // Indonesia NIK: no check digit exists; day 01-31 (male) or 41-71 (female +40), month, serial
  function validNik(raw) {
    const s = raw.replace(/\D/g, '');
    if (!/^\d{16}$/.test(s)) return false;
    const day = Number(s.slice(6, 8));
    const month = Number(s.slice(8, 10));
    const serial = Number(s.slice(12, 16));
    return ((day >= 1 && day <= 31) || (day >= 41 && day <= 71)) && month >= 1 && month <= 12 && serial >= 1;
  }

  /* ------------------------------------------------------------------ */
  /* Scan                                                                */
  /* ------------------------------------------------------------------ */
  // Filters human-readable strings (URLs, file paths, kebab/snake slugs)
  // out of the catch-all entropy check, which reports one finding at a time.
  function isHighEntropyToken(t) {
    if (t.includes('/')) return false;                       // url or path fragment
    if (!/[0-9+/=]/.test(t)) return false;                   // plain word runs are never secrets
    if (/^[a-f0-9]{32,}$/i.test(t)) return false;            // looks like a hash
    if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(t)) return false; // UUID
    const segs = t.split(/[-_]/);
    if (segs.length >= 3) {
      const wordy = s =>
        /^[A-Za-z]{1,16}$/.test(s) ||
        /^\d{1,10}$/.test(s) ||
        /^[A-Za-z]{1,14}\d{1,4}$/.test(s);
      if (segs.every(wordy)) return false;                   // slug built from plain words
    }
    return shannon(t) >= ENTROPY_MIN;                        // random-looking enough to be a key
  }

  // Pro capabilities (PII, IP, custom patterns, redaction) come with a Pro
  // license or a fresh server-confirmed paid entitlement bound to the org.
  // Managed installs and typed org IDs never unlock them; enterprise policy
  // controls settings and locking only.
  function hasProCapabilities(opts) {
    return !!opts.isPro || !!opts.entitled;
  }

  // Category + plan gating for a pattern.
  function categoryAllowed(p, opts) {
    const c = opts.categories || {};
    const pro = hasProCapabilities(opts);
    if (p.cat === 'net') return pro && !!c.network;
    if (p.cat === 'pii') return pro && !!c.pii;
    return !!c.apiKeys;
  }

  function customPatternsAllowed(opts) {
    return hasProCapabilities(opts);
  }

  function globalRe(re) {
    return re.global ? re : new RegExp(re.source, re.flags + 'g');
  }

  function previewOf(raw) {
    return raw.length > 24 ? raw.slice(0, 12) + '…' + raw.slice(-6) : raw;
  }

  // Overlap priority: when two matches share characters, the higher rank is
  // kept and the other is dropped, so the modal shows one row per secret.
  // Shape-only rules rank low; context rules (keyword, scheme, format) rank high.
  const RANK = {
    'High-entropy token': 0,
    'Generic secret assignment': 1, '.env file block': 1, 'IPv4 address': 1,
    'AWS Secret Access Key': 2, 'US phone number': 2,
    'Bearer token': 3, 'Email address': 3, 'Password assignment': 3, 'EU phone number': 3,
    'Telegram bot token': 4, 'Twilio API key': 4, 'Database connection string': 4,
    'IBAN': 4, 'Italian codice fiscale': 4, 'Italian partita IVA': 4,
    'Indian Aadhaar number': 4, 'Chinese resident ID': 4, 'Brazilian CPF': 4,
    'Canadian SIN / Australian TFN': 4, 'German tax ID (Steuer-ID)': 4,
    'German VAT ID': 4, 'French NIR (social security)': 4, 'Spanish NIF/NIE': 4,
    'Argentine CUIL': 4, 'Chilean RUT': 4, 'South African ID number': 4,
    'Russian SNILS': 4, 'Turkish ID number': 4, 'South Korean resident number': 4,
    'Japanese My Number': 4, 'Dutch BSN': 4, 'Polish PESEL': 4,
    'Swedish personnummer': 4, 'Danish CPR number': 4, 'Norwegian fødselsnummer': 4,
    'Finnish hetu': 4, 'Irish PPS number': 4, 'Portuguese NIF': 4,
    'UK National Insurance number': 4, 'Indian PAN card': 4,
    'Mexican CURP': 4, 'Mexican RFC': 4, 'Singapore NRIC / FIN': 4, 'NZ IRD number': 4,
    // structured shapes outrank the generic card shape when both validate
    'French NIR (social security)': 5,
    'Indonesian NIK': 5,
    'Russian SNILS': 5,
    'US SSN': 4, 'Credit card number': 4,
    'Custom pattern': 5,
  };
  const rankOf = name => (name in RANK ? RANK[name] : 5);

  // Inputs are scanned in bounded windows so a 1 MB file is fully covered
  // while no single regex pass runs over more than MAX_SCAN_CHARS.
  function eachWindow(text, visit) {
    const s = String(text);
    const total = Math.min(s.length, MAX_SCAN_TOTAL);
    if (total <= MAX_SCAN_CHARS) {
      visit(s.slice(0, total), 0);
      return;
    }
    for (let off = 0; off < total; off += MAX_SCAN_CHARS - WINDOW_OVERLAP) {
      const end = Math.min(off + MAX_SCAN_CHARS, total);
      visit(s.slice(off, end), off);
      if (end >= total) break;
    }
  }

  function scan(text, opts) {
    const o = { ...DEFAULT_OPTS, ...(opts || {}) };
    if (!text || !o.enabled) return [];
    const hits = [];
    let done = false;
    const add = (name, sev, raw, start, preview, confidence) => {
      const rank = rankOf(name);
      const end = start + raw.length;
      // the same value counts as one secret, and overlapping spans compete on rank
      const taken = hits.filter(h => h.raw === raw || (h.start < end && start < h.end));
      if (taken.some(h => h.rank >= rank)) return;
      for (const h of taken) hits.splice(hits.indexOf(h), 1);
      hits.push({ name, sev, preview: preview || previewOf(raw), raw, start, end, rank, confidence: confidence || 'high' });
    };
    const out = () => hits
      .sort((a, b) => a.start - b.start)
      .map(({ name, sev, preview, raw, start, end, confidence }) => ({ name, sev, preview, raw, start, end, confidence }));
    eachWindow(text, (s, off) => {
      if (done) return;
      // Built-in patterns
      for (const p of PATTERNS) {
        if (!categoryAllowed(p, o)) continue;
        for (const m of s.matchAll(globalRe(p.re))) {
          if (hits.length >= MAX_FINDINGS) { done = true; return; }
          if (!m[0] || (p.valid && !p.valid(m[0]))) continue;
          add(p.name, p.sev, m[0], off + m.index, undefined, p.confidence);
        }
      }
      // Custom patterns (Pro or Team), length- and count-capped
      if (customPatternsAllowed(o)) {
        for (const cp of (o.customPatterns || []).slice(0, 50)) {
          if (typeof cp !== 'string' || cp.length > 2000) continue;
          let re;
          try { re = new RegExp(cp, 'g'); } catch (e) { continue; }
          for (const m of s.matchAll(re)) {
            if (hits.length >= MAX_FINDINGS) { done = true; return; }
            if (m[0]) add('Custom pattern', 'high', m[0], off + m.index, undefined, 'high');
          }
        }
      }
      // High-entropy token detection: long runs of base64-ish chars
      if (categoryAllowed({ cat: 'api' }, o)) {
        for (const m of s.matchAll(/\b[A-Za-z0-9+/=_-]{32,}\b/g)) {
          if (hits.length >= MAX_FINDINGS) { done = true; return; }
          const t = m[0];
          if (!isHighEntropyToken(t)) continue;
          add('High-entropy token', 'med', t, off + m.index, t.slice(0, 8) + '…' + t.slice(-4), 'low');
        }
      }
    });
    return out();
  }

  const TEXT_FILE_EXT_RE = /(?:^|\.)(txt|md|json|env|csv|log|yml|yaml|toml|ini|js|ts|py|sh)$/i;
  const MAX_FILE_BYTES = 1024 * 1024; // 1 MB

  function isTextLikeFile(file) {
    if (!file || typeof file.name !== 'string') return false;
    if (typeof file.size !== 'number' || file.size <= 0 || file.size > MAX_FILE_BYTES) return false;
    const name = file.name.trim();
    if (/^\.env(?:\.(?:local|development|production|staging|test|example))?$/i.test(name)) return true;
    return TEXT_FILE_EXT_RE.test(name);
  }


  /* ------------------------------------------------------------------ */
  /* Redaction with numbered placeholders                               */
  /* ------------------------------------------------------------------ */
  const PLACEHOLDER_TYPE = {
    'OpenAI API key': 'API_KEY', 'Anthropic API key': 'API_KEY', 'AWS Access Key ID': 'AWS_KEY',
    'AWS Secret Access Key': 'AWS_SECRET', 'GitHub token': 'GITHUB_TOKEN', 'Stripe secret key': 'STRIPE_KEY',
    'Stripe restricted key': 'STRIPE_KEY', 'Google API key': 'API_KEY', 'Slack token': 'SLACK_TOKEN',
    'Slack webhook URL': 'WEBHOOK_URL', 'Discord webhook URL': 'WEBHOOK_URL', 'Telegram bot token': 'TELEGRAM_TOKEN',
    'Hugging Face token': 'HF_TOKEN', 'Groq API key': 'API_KEY', 'npm token': 'NPM_TOKEN',
    'GitLab token': 'GITLAB_TOKEN', 'SendGrid API key': 'SENDGRID_KEY', 'Twilio API key': 'TWILIO_KEY',
    'JWT': 'JWT', 'Private key (PEM)': 'PRIVATE_KEY', 'Bearer token': 'BEARER_TOKEN',
    'Database connection string': 'DB_URL', '.env file block': 'ENV', 'Password assignment': 'PASSWORD',
    'Generic secret assignment': 'SECRET', 'Email address': 'EMAIL', 'US SSN': 'SSN',
    'Credit card number': 'CARD', 'US phone number': 'PHONE', 'EU phone number': 'PHONE',
    'IBAN': 'IBAN', 'Italian codice fiscale': 'CODICE_FISCALE', 'Italian partita IVA': 'VAT',
    'Indian Aadhaar number': 'AADHAAR', 'Chinese resident ID': 'CN_ID', 'Brazilian CPF': 'CPF',
    'Canadian SIN / Australian TFN': 'SIN_TFN', 'German tax ID (Steuer-ID)': 'STEUER_ID',
    'German VAT ID': 'VAT', 'French NIR (social security)': 'NIR', 'Spanish NIF/NIE': 'NIF',
    'Argentine CUIL': 'CUIL', 'Chilean RUT': 'RUT', 'South African ID number': 'ZA_ID',
    'Russian SNILS': 'SNILS', 'Turkish ID number': 'KIMLIK', 'South Korean resident number': 'RRN',
    'Japanese My Number': 'MY_NUMBER', 'Dutch BSN': 'BSN', 'Polish PESEL': 'PESEL',
    'Swedish personnummer': 'PERSONNUMMER', 'Danish CPR number': 'CPR',
    'Norwegian fødselsnummer': 'FODSELSNUMMER', 'Finnish hetu': 'HETU',
    'Irish PPS number': 'PPS', 'Portuguese NIF': 'NIF', 'UK National Insurance number': 'NINO',
    'Indian PAN card': 'PAN', 'Mexican CURP': 'CURP', 'Mexican RFC': 'RFC',
    'Singapore NRIC / FIN': 'NRIC', 'NZ IRD number': 'IRD', 'Indonesian NIK': 'NIK',
    'IPv4 address': 'IP', 'High-entropy token': 'TOKEN', 'Custom pattern': 'SECRET',
  };
  function placeholderType(name) {
    if (PLACEHOLDER_TYPE[name]) return PLACEHOLDER_TYPE[name];
    return String(name || 'SECRET').toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'SECRET';
  }

  function redact(text, opts, redactOpts) {
    redactOpts = redactOpts || {};
    const highOnly = !!redactOpts.highOnly;
    const o = { ...DEFAULT_OPTS, ...(opts || {}) };
    const full = String(text);
    const spans = [];
    const addSpan = (name, sev, raw, start, confidence) => {
      const rank = rankOf(name);
      const end = start + raw.length;
      // overlap handling: higher rank replaces lower; equal/lower ignored
      const taken = spans.filter(h => h.start < end && start < h.end);
      if (taken.some(h => h.rank >= rank)) return;
      for (const h of taken) spans.splice(spans.indexOf(h), 1);
      spans.push({ name, sev, raw, start, end, rank, confidence: confidence || 'high' });
    };
    eachWindow(full, (s, off) => {
      // Built-in patterns
      for (const p of PATTERNS) {
        if (!categoryAllowed(p, o)) continue;
        for (const m of s.matchAll(globalRe(p.re))) {
          if (!m[0] || (p.valid && !p.valid(m[0]))) continue;
          addSpan(p.name, p.sev, m[0], off + m.index, p.confidence);
        }
      }
      // Custom patterns
      if (customPatternsAllowed(o)) {
        for (const cp of (o.customPatterns || []).slice(0, 50)) {
          if (typeof cp !== 'string' || cp.length > 2000) continue;
          let re;
          try { re = new RegExp(cp, 'g'); } catch (e) { continue; }
          for (const m of s.matchAll(re)) {
            if (m[0]) addSpan('Custom pattern', 'high', m[0], off + m.index, 'high');
          }
        }
      }
      // High-entropy tokens
      if (categoryAllowed({ cat: 'api' }, o)) {
        for (const m of s.matchAll(/\b[A-Za-z0-9+/=_-]{32,}\b/g)) {
          const t = m[0];
          if (!isHighEntropyToken(t)) continue;
          addSpan('High-entropy token', 'med', t, off + m.index, 'low');
        }
      }
    });

    // Filter by confidence if requested
    const filtered = highOnly ? spans.filter(sp => sp.confidence === 'high') : spans;

    // Assign numbered placeholders: same type+value -> same number
    const typeCounter = {};
    const valueMap = new Map();
    const sorted = [...filtered].sort((a, b) => a.start - b.start);
    for (const sp of sorted) {
      const type = placeholderType(sp.name);
      const key = type + '\u0000' + sp.raw;
      if (!valueMap.has(key)) {
        typeCounter[type] = (typeCounter[type] || 0) + 1;
        valueMap.set(key, '[' + type + '_' + typeCounter[type] + ']');
      }
    }
    // Reconstruct over the full input so nothing past the scan budget is dropped
    let result = '';
    let last = 0;
    for (const sp of sorted) {
      if (sp.start < last) continue;
      result += full.slice(last, sp.start);
      const type = placeholderType(sp.name);
      const key = type + '\u0000' + sp.raw;
      result += valueMap.get(key);
      last = sp.end;
    }
    result += full.slice(last);
    return { text: result, count: filtered.length };
  }

  const api = {
    PATTERNS,
    redact,
    MAX_SCAN_CHARS,
    MAX_SCAN_TOTAL,
    MAX_FINDINGS,
    MAX_FILE_BYTES,
    scan,
    luhn,
    shannon,
    ENTROPY_MIN,
    isHighEntropyToken,
    isTextLikeFile,
    categoryAllowed,
    customPatternsAllowed,
    checksums: {
      luhn, verhoeff: validVerhoeff, cpf: validCpf, cnId: validCnId, tfn: validTfn,
      steuerId: validSteuerId, ustId: validUstId, nir: validNir, nifEs: validNifEs,
      cuil: validCuil, rut: validRut, snils: validSnils, kimlik: validKimlik,
      rrn: validRrn, myNumber: validMyNumber, bsn: validBsn, pesel: validPesel,
      cpr: validCpr, fodselsnummer: validFodselsnummer, personnummer: validPersonnummer,
      hetu: validHetu, pps: validPps, nifPt: validNifPt, codiceFiscale: validCodiceFiscale,
      curp: validCurp, rfc: validRfc, nric: validNric, ird: validIrd, nik: validNik,
    },
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.SGDetect = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
