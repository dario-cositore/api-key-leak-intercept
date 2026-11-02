'use strict';

// Run from the project root: node --test
// Fixtures live in tests/fixtures/ (fake secrets are assembled at runtime).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const D = require('../extension/detect.js');
const { ALNUM, DIGITS, from, rep, POSITIVES } = require('./fixtures/samples.js');

const { PATTERNS, scan, luhn, shannon, isHighEntropyToken, isTextLikeFile, categoryAllowed, MAX_SCAN_CHARS, MAX_SCAN_TOTAL, MAX_FINDINGS, MAX_FILE_BYTES, ENTROPY_MIN } = D;

const FREE = { enabled: true, categories: { apiKeys: true, pii: false, network: false }, isPro: false };
const FULL = { enabled: true, categories: { apiKeys: true, pii: true, network: true }, isPro: true };

const names = (text, opts) => scan(text, opts).map(f => f.name);

const PII_NAMES = [
  'Email address', 'US SSN', 'Credit card number', 'US phone number', 'EU phone number',
  'IBAN', 'Italian codice fiscale', 'Italian partita IVA',
  'Indian Aadhaar number', 'Chinese resident ID', 'Brazilian CPF',
  'Canadian SIN / Australian TFN', 'German tax ID (Steuer-ID)', 'German VAT ID',
  'French NIR (social security)', 'Spanish NIF/NIE', 'Argentine CUIL', 'Chilean RUT',
  'South African ID number', 'Russian SNILS', 'Turkish ID number',
  'South Korean resident number', 'Japanese My Number', 'Dutch BSN', 'Polish PESEL',
  'Swedish personnummer', 'Danish CPR number', 'Norwegian fødselsnummer',
  'Finnish hetu', 'Irish PPS number', 'Portuguese NIF',
  'UK National Insurance number', 'Indian PAN card',
  'Mexican CURP', 'Mexican RFC', 'Singapore NRIC / FIN', 'NZ IRD number', 'Indonesian NIK',
];
const NET_NAMES = ['IPv4 address'];

/* ------------------------------------------------------------------ */
/* Pattern table and plan gating                                       */
/* ------------------------------------------------------------------ */
test('every pattern has an explicit cat of api, pii or net', () => {
  for (const p of PATTERNS) {
    const expected = PII_NAMES.includes(p.name) ? 'pii' : NET_NAMES.includes(p.name) ? 'net' : 'api';
    assert.equal(p.cat, expected, p.name);
  }
});

test('Stripe secret key is a free API key pattern, not PII (regression)', () => {
  const stripe = PATTERNS.find(p => p.name === 'Stripe secret key');
  assert.equal(stripe.cat, 'api');
  assert.equal(categoryAllowed(stripe, FREE), true);
  assert.deepEqual(names('sk_live_' + from(ALNUM, 24), FREE), ['Stripe secret key']);
});

test('free plan never reports PII or IP findings, even with the category on', () => {
  const freeWithPii = { ...FREE, categories: { apiKeys: true, pii: true, network: true } };
  const text = 'mail anna.rossi@example.org from 10.0.0.12';
  assert.deepEqual(names(text, freeWithPii), []);
});

test('pii and net findings need Pro and their category toggle', () => {
  const text = 'mail anna.rossi@example.org from 10.0.0.12';
  assert.deepEqual(names(text, { ...FULL, categories: { apiKeys: true, pii: false, network: false } }), []);
  assert.deepEqual(names(text, FULL).sort(), ['Email address', 'IPv4 address']);
});

test('apiKeys off disables every api finding', () => {
  const off = { ...FREE, categories: { apiKeys: false, pii: false, network: false } };
  assert.deepEqual(names('sk-' + from(ALNUM, 32), off), []);
});

test('enabled false returns nothing', () => {
  assert.deepEqual(scan('sk-' + from(ALNUM, 32), { ...FREE, enabled: false }), []);
});

/* ------------------------------------------------------------------ */
/* True positives, per pattern                                         */
/* ------------------------------------------------------------------ */
for (const p of PATTERNS) {
  test('true positives: ' + p.name, () => {
    const samples = POSITIVES[p.name] || [];
    assert.ok(samples.length >= 3, 'needs at least 3 samples');
    const opts = p.cat === 'api' ? FREE : FULL;
    for (const sample of samples) {
      assert.ok(names(sample, opts).includes(p.name), 'missed: ' + JSON.stringify(sample.slice(0, 60)));
    }
  });
}

test('true positives: High-entropy token', () => {
  for (const sample of POSITIVES['High-entropy token']) {
    assert.ok(names(sample, FREE).includes('High-entropy token'), sample);
  }
});

/* ------------------------------------------------------------------ */
/* Password assignment: separator and value rules                      */
/* ------------------------------------------------------------------ */
test('password: flagged when the value has a digit or a symbol', () => {
  assert.ok(names('password: ' + 'Tr0ub4dor', FREE).includes('Password assignment'));
  assert.ok(names('password: ' + 'pa$$word', FREE).includes('Password assignment'));
  assert.ok(names('password: ' + 'correct-horse', FREE).includes('Password assignment'));
});

test('password with an equals sign is flagged even for a bare lowercase word', () => {
  assert.ok(names('password=' + 'please', FREE).includes('Password assignment'));
});

test('password: flagged when the value is quoted', () => {
  assert.ok(names('password: "' + 'please' + '"', FREE).includes('Password assignment'));
  assert.ok(names("pwd: '" + 'hunter2x' + "'", FREE).includes('Password assignment'));
});

test('password value in code is not flagged', () => {
  assert.deepEqual(names('var secret = this.req.secret;', FREE), []);
  assert.deepEqual(names('password = PasswordField(label=x)', FREE), []);
  assert.deepEqual(names("password = request.form['pw']", FREE), []);
  assert.deepEqual(names('password:\n  <input type=password>', FREE), []);
});

test('password: with a bare lowercase word is not flagged', () => {
  assert.deepEqual(names('password: please', FREE), []);
  assert.deepEqual(names('Password: hello world', FREE), []);
});

test('password: at the end of a sentence is not flagged', () => {
  assert.deepEqual(names('Your password: please.', FREE), []);
});

test('password: pointing at a code reference is not flagged', () => {
  assert.deepEqual(names('password: process.env.DBPASS', FREE), []);
});

test('password rule needs 6+ value characters', () => {
  assert.deepEqual(names('password=abc', FREE), []);
  assert.deepEqual(names('password: a1b2c', FREE), []);
});

/* ------------------------------------------------------------------ */
/* Randomness: entropy threshold and mixed classes                     */
/* ------------------------------------------------------------------ */
test('ENTROPY_MIN separates every true-positive fixture', () => {
  for (const name of ['AWS Secret Access Key', 'High-entropy token']) {
    for (const sample of POSITIVES[name]) {
      const re = name === 'AWS Secret Access Key'
        ? /\b(?![0-9a-fA-F]{40}\b)[A-Za-z0-9/+=]{40}\b/g
        : /\b[A-Za-z0-9+/=_-]{32,}\b/g;
      for (const m of sample.matchAll(re)) {
        assert.ok(shannon(m[0]) >= ENTROPY_MIN, name + ' ' + shannon(m[0]).toFixed(3));
      }
    }
  }
  assert.equal(ENTROPY_MIN, 4.5);
});

test('AWS-shaped token with low entropy is not reported', () => {
  assert.deepEqual(names(' ' + rep('aA1', 40) + ' ', FREE), []);
});

test('AWS-shaped token without mixed case is not reported', () => {
  const lower = rep('abcdefghijklmnopqrstuvwxyz' + DIGITS, 40);
  const upper = rep('ABCDEFGHIJKLMNOPQRSTUVWXYZ' + DIGITS, 40);
  assert.ok(!names(' ' + lower + ' ', FREE).includes('AWS Secret Access Key'));
  assert.ok(!names(' ' + upper + ' ', FREE).includes('AWS Secret Access Key'));
});

test('catch-all rejects flag-like tokens with low entropy', () => {
  assert.equal(isHighEntropyToken('args=--only=terraform_documented_variables'), false);
  assert.equal(isHighEntropyToken('FLASK_MYAPI__credentials__username=user123'), false);
  assert.equal(isHighEntropyToken(from(ALNUM, 40)), true);
});

/* ------------------------------------------------------------------ */
/* Overlapping matches: one row per secret                             */
/* ------------------------------------------------------------------ */
test('+39 number is reported once, as EU phone, not also as US phone', () => {
  assert.deepEqual(names('call ' + '+39 ' + '333 123 4567' + ' now', FULL), ['EU phone number']);
});

test('IPv4 loopback and unspecified addresses are not reported', () => {
  assert.deepEqual(names('bind ' + '127.0.0.1' + ' or ' + '0.0.0.0', FULL), []);
});

test('credit card made of one repeated digit is not reported', () => {
  assert.deepEqual(names(['0000', '0000', '0000', '0000'].join(' '), FULL), []);
});

test('.env rule ignores python keyword arguments', () => {
  const kwargs = 'app.config.update(\nSESSION_COOKIE_SECURE=True,\nSESSION_COOKIE_HTTPONLY=True,\nSESSION_COOKIE_SAMESITE=' + "'Lax'" + ',\n)';
  assert.ok(!names(kwargs, FREE).includes('.env file block'));
});

test('api_key: with an OpenAI key is reported once, as OpenAI', () => {
  assert.deepEqual(names('api_key: sk-' + from(ALNUM, 32), FREE), ['OpenAI API key']);
});

test('Bearer JWT is reported once, as JWT', () => {
  const jwt = 'eyJ' + from(ALNUM, 20) + '.eyJ' + from(ALNUM, 30) + '.' + from(ALNUM, 30);
  assert.deepEqual(names('Authorization: Bearer ' + jwt, FREE), ['JWT']);
});

test('secret = "..." is reported once, as Password assignment', () => {
  assert.deepEqual(names('secret = "' + from(ALNUM, 20) + '"', FREE), ['Password assignment']);
});

test('two distinct OpenAI keys produce two findings', () => {
  const a = 'sk-' + from(ALNUM, 32);
  const b = 'sk-' + from(ALNUM, 30) + 'Z';
  const found = scan(a + ' and ' + b, FREE).filter(f => f.name === 'OpenAI API key');
  assert.equal(found.length, 2);
  assert.deepEqual(found.map(f => f.raw).sort(), [a, b].sort());
});

test('the same secret twice is reported once', () => {
  const key = 'sk-' + from(ALNUM, 32);
  assert.equal(scan(key + ' ' + key, FREE).length, 1);
});

test('findings are capped at 20', () => {
  assert.equal(MAX_FINDINGS, 20);
  const text = Array.from({ length: 30 }, (_, i) => 'user' + i + '@example.org').join(' ');
  assert.equal(scan(text, FULL).length, 20);
});

test('scanning covers the full 1 MB budget in bounded windows', () => {
  assert.equal(MAX_SCAN_CHARS, 200000);
  assert.equal(MAX_SCAN_TOTAL, 1024 * 1024);
  const key = 'sk-' + from(ALNUM, 32);
  const late = rep('a ', MAX_SCAN_CHARS) + key;
  assert.deepEqual(names(late, FREE), ['OpenAI API key']);
  assert.deepEqual(names(key + ' ' + rep('a ', MAX_SCAN_CHARS), FREE), ['OpenAI API key']);
  assert.deepEqual(names(rep('a ', MAX_SCAN_TOTAL) + key, FREE), []);
});

test('redact keeps the tail of a long message and redacts past 200k', () => {
  const key = 'sk-' + from(ALNUM, 32);
  const head = rep('a ', 210000);
  const tail = 'TAIL-MARKER-DO-NOT-DROP';
  const text = head + key + ' ' + tail;
  const out = D.redact(text, FREE);
  assert.ok(out.text.startsWith(head), 'head must survive');
  assert.ok(out.text.endsWith(tail), 'tail must survive');
  assert.ok(!out.text.includes(key), 'the late secret must be redacted');
  assert.ok(out.text.includes('[API_KEY_1]'));
  assert.equal(out.text.length, text.length - key.length + '[API_KEY_1]'.length);
});

/* ------------------------------------------------------------------ */
/* Checksums and negative cases for the rules                          */
/* ------------------------------------------------------------------ */
test('IBAN with a bad mod-97 check is ignored', () => {
  assert.deepEqual(names(['GB82', 'WEST', '1234', '5698', '7654', '33'].join(' '), FULL), []);
});

test('codice fiscale with a bad check character is ignored', () => {
  assert.deepEqual(names('RSSMRA85T10' + 'A562A', FULL), []);
});

test('partita IVA with a bad checksum is ignored', () => {
  assert.ok(!names('P.IVA ' + '01234567890', FULL).includes('Italian partita IVA'));
});

test('partita IVA needs its keyword (bare 11 digits are not flagged as PIVA)', () => {
  assert.ok(!names('ref ' + '01234567897', FULL).includes('Italian partita IVA'));
});

test('credit card that fails Luhn is ignored', () => {
  assert.deepEqual(names(['4111', '1111', '1111', '1112'].join(' '), FULL), []);
});

test('connection string without credentials is ignored', () => {
  assert.deepEqual(names('postgres://localhost:5432/app', FREE), []);
  assert.deepEqual(names('mongodb+srv://cluster0.example.net/prod', FREE), []);
});

test('two lines of UPPER_CASE=value is not an env block', () => {
  assert.ok(!names('A=1\nB=2', FREE).includes('.env file block'));
});

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
test('luhn', () => {
  assert.equal(luhn(['4111', '1111', '1111', '1111'].join('')), true);
  assert.equal(luhn(['4111', '1111', '1111', '1112'].join('')), false);
});

test('isHighEntropyToken keeps hashes, UUIDs, paths and word slugs out', () => {
  assert.equal(isHighEntropyToken('9fceb02d0ae598e95dc970b74767f19372d61af8'), false);
  assert.equal(isHighEntropyToken('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), false);
  assert.equal(isHighEntropyToken('550e8400-e29b-41d4-a716-446655440000'), false);
  assert.equal(isHighEntropyToken('some/path/with/digits2026/file'), false);
  assert.equal(isHighEntropyToken('my-long-slug-with-words-only'), false);
});

test('module exposes the engine (Node export)', () => {
  assert.equal(typeof scan, 'function');
  assert.ok(Array.isArray(PATTERNS));
  const names = PATTERNS.map(p => p.name);
  assert.equal(new Set(names).size, names.length, 'pattern names must be unique');
});

test('isTextLikeFile accepts the 14 text extensions up to 1 MB and rejects binaries/oversized', () => {
  assert.equal(MAX_FILE_BYTES, 1024 * 1024);
  const allowed = ['txt', 'md', 'json', 'env', 'csv', 'log', 'yml', 'yaml', 'toml', 'ini', 'js', 'ts', 'py', 'sh'];
  for (const ext of allowed) {
    assert.equal(isTextLikeFile({ name: 'sample.' + ext, size: 120 }), true, ext);
    assert.equal(isTextLikeFile({ name: 'SAMPLE.' + ext.toUpperCase(), size: MAX_FILE_BYTES }), true, ext);
  }
  assert.equal(isTextLikeFile({ name: '.env', size: 64 }), true);
  assert.equal(isTextLikeFile({ name: '.env.local', size: 64 }), true);
  assert.equal(isTextLikeFile({ name: 'sample.txt', size: 0 }), false);
  assert.equal(isTextLikeFile({ name: 'sample.txt', size: MAX_FILE_BYTES + 1 }), false);
  for (const bin of ['image.png', 'photo.jpg', 'archive.zip', 'doc.pdf', 'app.exe', 'movie.mp4']) {
    assert.equal(isTextLikeFile({ name: bin, size: 512 }), false, bin);
  }
});

/* ------------------------------------------------------------------ */
/* Benign corpus: zero findings, even with every category enabled      */
/* ------------------------------------------------------------------ */
const corpusPath = path.join(__dirname, 'fixtures', 'benign-corpus.txt');
const corpus = fs.readFileSync(corpusPath, 'utf8');

test('benign corpus: every line produces zero findings', () => {
  for (const line of corpus.split('\n')) {
    if (!line.trim()) continue;
    assert.deepEqual(scan(line, FULL), [], 'false positive on: ' + line);
  }
});

test('benign corpus: whole file produces zero findings', () => {
  assert.deepEqual(scan(corpus, FULL), []);
});

/* ------------------------------------------------------------------ */
/* Performance: adversarial inputs must stay fast                      */
/* ------------------------------------------------------------------ */
test('100k-char adversarial inputs scan in under 250 ms', () => {
  const shapes = {
    'one long digit run': '1'.repeat(100000),
    'digit groups with spaces': rep('1234567890123 ', 100000),
    'digit groups with dashes': rep('12-34-56-78-90-12-34-5', 100000),
    'digits separated by letters': rep('1x2y3z4w5v6u7t8s9r0q', 100000),
    'local-part run with @ signs': rep('a1.b-2_c+3@', 100000),
    'domain-like run after @': '@' + rep('0-0.0-', 99999),
  };
  scan('warm up 1234 5678', FULL);
  for (const [label, text] of Object.entries(shapes)) {
    assert.equal(text.length, 100000);
    const t0 = performance.now();
    scan(text, FULL);
    const ms = performance.now() - t0;
    assert.ok(ms < 250, label + ' took ' + ms.toFixed(1) + ' ms');
  }
});

test('1 MB adversarial input stays bounded', () => {
  const text = rep('1x2y3z4w5v6u7t8s9r0q', 1024 * 1024);
  scan('warm up 1234 5678', FULL);
  const t0 = performance.now();
  scan(text, FULL);
  const ms = performance.now() - t0;
  assert.ok(ms < 5000, '1 MB adversarial scan took ' + ms.toFixed(1) + ' ms');
});

/* ------------------------------------------------------------------ */
/* Capability gating: Pro license or team/managed install              */
/* ------------------------------------------------------------------ */
const PII_PATTERN = PATTERNS.find(p => p.name === 'Email address');
const NET_PATTERN = PATTERNS.find(p => p.name === 'IPv4 address');

test('personal free plan cannot enable PII or network detection', () => {
  const wants = { enabled: true, categories: { apiKeys: true, pii: true, network: true }, isPro: false };
  assert.equal(categoryAllowed(PII_PATTERN, wants), false);
  assert.equal(categoryAllowed(NET_PATTERN, wants), false);
  assert.equal(D.customPatternsAllowed(wants), false);
});

test('a typed org ID alone never unlocks Pro capabilities', () => {
  const spoofed = { enabled: true, categories: { apiKeys: true, pii: true, network: true }, isPro: false, teamMode: true, orgId: 'org_abc12345' };
  assert.equal(categoryAllowed(PII_PATTERN, spoofed), false);
  assert.equal(categoryAllowed(NET_PATTERN, spoofed), false);
  assert.equal(D.customPatternsAllowed(spoofed), false);
});

test('a managed install without a paid org gets free capabilities only', () => {
  const managed = { enabled: true, categories: { apiKeys: true, pii: true, network: true }, isPro: false, managedMode: true };
  assert.equal(categoryAllowed(PII_PATTERN, managed), false);
  assert.equal(categoryAllowed(NET_PATTERN, managed), false);
  assert.equal(D.customPatternsAllowed(managed), false);
  assert.equal(categoryAllowed(PATTERNS.find(p => p.name === 'OpenAI API key'), managed), true);
});

test('a locally set policy or installType never unlocks Pro', () => {
  const policyOnly = {
    enabled: true,
    categories: { apiKeys: true, pii: true, network: true },
    isPro: false,
    managedMode: true,
    teamMode: true,
    orgId: 'org_abc12345',
  };
  assert.equal(categoryAllowed(PII_PATTERN, policyOnly), false);
  assert.equal(categoryAllowed(NET_PATTERN, policyOnly), false);
  assert.equal(D.customPatternsAllowed(policyOnly), false);
});

test('a server-confirmed paid entitlement unlocks Pro capabilities', () => {
  const entitled = { enabled: true, categories: { apiKeys: true, pii: true, network: true }, isPro: false, entitled: true };
  assert.equal(categoryAllowed(PII_PATTERN, entitled), true);
  assert.equal(categoryAllowed(NET_PATTERN, entitled), true);
  assert.equal(D.customPatternsAllowed(entitled), true);
});

test('category switches still decide what runs for entitled installs', () => {
  const piiOff = { enabled: true, categories: { apiKeys: true, pii: false, network: false }, isPro: false, entitled: true };
  assert.equal(categoryAllowed(PII_PATTERN, piiOff), false);
  assert.equal(categoryAllowed(NET_PATTERN, piiOff), false);
});

/* ------------------------------------------------------------------ */
/* Regression: case-mangled keys must still be caught                  */
/* ------------------------------------------------------------------ */
const CASE_SAMPLES = {
  'OpenAI API key': ('sk-' + from(ALNUM, 32)).toLowerCase(),
  'Anthropic API key': ('sk-ant-api03-' + from(ALNUM, 40)).toLowerCase(),
  'AWS Access Key ID': ('akia' + from(ALNUM, 16)).toLowerCase(),
  'GitHub token': ('ghp_' + from(ALNUM, 36)).toLowerCase(),
  'Stripe secret key': ('sk_live_' + from(ALNUM, 24)).toLowerCase(),
  'Stripe restricted key': ('rk_live_' + from(ALNUM, 24)).toLowerCase(),
  'Google API key': ('AIza' + from(ALNUM, 35)).toLowerCase(),
  'Slack token': ('xoxb-' + from(DIGITS, 10) + '-' + from(ALNUM, 12)).toLowerCase(),
  'Slack webhook URL': ('https://hooks.slack.com/services/TA1B2C3D4/BE5F6G7H8/' + from(ALNUM, 24)).toLowerCase(),
  'Discord webhook URL': ('https://discord.com/api/webhooks/' + from(DIGITS, 18) + '/' + from(ALNUM, 68)).toLowerCase(),
  'Hugging Face token': ('hf_' + from(ALNUM, 34)).toLowerCase(),
  'Groq API key': ('gsk_' + from(ALNUM, 52)).toLowerCase(),
  'npm token': ('npm_' + from(ALNUM, 36)).toLowerCase(),
  'GitLab token': ('glpat-' + from(ALNUM, 20)).toLowerCase(),
  'SendGrid API key': ('SG.' + from(ALNUM, 22) + '.' + from(ALNUM, 43)).toLowerCase(),
  'Twilio API key': 'sk' + rep('a1b2c3d4e5f6', 32),
  'Private key (PEM)': '-----begin rsa private key-----',
  'Bearer token': ('bearer ' + from(ALNUM, 24)).toLowerCase(),
};

test('regression: hand-typed lowercase variants are caught', () => {
  // Dario typed "akiaiosfodnn7example" into ChatGPT (2026-10-29) and it
  // passed through while the uppercase form was caught.
  assert.ok(names('akiaiosfodnn7example', FREE).includes('AWS Access Key ID'),
    'the exact lowercase AWS example must be caught');
  for (const [pattern, sample] of Object.entries(CASE_SAMPLES)) {
    assert.ok(names(sample, FREE).includes(pattern),
      'missed lowercase variant of ' + pattern + ': ' + JSON.stringify(sample.slice(0, 40)));
  }
});

test('PII placeholders keep their own type, never an IP placeholder', () => {
  const mixed = D.redact('cf CSTDRA91R11F839X ip 182.128.255.255 mail a@b.co', FULL);
  assert.match(mixed.text, /cf \[CODICE_FISCALE_1\]/, 'codice fiscale must sit at its own position with its own type');
  assert.match(mixed.text, /ip \[IP_1\]/);
  assert.match(mixed.text, /mail \[EMAIL_1\]/);
  assert.ok(!mixed.text.includes('CSTDRA91R11F839X'), 'the CF must be replaced');
  const alone = D.redact('CSTDRA91R11F839X', FULL);
  assert.equal(alone.text, '[CODICE_FISCALE_1]');
});

/* ------------------------------------------------------------------ */
/* Published test vectors: cross-validate the checksum implementations */
/* against real-world examples, not generator output                   */
/* ------------------------------------------------------------------ */
test('national ID checksums accept published test vectors', () => {
  const vectors = [
    ['Brazilian CPF', '529.982.247-25'],
    ['Chinese resident ID', '11010519491231002X'],
    ['Canadian SIN / Australian TFN', '046-454-286'],
    ['Canadian SIN / Australian TFN', '123 456 782'],
    ['Spanish NIF/NIE', '12345678Z'],
    ['Spanish NIF/NIE', 'X1234567L'],
    ['Turkish ID number', '10000000146'],
    ['South African ID number', '8001015009087'],
    ['Polish PESEL', '44051401458'],
    ['Mexican CURP', 'SABC560626MDFLRN09'],
    ['Mexican CURP', 'RACW050729MMCSHNA2'],
    ['Mexican RFC', 'GODE561231GR8'],
    ['Singapore NRIC / FIN', 'S0000001I'],
    ['Singapore NRIC / FIN', 'F8179599K'],
    ['NZ IRD number', '049091850'],
    ['NZ IRD number', '049091808'],
  ];
  for (const [want, sample] of vectors) {
    assert.ok(names(sample, FULL).includes(want), want + ' missed for ' + sample);
  }
});

test('previews never hand the secret to the page DOM', () => {
  // The preview is written into #sg-overlay, which any script on the site can
  // read. previewOf used to return the whole value for anything up to 24
  // characters, so a US SSN, a card number or a codice fiscale was printed
  // in full to the very site the user was declining to send it to.
  for (const s of ['123-45-6789', '4111111111111111', 'RSSMRA85M12F205X', 'Tr0ub4dor']) {
    const p = D.previewOf(s);
    assert.ok(!p.includes(s), `full value printed for ${s}: ${p}`);
    for (let i = 0; i + 3 <= s.length; i++) {
      assert.ok(
        !p.includes(s.slice(i, i + 3)),
        `fragment ${JSON.stringify(s.slice(i, i + 3))} of ${s} leaked as ${JSON.stringify(p)}`
      );
    }
  }
});

test('a long key keeps two characters at each end and nothing more', () => {
  const key = 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789';
  const p = D.previewOf(key);
  assert.equal(p, 'sk…89');
  assert.equal(p.replace(/[^A-Za-z0-9]/g, '').length, 4, 'at most four characters survive');
});

test('previewOf on empty input returns nothing', () => {
  assert.equal(D.previewOf(''), '');
  assert.equal(D.previewOf(undefined), '');
});

const PII_OPTS = {
  enabled: true,
  categories: { apiKeys: true, pii: true, network: true },
  isPro: true, entitled: true, customPatterns: [],
};
const foundNames = (s) => D.scan(s, PII_OPTS).map((f) => f.name);

test('Irish PPS: the check letter is the one verified, and the second letter is not always weighted', () => {
  // Vectors from stdnum.ie.pps. The old code put weight 9 on the check letter
  // and ignored the second letter, so every verdict was inverted.
  for (const good of ['6433435F', '6433435FT', '6433435FW', '6433435OA', '6433435IH']) {
    assert.equal(D.checksums.pps(good), true, good + ' must be accepted');
  }
  assert.equal(D.checksums.pps('6433435G'), false, 'a wrong check letter must be rejected');
  assert.equal(D.checksums.pps('1234567A'), false, '1234567 checks to T, not A');
  assert.equal(D.checksums.pps('6433435FZ'), false, 'Z is not a valid second letter');
});

test('JSON config: a quoted key still reaches the keyword rules', () => {
  // JSON puts a quote between the key and the colon. Both rules needed
  // `keyword[ \t]*[:=]`, so pasting a JSON config leaked passwords silently.
  for (const line of ['{"password": "Tr0ub4dor"}', '{"token": "abcdefghijklmnop"}', '{"secret": "s3cret-value-here"}']) {
    assert.ok(foundNames(line).length > 0, 'nothing matched for ' + line);
  }
  assert.ok(foundNames('{"password": "Tr0ub4dor"}').some(n => /password/i.test(n)));
});

test('hand-typed lowercase PII is caught too', () => {
  // The validators already normalise case, but the gates were case strict, so
  // a hand-typed lowercase codice fiscale, IBAN or NIF produced no warning.
  const cases = [
    ['cstdra91r11f839x', 'Italian codice fiscale'],
    ['de89370400440532013000', 'IBAN'],
    ['12345678z', 'Spanish NIF/NIE'],
    ['abcde1234f', 'Indian PAN card'],
  ];
  for (const [sample, want] of cases) {
    assert.ok(foundNames(sample).includes(want), want + ' missed for ' + sample);
  }
});

test('a 40-char secret whose edges are + or / is still matched', () => {
  // The rule was anchored with \b, and \b sits between a word character and a
  // non-word one. + and / are both non-word, so a key opening or closing with
  // either could never satisfy the boundary and matched nothing at all.
  const awsRule = D.PATTERNS.find(p => p.name === 'AWS Secret Access Key');
  assert.ok(awsRule, 'the AWS rule must exist');
  const run = (s) => new RegExp(awsRule.re.source, awsRule.re.flags).test(s);
  const mk = (prefix, suffix) => {
    const need = 40 - prefix.length - suffix.length;
    const FILL = 'aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zAb'.repeat(2);
    return prefix + FILL.slice(0, need) + suffix;
  };
  for (const [prefix, suffix] of [['+', '/'], ['/', '+'], ['', ''], ['+', '+'], ['/', '/']]) {
    const s = mk(prefix, suffix);
    assert.equal(s.length, 40, 'fixture must be exactly 40 characters: ' + s);
    assert.ok(run(s), 'not matched: ' + s);
  }
  // A plain hex run is still excluded: those are git SHAs and hashes.
  assert.equal(run('a'.repeat(40)), false);
});

test('isHighEntropyToken keeps base64 that happens to contain a slash', () => {
  // The old guard rejected every token with a / in it, which threw away
  // standard-alphabet base64 secrets along with the URLs.
  assert.equal(D.isHighEntropyToken('aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5/zAb'), true);
  assert.equal(D.isHighEntropyToken('https://example.com/very/long/path/here'), false);
  assert.equal(D.isHighEntropyToken('docs/readme.md'), false);
  assert.equal(D.isHighEntropyToken('aaa/bbb/ccc/ddd/eee'), false);
});

test('custom patterns with nested quantifiers are refused, not run', () => {
  // (a+)+$ against forty characters did not finish in fifteen seconds. Team
  // policy can push one pattern to every seat, so the shape is refused at
  // compile time rather than survived at match time.
  const opts = { ...PII_OPTS, customPatterns: ['(a+)+$'] };
  const started = Date.now();
  const out = D.scan('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', opts);
  assert.ok(Date.now() - started < 2000, 'a catastrophic pattern must not be run');
  assert.equal(out.filter(f => f.name === 'Custom pattern').length, 0);
});

test('a well formed custom pattern still matches', () => {
  const opts = { ...PII_OPTS, customPatterns: ['corp-[0-9]{4}-[a-f]{8}'] };
  assert.ok(D.scan('token corp-1234-deadbeef end', opts).some(f => f.name === 'Custom pattern'));
  const bad = { ...PII_OPTS, customPatterns: ['([unclosed'] };
  assert.equal(D.scan('anything at all', bad).filter(f => f.name === 'Custom pattern').length, 0);
});

test('placeholder numbers never alert as identity documents', () => {
  // A weighted sum of zeros is zero, so all-zero padding sailed through most
  // of the checksums and fired high-severity identity warnings on fixtures.
  for (const s of ['0000000000000', '000000-0000', '000-000-000', '00000000000', '000000000000', '00-00000000-0', '000000-00000']) {
    assert.equal(foundNames(s).length, 0, 'placeholder alerted as PII: ' + s);
  }
});

test('US SSN rejects the numbers that are never issued', () => {
  assert.ok(foundNames('123-45-6789').includes('US SSN'));
  for (const bad of ['000-00-0000', '666-12-3456', '999-99-9999', '123-00-6789', '123-45-0000']) {
    assert.ok(!foundNames(bad).includes('US SSN'), 'never-issued SSN alerted: ' + bad);
  }
});

test('Swedish personnummer reaches its twelve digit form', () => {
  // validPersonnummer has always handled twelve digits, but the pattern only
  // ever delivered ten, so that branch was dead and YYYYMMDDNNNN from a data
  // export was never matched at all.
  const pn = D.PATTERNS.find(p => p.name === 'Swedish personnummer');
  assert.ok(pn.re.test('19850101-1234'), 'the 12-digit form must reach the pattern');
  assert.ok(pn.re.test('850101-1234'), 'the 10-digit form still reaches it');
});

test('luhn and the Dutch BSN do not reject on a zero checksum', () => {
  assert.equal(D.luhn(''), false, 'an empty string is not a valid card');
  // 000000012 has a weighted sum of exactly zero and is a genuine BSN.
  assert.equal(D.checksums.bsn('000000012'), true);
  assert.equal(D.checksums.bsn('00000000'), false, 'all-zero is still a placeholder');
});
