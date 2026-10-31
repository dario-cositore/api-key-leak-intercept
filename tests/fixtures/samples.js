'use strict';

// True-positive samples, one array per pattern name. Fake secrets are
// assembled at runtime from short alphabets, so no secret-shaped literal sits
// in the repo (GitHub push protection stays quiet).

const ALNUM = 'k7Qp2Zx9Lm4Rw8TvHc3Ye6Ns1Ub5Jd0Gf';
const UPPER_DIGITS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const HEX_UPPER = '0123456789ABCDEF';
const HEX_LOWER = '0123456789abcdef';
const DIGITS = '0123456789';

// Deterministic filler. The stride is coprime with every alphabet above.
function from(alphabet, n) {
  let s = '';
  for (let i = 0; i < n; i++) s += alphabet[(i * 7) % alphabet.length];
  return s;
}
const rep = (chunk, n) => chunk.repeat(Math.ceil(n / chunk.length)).slice(0, n);

const POSITIVES = {
  'OpenAI API key': [
    'sk-' + from(ALNUM, 32),
    'sk-proj-' + from(ALNUM, 40),
    'my key is sk-' + from(ALNUM, 24),
  ],
  'Anthropic API key': [
    'sk-ant-api03-' + from(ALNUM, 40),
    'sk-ant-' + from(ALNUM, 30),
    'export KEY=sk-ant-' + from(ALNUM, 26),
  ],
  'AWS Access Key ID': [
    'AKIA' + from(UPPER_DIGITS, 16),
    'id AKIA' + from(UPPER_DIGITS, 16) + ' end',
    'AKIA' + from(UPPER_DIGITS, 16) + '\n',
  ],
  'AWS Secret Access Key': [
    ' ' + from(ALNUM, 40) + ' ',
    'value ' + from(ALNUM, 40) + ' here',
    '\n' + from(ALNUM, 40) + '\n',
  ],
  'GitHub token': [
    'ghp_' + from(ALNUM, 36),
    'gho_' + from(ALNUM, 40),
    'ghs_' + from(ALNUM, 36),
  ],
  'Stripe secret key': [
    'sk_live_' + from(ALNUM, 24),
    'sk_test_' + from(ALNUM, 30),
    'charge with sk_live_' + from(ALNUM, 32),
  ],
  'Stripe restricted key': [
    'rk_live_' + from(ALNUM, 24),
    'rk_test_' + from(ALNUM, 30),
    'use rk_live_' + from(ALNUM, 28),
  ],
  'Google API key': [
    'AIza' + from(ALNUM, 35),
    'key=AIza' + from(ALNUM, 35),
    'AIza' + from(ALNUM, 35) + ' is ours',
  ],
  'Slack token': [
    'xoxb-' + from(DIGITS, 10) + '-' + from(ALNUM, 12),
    'xoxp-' + from(DIGITS, 10) + '-' + from(ALNUM, 14),
    'xoxa-' + from(DIGITS, 12) + '-' + from(ALNUM, 16),
  ],
  'Slack webhook URL': [
    'https://hooks.slack.com/services/T' + 'A1B2C3D4' + '/B' + 'E5F6G7H8' + '/' + from(ALNUM, 24),
    'post to https://hooks.slack.com/services/T' + 'Q9W8E7R6' + '/B' + 'T5Y4U3I2' + '/' + from(ALNUM, 24),
    'https://hooks.slack.com/services/TZ1X2C3V4/BM5N6B7V8/' + from(ALNUM, 24),
  ],
  'Discord webhook URL': [
    'https://discord.com/api/webhooks/' + from(DIGITS, 18) + '/' + from(ALNUM, 68),
    'https://discordapp.com/api/webhooks/' + from(DIGITS, 18) + '/' + from(ALNUM, 30),
    'https://ptb.discord.com/api/v10/webhooks/' + from(DIGITS, 19) + '/' + from(ALNUM, 40),
  ],
  'Telegram bot token': [
    from(DIGITS, 9) + ':' + from(ALNUM, 35),
    from(DIGITS, 10) + ':' + from(ALNUM, 35),
    'bot ' + from(DIGITS, 8) + ':' + from(ALNUM, 35) + ' ok',
  ],
  'Hugging Face token': [
    'hf_' + from(ALNUM, 34),
    'hf_' + from(ALNUM, 30),
    'HF_TOKEN hf_' + from(ALNUM, 36),
  ],
  'Groq API key': [
    'gsk_' + from(ALNUM, 52),
    'gsk_' + from(ALNUM, 40),
    'groq gsk_' + from(ALNUM, 48),
  ],
  'npm token': [
    'npm_' + from(ALNUM, 36),
    '//registry.npmjs.org/:_authToken=npm_' + from(ALNUM, 36),
    'npm_' + from(ALNUM, 36) + ' publish',
  ],
  'GitLab token': [
    'glpat-' + from(ALNUM, 20),
    'glpat-' + from(ALNUM, 26),
    'token glpat-' + from(ALNUM, 30),
  ],
  'SendGrid API key': [
    'SG.' + from(ALNUM, 22) + '.' + from(ALNUM, 43),
    'SG.' + from(ALNUM, 22) + '.' + from(ALNUM, 43) + ' end',
    'send with SG.' + from(ALNUM, 22) + '.' + from(ALNUM, 43),
  ],
  'Twilio API key': [
    'SK' + from(HEX_UPPER, 32),
    'SK' + from(HEX_LOWER, 32),
    'sid SK' + from(HEX_UPPER, 32) + ' end',
  ],
  'JWT': [
    'eyJ' + from(ALNUM, 20) + '.eyJ' + from(ALNUM, 30) + '.' + from(ALNUM, 30),
    'Token eyJ' + from(ALNUM, 24) + '.eyJ' + from(ALNUM, 24) + '.' + from(ALNUM, 24),
    'eyJ' + from(ALNUM, 16) + '.eyJ' + from(ALNUM, 16) + '.' + from(ALNUM, 16) + ' done',
  ],
  'Private key (PEM)': [
    '-----BEGIN ' + 'RSA ' + 'PRIVATE KEY-----',
    '-----BEGIN ' + 'OPENSSH ' + 'PRIVATE KEY-----',
    '-----BEGIN ' + 'PRIVATE KEY-----',
  ],
  'Bearer token': [
    'Authorization: Bearer ' + from(ALNUM, 32),
    'Bearer ' + from(ALNUM, 24),
    'curl -H "Bearer ' + from(ALNUM, 40) + '"',
  ],
  'Database connection string': [
    'postgres://app_user:' + from(ALNUM, 12) + '@db.internal.example:5432/app',
    'postgresql://admin:' + from(ALNUM, 14) + '@pg.example.net/prod',
    'mysql://root:' + from(ALNUM, 10) + '@10.example.local/shop',
    'mongodb+srv://svc:' + from(ALNUM, 12) + '@cluster0.example.net/prod',
    'redis://:' + from(ALNUM, 12) + '@cache.example:6379',
    'amqp://guest:' + from(ALNUM, 12) + '@mq.example:5672',
  ],
  '.env file block': [
    'DB_HOST=db.internal\nDB_USER=app_user\nDB_PASS=' + from(ALNUM, 12),
    'APP_ENV=production\nPORT=8080\nLOG_LEVEL=info',
    'A=1\r\nB=2\r\nC=' + from(ALNUM, 8),
  ],
  'Password assignment': [
    'password=' + 'Tr0ub4dor',
    'pwd: ' + 'hunter22',
    'passwd="' + 'Vx9qLm2w' + '"',
  ],
  'Generic secret assignment': [
    'api_key: ' + from(ALNUM, 20),
    'token=' + from(ALNUM, 20),
    'api-key = "' + from(ALNUM, 20) + '"',
  ],
  'High-entropy token': [
    'value ' + from(ALNUM, 46) + ' end',
    'see ' + from(ALNUM, 32) + ' now',
    'blob: ' + from(ALNUM, 64),
  ],
  // --- PII (Pro) ---
  'Email address': [
    'contact anna.rossi@example.org today',
    'name@company.co.uk',
    'j.doe+billing@mail.example.com',
  ],
  'US SSN': [
    ['512', '38', '9047'].join('-'),
    ['604', '21', '7733'].join('-'),
    'ssn ' + ['317', '55', '2086'].join('-'),
  ],
  'Credit card number': [
    ['4111', '1111', '1111', '1111'].join(' '),
    ['5555', '5555', '5555', '4444'].join(''),
    ['3782', '822463', '10005'].join(''),
  ],
  'US phone number': [
    '(415) 555-' + '2671',
    '+1 415-555-2671',
    '415.555.2671',
  ],
  'EU phone number': [
    '+39 ' + '333 123 4567',
    '+44 20 7946 0958',
    '+49 30 ' + '901820',
    '+33 1 42 68 53 00',
    '+34 91 123 45 67',
  ],
  'IBAN': [
    ['GB82', 'WEST', '1234', '5698', '7654', '32'].join(' '),
    ['DE89', '3704', '0044', '0532', '0130', '00'].join(' '),
    ['IT60', 'X054', '2811', '1010', '0000', '0123', '456'].join(' '),
  ],
  'Italian codice fiscale': [
    'RSSMRA85T10' + 'A562S',
    'MRTLCU80A01' + 'F205Y',
    'CF: BNCLRA70B41' + 'H501A',
  ],
  'Italian partita IVA': [
    'P.IVA ' + '01234567897',
    'partita IVA: IT' + '01234567897',
    'VAT ' + '00743110157',
  ],
  // --- Network (Pro) ---
  'IPv4 address': [
    ['10', '0', '0', '12'].join('.'),
    '192.168.' + '1.10',
    'host 203.0.113.' + '45 up',
  ],
};

/* --- national identity numbers: check digits are brute-forced through the
   real validators, so fixtures cannot drift from the detection logic --- */
const C = require('../../extension/detect.js').checksums;

function withCheck(base, build, valid, attempts) {
  // some bases have no valid check digit at all; nudge the last base digit
  for (let round = 0; round < 10; round++) {
    const b = round === 0 ? base : base.slice(0, -1) + String(round - 1);
    for (let i = 0; i < (attempts || 100); i++) {
      const s = build(b, i);
      if (valid(s)) return s;
    }
  }
  throw new Error('cannot build a valid sample from ' + base);
}
const digit = (base, i) => base + String(i);
const twoDigits = (base, i) => base + String(i).padStart(2, '0');
const letters = (base, i) => base + String.fromCharCode(65 + i);

Object.assign(POSITIVES, {
  'Indian Aadhaar number': [
    ...[2, 5, 8].map(seed => {
      const full = withCheck(String(seed) + from(DIGITS, 10), digit, C.verhoeff);
      return full.slice(0, 4) + ' ' + full.slice(4, 8) + ' ' + full.slice(8);
    }),
  ],
  'Chinese resident ID': [
    ...[['110105', '19850311', '021'], ['310101', '20011222', '043'], ['440305', '19790715', '187']].map(([region, birth, ord]) =>
      withCheck(region + birth + ord, (b, i) => b + (i < 10 ? String(i) : 'X'), C.cnId, 11)),
  ],
  'Brazilian CPF': [
    ...['529982247', '111444777', '123456789'].map(b => {
      const full = withCheck(b, twoDigits, C.cpf);
      return full.slice(0, 3) + '.' + full.slice(3, 6) + '.' + full.slice(6, 9) + '-' + full.slice(9);
    }),
  ],
  'Canadian SIN / Australian TFN': [
    ...['04645428', '12345678', '98765432'].map(b => withCheck(b, digit, (s) => C.luhn(s) || C.tfn(s))),
  ],
  'German tax ID (Steuer-ID)': [
    ...['269543718', '123456782', '845729316'].map(b => withCheck('7' + b, digit, C.steuerId)),
  ],
  'German VAT ID': [
    ...['12345678', '98765432', '44556677'].map(b => withCheck('DE' + b, digit, C.ustId)),
  ],
  'French NIR (social security)': [
    ...[['1', '85', '05', '75', '006', '082'], ['2', '90', '11', '13', '204', '115'], ['1', '78', '07', '69', '331', '044']].map(
      ([sex, year, month, dept, comm, ord]) => {
        const base = sex + year + month + dept + comm + ord;
        const full = withCheck(base, twoDigits, C.nir);
        return [sex, year, month, dept, comm, ord, full.slice(13)].join(' ');
      }),
  ],
  'Spanish NIF/NIE': [
    ...['12345678', '87654321', '22223333'].map(b => withCheck(b, letters, C.nifEs, 26)),
    ...['X1234567', 'Y7654321'].map(b => withCheck(b, letters, C.nifEs, 26)),
  ],
  'Argentine CUIL': [
    ...['2012345678', '2723456789', '301112223'].map(b =>
      withCheck(b, digit, C.cuil).replace(/^(.{2})(.{8})(.)$/, '$1-$2-$3')),
  ],
  'Chilean RUT': [
    ...[['12', '345678'], ['7', '654321'], ['11', '222333']].map(([head, body]) => {
      const full = withCheck(head + body, (b, i) => b + (i < 10 ? String(i) : 'K'), C.rut, 11);
      return head + '.' + full.slice(head.length, head.length + 3) + '.' + full.slice(head.length + 3, -1) + '-' + full.slice(-1);
    }),
  ],
  'South African ID number': [
    ...['800101500908', '991231987654', '750228543211'].map(b => withCheck(b, digit, C.luhn)),
  ],
  'Russian SNILS': [
    ...['112233445', '987654321', '555444333'].map(b => {
      const full = withCheck(b, twoDigits, C.snils);
      return full.slice(0, 3) + '-' + full.slice(3, 6) + '-' + full.slice(6, 9) + ' ' + full.slice(9);
    }),
  ],
  'Turkish ID number': [
    ...['100000001', '234567895', '887766554'].map(b => withCheck(b, twoDigits, C.kimlik)),
  ],
  'South Korean resident number': [
    ...['9001011', '8512312', '0207154'].map(b => {
      const full = withCheck(b + from(DIGITS, 5), digit, C.rrn);
      return full.slice(0, 6) + '-' + full.slice(6);
    }),
  ],
  'Japanese My Number': [
    ...['12345678901', '98765432109', '55554444333'].map(b => withCheck(b, digit, C.myNumber)),
  ],
  'Dutch BSN': [
    ...['11122233', '98765432', '24681355'].map(b => withCheck(b, digit, C.bsn)),
  ],
  'Polish PESEL': [
    ...['4405140138', '9901011234', '8506072222'].map(b => withCheck(b, digit, C.pesel)),
  ],
  'Swedish personnummer': [
    ...['850522383', '991231123', '740315444'].map(b => {
      const full = withCheck(b, digit, (s) => C.personnummer(s));
      return full.slice(0, 6) + '-' + full.slice(6);
    }),
  ],
  'Danish CPR number': [
    ...['050575123', '010190987', '311285555'].map(b => {
      const full = withCheck(b, digit, C.cpr);
      return full.slice(0, 6) + '-' + full.slice(6);
    }),
  ],
  'Norwegian fødselsnummer': [
    ...['150311399', '010203111', '311299222'].map(b => {
      const full = withCheck(b, twoDigits, C.fodselsnummer);
      return full.slice(0, 6) + '-' + full.slice(6);
    }),
  ],
  'Finnish hetu': [
    ...['131052-308', '290115-111', '771125-222'].map(b => {
      for (const ch of '0123456789ABCDEFHJKLMNPRSTUVWXY') {
        if (C.hetu(b + ch)) return b + ch;
      }
      throw new Error('cannot build a valid hetu from ' + b);
    }),
  ],
  'Irish PPS number': [
    ...['1234567', '7654321', '2468135'].map(b => withCheck(b, letters, C.pps, 23)),
  ],
  'Portuguese NIF': [
    ...['12345678', '87654321', '33344455'].map(b => withCheck(b, digit, C.nifPt)),
  ],
  'UK National Insurance number': [
    'SA' + from(DIGITS, 6) + 'A',
    'JH' + from(DIGITS, 6) + 'B',
    'PT' + from(DIGITS, 6) + 'C',
  ],
  'Indian PAN card': [
    'AAAPL' + from(DIGITS, 4) + 'C',
    'BXZPR' + from(DIGITS, 4) + 'F',
    'QWMNB' + from(DIGITS, 4) + 'K',
  ],
  'Mexican CURP': [
    ...['XAXX000101HDFXXX0', 'LOPM850312MDFNTR5', 'GARC900215HNLGRL8'].map(b => withCheck(b, digit, C.curp)),
  ],
  'Mexican RFC': [
    ...['XAXX000101XX', 'LOPM850312NQ', 'GARC900215KT'].map(b => withCheck(b, (b2, i) => b2 + (i < 10 ? String(i) : 'A'), C.rfc, 11)),
    ...['ABC680524XX', 'HOL850312PZ'].map(b => withCheck(b, (b2, i) => b2 + (i < 10 ? String(i) : 'A'), C.rfc, 11)),
  ],
  'Singapore NRIC / FIN': [
    ...['S1234567', 'T7654321', 'F2468135', 'G1357924'].map(b => withCheck(b, (b2, i) => b2 + String.fromCharCode(65 + i), C.nric, 26)),
  ],
  'NZ IRD number': [
    ...['04909185', '08206319', '5512345'].map(b => withCheck(b, digit, C.ird)),
  ],
  'Indonesian NIK': [
    ...['327301170890000', '317102570890000', '327301010185000'].map(b => withCheck(b, digit, C.nik)),
  ],
});

module.exports = { ALNUM, UPPER_DIGITS, HEX_UPPER, HEX_LOWER, DIGITS, from, rep, POSITIVES };
