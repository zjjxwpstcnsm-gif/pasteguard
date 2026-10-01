import assert from 'node:assert/strict';
import test from 'node:test';
import { RULES, sanitize } from '../dist/engine/index.js';

const defaults = RULES.filter((rule) => rule.enabledByDefault).map((rule) => rule.id);

test('scans across removed controls in assignment keys and secret values', () => {
  const input = 'pa\u200bssword=al\u001b[31mpha\u001b[0mbravo\npassword=alphabravo';
  const result = sanitize(input);

  assert.equal(result.text, 'password=<SECRET_1>\npassword=<SECRET_1>');
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'secret-assignment').length, 2);
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'zero-width').length, 1);
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'ansi-sequence').length, 0);
});

test('redacts email and access tokens assembled by hygiene removal', () => {
  const input = [
    'al\u200bice@exam\u202eple.test',
    'ghp_abcdefghijkl\u2060mnopqrstuv123456',
    'ghp_abcdefghijklmnopqrstuvwxyz123456',
  ].join('\n');
  const result = sanitize(input);

  assert.equal(result.text, '<EMAIL_1>\n<ACCESS_TOKEN_1>\n<ACCESS_TOKEN_2>');
  assert.equal(result.findings.filter((finding) => finding.category === 'hygiene').length, 0);
});

test('reuses canonical placeholders for clean and hidden-character variants', () => {
  const input = 'alice@example.test al\u200bice@example.test\n' +
    'ghp_abcdefghijklmnopqrstuv123456 ghp_abcdefghijkl\u2060mnopqrstuv123456';
  const result = sanitize(input);

  assert.equal(result.text, '<EMAIL_1> <EMAIL_1>\n<ACCESS_TOKEN_1> <ACCESS_TOKEN_1>');
});

test('maps projected ranges back to original UTF-16 positions after emoji and CRLF', () => {
  const input = '😀\u200b note\r\n😀 al\u200bice@example.test\r\nleft\u202eright';
  const result = sanitize(input);
  const email = result.findings.find((finding) => finding.ruleId === 'email');
  const hiddenBeforeEmail = result.findings.find((finding) => finding.ruleId === 'zero-width');
  const originalEmail = 'al\u200bice@example.test';

  assert.equal(result.text, '😀 note\r\n😀 <EMAIL_1>\r\nleftright');
  assert.equal(email.start, input.indexOf(originalEmail));
  assert.equal(email.end, input.indexOf(originalEmail) + originalEmail.length);
  assert.equal(input.slice(email.start, email.end), originalEmail);
  assert.equal(email.line, 2);
  assert.equal(email.column, 4);
  assert.equal(hiddenBeforeEmail.line, 1);
  assert.equal(hiddenBeforeEmail.column, 3);
  assert.equal(hiddenBeforeEmail.start, 2);
  assert.equal(hiddenBeforeEmail.end, 3);
  assert.equal(result.summary.changedCharacters, originalEmail.length + 2);
});

test('suppresses nested hygiene findings without duplicate output or character counts', () => {
  const input = 'password="alpha\u200bbravo\u001b[31mcharlie\u001b[0mdelta"';
  const result = sanitize(input);
  const secret = result.findings.find((finding) => finding.ruleId === 'secret-assignment');

  assert.equal(result.text, 'password="<SECRET_1>"');
  assert.equal(result.findings.length, 1);
  assert.equal(result.summary.changedCharacters, input.length - 'password=""'.length);
  assert.equal(secret.line, 1);
  assert.equal(secret.column, 11);
});

test('preserves contextual precedence when token and header detections overlap', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.demo_signature_value';
  const input = `Authorization: Bea\u200brer ${jwt.slice(0, 10)}\u202e${jwt.slice(10)}`;
  const result = sanitize(input);

  assert.equal(result.text, 'Authorization: Bearer <BEARER_TOKEN_1>');
  assert.equal(result.findings.filter((finding) => finding.category === 'secrets').length, 1);
  assert.equal(result.findings.find((finding) => finding.category === 'secrets').ruleId, 'bearer-token');
  assert.equal(result.findings.filter((finding) => finding.category === 'hygiene').length, 1);
});

test('does not normalize controls for a disabled hygiene rule', () => {
  const input = 'pa\u200bssword=alphabravo';
  const result = sanitize(input, {
    enabledRuleIds: defaults.filter((id) => id !== 'zero-width'),
  });

  assert.equal(result.text, input);
  assert.equal(result.findings.length, 0);
});

test('only enabled hygiene rules alter the scanning projection', () => {
  const input = 'pa\u200bssword=alphabravo left\u202eright';
  const result = sanitize(input, { enabledRuleIds: ['zero-width'] });

  assert.equal(result.text, 'password=alphabravo left\u202eright');
  assert.deepEqual(result.findings.map((finding) => finding.ruleId), ['zero-width']);
});

test('removes controls around adjacent values without swallowing punctuation', () => {
  const input = '\u200balice@example.test\u200b,\u202ebob@example.test\u001b[0m';
  const result = sanitize(input);

  assert.equal(result.text, '<EMAIL_1>,<EMAIL_2>');
  assert.equal(result.summary.changedCharacters, input.length - 1);
});

test('handles an input containing only removable controls', () => {
  const input = '\u200b\u202e\u001b[31m\u001b[0m';
  const result = sanitize(input);

  assert.equal(result.text, '');
  assert.equal(result.summary.changedCharacters, input.length);
  assert.equal(result.findings.length, 4);
});

test('sanitized output is text-idempotent after hidden-character redaction', () => {
  const input = 'pa\u200bssword=alphabravo al\u200bice@example.test';
  const first = sanitize(input);
  const second = sanitize(first.text);

  assert.equal(first.text, 'password=<SECRET_1> <EMAIL_1>');
  assert.equal(second.text, first.text);
});

test('reserves placeholders that appear after enabled hygiene removal', () => {
  const result = sanitize('<SEC\u200bRET_1> password=synthetic');

  assert.equal(result.text, '<SECRET_1> password=<SECRET_2>');
  assert.equal(sanitize(result.text).text, result.text);
});

test('redacts an entire assigned secret instead of only its inner URL token', () => {
  const input = 'password="prefix?token=inner"';
  const result = sanitize(input);

  assert.equal(result.text, 'password="<SECRET_1>"');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'secret-assignment');
  assert.equal(result.findings[0].start, input.indexOf('prefix'));
  assert.equal(result.findings[0].end, input.lastIndexOf('"'));
});

test('enclosing secret precedence also covers normalized hidden-character values', () => {
  const input = 'password="prefix?token=in\u200bner suffix"';
  const result = sanitize(input);

  assert.equal(result.text, 'password="<SECRET_1>"');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'secret-assignment');
  assert.equal(result.summary.changedCharacters, 'prefix?token=in\u200bner suffix'.length);
});

test('an enclosing private key block wins over nested assignments and controls', () => {
  const input = '-----BEGIN PRIVATE KEY-----\npassword=alpha\u200bbravo\n-----END PRIVATE KEY-----';
  const result = sanitize(input);

  assert.equal(result.text, '<PRIVATE_KEY_1>');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'private-key');
  assert.equal(result.summary.changedCharacters, input.length);
});

test('keeps 2,000 obfuscated log lines complete, stable, and non-overlapping', () => {
  const lineCount = 2_000;
  const input = Array.from({ length: lineCount }, (_, index) =>
    `row=${index} pa\u200bssword="prefix-${index}?token=in\u2060ner-${index}" owner: al\u200bice@example.test`,
  ).join('\n');
  const expected = Array.from({ length: lineCount }, (_, index) =>
    `row=${index} password="<SECRET_${index + 1}>" owner: <EMAIL_1>`,
  ).join('\n');
  const result = sanitize(input);

  assert.equal(result.text, expected);
  assert.equal(result.findings.length, lineCount * 3);
  assert.equal(result.findings.at(-1).line, lineCount);
  for (let index = 1; index < result.findings.length; index += 1) {
    assert.ok(result.findings[index].start >= result.findings[index - 1].end);
  }
  assert.equal(sanitize(result.text).text, result.text);
});
