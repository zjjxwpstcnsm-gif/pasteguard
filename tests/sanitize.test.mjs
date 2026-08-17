import assert from 'node:assert/strict';
import test from 'node:test';
import { PRESETS, RULES, sanitize } from '../dist/engine/index.js';

const balanced = PRESETS.find((preset) => preset.id === 'balanced').ruleIds;
const secretsOnly = PRESETS.find((preset) => preset.id === 'secrets').ruleIds;
const strict = PRESETS.find((preset) => preset.id === 'strict').ruleIds;

test('reuses stable placeholders for repeated values', () => {
  const result = sanitize(
    'From maya@example.com to lee@example.com; cc maya@example.com',
    { enabledRuleIds: balanced },
  );

  assert.equal(
    result.text,
    'From <EMAIL_1> to <EMAIL_2>; cc <EMAIL_1>',
  );
  assert.equal(result.findings.length, 3);
});

test('the secrets-only preset leaves personal data untouched', () => {
  const result = sanitize('Email maya@example.com, password: very-secret-value', {
    enabledRuleIds: secretsOnly,
  });

  assert.match(result.text, /maya@example\.com/);
  assert.match(result.text, /password: <SECRET_1>/);
});

test('redacts a private key block as one critical finding', () => {
  const input = `before\n-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\nafter`;
  const result = sanitize(input, { enabledRuleIds: balanced });

  assert.equal(result.text, 'before\n<PRIVATE_KEY_1>\nafter');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].severity, 'critical');
});

test('redacts quoted JSON and env-style secret assignments without removing keys', () => {
  const input = `{"api_key":"sk-demo-abcdefghijklmnop"}\npassword = 'correct-horse-battery-staple'`;
  const result = sanitize(input, { enabledRuleIds: balanced });

  assert.equal(result.text, `{"api_key":"<SECRET_1>"}\npassword = '<SECRET_2>'`);
});

test('redacts only the sensitive value inside URL query parameters', () => {
  const input = 'GET https://example.test/a?lang=en&token=abc123456789&mode=full';
  const result = sanitize(input, { enabledRuleIds: balanced });

  assert.equal(
    result.text,
    'GET https://example.test/a?lang=en&token=<URL_SECRET_1>&mode=full',
  );
});

test('prefers contextual bearer-token detection over overlapping JWT detection', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.demo_signature_value';
  const result = sanitize(`Authorization: Bearer ${jwt}`, { enabledRuleIds: balanced });

  assert.equal(result.text, 'Authorization: Bearer <BEARER_TOKEN_1>');
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].ruleId, 'bearer-token');
});

test('uses a Luhn checksum to reduce payment-card false positives', () => {
  const valid = sanitize('Card 4242 4242 4242 4242', { enabledRuleIds: balanced });
  const invalid = sanitize('Number 4242 4242 4242 4241', { enabledRuleIds: balanced });

  assert.equal(valid.text, 'Card <PAYMENT_CARD_1>');
  assert.equal(invalid.findings.some((finding) => finding.ruleId === 'payment-card'), false);
});

test('masks usernames while preserving the rest of local paths', () => {
  const input = '/Users/maya/work/a.log C:\\Users\\Maya\\work\\b.log /home/lee/app.log';
  const result = sanitize(input, { enabledRuleIds: balanced });

  assert.equal(
    result.text,
    '/Users/<LOCAL_USER_1>/work/a.log C:\\Users\\<LOCAL_USER_1>\\work\\b.log /home/<LOCAL_USER_2>/app.log',
  );
});

test('removes ANSI, zero-width, and bidirectional control characters', () => {
  const input = '\u001b[31mred\u001b[0m safe\u200Btext left\u202Eright';
  const result = sanitize(input, { enabledRuleIds: balanced });

  assert.equal(result.text, 'red safetext leftright');
  assert.equal(result.findings.length, 4);
});

test('accepts valid IPv4 addresses and rejects invalid octets', () => {
  const result = sanitize('good=10.24.5.18 bad=999.24.5.18', { enabledRuleIds: balanced });

  assert.match(result.text, /good=<IP_ADDRESS_1>/);
  assert.match(result.text, /bad=999\.24\.5\.18/);
});

test('strict mode redacts generic identifiers and UUIDs', () => {
  const input = 'userId: customer-123 request=7a9e6679-7425-40de-944b-e07fc1f90ae7';
  const result = sanitize(input, { enabledRuleIds: strict });

  assert.match(result.text, /userId: <IDENTIFIER_1>/);
  assert.match(result.text, /request=<UUID_1>/);
});

test('reports one-based line and column positions', () => {
  const result = sanitize('line one\nemail: maya@example.com', { enabledRuleIds: balanced });
  const email = result.findings.find((finding) => finding.ruleId === 'email');

  assert.equal(email.line, 2);
  assert.equal(email.column, 8);
});

test('all preset rule IDs resolve to real rules', () => {
  const ids = new Set(RULES.map((rule) => rule.id));
  for (const preset of PRESETS) {
    for (const id of preset.ruleIds) {
      assert.equal(ids.has(id), true, `${preset.id} contains unknown rule ${id}`);
    }
  }
});
