import assert from 'node:assert/strict';
import test from 'node:test';
import { detectLocalUsernames, detectPhoneNumbers } from '../dist/engine/personal.js';

function values(detector, input) {
  const detections = detector(input);
  for (const detection of detections) {
    assert.equal(input.slice(detection.start, detection.end), detection.value, input);
  }
  return detections.map((detection) => detection.value);
}

test('local username detectors include terminal home directories and preserve punctuation', () => {
  for (const [input, expected] of [
    ['/Users/alice', 'alice'],
    ['/home/bob', 'bob'],
    [String.raw`C:\Users\Charlie`, 'Charlie'],
    [String.raw`c:\users\charlie\work\app.log`, 'charlie'],
    ['cwd=/Users/alice, next', 'alice'],
    ['(/home/bob).', 'bob'],
    ['"/Users/alice"', 'alice'],
    ['"/Users/alice/work', 'alice'],
    ['/home/alice./work', 'alice.'],
    ['/Users/张三/project', '张三'],
  ]) {
    assert.deepEqual(values(detectLocalUsernames, input), [expected], input);
  }
});

test('local username detectors preserve JSON-escaped Windows separators and quoted spaces', () => {
  for (const [input, expected] of [
    [String.raw`{"path":"C:\\Users\\Charlie\\work\\app.log"}`, 'Charlie'],
    [String.raw`{"path":"C:\\users\\Charlie Brown"}`, 'Charlie Brown'],
    ['"/Users/Alice Smith/work/app.log"', 'Alice Smith'],
    ["'/home/Bob Smith'", 'Bob Smith'],
    [String.raw`"C:\Users\Charlie Brown\work"`, 'Charlie Brown'],
    ['/Users/"Alice Smith"/work', 'Alice Smith'],
  ]) {
    assert.deepEqual(values(detectLocalUsernames, input), [expected], input);
  }
});

test('local username canonicalization preserves POSIX case and folds Windows case', () => {
  assert.equal(detectLocalUsernames('/Users/Alice')[0].canonicalValue, 'Alice');
  assert.equal(detectLocalUsernames(String.raw`C:\Users\Alice`)[0].canonicalValue, 'alice');
});

test('nearby non-home paths, URLs, and existing placeholders are not usernames', () => {
  for (const input of [
    '/srv/home/alice/project',
    'https://example.test/home/alice',
    'https://example.test/Users/alice',
    'relative/home/alice',
    '/Users/',
    '/home/..',
    '/home/.',
    '/Users/<LOCAL_USER_1>/work',
    String.raw`C:\Users\<LOCAL_USER_1>\work`,
    String.raw`abcC:\Users\Alice`,
    '"/Users/unterminated name',
  ]) {
    assert.deepEqual(values(detectLocalUsernames, input), [], input);
  }
});

test('explicit phone labels allow compact and simply formatted phone values', () => {
  for (const [input, expected] of [
    ['phone=13800138000', '13800138000'],
    ['mobile: 13800138000', '13800138000'],
    ['tel=2025550100', '2025550100'],
    ['telephone: 02079460958', '02079460958'],
    ['Phone number: 2025550100', '2025550100'],
    ['{"phone_number":"13800138000"}', '13800138000'],
    ["'mobile-number' = '13800138000'", '13800138000'],
    ['cell_phone=2025550100', '2025550100'],
    ['phone: 555-0100', '555-0100'],
    ['tel: +86 138 0013 8000', '+86 138 0013 8000'],
  ]) {
    assert.deepEqual(values(detectPhoneNumbers, input), [expected], input);
  }
});

test('common unlabelled US and international phone shapes are detected', () => {
  for (const input of [
    '(202) 555-0100',
    '(202)5550100',
    '202-555-0100',
    '202.555.0100',
    '202 555 0100',
    '1-202-555-0100',
    '+1 (202) 555-0100',
    '+12025550100',
    '+44 20 7946 0958',
    '020 7946 0958',
    '+86 13800138000',
  ]) {
    assert.deepEqual(values(detectPhoneNumbers, input), [input], input);
  }
});

test('phone ranges and digits-only canonicalization exclude labels, quotes, and sentence punctuation', () => {
  const input = '😀 mobile="+1 (202) 555-0100".';
  const detections = detectPhoneNumbers(input);
  assert.equal(detections.length, 1);
  assert.equal(input.slice(detections[0].start, detections[0].end), '+1 (202) 555-0100');
  assert.equal(detections[0].canonicalValue, '12025550100');
  assert.equal(detections[0].confidence, 'medium');
});

test('phone detector keeps nearby date, IP, version, ID, card, and long-number negatives', () => {
  for (const input of [
    '2026-10-01',
    '2026-01-01 12-34-56',
    'phone: 2026-01-01 12-34-56',
    '10-01-2026',
    '2026/10/01',
    'phone: 2026-10-01',
    '192.168.100.123',
    'phone: 192.168.100.123',
    'v202.555.0100',
    'version=202.555.0100',
    'order_id=202-555-0100',
    '1.23.456.7890',
    'release-202-555-0100',
    'item_202-555-0100',
    '202-555-0100_suffix',
    'id=13800138000',
    '13800138000',
    'phone_id=13800138000',
    'smartphone=13800138000',
    'account_phone=13800138000',
    'phone=12345678901234567890',
    '+12345678901234567890',
    'phone=4242 4242 4242 4242',
    'phone=0000000000',
    'phone=123456',
  ]) {
    assert.deepEqual(values(detectPhoneNumbers, input), [], input);
  }
});


test('adjacent phone shapes remain separate within a line and across line breaks', () => {
  for (const separator of [' ', '\n', '\r\n', ', ']) {
    assert.deepEqual(values(detectPhoneNumbers, `202-555-0100${separator}202-555-0101`), [
      '202-555-0100', '202-555-0101',
    ]);
    assert.deepEqual(values(detectPhoneNumbers, `(202) 555-0100${separator}(202) 555-0101`), [
      '(202) 555-0100', '(202) 555-0101',
    ]);
  }
  assert.deepEqual(values(detectPhoneNumbers, '+1 (202) 555-0100 (202) 555-0101'), [
    '+1 (202) 555-0100', '(202) 555-0101',
  ]);
});

test('malformed long numeric input does not backtrack through ambiguous digit groups', () => {
  assert.deepEqual(values(detectPhoneNumbers, 'phone=' + '1234567890'.repeat(1000) + '(12 34)56'), []);
});


test('explicit Chinese phone labels support compact values without guessing bare mobile numbers', () => {
  for (const label of ['手机', '手机号', '手机号码', '电话', '电话号码', '联系电话']) {
    for (const separator of ['=', ': ', '：']) {
      assert.deepEqual(values(detectPhoneNumbers, `${label}${separator}13800138000`), ['13800138000']);
    }
    assert.deepEqual(values(detectPhoneNumbers, `{"${label}":"13800138000"}`), ['13800138000']);
  }
  for (const input of [
    '13800138000',
    '订单号=13800138000',
    '订单号：202-555-0100',
    '编号: 202-555-0100',
    'id=13800138000',
    '手机id=13800138000',
    '手机号_id=13800138000',
    '手机=12345678901234567890',
    '电话：2026-01-01 12-34-56',
  ]) {
    assert.deepEqual(values(detectPhoneNumbers, input), [], input);
  }
});
