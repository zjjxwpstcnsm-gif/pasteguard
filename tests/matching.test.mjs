import assert from 'node:assert/strict';
import test from 'node:test';
import { PRESETS, sanitize } from '../dist/engine/index.js';
import { matchingCorpus } from './matching-corpus.mjs';

for (const fixture of matchingCorpus) {
  test(`matching regression: ${fixture.name}`, () => {
    const options = { enabledRuleIds: PRESETS.find((preset) => preset.id === (fixture.preset ?? 'balanced')).ruleIds };
    const result = sanitize(fixture.input, options);
    assert.equal(result.text, fixture.output);
    assert.equal(sanitize(result.text, options).text, result.text, 'sanitizing again should be stable');
    for (const finding of result.findings) {
      assert.ok(finding.start >= 0 && finding.end <= fixture.input.length && finding.start < finding.end);
      if (finding.category === 'secrets') {
        assert.match(finding.originalPreview, /^\d+ characters?$/);
      }
    }
  });
}


test('nested assignment-shaped contents remain one bounded secret', () => {
  const input = `password=${'password='.repeat(4000)}synthetic`;
  const result = sanitize(input);
  assert.equal(result.text, 'password=<SECRET_1>');
  assert.equal(result.findings.length, 1);
});

test('multiple authorization headers on one log line remain separate', () => {
  const result = sanitize('Authorization: Bearer first-demo Authorization: Bearer second-demo');
  assert.equal(result.text, 'Authorization: Bearer <BEARER_TOKEN_1> Authorization: Bearer <BEARER_TOKEN_2>');
});
