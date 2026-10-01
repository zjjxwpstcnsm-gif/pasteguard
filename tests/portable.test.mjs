import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { Script } from 'node:vm';

test('portable build embeds syntactically valid application code exactly once', () => {
  const html = readFileSync(new URL('../portable/pasteguard-local.html', import.meta.url), 'utf8');
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  assert.equal(scripts.length, 1);
  assert.doesNotThrow(() => new Script(scripts[0][1]));
  assert.equal((html.match(/<!doctype html>/gi) ?? []).length, 1);
  assert.equal((html.match(/End bundled module: engine\/personal.js/g) ?? []).length, 1);
  assert.equal(html, readFileSync(new URL('../sharesafe-local.html', import.meta.url), 'utf8'));
  assert.ok(html.includes("connect-src 'none'"));
  assert.ok(!html.includes('src="./app.js"'));
});
