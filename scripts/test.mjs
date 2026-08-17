import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const build = spawnSync(process.execPath, ['scripts/build.mjs'], {
  cwd: root,
  stdio: 'inherit',
});
if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

const testFiles = readdirSync(path.join(root, 'tests'))
  .filter((name) => name.endsWith('.test.mjs'))
  .map((name) => path.join('tests', name));

const test = spawnSync(process.execPath, ['--test', ...testFiles], {
  cwd: root,
  stdio: 'inherit',
});
process.exit(test.status ?? 1);
