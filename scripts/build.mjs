import { cp, copyFile, mkdir, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dist = path.join(root, 'dist');

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });

const compiler = process.platform === 'win32' ? 'tsc.cmd' : 'tsc';
const result = spawnSync(compiler, ['-p', 'tsconfig.json'], {
  cwd: root,
  stdio: 'inherit',
});

if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

await copyFile(path.join(root, 'index.html'), path.join(dist, 'index.html'));
await copyFile(path.join(root, 'src', 'styles.css'), path.join(dist, 'styles.css'));
await cp(path.join(root, 'public'), dist, { recursive: true });

console.log(`Built PasteGuard → ${path.relative(process.cwd(), dist) || 'dist'}`);
