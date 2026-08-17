import { spawn, spawnSync } from 'node:child_process';
import { watch } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let building = false;
let buildQueued = false;
let debounceTimer;

runBuild();
const server = spawn(process.execPath, ['scripts/serve.mjs', 'dist'], {
  cwd: root,
  stdio: 'inherit',
  env: process.env,
});

const watchTargets = ['src', 'public', 'index.html'];
const watchers = watchTargets.map((target) =>
  watch(path.join(root, target), { recursive: true }, () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(queueBuild, 80);
  }),
);

function queueBuild() {
  if (building) {
    buildQueued = true;
    return;
  }
  runBuild();
}

function runBuild() {
  building = true;
  const result = spawnSync(process.execPath, ['scripts/build.mjs'], {
    cwd: root,
    stdio: 'inherit',
  });
  building = false;

  if (result.status !== 0) {
    console.error('Build failed. Watching for the next change.');
  }
  if (buildQueued) {
    buildQueued = false;
    runBuild();
  }
}

function shutdown() {
  for (const watcher of watchers) {
    watcher.close();
  }
  server.kill('SIGTERM');
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
