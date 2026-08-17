import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const portableDir = path.join(root, 'portable');

const buildResult = spawnSync(process.execPath, ['scripts/build.mjs'], {
  cwd: root,
  stdio: 'inherit',
});
if (buildResult.error) {
  throw buildResult.error;
}
if (buildResult.status !== 0) {
  process.exit(buildResult.status ?? 1);
}

const moduleFiles = [
  'config.js',
  'engine/luhn.js',
  'engine/detectors.js',
  'engine/placeholders.js',
  'engine/rules.js',
  'engine/presets.js',
  'engine/sanitize.js',
  'app.js',
];

const modules = [];
for (const relativePath of moduleFiles) {
  const source = await readFile(path.join(root, 'dist', relativePath), 'utf8');
  modules.push(stripModuleSyntax(source, relativePath));
}

let bundledJavaScript = `(() => {\n'use strict';\n${modules.join('\n\n')}\n})();\n`;
// Inline scripts must not contain a literal closing script tag.
bundledJavaScript = bundledJavaScript.replaceAll('</script', '<\\/script');
// A file:// page cannot register a service worker. The core sanitizer does not need one.
bundledJavaScript = bundledJavaScript.replace(/\n\s*registerServiceWorker\(\);/, '');

let html = await readFile(path.join(root, 'index.html'), 'utf8');
const css = (await readFile(path.join(root, 'src', 'styles.css'), 'utf8')).replaceAll('</style', '<\\/style');

html = html
  .replace(
    /<meta\s+http-equiv="Content-Security-Policy"[\s\S]*?\/>/,
    `<meta\n      http-equiv="Content-Security-Policy"\n      content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"\n    />`,
  )
  .replace(/^\s*<link rel="icon"[^>]*>\s*$/m, '')
  .replace(/^\s*<link rel="manifest"[^>]*>\s*$/m, '')
  .replace(/^\s*<link rel="stylesheet" href="\.\/styles\.css" \/>\s*$/m, `    <style>\n${css}\n    </style>`)
  .replace(
    /^\s*<script type="module" src="\.\/app\.js"><\/script>\s*$/m,
    `    <script>\n${bundledJavaScript}\n    </script>`,
  )
  .replace(
    '<span class="privacy-dot" aria-hidden="true"></span>\n            Browser-only processing',
    '<span class="privacy-dot" aria-hidden="true"></span>\n            Offline single-file processing',
  );

if (html.includes('./app.js') || html.includes('./styles.css') || html.includes('./manifest.webmanifest')) {
  throw new Error('Portable build still contains external application assets.');
}

await rm(portableDir, { recursive: true, force: true });
await mkdir(portableDir, { recursive: true });
const outputPath = path.join(portableDir, 'pasteguard-local.html');
const legacyOutputPath = path.join(root, 'sharesafe-local.html');
await writeFile(outputPath, html, 'utf8');
await writeFile(legacyOutputPath, html, 'utf8');

console.log(`Built portable PasteGuard → ${path.relative(process.cwd(), outputPath)}`);
console.log(`Built compatibility copy → ${path.relative(process.cwd(), legacyOutputPath)}`);

function stripModuleSyntax(source, relativePath) {
  return source
    .replace(/^\s*import\s+[^;]+;\s*$/gm, '')
    .replace(/\bexport\s+(?=(?:async\s+)?(?:function|class|const|let|var)\b)/g, '')
    .replace(/^\s*export\s*\{[^}]*\};?\s*$/gm, '')
    .replace(/^\s*\/\/# sourceMappingURL=.*$/gm, '')
    .trim()
    .concat(`\n// End bundled module: ${relativePath}`);
}
