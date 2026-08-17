import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const directory = path.resolve(root, process.argv[2] ?? 'dist');
const port = Number(process.env.PORT ?? 4173);

const mimeTypes = new Map([
  ['.css', 'text/css; charset=utf-8'],
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.map', 'application/json; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.webmanifest', 'application/manifest+json'],
]);

const server = createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);
    const decodedPath = decodeURIComponent(requestUrl.pathname);
    const relativePath = decodedPath === '/' ? 'index.html' : decodedPath.replace(/^\/+/, '');
    const candidate = path.resolve(directory, relativePath);

    if (candidate !== directory && !candidate.startsWith(`${directory}${path.sep}`)) {
      respondText(response, 403, 'Forbidden');
      return;
    }

    let filePath = candidate;
    let fileStat = await stat(filePath).catch(() => null);
    if (fileStat?.isDirectory()) {
      filePath = path.join(filePath, 'index.html');
      fileStat = await stat(filePath).catch(() => null);
    }

    if (!fileStat?.isFile()) {
      respondText(response, 404, 'Not found');
      return;
    }

    response.statusCode = 200;
    response.setHeader('Content-Type', mimeTypes.get(path.extname(filePath)) ?? 'application/octet-stream');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    createReadStream(filePath).pipe(response);
  } catch (error) {
    console.error(error);
    respondText(response, 500, 'Internal server error');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`PasteGuard: http://127.0.0.1:${port}`);
  console.log(`Serving ${directory}`);
});

function respondText(response, status, body) {
  response.statusCode = status;
  response.setHeader('Content-Type', 'text/plain; charset=utf-8');
  response.end(body);
}
