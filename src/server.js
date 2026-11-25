import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { buildStoragePaths, ENV, STORAGE_PATHS, validateSecurityConfig } from './config.js';
import { getDb } from './db/database.js';
import { seedDatabase } from './db/seed.js';
import { randomToken } from './lib/crypto.js';
import { handleAdminApi } from './routes/api-admin.js';
import { handlePublicApi } from './routes/api-public.js';
import { handleAdminPages } from './routes/admin-pages.js';
import { handlePublicRoute } from './routes/public.js';
import { startBackgroundWorker, stopBackgroundWorker } from './services/delivery-worker.js';

export async function createAppServer({ dbPath = null, storageRoot = null, startWorker = true } = {}) {
  validateSecurityConfig(process.env);
  const storagePaths = storageRoot ? buildStoragePaths(storageRoot) : STORAGE_PATHS;
  const db = await getDb(dbPath, storagePaths);
  await seedDatabase(db);

  const server = http.createServer(async (req, res) => {
    const nonce = randomToken(16);

    // Phase 3 Security & Companion Headers (modern-web-guidance security standard)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Vary', 'Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site');

    const csp = [
      `default-src 'self'`,
      `script-src 'nonce-${nonce}' 'strict-dynamic'`,
      `style-src 'self' 'unsafe-inline'`,
      `img-src 'self' data:`,
      `object-src 'none'`,
      `base-uri 'none'`,
      `frame-ancestors 'none'`,
      `form-action 'self'`,
    ].join('; ');
    res.setHeader('Content-Security-Policy', csp);

    // Fetch Metadata resource isolation for cross-site non-navigational API requests
    const fetchSite = req.headers['sec-fetch-site'];
    const fetchMode = req.headers['sec-fetch-mode'];
    if (fetchSite === 'cross-site' && !(fetchMode === 'navigate' && req.method === 'GET')) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Cross-site request blocked');
      return;
    }

    try {
      const urlObj = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);

      if (urlObj.pathname === '/api/health' && req.method === 'GET') {
        const probe = await db.prepare('SELECT 1 as ok').get();
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({ ok: probe?.ok === 1, dialect: db.dialect, branch: ENV.NEON_BRANCH || 'local' }));
        return;
      }

      if (await handlePublicApi(req, res, db, urlObj, storagePaths)) return;
      if (await handleAdminApi(req, res, db, urlObj, storagePaths)) return;
      if (await handleAdminPages(req, res, db, urlObj, nonce)) return;
      if (await handlePublicRoute(req, res, db, urlObj, nonce, storagePaths)) return;

      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
    } catch (err) {
      // Never expose raw stack traces or credentials to visitors (PRD 12.04)
      console.error('[server] request error:', err?.message || err);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ ok: false, message: 'Internal server error.' }));
      }
    }
  });

  if (startWorker) {
    startBackgroundWorker(db, 10_000, storagePaths);
  }

  server.on('close', () => {
    if (startWorker) stopBackgroundWorker();
  });

  return { server, db };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { server, db } = await createAppServer();
  server.listen(ENV.PORT, ENV.HOST, () => {
    console.log(
      `Service Maintenance Website & Staff Dashboard listening at http://${ENV.HOST}:${ENV.PORT} (db=${db.dialect}${ENV.NEON_BRANCH ? `, branch=${ENV.NEON_BRANCH}` : ''})`
    );
  });
}
