import crypto from 'node:crypto';
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
import { isS3StorageConfigured } from './services/object-store.js';
import { getFreshsalesStatus } from './services/crm-adapter.js';
import { getMailerStatus } from './services/mailer.js';
import { syncAuthPolicyState } from './services/auth.js';
import { runScheduledWorkerTick, startBackgroundWorker, stopBackgroundWorker } from './services/delivery-worker.js';

function isAuthorizedCronRequest(req) {
  const secret = String(process.env.CRON_SECRET ?? ENV.CRON_SECRET ?? '').trim();
  if (!secret) return false;
  const authHeader = String(req.headers.authorization || '');
  const expected = `Bearer ${secret}`;
  const a = Buffer.from(authHeader);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function createRequestHandler({ db, storagePaths = STORAGE_PATHS }) {
  return async (req, res) => {
    const nonce = randomToken(16);

    // Phase 3 Security & Companion Headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Vary', 'Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site');

    const s3Endpoint = String(process.env.AWS_ENDPOINT_URL_S3 ?? ENV.AWS_ENDPOINT_URL_S3 ?? '').trim();
    let s3Origin = '';
    if (s3Endpoint) {
      try {
        s3Origin = new URL(s3Endpoint).origin;
      } catch {}
    }
    const connectSrc = s3Origin ? `connect-src 'self' ${s3Origin}` : `connect-src 'self'`;

    const csp = [
      `default-src 'self'`,
      connectSrc,
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
      const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || '127.0.0.1';
      const protoHeader = req.headers['x-forwarded-proto'] || (ENV.BASE_URL.startsWith('https://') ? 'https' : 'http');
      const urlObj = new URL(req.url || '/', `${protoHeader}://${hostHeader}`);

      if (urlObj.pathname === '/api/health' && req.method === 'GET') {
        const probe = await db.prepare('SELECT 1 as ok').get();
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(
          JSON.stringify({
            ok: probe?.ok === 1,
            dialect: db.dialect,
            storage: isS3StorageConfigured() ? 's3' : 'local',
            branch: ENV.NEON_BRANCH || 'local',
            integrations: {
              freshsales: getFreshsalesStatus().mode,
              m365_mail: getMailerStatus().configured ? 'configured' : 'unconfigured',
            },
          })
        );
        return;
      }

      if (urlObj.pathname === '/api/cron/worker' && (req.method === 'GET' || req.method === 'POST')) {
        if (!isAuthorizedCronRequest(req)) {
          res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
          res.end(JSON.stringify({ ok: false, message: 'Unauthorized cron trigger.' }));
          return;
        }
        const summary = await runScheduledWorkerTick(db, storagePaths, {
          runMaintenance: !ENV.IS_VERCEL || isS3StorageConfigured(),
        });
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(JSON.stringify({ ok: true, ...summary }));
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
  };
}

export async function initializeAppRuntime({ dbPath = null, storageRoot = null } = {}) {
  validateSecurityConfig(process.env);
  const storagePaths = storageRoot ? buildStoragePaths(storageRoot) : STORAGE_PATHS;
  const db = await getDb(dbPath, storagePaths);
  const existingSettings = await db.prepare('SELECT id FROM business_settings WHERE id = 1').get();
  if (!existingSettings) {
    await seedDatabase(db);
  }
  await syncAuthPolicyState(db);
  const handler = createRequestHandler({ db, storagePaths });
  return { db, storagePaths, handler };
}

export async function createAppServer({ dbPath = null, storageRoot = null, startWorker = !ENV.IS_VERCEL } = {}) {
  const { db, storagePaths, handler } = await initializeAppRuntime({ dbPath, storageRoot });
  const server = http.createServer(handler);

  if (startWorker) {
    startBackgroundWorker(db, 10_000, storagePaths);
  }

  server.on('close', () => {
    if (startWorker) stopBackgroundWorker();
  });

  return { server, db, handler };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { server, db } = await createAppServer();
  server.listen(ENV.PORT, ENV.HOST, () => {
    console.log(
      `Service Maintenance Website & Staff Dashboard listening at http://${ENV.HOST}:${ENV.PORT} (db=${db.dialect}, storage=${isS3StorageConfigured() ? 's3' : 'local'}${ENV.NEON_BRANCH ? `, branch=${ENV.NEON_BRANCH}` : ''})`
    );
  });
}
