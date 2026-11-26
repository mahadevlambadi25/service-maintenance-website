import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.resolve(__dirname, '..');

function parseDotEnvLine(line) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;
  const eqIdx = trimmed.indexOf('=');
  if (eqIdx === -1) return null;
  const key = trimmed.slice(0, eqIdx).trim();
  let val = trimmed.slice(eqIdx + 1).trim();
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    val = val.slice(1, -1);
  }
  return { key, val };
}

export function loadLocalEnvFiles(rootDir = ROOT_DIR) {
  for (const filename of ['.env', '.env.local']) {
    const filePath = path.join(rootDir, filename);
    if (!fs.existsSync(filePath)) continue;
    const raw = fs.readFileSync(filePath, 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const parsed = parseDotEnvLine(line);
      if (parsed && parsed.key && process.env[parsed.key] === undefined) {
        process.env[parsed.key] = parsed.val;
      }
    }
  }
}

loadLocalEnvFiles();

export function getValidatedNeonPostgresEnv() {
  if (!process.env.DATABASE_URL) return null;
  const databaseUrl = String(process.env.DATABASE_URL || '').trim();
  const databaseUrlUnpooled = String(process.env.DATABASE_URL_UNPOOLED || databaseUrl).trim();
  if (!/^postgres(ql)?:\/\//i.test(databaseUrl)) {
    throw new Error('Invalid DATABASE_URL: expected a PostgreSQL connection string.');
  }
  return { databaseUrl, databaseUrlUnpooled };
}

function resolveDefaultBaseUrl() {
  if (process.env.BASE_URL) return process.env.BASE_URL.replace(/\/+$/, '');
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) {
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  }
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`;
  }
  return `http://127.0.0.1:${process.env.PORT || 3000}`;
}

export const DEV_FALLBACK_SESSION_SECRET = 'dev-session-secret-change-in-production-32chars';

export function isAdminMfaRequired(env = process.env) {
  const raw = String(env.ADMIN_MFA_REQUIRED ?? '').trim().toLowerCase();
  return raw === 'true' || raw === '1' || raw === 'yes';
}

export function validateSecurityConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV || 'development';
  const secret = env.SESSION_SECRET || '';
  if (nodeEnv === 'production') {
    if (!secret || secret === DEV_FALLBACK_SESSION_SECRET || secret.length < 32) {
      throw new Error(
        'FATAL SECURITY ERROR: SESSION_SECRET must be explicitly configured with a strong secret (>= 32 characters) when NODE_ENV=production.'
      );
    }
  }
}

validateSecurityConfig(process.env);

export const ENV = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: Number(process.env.PORT || 3000),
  HOST: process.env.HOST || '127.0.0.1',
  BASE_URL: resolveDefaultBaseUrl(),
  IS_VERCEL: process.env.VERCEL === '1',
  DB_PATH: process.env.DB_PATH || path.join(ROOT_DIR, 'storage', 'private', 'service_maintenance.db'),
  DATABASE_URL: process.env.DATABASE_URL || '',
  DATABASE_URL_UNPOOLED: process.env.DATABASE_URL_UNPOOLED || '',
  NEON_BRANCH: process.env.NEON_BRANCH || '',
  NEON_BRANCH_ID: process.env.NEON_BRANCH_ID || '',
  NEON_FUNCTION_HOST_SUFFIX: process.env.NEON_FUNCTION_HOST_SUFFIX || '',
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID || '',
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY || '',
  AWS_ENDPOINT_URL_S3: process.env.AWS_ENDPOINT_URL_S3 || '',
  AWS_REGION: process.env.AWS_REGION || 'ap-southeast-1',
  S3_BUCKET: process.env.S3_BUCKET || process.env.NEON_STORAGE_BUCKET || 'storage',
  CRON_SECRET: process.env.CRON_SECRET || '',
  SESSION_SECRET: process.env.SESSION_SECRET || DEV_FALLBACK_SESSION_SECRET,
  MFA_ENCRYPTION_KEY: process.env.MFA_ENCRYPTION_KEY || '',
  ADMIN_MFA_REQUIRED: isAdminMfaRequired(),
  IS_STAGING: process.env.APP_ENV === 'staging',
  FRESHSALES_DOMAIN: process.env.FRESHSALES_DOMAIN || '',
  FRESHSALES_API_KEY: process.env.FRESHSALES_API_KEY || '',
  FRESHSALES_DEAL_STAGE_QUALIFIED: process.env.FRESHSALES_DEAL_STAGE_QUALIFIED || '',
  FRESHSALES_DEAL_STAGE_PROPOSAL: process.env.FRESHSALES_DEAL_STAGE_PROPOSAL || '',
  FRESHSALES_DEAL_STAGE_WON: process.env.FRESHSALES_DEAL_STAGE_WON || '',
  M365_SENDER: process.env.M365_SENDER || 'notifications@smiaz.com',
  MS_GRAPH_TENANT_ID: process.env.MS_GRAPH_TENANT_ID || '',
  MS_GRAPH_CLIENT_ID: process.env.MS_GRAPH_CLIENT_ID || '',
  MS_GRAPH_CLIENT_SECRET: process.env.MS_GRAPH_CLIENT_SECRET || '',
  CLAMAV_HOST: process.env.CLAMAV_HOST || '',
  CLAMAV_PORT: Number(process.env.CLAMAV_PORT || 3310),
  MALWARE_SCAN_FAIL_CLOSED: process.env.MALWARE_SCAN_FAIL_CLOSED === 'true' || process.env.NODE_ENV === 'production',
  BACKUP_INTERVAL_HOURS: Number(process.env.BACKUP_INTERVAL_HOURS || 24),
  BACKUP_KEEP_COUNT: Number(process.env.BACKUP_KEEP_COUNT || 14),
};

export function buildStoragePaths(
  storageRoot = process.env.VERCEL === '1'
    ? path.join(os.tmpdir(), 'sm-runtime-storage')
    : path.join(ROOT_DIR, 'storage')
) {
  return {
    privateRoot: path.join(storageRoot, 'private'),
    resumes: path.join(storageRoot, 'private', 'resumes'),
    originals: path.join(storageRoot, 'private', 'originals'),
    quarantine: path.join(storageRoot, 'private', 'quarantine'),
    backups: path.join(storageRoot, 'private', 'backups'),
    publicMedia: path.join(storageRoot, 'public', 'media'),
  };
}

export const STORAGE_PATHS = buildStoragePaths();

export const BRAND_TOKENS = {
  limestone: '#F4F0E8',
  bone: '#E4DCCE',
  carbon: '#24251F',
  oxide: '#6B3026',
  bronze: '#9B815D',
  mutedStone: '#625F55',
};

export const BUSINESS_TZ = 'America/Phoenix';

export const ROLES = {
  PLATFORM_ADMIN: 'Platform Administrator',
  CONTENT_EDITOR: 'Content Editor',
  APPROVER_PUBLISHER: 'Approver and Publisher',
  HIRING_OWNER: 'Hiring Owner',
  HIRING_REVIEWER: 'Hiring Reviewer',
  PROJECT_CONTRIBUTOR: 'Project Contributor',
  ANALYST: 'Analyst',
};

export const UPLOAD_LIMITS = {
  inquiry: {
    maxFiles: 5,
    maxFileBytes: 10 * 1024 * 1024,
    maxTotalBytes: 25 * 1024 * 1024,
    allowedTypes: ['application/pdf', 'image/jpeg', 'image/png'],
  },
  resume: {
    maxFiles: 1,
    maxFileBytes: 10 * 1024 * 1024,
    allowedTypes: [
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ],
  },
  projectMedia: {
    maxFiles: 20,
    maxFileBytes: 20 * 1024 * 1024,
    maxBatchBytes: 200 * 1024 * 1024,
    maxMegapixels: 64,
    allowedTypes: ['image/jpeg', 'image/png', 'image/webp', 'image/heic'],
  },
};

export const SERVICE_FAMILIES = [
  { id: 'day-porter', label: 'Day porter services', pillar: 'Recurring property care', route: '/services/day-porter/', queue: 'day_porter_sales' },
  { id: 'recurring-property-care', label: 'Recurring property care', pillar: 'Recurring property care', route: '/services/recurring-property-care/', queue: 'day_porter_sales' },
  { id: 'building-engineer', label: 'Building engineer services', pillar: 'Recurring property care', route: '/services/building-engineer/', queue: 'sales_estimating', conditional: true },
  { id: 'commercial-maintenance', label: 'Commercial maintenance & repairs', pillar: 'Commercial maintenance and repairs', route: '/services/commercial-maintenance/', queue: 'sales_estimating' },
  { id: 'warehouse-repairs', label: 'Warehouse & industrial repairs', pillar: 'Commercial maintenance and repairs', route: '/services/warehouse-repairs/', queue: 'sales_estimating' },
  { id: 'exterior-site-maintenance', label: 'Exterior & site maintenance', pillar: 'Commercial maintenance and repairs', route: '/services/exterior-site-maintenance/', queue: 'sales_estimating' },
  { id: 'tenant-improvements', label: 'Tenant improvements & renovations', pillar: 'Tenant improvements and renovations', route: '/services/tenant-improvements/', queue: 'sales_estimating' },
  { id: 'tenant-move-outs', label: 'Tenant move-outs & make-ready', pillar: 'Tenant improvements and renovations', route: '/services/tenant-move-outs/', queue: 'sales_estimating' },
  { id: 'procurement', label: 'Procurement / vendor documentation', pillar: 'Credentials & procurement', route: '/credentials/', queue: 'operations_admin' },
  { id: 'not-sure', label: 'Not sure / general commercial inquiry', pillar: 'General', route: '/request-proposal/', queue: 'general_monitored' },
];

export const CONSENT_VERSION = '2026-11-24-v1';
export const PRIVACY_NOTICE_VERSION = '2026-11-24-v1';
