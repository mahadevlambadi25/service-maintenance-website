import { ENV, ROLES } from '../config.js';
import { generateUuid, randomToken, sha256Hex, verifyPassword, verifyTotpCode } from '../lib/crypto.js';
import { redactForLog } from '../lib/sanitize.js';

export const PERMISSIONS = {
  MANAGE_USERS: 'manage_users',
  MANAGE_SETTINGS: 'manage_settings',
  EDIT_CONTENT: 'edit_content',
  PUBLISH_CONTENT: 'publish_content',
  MANAGE_CAMPAIGNS: 'manage_campaigns',
  PUBLISH_CAMPAIGNS: 'publish_campaigns',
  EDIT_PROJECTS: 'edit_projects',
  PUBLISH_PROJECTS: 'publish_projects',
  MANAGE_VACANCIES: 'manage_vacancies',
  REVIEW_APPLICATIONS: 'review_applications',
  EXPORT_APPLICATIONS: 'export_applications',
  MANAGE_LEADS_CRM: 'manage_leads_crm',
  VIEW_ANALYTICS: 'view_analytics',
  VIEW_AUDIT: 'view_audit',
  MANAGE_BACKUPS: 'manage_backups',
};

export const ROLE_PERMISSION_MAP = {
  [ROLES.PLATFORM_ADMIN]: [
    PERMISSIONS.MANAGE_USERS,
    PERMISSIONS.MANAGE_SETTINGS,
    PERMISSIONS.MANAGE_LEADS_CRM,
    PERMISSIONS.VIEW_AUDIT,
    PERMISSIONS.MANAGE_BACKUPS,
    // Explicitly NO hiring-data access by default per PRD 16.03!
  ],
  [ROLES.CONTENT_EDITOR]: [
    PERMISSIONS.EDIT_CONTENT,
    PERMISSIONS.MANAGE_CAMPAIGNS,
    PERMISSIONS.EDIT_PROJECTS,
  ],
  [ROLES.APPROVER_PUBLISHER]: [
    PERMISSIONS.EDIT_CONTENT,
    PERMISSIONS.PUBLISH_CONTENT,
    PERMISSIONS.MANAGE_CAMPAIGNS,
    PERMISSIONS.PUBLISH_CAMPAIGNS,
    PERMISSIONS.EDIT_PROJECTS,
    PERMISSIONS.PUBLISH_PROJECTS,
    PERMISSIONS.VIEW_AUDIT,
  ],
  [ROLES.HIRING_OWNER]: [
    PERMISSIONS.MANAGE_VACANCIES,
    PERMISSIONS.REVIEW_APPLICATIONS,
    PERMISSIONS.EXPORT_APPLICATIONS,
  ],
  [ROLES.HIRING_REVIEWER]: [
    PERMISSIONS.REVIEW_APPLICATIONS,
  ],
  [ROLES.PROJECT_CONTRIBUTOR]: [
    PERMISSIONS.EDIT_PROJECTS,
  ],
  [ROLES.ANALYST]: [
    PERMISSIONS.VIEW_ANALYTICS,
  ],
};

export function getUserRoles(user) {
  if (!user) return [];
  let extra = [];
  try {
    extra = JSON.parse(user.extra_roles_json || '[]');
  } catch {
    extra = [];
  }
  return Array.from(new Set([user.role, ...extra].filter(Boolean)));
}

export function hasPermission(user, perm) {
  if (!user || !user.active) return false;
  const roles = getUserRoles(user);
  for (const r of roles) {
    const perms = ROLE_PERMISSION_MAP[r] || [];
    if (perms.includes(perm)) return true;
  }
  return false;
}

export function canAccessJobRecord(user, job) {
  if (!user || !user.active || !job) return false;
  const roles = getUserRoles(user);
  if (roles.includes(ROLES.HIRING_OWNER)) {
    if (job.hiring_owner_id === user.user_id || job.backup_owner_id === user.user_id) {
      return true;
    }
  }
  if (roles.includes(ROLES.HIRING_REVIEWER)) {
    let assigned = [];
    try {
      assigned = JSON.parse(job.assigned_reviewers_json || '[]');
    } catch {
      assigned = [];
    }
    return assigned.includes(user.user_id);
  }
  return false;
}

export async function canAccessApplicationRecord(db, user, application) {
  if (!user || !user.active || !application) return false;
  const roles = getUserRoles(user);
  if (!roles.includes(ROLES.HIRING_OWNER) && !roles.includes(ROLES.HIRING_REVIEWER)) {
    return false;
  }
  const job = await db.prepare('SELECT * FROM jobs WHERE requisition_id = ?').get(application.requisition_id);
  if (!job) return false;
  if (roles.includes(ROLES.HIRING_OWNER)) {
    if (job.hiring_owner_id === user.user_id || job.backup_owner_id === user.user_id) {
      return true;
    }
  }
  if (roles.includes(ROLES.HIRING_REVIEWER)) {
    if (application.assigned_reviewer_id === user.user_id) return true;
    let assigned = [];
    try {
      assigned = JSON.parse(job.assigned_reviewers_json || '[]');
    } catch {
      assigned = [];
    }
    return assigned.includes(user.user_id);
  }
  return false;
}

export async function recordAudit(db, actor, domain, action, objectType, objectId, details = {}) {
  await db.prepare(
    `INSERT INTO audit_log (audit_id, actor_id, actor_name, actor_role, domain, action, object_type, object_id, details_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    generateUuid(),
    actor?.user_id || 'system',
    actor?.full_name || 'System',
    actor?.role || 'System',
    domain,
    action,
    objectType,
    String(objectId || ''),
    JSON.stringify(redactForLog(details)),
    new Date().toISOString()
  );
}

// Simple in-memory sliding window rate limiter
const rateBuckets = new Map();
export function checkRateLimit(key, maxRequests = 20, windowMs = 60_000) {
  const now = Date.now();
  const list = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
  if (list.length >= maxRequests) {
    return { allowed: false, retryAfterSec: Math.ceil((windowMs - (now - list[0])) / 1000) };
  }
  list.push(now);
  rateBuckets.set(key, list);
  return { allowed: true, retryAfterSec: 0 };
}

export function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  }
  return out;
}

export const SESSION_COOKIE_NAME = 'sm_staff_session';

export function buildSessionCookie(sessionId, maxAgeSec = 28_800) {
  const isHttps = ENV.BASE_URL.startsWith('https://');
  const flags = [`${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionId)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
  if (isHttps) flags.push('Secure');
  return flags.join('; ');
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export async function authenticateSession(db, req) {
  const cookies = parseCookies(req);
  const sid = cookies[SESSION_COOKIE_NAME];
  if (!sid) return null;

  const row = await db
    .prepare(
      `SELECT s.*, u.email, u.full_name, u.role, u.extra_roles_json, u.mfa_enabled, u.active
       FROM sessions s
       JOIN users u ON u.user_id = s.user_id
       WHERE s.session_id = ?`
    )
    .get(sid);

  if (!row) return null;
  if (!row.active || new Date(row.expires_at).getTime() <= Date.now()) {
    await db.prepare('DELETE FROM sessions WHERE session_id = ?').run(sid);
    return null;
  }
  return row;
}

export async function createPendingOrVerifiedSession(db, { email, password, totpCode, ip }) {
  const user = await db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').trim().toLowerCase());
  if (!user || !user.active || !verifyPassword(password, user.password_hash)) {
    return { ok: false, error: 'Invalid email or password.' };
  }

  if (user.mfa_enabled) {
    if (!totpCode) {
      return { ok: false, requireMfa: true, error: 'Enter your 6-digit authenticator MFA code.' };
    }
    if (!verifyTotpCode(user.totp_secret, totpCode)) {
      return { ok: false, requireMfa: true, error: 'Invalid or expired MFA code.' };
    }
  }

  const sessionId = randomToken(32);
  const csrfToken = randomToken(24);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 8 * 3600 * 1000).toISOString();

  await db.prepare(
    `INSERT INTO sessions (session_id, user_id, csrf_token, mfa_verified, expires_at, created_at, ip_hash)
     VALUES (?, ?, ?, 1, ?, ?, ?)`
  ).run(sessionId, user.user_id, csrfToken, expiresAt, now.toISOString(), sha256Hex(ip || 'unknown'));

  await recordAudit(db, user, 'auth', 'login_success', 'session', sessionId, { mfa_verified: true });

  return { ok: true, sessionId, csrfToken, user };
}

export async function revokeUserSessions(db, userId) {
  await db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}
