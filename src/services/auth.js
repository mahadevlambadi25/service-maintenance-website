import { ENV, isAdminMfaRequired, ROLES } from '../config.js';
import {
  buildTotpOtpAuthUri,
  decryptSecret,
  encryptSecret,
  generateRecoveryCodes,
  generateTotpSecret,
  generateUuid,
  hashPassword,
  hashRecoveryCodeList,
  randomToken,
  sha256Hex,
  signHmac,
  verifyHmac,
  verifyPassword,
  verifyRecoveryCodeInList,
  verifyTotpCode,
} from '../lib/crypto.js';
import { redactForLog } from '../lib/sanitize.js';

export const PERMISSIONS = {
  MANAGE_USERS: 'manage_users',
  MANAGE_SETTINGS: 'manage_settings',
  VIEW_CONTENT: 'view_content',
  EDIT_CONTENT: 'edit_content',
  APPROVE_CONTENT: 'approve_content',
  PUBLISH_CONTENT: 'publish_content',
  MANAGE_CAMPAIGNS: 'manage_campaigns',
  PUBLISH_CAMPAIGNS: 'publish_campaigns',
  EDIT_PROJECTS: 'edit_projects',
  UPLOAD_PROJECT_MEDIA: 'upload_project_media',
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
    PERMISSIONS.VIEW_CONTENT,
    PERMISSIONS.MANAGE_USERS,
    PERMISSIONS.MANAGE_SETTINGS,
    PERMISSIONS.MANAGE_LEADS_CRM,
    PERMISSIONS.VIEW_ANALYTICS,
    PERMISSIONS.VIEW_AUDIT,
    PERMISSIONS.MANAGE_BACKUPS,
    // Explicitly NO hiring-data access and NO publish/edit content by default per PRD 16.03!
  ],
  [ROLES.CONTENT_EDITOR]: [
    PERMISSIONS.VIEW_CONTENT,
    PERMISSIONS.EDIT_CONTENT,
    PERMISSIONS.MANAGE_CAMPAIGNS,
    PERMISSIONS.EDIT_PROJECTS,
    PERMISSIONS.UPLOAD_PROJECT_MEDIA,
  ],
  [ROLES.APPROVER_PUBLISHER]: [
    PERMISSIONS.VIEW_CONTENT,
    PERMISSIONS.EDIT_CONTENT,
    PERMISSIONS.APPROVE_CONTENT,
    PERMISSIONS.PUBLISH_CONTENT,
    PERMISSIONS.MANAGE_CAMPAIGNS,
    PERMISSIONS.PUBLISH_CAMPAIGNS,
    PERMISSIONS.EDIT_PROJECTS,
    PERMISSIONS.UPLOAD_PROJECT_MEDIA,
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
    PERMISSIONS.UPLOAD_PROJECT_MEDIA,
  ],
  [ROLES.ANALYST]: [
    PERMISSIONS.VIEW_ANALYTICS,
  ],
};

export function getMfaKeyMaterial() {
  return process.env.MFA_ENCRYPTION_KEY || process.env.SESSION_SECRET || ENV.MFA_ENCRYPTION_KEY || ENV.SESSION_SECRET;
}

export function resolveTotpSecret(storedSecret) {
  try {
    return decryptSecret(storedSecret, getMfaKeyMaterial());
  } catch {
    return '';
  }
}

export function encryptMfaSecret(plainSecret) {
  return encryptSecret(plainSecret, getMfaKeyMaterial());
}

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
export function resetRateLimitBuckets() {
  if (process.env.NODE_ENV !== 'production') {
    rateBuckets.clear();
  }
}
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
export const MFA_PENDING_COOKIE_NAME = 'sm_mfa_pending';

export function buildSessionCookie(sessionId, maxAgeSec = 28_800) {
  const isHttps = ENV.BASE_URL.startsWith('https://');
  const flags = [`${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionId)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
  if (isHttps) flags.push('Secure');
  return flags.join('; ');
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export function buildMfaPendingCookie(payloadObj, maxAgeSec = 900) {
  const secret = process.env.SESSION_SECRET || ENV.SESSION_SECRET;
  const encoded = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const sig = signHmac(encoded, secret);
  const token = `${encoded}.${sig}`;
  const isHttps = ENV.BASE_URL.startsWith('https://');
  const flags = [
    `${MFA_PENDING_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/admin/mfa-setup',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSec}`,
  ];
  if (isHttps) flags.push('Secure');
  return flags.join('; ');
}

export function readMfaPendingCookie(req) {
  const cookies = parseCookies(req);
  const raw = cookies[MFA_PENDING_COOKIE_NAME];
  if (!raw || !raw.includes('.')) return null;
  const [encoded, sig] = raw.split('.');
  const secret = process.env.SESSION_SECRET || ENV.SESSION_SECRET;
  if (!verifyHmac(encoded, sig, secret)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!parsed || !parsed.exp || Number(parsed.exp) < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function clearMfaPendingCookie() {
  return `${MFA_PENDING_COOKIE_NAME}=; Path=/admin/mfa-setup; HttpOnly; SameSite=Lax; Max-Age=0`;
}

export async function syncAuthPolicyState(db, actor = null) {
  const desired = isAdminMfaRequired() ? 1 : 0;
  const nowIso = new Date().toISOString();
  const existing = await db.prepare('SELECT mfa_required FROM auth_policy_state WHERE id = 1').get();

  if (!existing) {
    await db
      .prepare('INSERT OR IGNORE INTO auth_policy_state (id, mfa_required, updated_at) VALUES (1, ?, ?)')
      .run(desired, nowIso);
    const del = await db.prepare('DELETE FROM sessions WHERE mfa_verified != ?').run(desired);
    return { changed: del.changes > 0, mfaRequired: Boolean(desired), sessionsInvalidated: del.changes || 0 };
  }

  if (Number(existing.mfa_required) !== desired) {
    const del = await db.prepare('DELETE FROM sessions').run();
    await db.prepare('UPDATE auth_policy_state SET mfa_required = ?, updated_at = ? WHERE id = 1').run(desired, nowIso);
    await recordAudit(db, actor, 'auth', 'auth_policy_changed', 'auth_policy_state', '1', {
      previous_mfa_required: Boolean(existing.mfa_required),
      new_mfa_required: Boolean(desired),
      sessions_invalidated: true,
    });
    return { changed: true, mfaRequired: Boolean(desired), sessionsInvalidated: del.changes || 0 };
  }

  return { changed: false, mfaRequired: Boolean(desired), sessionsInvalidated: 0 };
}

export async function authenticateSession(db, req) {
  await syncAuthPolicyState(db);
  const cookies = parseCookies(req);
  const sid = cookies[SESSION_COOKIE_NAME];
  if (!sid) return null;

  const row = await db
    .prepare(
      `SELECT s.*, u.email, u.full_name, u.role, u.extra_roles_json, u.mfa_enabled, u.mfa_enrolled, u.last_login_at, u.active
       FROM sessions s
       JOIN users u ON u.user_id = s.user_id
       WHERE s.session_id = ?`
    )
    .get(sid);

  if (!row) return null;
  const expectedMfaVerified = isAdminMfaRequired() ? 1 : 0;
  if (!row.active || new Date(row.expires_at).getTime() <= Date.now() || Number(row.mfa_verified) !== expectedMfaVerified) {
    await db.prepare('DELETE FROM sessions WHERE session_id = ?').run(sid);
    return null;
  }
  return row;
}

export async function createPendingOrVerifiedSession(db, { email, password, totpCode, ip }) {
  await syncAuthPolicyState(db);
  const user = await db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').trim().toLowerCase());
  if (!user || !user.active) {
    return { ok: false, error: 'Invalid email or password.' };
  }
  if (user.must_set_password) {
    return {
      ok: false,
      error: 'Account onboarding is incomplete. Open your single-use setup link at /admin/mfa-setup to create your password and enroll Google Authenticator.',
    };
  }
  if (!verifyPassword(password, user.password_hash)) {
    return { ok: false, error: 'Invalid email or password.' };
  }

  const mfaRequired = isAdminMfaRequired();
  if (mfaRequired && user.mfa_enabled) {
    const decryptedSecret = resolveTotpSecret(user.totp_secret);
    if (!totpCode) {
      return {
        ok: false,
        requireMfa: true,
        mfaEnrolled: Boolean(user.mfa_enrolled),
        error: user.mfa_enrolled
          ? 'Enter your 6-digit authenticator MFA code.'
          : 'Enter your 6-digit authenticator MFA code. If you have not linked Google Authenticator yet, use your authorized setup link at /admin/mfa-setup.',
      };
    }
    if (!decryptedSecret || !verifyTotpCode(decryptedSecret, totpCode)) {
      return {
        ok: false,
        requireMfa: true,
        mfaEnrolled: Boolean(user.mfa_enrolled),
        error: 'Invalid or expired MFA code.',
      };
    }
  }

  const sessionId = randomToken(32);
  const csrfToken = randomToken(24);
  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = new Date(now.getTime() + 8 * 3600 * 1000).toISOString();
  const sessionMfaVerified = mfaRequired ? 1 : 0;

  if (mfaRequired && user.mfa_enabled && !user.mfa_enrolled) {
    await db
      .prepare(`UPDATE users SET mfa_enrolled = 1, mfa_enrolled_at = COALESCE(mfa_enrolled_at, ?), last_login_at = ?, updated_at = ? WHERE user_id = ?`)
      .run(nowIso, nowIso, nowIso, user.user_id);
  } else {
    await db
      .prepare(`UPDATE users SET last_login_at = ?, updated_at = ? WHERE user_id = ?`)
      .run(nowIso, nowIso, user.user_id);
  }

  await db.prepare(
    `INSERT INTO sessions (session_id, user_id, csrf_token, mfa_verified, expires_at, created_at, ip_hash)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(sessionId, user.user_id, csrfToken, sessionMfaVerified, expiresAt, nowIso, sha256Hex(ip || 'unknown'));

  await recordAudit(db, user, 'auth', 'login_success', 'session', sessionId, {
    mfa_required: mfaRequired,
    mfa_verified: Boolean(sessionMfaVerified),
  });

  return { ok: true, sessionId, csrfToken, user, mfaRequired };
}

export async function revokeUserSessions(db, userId) {
  await db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}

export async function issueMfaSetupToken(db, { userId, purpose = 'first_time_enroll', issuedBy = 'operator', ttlMinutes = 15 }) {
  const user = await db.prepare('SELECT user_id, email, full_name, role, mfa_enrolled, active FROM users WHERE user_id = ?').get(userId);
  if (!user || !user.active) {
    return { ok: false, status: 404, error: 'Active staff account not found.' };
  }
  const normalizedPurpose = purpose === 'recovery' ? 'recovery' : 'first_time_enroll';
  if (normalizedPurpose === 'first_time_enroll' && user.mfa_enrolled) {
    return {
      ok: false,
      status: 409,
      error: 'Account already has an enrolled MFA device. Use the administrator recovery flow instead.',
    };
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = new Date(now.getTime() + Math.max(5, Math.min(1440, Number(ttlMinutes) || 15)) * 60_000).toISOString();
  const rawToken = randomToken(32);
  const tokenHash = sha256Hex(rawToken);
  const tokenId = generateUuid();

  await db
    .prepare(`UPDATE mfa_recovery_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL`)
    .run(nowIso, user.user_id);

  await db
    .prepare(
      `INSERT INTO mfa_recovery_tokens (token_id, user_id, token_hash, purpose, issued_by, expires_at, used_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`
    )
    .run(tokenId, user.user_id, tokenHash, normalizedPurpose, String(issuedBy || 'operator'), expiresAt, nowIso);

  await recordAudit(
    db,
    { user_id: issuedBy, full_name: issuedBy, role: 'Administrator' },
    'auth',
    'mfa_setup_token_issued',
    'user',
    user.user_id,
    { token_id: tokenId, purpose: normalizedPurpose, expires_at: expiresAt }
  );

  return { ok: true, tokenId, rawToken, expiresAt, purpose: normalizedPurpose, user };
}

export async function validateMfaSetupToken(db, rawToken) {
  const clean = String(rawToken || '').trim();
  if (!clean || clean.length < 16) {
    return { ok: false, status: 403, error: 'Valid single-use MFA setup token is required.' };
  }
  const tokenHash = sha256Hex(clean);
  const row = await db
    .prepare(
      `SELECT t.*, u.email, u.full_name, u.role, u.mfa_enrolled, u.must_set_password, u.active
       FROM mfa_recovery_tokens t
       JOIN users u ON u.user_id = t.user_id
       WHERE t.token_hash = ?`
    )
    .get(tokenHash);

  if (!row || !row.active || row.used_at || new Date(row.expires_at).getTime() <= Date.now()) {
    return { ok: false, status: 403, error: 'MFA setup token is invalid, expired, or already used.' };
  }
  if (row.purpose === 'first_time_enroll' && row.mfa_enrolled) {
    return {
      ok: false,
      status: 409,
      error: 'MFA is already enrolled for this account. Request an administrator recovery token to re-enroll.',
    };
  }
  return { ok: true, tokenRow: row };
}

export async function beginMfaEnrollment(
  db,
  { email, password, newPassword = '', confirmPassword = '', setupToken, recoveryCode, currentTotp, session, ip }
) {
  const rl = checkRateLimit(`mfa_begin:${ip || 'unknown'}`, 15, 60_000);
  if (!rl.allowed) {
    return { ok: false, status: 429, error: `Too many MFA setup attempts. Wait ${rl.retryAfterSec}s.` };
  }

  const normalizedEmail = String(email || '').trim().toLowerCase();
  const user = await db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);
  if (!user || !user.active) {
    await recordAudit(db, null, 'auth', 'mfa_setup_failed_identity', 'user', normalizedEmail || 'unknown', { ip_hash: sha256Hex(ip || 'unknown') });
    return { ok: false, status: 401, error: 'Invalid staff email or credentials.' };
  }

  let pendingPasswordHash = null;
  if (user.must_set_password) {
    if (!setupToken || !String(setupToken).trim()) {
      await recordAudit(db, user, 'auth', 'mfa_setup_denied_unauth', 'user', user.user_id, { ip_hash: sha256Hex(ip || 'unknown') });
      return {
        ok: false,
        status: 403,
        error: 'Initial onboarding requires a valid single-use setup link issued by a Platform Administrator.',
      };
    }
    const np = String(newPassword || '');
    const cp = String(confirmPassword || '');
    if (np.length < 10) {
      return { ok: false, status: 422, mustSetPassword: true, error: 'Create a password with at least 10 characters.' };
    }
    if (np !== cp) {
      return { ok: false, status: 422, mustSetPassword: true, error: 'Password and confirmation do not match.' };
    }
    pendingPasswordHash = hashPassword(np);
  } else if (!verifyPassword(String(password || ''), user.password_hash)) {
    await recordAudit(db, null, 'auth', 'mfa_setup_failed_identity', 'user', normalizedEmail || 'unknown', { ip_hash: sha256Hex(ip || 'unknown') });
    return { ok: false, status: 401, error: 'Invalid staff email or password.' };
  }

  let authMode = null;
  let tokenRow = null;
  let recoveryCodeId = null;

  // Authorization Gate 1: Valid single-use setup/recovery token issued by operator or Platform Administrator
  if (setupToken && String(setupToken).trim()) {
    const tokenRes = await validateMfaSetupToken(db, setupToken);
    if (!tokenRes.ok || tokenRes.tokenRow.user_id !== user.user_id) {
      await recordAudit(db, user, 'auth', 'mfa_setup_denied_token', 'user', user.user_id, { reason: tokenRes.error || 'user_mismatch' });
      return { ok: false, status: tokenRes.status || 403, error: tokenRes.error || 'Setup token does not match this account.' };
    }
    tokenRow = tokenRes.tokenRow;
    authMode = tokenRow.purpose;
  } else if (recoveryCode && String(recoveryCode).trim()) {
    // Authorization Gate 2: Single-use emergency recovery code + password verification
    if (!user.mfa_enrolled) {
      return { ok: false, status: 403, error: 'First-time enrollment requires an authorized setup link issued by an administrator.' };
    }
    const recRes = verifyRecoveryCodeInList(recoveryCode, user.recovery_codes_json);
    if (!recRes.matched) {
      await recordAudit(db, user, 'auth', 'mfa_recovery_denied_code', 'user', user.user_id);
      return { ok: false, status: 403, error: 'Invalid or already-used MFA recovery code.' };
    }
    recoveryCodeId = recRes.codeId;
    authMode = 'recovery_code';
  } else if (session && session.mfa_verified === 1) {
    // Authorization Gate 3: Already-authenticated session verifying password + current TOTP for self re-enrollment
    if (session.user_id !== user.user_id) {
      await recordAudit(db, session, 'auth', 'mfa_setup_denied_cross_user', 'user', user.user_id);
      return { ok: false, status: 403, error: 'You may only enroll or rotate your own authenticator device here.' };
    }
    if (user.mfa_enrolled) {
      const currentPlain = resolveTotpSecret(user.totp_secret);
      if (!currentTotp || !verifyTotpCode(currentPlain, currentTotp)) {
        return { ok: false, status: 401, error: 'Enter your current 6-digit authenticator code to rotate MFA.' };
      }
    }
    authMode = 'authenticated_self';
  } else {
    // Unauthorized / unauthenticated direct attempt -> STRICTLY DENIED
    await recordAudit(db, user, 'auth', 'mfa_setup_denied_unauth', 'user', user.user_id, { ip_hash: sha256Hex(ip || 'unknown') });
    return {
      ok: false,
      status: 403,
      error: 'Unauthorized: first-time enrollment requires a single-use administrator setup token or signed-in MFA verification.',
    };
  }

  const pendingPlainSecret = generateTotpSecret();
  const encryptedPending = encryptMfaSecret(pendingPlainSecret);
  const nowIso = new Date().toISOString();

  await db
    .prepare(`UPDATE users SET mfa_pending_secret = ?, updated_at = ? WHERE user_id = ?`)
    .run(encryptedPending, nowIso, user.user_id);

  await recordAudit(db, user, 'auth', 'mfa_enrollment_started', 'user', user.user_id, {
    mode: authMode,
    token_id: tokenRow?.token_id || null,
  });

  const csrfToken = randomToken(24);
  const otpauthUri = buildTotpOtpAuthUri({
    issuer: 'ServiceMaintenance',
    email: user.email,
    secret: pendingPlainSecret,
  });

  return {
    ok: true,
    user,
    pendingPlainSecret,
    otpauthUri,
    csrfToken,
    pendingContext: {
      uid: user.user_id,
      csrf: csrfToken,
      mode: authMode,
      tokenId: tokenRow?.token_id || null,
      recoveryCodeId,
      pendingPasswordHash,
      exp: Date.now() + 15 * 60_000,
    },
  };
}

export async function completeMfaEnrollment(db, { pendingContext, totpCode, ip }) {
  const rl = checkRateLimit(`mfa_complete:${ip || 'unknown'}`, 20, 60_000);
  if (!rl.allowed) {
    return { ok: false, status: 429, error: `Too many verification attempts. Wait ${rl.retryAfterSec}s.` };
  }
  if (!pendingContext || !pendingContext.uid) {
    return { ok: false, status: 403, error: 'MFA setup session missing or expired. Restart enrollment with an authorized link.' };
  }

  const user = await db.prepare('SELECT * FROM users WHERE user_id = ?').get(pendingContext.uid);
  if (!user || !user.active || !user.mfa_pending_secret) {
    return { ok: false, status: 400, error: 'No pending MFA enrollment found. Please restart setup.' };
  }

  const pendingPlain = resolveTotpSecret(user.mfa_pending_secret);
  if (!pendingPlain || !verifyTotpCode(pendingPlain, totpCode)) {
    return {
      ok: false,
      status: 422,
      error: 'Invalid 6-digit verification code. Confirm your Google Authenticator clock is synced and try again.',
      pendingPlainSecret: pendingPlain,
      otpauthUri: buildTotpOtpAuthUri({ issuer: 'ServiceMaintenance', email: user.email, secret: pendingPlain }),
      user,
    };
  }

  const now = new Date();
  const nowIso = now.toISOString();

  // Consume recovery code if used
  let existingCodes = [];
  try {
    existingCodes = JSON.parse(user.recovery_codes_json || '[]');
  } catch {
    existingCodes = [];
  }
  if (pendingContext.recoveryCodeId) {
    const targetEntry = Array.isArray(existingCodes) ? existingCodes.find((e) => e.id === pendingContext.recoveryCodeId) : null;
    if (!targetEntry || targetEntry.used_at) {
      return { ok: false, status: 403, error: 'Recovery code has already been used.' };
    }
  }

  // Generate fresh recovery codes and encrypt confirmed MFA secret
  const plainRecoveryCodes = generateRecoveryCodes(8);
  const hashedRecoveryCodes = hashRecoveryCodeList(plainRecoveryCodes);
  const encryptedConfirmed = encryptMfaSecret(pendingPlain);

  // Consume single-use token atomically (verify still unused)
  if (pendingContext.tokenId) {
    const tokenRes = await db
      .prepare(`UPDATE mfa_recovery_tokens SET used_at = ? WHERE token_id = ? AND used_at IS NULL`)
      .run(nowIso, pendingContext.tokenId);
    if (!tokenRes.changes) {
      return { ok: false, status: 403, error: 'Setup token was already consumed. Request a new token to re-enroll.' };
    }
  }

  if (pendingContext.pendingPasswordHash && user.must_set_password) {
    await db
      .prepare(
        `UPDATE users
         SET password_hash = ?, must_set_password = 0, totp_secret = ?, mfa_pending_secret = NULL,
             mfa_enabled = 1, mfa_enrolled = 1, mfa_enrolled_at = COALESCE(mfa_enrolled_at, ?),
             last_login_at = ?, recovery_codes_json = ?, updated_at = ?
         WHERE user_id = ?`
      )
      .run(
        pendingContext.pendingPasswordHash,
        encryptedConfirmed,
        nowIso,
        nowIso,
        JSON.stringify(hashedRecoveryCodes),
        nowIso,
        user.user_id
      );
  } else {
    await db
      .prepare(
        `UPDATE users
         SET totp_secret = ?, mfa_pending_secret = NULL, mfa_enabled = 1, mfa_enrolled = 1,
             mfa_enrolled_at = COALESCE(mfa_enrolled_at, ?), last_login_at = ?, recovery_codes_json = ?, updated_at = ?
         WHERE user_id = ?`
      )
      .run(encryptedConfirmed, nowIso, nowIso, JSON.stringify(hashedRecoveryCodes), nowIso, user.user_id);
  }

  // Revoke any prior sessions across all devices, then issue a fresh verified session
  await revokeUserSessions(db, user.user_id);

  const sessionId = randomToken(32);
  const sessionCsrf = randomToken(24);
  const expiresAt = new Date(now.getTime() + 8 * 3600 * 1000).toISOString();

  await db
    .prepare(
      `INSERT INTO sessions (session_id, user_id, csrf_token, mfa_verified, expires_at, created_at, ip_hash)
       VALUES (?, ?, ?, 1, ?, ?, ?)`
    )
    .run(sessionId, user.user_id, sessionCsrf, expiresAt, nowIso, sha256Hex(ip || 'unknown'));

  await recordAudit(db, user, 'auth', 'mfa_enrollment_completed', 'user', user.user_id, {
    mode: pendingContext.mode,
    token_id: pendingContext.tokenId || null,
    password_initialized: Boolean(pendingContext.pendingPasswordHash),
    sessions_revoked: true,
    recovery_codes_rotated: true,
  });

  return {
    ok: true,
    user,
    sessionId,
    sessionCsrf,
    recoveryCodes: plainRecoveryCodes,
  };
}
