import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ENV, isAdminMfaRequired, ROLES, ROOT_DIR } from '../config.js';
import { escapeHtml } from '../lib/sanitize.js';
import { formatPhoenixDateTime, utcIsoToPhoenixInput } from '../lib/time.js';
import { getUserRoles, hasPermission, PERMISSIONS } from '../services/auth.js';

function computeAdminAssetVersion() {
  try {
    const hash = crypto.createHash('sha1');
    for (const rel of ['public/css/tokens.css', 'public/css/main.css', 'public/css/admin.css', 'public/js/admin.js']) {
      hash.update(fs.readFileSync(path.join(ROOT_DIR, rel)));
    }
    return hash.digest('hex').slice(0, 10);
  } catch {
    return '1';
  }
}

const ADMIN_ASSET_VERSION = computeAdminAssetVersion();

const ROLE_DISPLAY_NAMES = {
  [ROLES.PLATFORM_ADMIN]: 'Platform Administrator',
  [ROLES.CONTENT_EDITOR]: 'Content Editor',
  [ROLES.APPROVER_PUBLISHER]: 'Approver and Publisher',
  [ROLES.HIRING_OWNER]: 'Hiring Owner / Administrator',
  [ROLES.PROJECT_CONTRIBUTOR]: 'Project Contributor',
  [ROLES.HIRING_REVIEWER]: 'Hiring Reviewer',
  [ROLES.ANALYST]: 'Analyst',
};

const ROLE_DESCRIPTIONS = {
  [ROLES.PLATFORM_ADMIN]: 'Manage staff accounts, roles, business settings, CRM delivery queues, backups, and system logs. No hiring or publishing access by default.',
  [ROLES.CONTENT_EDITOR]: 'Create and update draft website pages, articles, factual claims, seasonal campaigns, and project drafts, and send work for approval.',
  [ROLES.APPROVER_PUBLISHER]: 'Review and publish approved website copy, factual claims, project photos, and seasonal campaigns, or return drafts for edits.',
  [ROLES.HIRING_OWNER]: 'Create, schedule, open, pause, and close assigned job openings; review applicants; assign reviewers; and export authorized applicant lists.',
  [ROLES.PROJECT_CONTRIBUTOR]: 'Create completed-project drafts, upload photos, adjust framing, and pair before/after images for review.',
  [ROLES.HIRING_REVIEWER]: 'Review applicants and record factual interview notes strictly for assigned job openings.',
  [ROLES.ANALYST]: 'Monitor non-identifying inquiry trends, website engagement events, seasonal campaign performance, and project readiness.',
};

const ROLE_GUIDE = {
  [ROLES.PLATFORM_ADMIN]: {
    purpose: 'Keeps staff access, company contact details, backups, and commercial lead queues running reliably.',
    canDo: [
      'Create and edit staff accounts, assign roles, and revoke active sessions',
      'Issue Google Authenticator MFA setup or recovery links',
      'Update company phone, hours, address, and ROC credentials',
      'Inspect and replay failed CRM or email notifications, run backups, and manage data retention',
    ],
    cannotDo: [
      'Cannot view private job applicants, interview notes, or resumes',
      'Cannot edit or publish website pages, projects, or seasonal campaigns',
    ],
    modules: ['Overview', 'Pages & Content (Read-only)', 'Leads & CRM', 'Analytics & Reports', 'Reviews & Activity (Audit Log)', 'Users & Roles', 'Settings & Backups'],
    extraPerms: 'Assign Approver & Publisher to publish website content, or Hiring Owner to manage vacancies.',
  },
  [ROLES.CONTENT_EDITOR]: {
    purpose: 'Prepares and updates website service copy, insights articles, claims, and seasonal promotion drafts.',
    canDo: [
      'Edit draft website pages, insights articles, factual claims, and URL redirects',
      'Save drafts with automatic conflict protection and preview desktop/mobile layouts',
      'Draft seasonal campaigns and submit pages, articles, or projects for approval',
    ],
    cannotDo: [
      'Cannot publish changes live to the public website without an Approver',
      'Cannot manage staff users, commercial leads, settings, or hiring records',
    ],
    modules: ['Overview', 'Pages & Content', 'Projects & Media', 'Seasonal Campaigns'],
    extraPerms: 'Requires Approver & Publisher to approve rights/claims and publish live.',
  },
  [ROLES.APPROVER_PUBLISHER]: {
    purpose: 'Reviews accuracy, client permissions, and media rights before anything goes live on the public site.',
    canDo: [
      'Review pending pages, articles, projects, and seasonal campaigns in one queue',
      'Return work to Draft with review comments or approve & publish live',
      'Approve or withdraw factual claims and photo publication rights',
      'Restore previous page versions to Draft safely',
    ],
    cannotDo: [
      'Cannot create or edit staff accounts or assign roles',
      'Cannot access private hiring records or company backup settings',
    ],
    modules: ['Overview', 'Pages & Content', 'Projects & Media', 'Seasonal Campaigns', 'Reviews & Activity'],
    extraPerms: 'Requires Platform Administrator for user or site settings changes.',
  },
  [ROLES.HIRING_OWNER]: {
    purpose: 'Runs job openings and coordinates applicant reviews from opening through closure.',
    canDo: [
      'Create, edit, schedule, open, pause, reopen, and close assigned job vacancies',
      'Review candidate answers and virus-scanned resumes securely',
      'Assign Hiring Reviewers, update stages, record notes, and export applicant CSVs',
    ],
    cannotDo: [
      'Cannot publish website pages, projects, or seasonal campaigns',
      'Cannot manage unrelated staff accounts or company settings',
    ],
    modules: ['Overview', 'Careers & Applications'],
    extraPerms: 'Isolated recruiting domain; assign Content Editor separately if website edits are also needed.',
  },
  [ROLES.PROJECT_CONTRIBUTOR]: {
    purpose: 'Documents finished commercial maintenance and TI work from desktop or mobile phones.',
    canDo: [
      'Create project case-study drafts and select related services',
      'Upload JPEG, PNG, WebP, or HEIC site photos (GPS metadata stripped automatically)',
      'Adjust focal points, reorder galleries, and pair Before & After images for review',
    ],
    cannotDo: [
      'Cannot publish projects live or approve image rights',
      'Cannot edit main website pages, leads, users, or hiring records',
    ],
    modules: ['Overview', 'Projects & Media'],
    extraPerms: 'Submitted projects are published live by an Approver & Publisher.',
  },
  [ROLES.HIRING_REVIEWER]: {
    purpose: 'Screens candidates assigned to specific open positions.',
    canDo: [
      'View applicant details, immutable submission snapshots, and scanned resumes for assigned jobs',
      'Record factual interview notes and update review stages',
    ],
    cannotDo: [
      'Cannot view candidates from unassigned job requisitions',
      'Cannot create/close vacancies, assign other reviewers, or export applicant CSVs',
    ],
    modules: ['Overview', 'Careers & Applications'],
    extraPerms: 'Requires Hiring Owner role to manage job openings or export CSV lists.',
  },
  [ROLES.ANALYST]: {
    purpose: 'Tracks lead volume, attribution channels, and content readiness safely without customer PII.',
    canDo: [
      'Inspect inquiry funnel trends by service family and UTM acquisition source',
      'View non-identifying website events, campaign clicks, and project readiness',
    ],
    cannotDo: [
      'Cannot view customer names, emails, phones, or inquiry attachments',
      'Cannot view job applicants, edit website copy, or change settings',
    ],
    modules: ['Overview', 'Analytics & Reports'],
    extraPerms: 'Read-only reporting role; pair with Content Editor or Leads role only if operational editing is needed.',
  },
};

const PERMISSION_META = [
  { key: PERMISSIONS.VIEW_CONTENT, label: 'View Content & Previews' },
  { key: PERMISSIONS.EDIT_CONTENT, label: 'Create & Edit Content' },
  { key: PERMISSIONS.APPROVE_CONTENT, label: 'Approve Content & Return Drafts' },
  { key: PERMISSIONS.PUBLISH_CONTENT, label: 'Publish & Restore Content' },
  { key: PERMISSIONS.EDIT_PROJECTS, label: 'Manage Projects & B/A Pairs' },
  { key: PERMISSIONS.UPLOAD_PROJECT_MEDIA, label: 'Upload & Crop Project Media' },
  { key: PERMISSIONS.PUBLISH_PROJECTS, label: 'Approve Rights & Publish Projects' },
  { key: PERMISSIONS.MANAGE_CAMPAIGNS, label: 'Create & Edit Campaigns' },
  { key: PERMISSIONS.PUBLISH_CAMPAIGNS, label: 'Approve & Schedule Campaigns' },
  { key: PERMISSIONS.MANAGE_VACANCIES, label: 'Manage Assigned Jobs & Resumes' },
  { key: PERMISSIONS.REVIEW_APPLICATIONS, label: 'Review Assigned Applications' },
  { key: PERMISSIONS.EXPORT_APPLICATIONS, label: 'Export Permitted Applicants CSV' },
  { key: PERMISSIONS.MANAGE_LEADS_CRM, label: 'Manage Leads & CRM Queue' },
  { key: PERMISSIONS.VIEW_ANALYTICS, label: 'View PII-Free Analytics' },
  { key: PERMISSIONS.MANAGE_USERS, label: 'Manage Users & Roles' },
  { key: PERMISSIONS.MANAGE_SETTINGS, label: 'Manage Business Settings' },
  { key: PERMISSIONS.MANAGE_BACKUPS, label: 'Manage Backups & Retention' },
  { key: PERMISSIONS.VIEW_AUDIT, label: 'View Non-Hiring Audit Logs' },
];

function getRoleDisplayLabel(role) {
  return ROLE_DISPLAY_NAMES[role] || role;
}

export function renderPaginationNav(basePath, meta, extraParams = {}) {
  if (!meta || meta.totalPages <= 1) {
    return meta ? `<p class="muted" style="font-size:0.84rem;margin:0.6rem 0 0;">Showing ${meta.total} record(s).</p>` : '';
  }
  const makeHref = (targetPage) => {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(extraParams)) {
      if (v !== undefined && v !== null && String(v) !== '') params.set(k, String(v));
    }
    params.set('page', String(targetPage));
    return `${basePath}?${params.toString()}`;
  };

  return `<nav aria-label="Pagination" style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;margin-top:0.85rem;">
    <span class="muted" style="font-size:0.85rem;">Page ${meta.page} of ${meta.totalPages} (${meta.total} total)</span>
    <div style="display:flex;gap:0.5rem;">
      ${meta.page > 1
      ? `<a href="${escapeHtml(makeHref(meta.page - 1))}" class="btn btn--secondary btn--compact">Previous</a>`
      : '<span class="btn btn--secondary btn--compact" aria-disabled="true" style="opacity:0.45;pointer-events:none;">Previous</span>'
    }
      ${meta.page < meta.totalPages
      ? `<a href="${escapeHtml(makeHref(meta.page + 1))}" class="btn btn--secondary btn--compact">Next</a>`
      : '<span class="btn btn--secondary btn--compact" aria-disabled="true" style="opacity:0.45;pointer-events:none;">Next</span>'
    }
    </div>
  </nav>`;
}

export function renderAdminLoginPage({ error = '', requireMfa = false, mfaRequired = isAdminMfaRequired(), email = '', nonce = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Staff Dashboard Sign In | Service Maintenance</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/svg+xml" href="/assets/brand-mark.svg">
  <link rel="stylesheet" href="/css/tokens.css?v=${ADMIN_ASSET_VERSION}">
  <link rel="stylesheet" href="/css/main.css?v=${ADMIN_ASSET_VERSION}">
  <link rel="stylesheet" href="/css/admin.css?v=${ADMIN_ASSET_VERSION}">
</head>
<body>
  <main id="main-content" class="section">
    <div class="container" style="max-width:34rem;">
      <span class="eyebrow">Protected Operations Workspace</span>
      <h1>Staff Dashboard Sign In</h1>
      <p class="muted">${mfaRequired
      ? 'Individual company identity and 6-digit MFA verification required. No shared administrator accounts.'
      : 'Individual company identity required. Multi-factor authentication is temporarily disabled (Email + Password mode).'
    }</p>

      ${!mfaRequired
      ? `<div class="status-banner status-banner--warning" role="status"><strong>Temporary Auth Policy Active:</strong> MFA check is disabled via <code>ADMIN_MFA_REQUIRED=false</code>. Re-enable <code>ADMIN_MFA_REQUIRED=true</code> to restore full PRD compliance.</div>`
      : ''
    }
      ${error ? `<div class="status-banner status-banner--error" role="alert">${escapeHtml(error)}</div>` : ''}

      <form method="POST" action="/admin/login" class="admin-card">
        <div class="field">
          <label for="login-email">Staff Email</label>
          <input type="email" id="login-email" name="email" value="${escapeHtml(email)}" required autocomplete="username">
        </div>
        <div class="field">
          <label for="login-pass">Password</label>
          <input type="password" id="login-pass" name="password" required autocomplete="current-password">
        </div>
        ${mfaRequired
      ? `<div class="field">
                <label for="login-totp">6-Digit Authenticator MFA Code ${requireMfa ? '(Required)' : ''}</label>
                <span class="hint">Time-based TOTP authenticator code.</span>
                <input type="text" id="login-totp" name="totp_code" inputmode="numeric" pattern="\\d{6}" maxlength="6" autocomplete="one-time-code" required>
              </div>`
      : ''
    }
        <button type="submit" class="btn btn--primary" style="width:100%;">${mfaRequired ? 'Sign in with MFA' : 'Sign in with Email & Password'}</button>
      </form>

      ${mfaRequired
      ? `<p style="margin-top:0.85rem;font-size:0.9rem;">
              <a href="/admin/mfa-setup">First-time Google Authenticator setup or MFA recovery &rarr;</a>
            </p>`
      : `<p style="margin-top:0.85rem;font-size:0.9rem;" class="muted">
              MFA enrollment &amp; recovery data are preserved in the database and can be pre-configured or restored via <a href="/admin/mfa-setup">/admin/mfa-setup</a>.
            </p>`
    }
      <p><a href="/">&larr; Return to public website</a></p>
    </div>
  </main>
  <script nonce="${escapeHtml(nonce)}"></script>
</body>
</html>`;
}

export function renderAdminMfaSetupPage({
  stage = 'verify_identity',
  error = '',
  info = '',
  email = '',
  setupToken = '',
  tokenPurpose = '',
  mustSetPassword = false,
  signedInUser = null,
  qrDataUri = '',
  manualSecret = '',
  recoveryCodes = [],
  csrfToken = '',
  nonce = '',
}) {
  const formattedManualSecret = String(manualSecret || '').replace(/(.{4})/g, '$1 ').trim();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Google Authenticator MFA Setup &amp; Recovery | Service Maintenance</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/svg+xml" href="/assets/brand-mark.svg">
  <link rel="stylesheet" href="/css/tokens.css?v=${ADMIN_ASSET_VERSION}">
  <link rel="stylesheet" href="/css/main.css?v=${ADMIN_ASSET_VERSION}">
  <link rel="stylesheet" href="/css/admin.css?v=${ADMIN_ASSET_VERSION}">
</head>
<body>
  <main id="main-content" class="section">
    <div class="container" style="max-width:40rem;">
      <span class="eyebrow">Authorized Multi-Factor Authentication</span>
      <h1>Google Authenticator Setup &amp; Recovery</h1>
      <p class="muted">Connecting or rotating MFA requires identity verification and live 6-digit TOTP confirmation. Unauthorized users cannot initiate setup.</p>

      ${error ? `<div class="status-banner status-banner--error" role="alert">${escapeHtml(error)}</div>` : ''}
      ${info ? `<div class="status-banner status-banner--success" role="status">${escapeHtml(info)}</div>` : ''}

      ${stage === 'verify_identity'
      ? `<form method="POST" action="/admin/mfa-setup" class="admin-card">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <input type="hidden" name="step" value="begin">
              <h2 style="font-size:1.25rem;">Step 1: Verify Identity &amp; Authorization</h2>
              <div class="field">
                <label for="mfa-email">Staff Email</label>
                <input type="email" id="mfa-email" name="email" value="${escapeHtml(email)}" required autocomplete="username" autocorrect="off" autocapitalize="none" spellcheck="false">
              </div>
              ${mustSetPassword
        ? `<input type="hidden" name="must_set_password" value="1">
                     <div class="field">
                       <label for="mfa-new-pass">Create Your Password (minimum 10 characters)</label>
                       <input type="password" id="mfa-new-pass" name="new_password" minlength="10" required autocomplete="new-password">
                     </div>
                     <div class="field">
                       <label for="mfa-confirm-pass">Confirm Password</label>
                       <input type="password" id="mfa-confirm-pass" name="confirm_password" minlength="10" required autocomplete="new-password">
                     </div>`
        : `<div class="field">
                       <label for="mfa-pass">Account Password</label>
                       <input type="password" id="mfa-pass" name="password" required autocomplete="current-password">
                     </div>`
      }

              ${setupToken
        ? `<input type="hidden" name="setup_token" value="${escapeHtml(setupToken)}">
                     <p class="muted" style="font-size:0.86rem;">Authorization mode: <strong>${escapeHtml(tokenPurpose === 'recovery' ? 'Administrator Recovery Token' : 'First-Time Enrollment Token')}</strong></p>`
        : signedInUser && signedInUser.mfa_verified === 1
          ? `<div class="field">
                        <label for="mfa-current-totp">Current 6-Digit Authenticator Code (if already enrolled)</label>
                        <span class="hint">Confirm your current authenticator device before rotating to a new QR code.</span>
                        <input type="text" id="mfa-current-totp" name="current_totp" inputmode="numeric" pattern="\\d{6}" maxlength="6" autocomplete="one-time-code">
                      </div>`
          : `<fieldset class="choice-group">
                        <legend>Authorization Credential (Required)</legend>
                        <div class="field">
                          <label for="mfa-setup-token">One-Time Setup / Recovery Token</label>
                          <span class="hint">Issued by an administrator or the server operator CLI (<code>npm run admin:mfa-setup</code>).</span>
                          <input type="text" id="mfa-setup-token" name="setup_token" value="${escapeHtml(setupToken)}" autocorrect="off" autocapitalize="none" spellcheck="false">
                        </div>
                        <div class="field" style="margin-block-end:0;">
                          <label for="mfa-recovery-code">Or Emergency Single-Use Recovery Code (if already enrolled)</label>
                          <span class="hint">Format: <code>XXXX-XXXX-XX</code> saved from your prior enrollment.</span>
                          <input type="text" id="mfa-recovery-code" name="recovery_code" placeholder="XXXX-XXXX-XX" autocorrect="off" autocapitalize="characters" spellcheck="false">
                        </div>
                      </fieldset>`
      }

              <button type="submit" class="btn btn--primary" style="width:100%;">Verify Identity &amp; Generate QR Code</button>
            </form>`
      : stage === 'verify_qr'
        ? `<div class="admin-card">
                <h2 style="font-size:1.25rem;">Step 2: Link Google Authenticator</h2>
                <p>Account: <strong>${escapeHtml(email)}</strong></p>
                <ol style="padding-inline-start:1.25rem;">
                  <li>Open <strong>Google Authenticator</strong> on your phone and tap <strong>+</strong>.</li>
                  <li>Choose <strong>Scan a QR code</strong> and scan the code below, <strong>or</strong> choose <strong>Enter a setup key</strong> (Time-based) with the manual key.</li>
                  <li>Enter the live <strong>6-digit code</strong> displayed in Google Authenticator to lock in MFA.</li>
                </ol>

                <div style="display:flex;flex-wrap:wrap;gap:1.5rem;align-items:center;margin-block:1.25rem;">
                  <div style="background:#FAF8F3;padding:0.75rem;border:1px solid rgba(36,37,31,0.2);border-radius:6px;">
                    <img src="${escapeHtml(qrDataUri)}" alt="Google Authenticator QR code for ${escapeHtml(email)}" width="220" height="220">
                  </div>
                  <div style="flex:1 1 220px;min-width:0;">
                    <p style="font-weight:700;margin-bottom:0.35rem;">Manual Setup Key (Time-based TOTP)</p>
                    <p class="muted" style="font-size:0.84rem;margin-bottom:0.5rem;">If camera scanning is unavailable, enter this key manually in Google Authenticator:</p>
                    <code style="display:block;padding:0.65rem 0.75rem;background:var(--color-bone);border:1px solid rgba(36,37,31,0.2);border-radius:4px;font-size:0.95rem;letter-spacing:0.06em;word-break:break-all;">${escapeHtml(formattedManualSecret)}</code>
                  </div>
                </div>

                <form method="POST" action="/admin/mfa-setup">
                  <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                  <input type="hidden" name="step" value="confirm">
                  <div class="field">
                    <label for="mfa-confirm-totp">6-Digit Code from Google Authenticator</label>
                    <span class="hint">Confirm your device shows the matching 6-digit time-based code before enrollment takes effect.</span>
                    <input type="text" id="mfa-confirm-totp" name="totp_code" inputmode="numeric" pattern="\\d{6}" maxlength="6" autocomplete="one-time-code" required>
                  </div>
                  <button type="submit" class="btn btn--primary" style="width:100%;">Verify &amp; Activate Google Authenticator</button>
                </form>
              </div>`
        : `<div class="admin-card">
                <h2 style="font-size:1.25rem;">Google Authenticator Enrolled &amp; Active</h2>
                <p>MFA enrollment succeeded for <strong>${escapeHtml(email)}</strong>. Prior sessions were revoked and your authenticated session is now active.</p>
                <div class="status-banner status-banner--warning" role="status">
                  <strong>Save These One-Time Recovery Codes Offline Now:</strong> Each code can authorize MFA device recovery once if you lose your phone. They cannot be viewed again after leaving this page.
                </div>
                <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:0.55rem;margin-bottom:1.25rem;">
                  ${recoveryCodes
          .map(
            (c) => `<code style="padding:0.45rem 0.6rem;background:var(--color-bone);border:1px solid rgba(36,37,31,0.18);border-radius:4px;text-align:center;font-weight:700;">${escapeHtml(c)}</code>`
          )
          .join('')}
                </div>
                <a href="/admin/" class="btn btn--primary" style="width:100%;">Continue to Admin Dashboard</a>
              </div>`
    }

      <p style="margin-top:1rem;">
        <a href="/admin/login">&larr; Return to Staff Sign In</a>
        ${signedInUser ? ' &middot; <a href="/admin/">Return to Dashboard</a>' : ''}
      </p>
    </div>
  </main>
  <script nonce="${escapeHtml(nonce)}"></script>
</body>
</html>`;
}

export function renderAdminShell({ title, subtitle = '', user, csrfToken, currentSection, bodyHtml, nonce = '', flash = '' }) {
  const navIcons = {
    overview: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>',
    pages: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg>',
    projects: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>',
    campaigns: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 2l3 6 6 .9-4.5 4.3 1.1 6.3L12 16.5 6.4 19.5l1.1-6.3L3 8.9 9 8z"/></svg>',
    leads: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
    jobs: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/></svg>',
    analytics: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
    reviews: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>',
    users: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    settings: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  };

  const navItems = [
    { id: 'overview', href: '/admin/', label: 'Dashboard', show: true },
    { id: 'pages', href: '/admin/pages', label: 'Pages & Content', show: hasPermission(user, PERMISSIONS.VIEW_CONTENT) || hasPermission(user, PERMISSIONS.EDIT_CONTENT) },
    { id: 'projects', href: '/admin/projects', label: 'Projects & Media', show: hasPermission(user, PERMISSIONS.EDIT_PROJECTS) || hasPermission(user, PERMISSIONS.UPLOAD_PROJECT_MEDIA) || hasPermission(user, PERMISSIONS.PUBLISH_PROJECTS) },
    { id: 'campaigns', href: '/admin/campaigns', label: 'Seasonal Campaigns', show: hasPermission(user, PERMISSIONS.MANAGE_CAMPAIGNS) || hasPermission(user, PERMISSIONS.PUBLISH_CAMPAIGNS) },
    { id: 'leads', href: '/admin/leads', label: 'Leads & CRM Queue', show: hasPermission(user, PERMISSIONS.MANAGE_LEADS_CRM) },
    { id: 'jobs', href: '/admin/jobs', label: 'Careers & Applications', show: hasPermission(user, PERMISSIONS.MANAGE_VACANCIES) || hasPermission(user, PERMISSIONS.REVIEW_APPLICATIONS) },
    { id: 'analytics', href: '/admin/analytics', label: 'Analytics & Reports', show: hasPermission(user, PERMISSIONS.VIEW_ANALYTICS) || hasPermission(user, PERMISSIONS.MANAGE_LEADS_CRM) || hasPermission(user, PERMISSIONS.MANAGE_VACANCIES) || hasPermission(user, PERMISSIONS.REVIEW_APPLICATIONS) },
    { id: 'reviews', href: '/admin/reviews', label: 'Reviews & Activity', show: hasPermission(user, PERMISSIONS.APPROVE_CONTENT) || hasPermission(user, PERMISSIONS.PUBLISH_CONTENT) || hasPermission(user, PERMISSIONS.VIEW_AUDIT) },
    { id: 'users', href: '/admin/users', label: 'Users & Roles', show: hasPermission(user, PERMISSIONS.MANAGE_USERS) },
    { id: 'settings', href: '/admin/settings', label: 'Settings & Backups', show: hasPermission(user, PERMISSIONS.MANAGE_USERS) || hasPermission(user, PERMISSIONS.MANAGE_SETTINGS) || hasPermission(user, PERMISSIONS.MANAGE_BACKUPS) },
  ].filter((item) => item.show);

  const userRoles = getUserRoles(user);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} | Staff Dashboard | Service Maintenance</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/svg+xml" href="/assets/brand-mark.svg">
  <link rel="stylesheet" href="/css/tokens.css?v=${ADMIN_ASSET_VERSION}">
  <link rel="stylesheet" href="/css/main.css?v=${ADMIN_ASSET_VERSION}">
  <link rel="stylesheet" href="/css/admin.css?v=${ADMIN_ASSET_VERSION}">
</head>
<body data-csrf="${escapeHtml(csrfToken)}">
  <a href="#admin-main" class="skip-link">Skip to dashboard content</a>
  <div class="admin-shell">
    <aside class="admin-sidebar">
      <div class="admin-sidebar__header">
        <div>
          <div class="admin-sidebar__brand">Service Maintenance</div>
          <div class="admin-sidebar__role">
            <strong>${escapeHtml(user.full_name)}</strong><br>
            <span>${escapeHtml(userRoles.map(getRoleDisplayLabel).join(' + '))}</span>
          </div>
        </div>
        <button type="button" id="admin-nav-toggle" class="btn btn--ghost-light admin-mobile-toggle" aria-expanded="false" aria-controls="admin-nav-panel">Menu</button>
      </div>
      <nav id="admin-nav-panel" class="admin-nav-panel" aria-label="Staff workspace">
        <ul class="admin-nav">
          ${navItems
      .map(
        (n) =>
          `<li><a href="${escapeHtml(n.href)}"${currentSection === n.id ? ' aria-current="page"' : ''}>${navIcons[n.id] || ''}<span>${escapeHtml(n.label)}</span></a></li>`
      )
      .join('')}
        </ul>
      </nav>
      <div class="admin-sidebar__footer">
        <a href="/" class="admin-sidebar__public-link">View Public Site &rarr;</a>
        <form method="POST" action="/admin/logout">
          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
          <button type="submit" class="btn btn--ghost-light" style="width:100%;font-size:0.85rem;">Sign out</button>
        </form>
      </div>
    </aside>

    <main id="admin-main" class="admin-main" tabindex="-1">
      <header class="admin-topbar">
        <div class="admin-topbar__title-group">
          <h1>${escapeHtml(title)}</h1>
          ${subtitle ? `<p class="admin-topbar__subtitle">${escapeHtml(subtitle)}</p>` : ''}
        </div>
        <div class="admin-topbar__meta">
          <span class="admin-meta-pill">America/Phoenix &middot; ${escapeHtml(formatPhoenixDateTime(new Date(), false))}</span>
        </div>
      </header>
      <div id="admin-toast-region" role="region" aria-label="Notifications">
        <div id="admin-inline-alert" class="admin-inline-alert" hidden tabindex="-1" role="status" aria-live="polite">
          <span id="admin-inline-alert-text"></span>
          <button type="button" id="admin-inline-alert-close" class="btn btn--secondary btn--compact" aria-label="Dismiss notification">Dismiss</button>
        </div>
      </div>
      ${!isAdminMfaRequired()
      ? `<div class="status-banner status-banner--warning" role="status"><strong>Temporary Auth Deviation:</strong> Staff MFA enforcement is currently disabled (<code>ADMIN_MFA_REQUIRED=false</code>). Re-enable <code>ADMIN_MFA_REQUIRED=true</code> in environment configuration for PRD compliance.</div>`
      : ''
    }
      ${flash ? `<div class="status-banner status-banner--success" role="status">${escapeHtml(flash)}</div>` : ''}
      ${bodyHtml}
    </main>
  </div>

  <dialog id="admin-confirm-dialog" aria-labelledby="admin-confirm-title">
    <h1 id="admin-confirm-title" style="margin-top:0;font-size:1.35rem;">Confirm Action</h1>
    <p id="admin-confirm-message" style="margin-bottom:0.75rem;"></p>
    <div id="admin-confirm-details" class="panel panel--light" style="margin-bottom:1rem;font-size:0.88rem;" hidden></div>
    <div style="display:flex;justify-content:flex-end;gap:0.65rem;flex-wrap:wrap;">
      <button type="button" id="admin-confirm-cancel" class="btn btn--secondary" autofocus>Cancel</button>
      <button type="button" id="admin-confirm-proceed" class="btn btn--primary">Confirm &amp; Proceed</button>
    </div>
  </dialog>

  <div id="admin-announcer" aria-live="polite" class="visually-hidden"></div>
  <script nonce="${escapeHtml(nonce)}" src="/js/admin.js?v=${ADMIN_ASSET_VERSION}" defer></script>
</body>
</html>`;
}

export function renderAdminOverview({ user, stats, quickActions = [], schedulerHealth, recentAudit, pendingReviews, expiringItems = [], rolePermissionMap = {}, contributorData = null }) {
  const userRoles = getUserRoles(user);
  const permLabelByKey = Object.fromEntries(PERMISSION_META.map((p) => [p.key, p.label]));
  const effectivePerms = Array.from(
    new Set(userRoles.flatMap((r) => rolePermissionMap[r] || []))
  );

  if (contributorData) {
    const { kpis, recentProjects, tasks } = contributorData;
    const kpiCards = [
      {
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>',
        label: 'My Projects',
        value: kpis.myProjectsCount,
        hint: `${kpis.totalProjectsCount} total in workspace`,
        href: '/admin/projects',
        cta: 'View all',
      },
      {
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',
        label: 'Draft Projects',
        value: kpis.draftCount,
        hint: 'In progress or missing details',
        href: '/admin/projects?state=Draft',
        cta: 'Open drafts',
        accent: true,
      },
      {
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
        label: 'Awaiting Review',
        value: kpis.awaitingReviewCount,
        hint: 'Pending publisher approval',
        href: '/admin/projects?state=In%20review',
        cta: 'Check status',
      },
      {
        icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>',
        label: 'Photos Awaiting Rights',
        value: kpis.pendingPhotosCount,
        hint: 'Need rights approval to publish',
        href: '/admin/projects?view=media',
        cta: 'Media library',
      },
    ];

    return `
    <div class="contrib-action-bar">
      <div>
        <strong style="font-size:0.98rem;color:var(--color-carbon);">Daily Project Workflow</strong>
        <p class="muted" style="margin:0.1rem 0 0;font-size:0.84rem;">Create drafts, attach Before/After photography, and complete evidence before requesting publication.</p>
      </div>
      <div class="admin-action-group">
        <a href="/admin/projects?view=media" class="btn btn--secondary">Manage Photos</a>
        <a href="/admin/projects?view=create" class="btn btn--primary">+ Create Project</a>
      </div>
    </div>

    <div class="kpi-grid kpi-grid--4">
      ${kpiCards
        .map(
          (k) => `<article class="kpi-card kpi-card--saas${k.accent ? ' kpi-card--accent' : ''}">
            <div class="kpi-card__head">
              <span class="kpi-card__label">${escapeHtml(k.label)}</span>
              <span class="kpi-card__icon">${k.icon}</span>
            </div>
            <span class="kpi-card__num">${escapeHtml(k.value)}</span>
            <div class="kpi-card__foot">
              <span class="kpi-card__hint">${escapeHtml(k.hint)}</span>
              <a href="${escapeHtml(k.href)}" class="kpi-card__link">${escapeHtml(k.cta)} &rarr;</a>
            </div>
          </article>`
        )
        .join('')}
    </div>

    <div class="dashboard-split">
      <section class="admin-card" aria-labelledby="contrib-recent-title">
        ${renderAdminPageHeader({
          title: 'My Recent Projects',
          subtitle: 'Jump back into recent drafts or add Before/After photos.',
          actionsHtml: '<a href="/admin/projects" class="btn btn--secondary btn--compact">View All</a>',
        })}
        ${
          recentProjects.length === 0
            ? renderAdminEmptyState({
                title: 'No projects created yet',
                description: 'Start documenting your first completed commercial project with scope details and Before/After photos.',
                ctaHtml: '<a href="/admin/projects?view=create" class="btn btn--primary">+ Create Project</a>',
              })
            : `<div class="contrib-project-list">
                ${recentProjects
                  .map(
                    (p) => `<article class="contrib-project-row">
                      <img src="${p.cover_asset_id ? `/admin/api/media/preview/${escapeHtml(p.cover_asset_id)}` : '/assets/brand-mark.svg'}" alt="" class="project-thumb" style="width:48px;height:48px;">
                      <div class="contrib-project-row__info">
                        <strong class="contrib-project-row__title" title="${escapeHtml(p.title)}" aria-label="${escapeHtml(p.title)}">${escapeHtml(p.title)}</strong>
                        <div class="muted" style="font-size:0.8rem;">
                          ${escapeHtml(p.property_type)} &middot; ${escapeHtml(p.city_region)} &middot; Updated ${escapeHtml(formatPhoenixDateTime(p.updated_at, false))}
                        </div>
                        <div style="display:flex;flex-wrap:wrap;gap:0.35rem;margin-top:0.3rem;align-items:center;">
                          <span class="badge ${p.activation_state === 'Live' ? 'badge--live' : 'badge--warn'}">${escapeHtml(p.editorial_state)} &middot; ${escapeHtml(p.activation_state)}</span>
                          <span class="muted" style="font-size:0.78rem;">${escapeHtml(p.photoCount)} photo(s) &middot; ${escapeHtml(p.pairCount)} pair(s)</span>
                        </div>
                      </div>
                      <div class="admin-action-group" style="flex-shrink:0;">
                        <a href="/admin/projects?view=edit&id=${encodeURIComponent(p.project_id)}" class="btn btn--primary btn--compact" style="min-height:36px;">Edit</a>
                        <a href="/admin/projects?view=edit&tab=photos&id=${encodeURIComponent(p.project_id)}" class="btn btn--secondary btn--compact" style="min-height:36px;">Add Photos</a>
                      </div>
                    </article>`
                  )
                  .join('')}
              </div>`
        }
      </section>

      <div style="display:flex;flex-direction:column;gap:1.25rem;min-width:0;">
        <section class="admin-card" style="margin-bottom:0;" aria-labelledby="contrib-tasks-title">
          ${renderAdminPageHeader({
            title: 'My Tasks & Next Actions',
            subtitle: 'Actionable steps derived from your current project drafts and publishing requirements.',
          })}
          ${
            tasks.length === 0
              ? renderAdminEmptyState({
                  title: 'No pending draft actions',
                  description: 'All active projects have photos, evidence, and permissions completed.',
                  ctaHtml: '<a href="/admin/projects?view=create" class="btn btn--secondary btn--compact">+ Create New Project</a>',
                })
              : `<ul class="contrib-task-list">
                  ${tasks
                    .map(
                      (t) => `<li class="contrib-task-item">
                        <div style="min-width:0;flex:1;">
                          <div style="display:flex;align-items:center;gap:0.4rem;margin-bottom:0.2rem;">
                            <span class="badge ${t.badgeTone === 'live' ? 'badge--live' : t.badgeTone === 'warn' ? 'badge--warn' : ''}">${escapeHtml(t.badge)}</span>
                          </div>
                          <strong style="display:block;font-size:0.88rem;line-height:1.35;">${escapeHtml(t.title)}</strong>
                          <span class="muted" style="font-size:0.8rem;">${escapeHtml(t.detail)}</span>
                        </div>
                        <a href="${escapeHtml(t.href)}" class="btn btn--secondary btn--compact" style="min-height:36px;flex-shrink:0;">${escapeHtml(t.cta)}</a>
                      </li>`
                    )
                    .join('')}
                </ul>`
          }
        </section>

        <section class="admin-card" style="margin-bottom:0;" aria-label="Quick Actions">
          <h3 style="margin-top:0;">Quick Actions</h3>
          <div class="contrib-quick-grid">
            <a href="/admin/projects?view=create" class="contrib-quick-tile contrib-quick-tile--primary">
              <strong>+ Create Project</strong>
              <span>Start a 4-step case study draft</span>
            </a>
            <a href="/admin/projects?view=media" class="contrib-quick-tile">
              <strong>Upload Photos</strong>
              <span>Add Before/After imagery</span>
            </a>
            <a href="/admin/projects" class="contrib-quick-tile">
              <strong>View My Projects</strong>
              <span>Filter drafts &amp; published work</span>
            </a>
          </div>
        </section>
      </div>
    </div>

    <details class="admin-accordion" style="margin-top:0.25rem;">
      <summary>My Role Scope &amp; Workspace Permissions (Project Contributor)</summary>
      <div class="grid-2" style="margin-top:0.5rem;">
        <div>
          <p style="font-size:0.88rem;margin:0 0 0.45rem;"><strong>Capabilities:</strong></p>
          <ul style="margin:0;padding-left:1.15rem;font-size:0.84rem;color:var(--color-muted-stone);">
            ${effectivePerms.map((p) => `<li>${escapeHtml(permLabelByKey[p] || p)}</li>`).join('')}
          </ul>
        </div>
        <div>
          <p style="font-size:0.88rem;margin:0 0 0.45rem;"><strong>Publishing Boundary:</strong></p>
          <p class="muted" style="font-size:0.84rem;margin:0;">Project Contributors prepare drafts, upload metadata-stripped photos, and pair Before/After views. An Approver &amp; Publisher approves media rights and publishes completed projects live.</p>
        </div>
      </div>
    </details>`;
  }

  return `
  ${quickActions.length > 0
      ? `<section class="admin-card" aria-label="Quick Actions for Your Role" style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.85rem;">
          <div>
            <h2 style="margin-bottom:0.2rem;font-size:1.05rem;">Quick Actions</h2>
            <p class="muted" style="margin:0;font-size:0.84rem;">Signed in as <strong>${escapeHtml(userRoles.map(getRoleDisplayLabel).join(' + '))}</strong>. Start a task below.</p>
          </div>
          <div class="admin-action-group">
            ${quickActions
        .map(
          (qa) => `<a href="${escapeHtml(qa.href)}" class="btn ${qa.primary ? 'btn--primary' : 'btn--secondary'}">${escapeHtml(qa.label)}</a>`
        )
        .join('')}
          </div>
        </section>`
      : ''
    }

  <div class="kpi-grid">
    ${stats.showContent
      ? `<div class="kpi-card"><span class="kpi-card__num">${stats.livePages}</span><span class="kpi-card__label">Live Public Pages</span><span class="kpi-card__hint">Published website routes</span></div>
           <div class="kpi-card kpi-card--accent"><span class="kpi-card__num">${stats.inReviewCount}</span><span class="kpi-card__label">Pages In Review</span><span class="kpi-card__hint">Awaiting publisher sign-off</span></div>`
      : ''
    }
    ${stats.showCampaigns
      ? `<div class="kpi-card"><span class="kpi-card__num">${stats.liveCampaigns}</span><span class="kpi-card__label">Live Seasonal Campaigns</span><span class="kpi-card__hint">Active in America/Phoenix</span></div>`
      : ''
    }
    ${stats.showProjects
      ? `<div class="kpi-card"><span class="kpi-card__num">${stats.liveProjects}</span><span class="kpi-card__label">Published Projects</span><span class="kpi-card__hint">Approved public proof</span></div>`
      : ''
    }
    ${stats.showHiring
      ? `<div class="kpi-card"><span class="kpi-card__num">${stats.openJobs}</span><span class="kpi-card__label">Open Vacancies</span><span class="kpi-card__hint">Active Careers postings</span></div>
           <div class="kpi-card kpi-card--accent"><span class="kpi-card__num">${stats.unassignedApps}</span><span class="kpi-card__label">Applications Received</span><span class="kpi-card__hint">Isolated recruiting queue</span></div>`
      : ''
    }
    ${stats.showLeads
      ? `<div class="kpi-card"><span class="kpi-card__num">${stats.newInquiries}</span><span class="kpi-card__label">Total Inquiries</span><span class="kpi-card__hint">Durable commercial ledger</span></div>
           <div class="kpi-card kpi-card--accent"><span class="kpi-card__num">${stats.crmFailed}</span><span class="kpi-card__label">CRM Delivery Failures</span><span class="kpi-card__hint">Requires replay or review</span></div>`
      : ''
    }
    ${stats.showAnalytics
      ? `<div class="kpi-card"><span class="kpi-card__num">${stats.analyticsEvents || 0}</span><span class="kpi-card__label">First-Party Events</span><span class="kpi-card__hint">PII-scrubbed measurements</span></div>`
      : ''
    }
  </div>

  <div class="${stats.showCampaigns || stats.showHiring ? 'grid-2' : ''}" style="align-items:start;">
    <section class="admin-card">
      <h2>Scheduler &amp; Delivery Health</h2>
      <p><strong>Scheduler Status:</strong> <span class="badge ${schedulerHealth?.status === 'healthy' ? 'badge--live' : 'badge--warn'}">${escapeHtml(schedulerHealth?.status || 'ready')}</span></p>
      <p><strong>Last Successful Sweep:</strong> ${escapeHtml(formatPhoenixDateTime(schedulerHealth?.last_success_at))}</p>
      <p class="muted" style="font-size:0.84rem;margin-bottom:0;">Counts reflect live database records as of page load.</p>
    </section>

    ${stats.showCampaigns || stats.showHiring
      ? `<section class="admin-card">
            <h2>Expiring Schedules (Next 14 Days)</h2>
            ${expiringItems.length === 0
        ? '<div class="admin-empty-state">No scheduled campaigns or vacancies expiring within 14 days for your role.</div>'
        : `<ul style="margin:0;padding-left:1.15rem;font-size:0.88rem;">
                    ${expiringItems
          .map(
            (ex) => `<li style="margin-bottom:0.45rem;"><span class="badge badge--warn">${escapeHtml(ex.type)}</span> <a href="${escapeHtml(ex.href)}"><strong>${escapeHtml(ex.title)}</strong></a> &middot; ${escapeHtml(ex.detail)} (${escapeHtml(formatPhoenixDateTime(ex.dueAt, false))})</li>`
          )
          .join('')}
                  </ul>`
      }
          </section>`
      : ''
    }
  </div>

  ${pendingReviews.length > 0
      ? `<section class="admin-card">
          <h2>Items Awaiting Review</h2>
          <div class="admin-desktop-only">
            <div class="table-scroll" tabindex="0" role="region" aria-label="Items Awaiting Review">
              <table class="data-table">
                <thead><tr><th scope="col">Type</th><th scope="col">Title</th><th scope="col">Owner</th><th scope="col">Updated (Phoenix)</th><th scope="col">Action</th></tr></thead>
                <tbody>
                  ${pendingReviews
        .map(
          (r) => `<tr><td><span class="badge badge--warn">${escapeHtml(r.type)}</span></td><td><strong>${escapeHtml(r.title)}</strong></td><td>${escapeHtml(r.owner)}</td><td>${escapeHtml(formatPhoenixDateTime(r.updated_at, false))}</td><td><a href="${escapeHtml(r.href)}" class="btn btn--secondary btn--compact">Open</a></td></tr>`
        )
        .join('')}
                </tbody>
              </table>
            </div>
          </div>
          <div class="admin-mobile-cards">
            ${pendingReviews
        .map(
          (r) => `<div class="admin-mobile-card">
                  <div class="admin-mobile-card__top"><span class="admin-mobile-card__title">${escapeHtml(r.title)}</span><span class="badge badge--warn">${escapeHtml(r.type)}</span></div>
                  <div class="admin-mobile-card__meta">Owner: ${escapeHtml(r.owner)} &middot; ${escapeHtml(formatPhoenixDateTime(r.updated_at, false))}</div>
                  <div class="admin-mobile-card__actions"><a href="${escapeHtml(r.href)}" class="btn btn--secondary btn--compact">Open Item</a></div>
                </div>`
        )
        .join('')}
          </div>
        </section>`
      : ''
    }

  ${recentAudit.length > 0
      ? `<section class="admin-card">
          <h2>Recent Non-Hiring Activity</h2>
          <div class="admin-desktop-only">
            <div class="table-scroll" tabindex="0" role="region" aria-label="Recent Non-Hiring Activity">
              <table class="data-table">
                <thead><tr><th scope="col">Time (Phoenix)</th><th scope="col">Actor</th><th scope="col">Domain</th><th scope="col">Action</th><th scope="col">Object</th></tr></thead>
                <tbody>
                  ${recentAudit
        .map(
          (a) => `<tr><td>${escapeHtml(formatPhoenixDateTime(a.created_at, false))}</td><td>${escapeHtml(a.actor_name)}</td><td><span class="badge">${escapeHtml(a.domain)}</span></td><td>${escapeHtml(a.action)}</td><td><code>${escapeHtml(a.object_type)}:${escapeHtml(a.object_id.slice(0, 12))}</code></td></tr>`
        )
        .join('')}
                </tbody>
              </table>
            </div>
          </div>
          <div class="admin-mobile-cards">
            ${recentAudit
        .map(
          (a) => `<div class="admin-mobile-card">
                  <div class="admin-mobile-card__top"><span class="admin-mobile-card__title">${escapeHtml(a.action)}</span><span class="badge">${escapeHtml(a.domain)}</span></div>
                  <div class="admin-mobile-card__meta">${escapeHtml(a.actor_name)} &middot; <code>${escapeHtml(a.object_type)}:${escapeHtml(a.object_id.slice(0, 12))}</code><br>${escapeHtml(formatPhoenixDateTime(a.created_at, false))}</div>
                </div>`
        )
        .join('')}
          </div>
        </section>`
      : ''
    }

  <details class="admin-accordion">
    <summary>My Role Scope &amp; Effective Permissions (${escapeHtml(userRoles.map(getRoleDisplayLabel).join(' + '))})</summary>
    <p style="font-size:0.88rem;margin-bottom:0.65rem;">${stats.showHiring ? 'Authorized access to assigned recruiting records.' : 'Hiring records and applicant resumes remain restricted from your role.'}</p>
    ${effectivePerms.length > 0
      ? `<div class="perm-chip-list" aria-label="Effective permissions">
            ${effectivePerms.map((p) => `<span class="perm-chip" title="${escapeHtml(p)}">${escapeHtml(permLabelByKey[p] || p)}</span>`).join('')}
          </div>`
      : ''
    }
  </details>`;
}

export function renderAdminPagesView({
  tab = 'pages',
  pages,
  pagesMeta,
  allPagesCount = 0,
  filters = {},
  selectedPage,
  revisions,
  revCompare,
  hasCompareQuery = false,
  articles = [],
  selectedArticle,
  claims,
  selectedClaim,
  redirects,
  user,
  csrfToken,
}) {
  const canPublish = hasPermission(user, PERMISSIONS.PUBLISH_CONTENT);
  const canApprove = hasPermission(user, PERMISSIONS.APPROVE_CONTENT) || canPublish;
  const canEdit = hasPermission(user, PERMISSIONS.EDIT_CONTENT);

  return `
  <nav class="admin-tabs" aria-label="Pages & Content sections">
    <a href="/admin/pages?tab=pages" class="admin-tab${tab === 'pages' ? ' is-active' : ''}"${tab === 'pages' ? ' aria-current="page"' : ''}>Website Pages (${allPagesCount})</a>
    <a href="/admin/pages?tab=articles" class="admin-tab${tab === 'articles' ? ' is-active' : ''}"${tab === 'articles' ? ' aria-current="page"' : ''}>Insights Articles (${articles.length})</a>
    <a href="/admin/pages?tab=claims" class="admin-tab${tab === 'claims' ? ' is-active' : ''}"${tab === 'claims' ? ' aria-current="page"' : ''}>Facts &amp; Claims (${claims.length})</a>
    <a href="/admin/pages?tab=redirects" class="admin-tab${tab === 'redirects' ? ' is-active' : ''}"${tab === 'redirects' ? ' aria-current="page"' : ''}>URL Redirects (${redirects.length})</a>
  </nav>

  ${!canEdit
      ? `<div class="status-banner status-banner--warning" role="status"><strong>Read-Only Governance View:</strong> You can inspect pages, diffs, articles, claims, and redirects, but cannot modify or publish copy.</div>`
      : ''
    }

  ${tab === 'pages'
      ? `<section class="admin-card">
          <form method="GET" action="/admin/pages" class="admin-filter-bar" style="margin-bottom:0;">
            <input type="hidden" name="tab" value="pages">
            <div class="field" style="flex:1;min-width:13rem;">
              <label for="cms-q">Search pages by route, title, or owner</label>
              <input id="cms-q" name="q" type="search" value="${escapeHtml(filters.q || '')}" placeholder="Search slug, title, owner...">
            </div>
            <div class="field" style="min-width:11rem;">
              <label for="cms-state">State</label>
              <select id="cms-state" name="state">
                <option value="">All states</option>
                ${['Draft', 'In review', 'Approved', 'Live', 'Unpublished']
        .map((st) => `<option value="${st}"${filters.state === st ? ' selected' : ''}>${st}</option>`)
        .join('')}
              </select>
            </div>
            <div class="admin-action-group">
              <button type="submit" class="btn btn--secondary">Filter</button>
              ${filters.q || filters.state ? '<a href="/admin/pages?tab=pages" class="btn btn--secondary">Clear</a>' : ''}
            </div>
          </form>
        </section>

        <div class="admin-split admin-split--pages">
          <section class="admin-card admin-pages-list">
            <div class="admin-card__header">
              <div>
                <h2>Website Pages</h2>
                <p class="muted" style="margin:0;font-size:0.84rem;">Select a page to ${canEdit ? 'edit draft copy' : 'inspect copy'} or preview revisions.</p>
              </div>
            </div>
            ${pages.length === 0
        ? '<div class="admin-empty-state">No pages match your current search or filter.</div>'
        : `<div class="admin-page-list" role="region" aria-label="Website Pages List">
                    ${pages
          .map(
            (p) => `<article data-page-id="${escapeHtml(p.page_id)}" class="admin-page-card${selectedPage?.page_id === p.page_id ? ' is-selected' : ''}">
                          <div class="admin-page-card__top">
                            <div style="display:flex;flex-wrap:wrap;align-items:center;gap:0.35rem;">
                              <span class="admin-page-card__slug">${escapeHtml(p.slug)}</span>
                              <span class="badge">${escapeHtml(p.editorial_state)}</span>
                              <span class="badge ${p.activation_state === 'Live' ? 'badge--live' : 'badge--warn'}">${escapeHtml(p.activation_state)}</span>
                            </div>
                            <a href="/admin/pages?tab=pages&id=${encodeURIComponent(p.page_id)}#page-editor-section" data-panel-swap="#page-editor-section" data-page-id="${escapeHtml(p.page_id)}" class="btn btn--secondary btn--compact" style="min-height:34px;padding:0.25rem 0.75rem;font-size:0.8rem;">${canEdit ? 'Edit' : 'Inspect'}</a>
                          </div>
                          <div class="admin-page-card__title">${escapeHtml(p.title)}</div>
                          <div class="admin-page-card__meta">${escapeHtml(p.owner_name)} &middot; v${escapeHtml(p.current_revision)}</div>
                        </article>`
          )
          .join('')}
                  </div>`
      }
            ${renderPaginationNav('/admin/pages', pagesMeta, { tab: 'pages', q: filters.q, state: filters.state, id: selectedPage?.page_id })}
          </section>

          ${selectedPage && revisions.length > 0
        ? (() => {
          const latest = revisions[0];
          const compareFields = [
            { key: 'title', label: 'Title' },
            { key: 'meta_title', label: 'Meta Title' },
            { key: 'meta_description', label: 'Meta Description' },
            { key: 'hero_headline', label: 'Hero Headline' },
            { key: 'hero_summary', label: 'Hero Summary' },
            { key: 'cta_label', label: 'CTA Label' },
            { key: 'body_html', label: 'Body HTML' },
          ];
          return `<section id="page-editor-section" class="admin-card">
                    <div class="admin-card__header">
                      <div>
                        <h2>${canEdit ? 'Edit' : 'Inspect'}: ${escapeHtml(selectedPage.slug)} (${escapeHtml(selectedPage.editorial_state)})</h2>
                        <p class="muted" style="margin:0;font-size:0.84rem;">Current: v${escapeHtml(selectedPage.current_revision)} | Published: ${selectedPage.published_revision ? `v${selectedPage.published_revision}` : 'Unpublished'}</p>
                      </div>
                      <span id="autosave-status" class="autosave-pill">${canEdit ? 'Saved' : 'Read-only'}</span>
                    </div>
                    ${latest.review_comment && selectedPage.editorial_state === 'Draft'
              ? `<div class="status-banner status-banner--warning" role="status"><strong>Returned from Review (v${escapeHtml(latest.revision_number)}):</strong> ${escapeHtml(latest.review_comment)}</div>`
              : ''
            }

                    <form id="page-editor-form" data-autosave-url="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/draft">
                      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                      <input type="hidden" name="expected_revision" value="${escapeHtml(selectedPage.current_revision)}">

                      <fieldset class="admin-fieldset">
                        <legend>Page Content &amp; Messaging</legend>
                        <div class="grid-2">
                          <div class="field">
                            <label for="pg-title">Page Title</label>
                            <input type="text" id="pg-title" name="title" value="${escapeHtml(latest.title)}" required ${canEdit ? '' : 'disabled'}>
                          </div>
                          <div class="field">
                            <label for="pg-cta">Primary CTA Label</label>
                            <input type="text" id="pg-cta" name="cta_label" value="${escapeHtml(latest.cta_label)}" ${canEdit ? '' : 'disabled'}>
                          </div>
                        </div>
                        <div class="field">
                          <label for="pg-headline">Hero Headline</label>
                          <input type="text" id="pg-headline" name="hero_headline" value="${escapeHtml(latest.hero_headline)}" required ${canEdit ? '' : 'disabled'}>
                        </div>
                        <div class="field">
                          <label for="pg-summary">Hero Summary</label>
                          <textarea id="pg-summary" name="hero_summary" style="min-height:4.2rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(latest.hero_summary)}</textarea>
                        </div>
                        <div class="field" style="margin-bottom:0;">
                          <label for="pg-body">Body Content (Sanitized Rich HTML)</label>
                          <textarea id="pg-body" name="body_html" style="min-height:9rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(latest.body_html)}</textarea>
                        </div>
                      </fieldset>

                      <fieldset class="admin-fieldset">
                        <legend>SEO &amp; Search Visibility</legend>
                        <div class="field">
                          <label for="pg-meta-title">SEO Meta Title</label>
                          <span class="hint" id="meta-title-count">0 / 60 recommended chars</span>
                          <input type="text" id="pg-meta-title" name="meta_title" value="${escapeHtml(latest.meta_title)}" data-char-target="meta-title-count" data-char-rec="60" aria-describedby="meta-title-count" required ${canEdit ? '' : 'disabled'}>
                        </div>
                        <div class="field" style="margin-bottom:0;">
                          <label for="pg-meta-desc">SEO Meta Description</label>
                          <span class="hint" id="meta-desc-count">0 / 160 recommended chars</span>
                          <textarea id="pg-meta-desc" name="meta_description" data-char-target="meta-desc-count" data-char-rec="160" aria-describedby="meta-desc-count" style="min-height:4.2rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(latest.meta_description)}</textarea>
                        </div>
                      </fieldset>

                      <div class="admin-action-group">
                        ${canEdit
              ? `<button type="button" class="btn btn--secondary" id="btn-save-draft">Save Draft</button>
                               <button type="button" class="btn btn--secondary" id="btn-submit-review" data-url="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/submit-review">Submit for Review</button>`
              : ''
            }
                        <a href="/admin/preview?path=${encodeURIComponent(selectedPage.slug)}&rev=${encodeURIComponent(latest.revision_number)}&viewport=desktop" target="_blank" class="btn btn--secondary">Preview Desktop</a>
                        <a href="/admin/preview?path=${encodeURIComponent(selectedPage.slug)}&rev=${encodeURIComponent(latest.revision_number)}&viewport=mobile" target="_blank" class="btn btn--secondary">Preview Mobile (390px)</a>
                        ${canPublish
              ? `<button type="button" class="btn btn--primary" id="btn-publish-page" data-url="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/publish" data-confirm="Approve draft v${escapeHtml(selectedPage.current_revision)} for ${escapeHtml(selectedPage.slug)} and publish it live immediately?">Approve &amp; Publish Live</button>`
              : ''
            }
                      </div>
                    </form>

                    ${canApprove && selectedPage.editorial_state === 'In review'
              ? `<form method="POST" action="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/return-draft" class="js-ajax-form admin-filter-bar" style="margin-top:1rem;" data-confirm-title="Return Revision to Draft?" data-confirm="Send revision v${escapeHtml(selectedPage.current_revision)} back to Draft with your reviewer comment?">
                            <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                            <div class="field" style="flex:1;min-width:14rem;">
                              <label for="pg-ret-comment">Return to Draft Review Comment</label>
                              <input type="text" id="pg-ret-comment" name="review_comment" placeholder="Explain required edits before publishing..." required>
                            </div>
                            <button type="submit" class="btn btn--secondary">Return to Draft</button>
                          </form>`
              : ''
            }

                    <details class="admin-accordion"${hasCompareQuery ? ' open' : ''}>
                      <summary>Revision Comparison &amp; History (${revisions.length} revision(s))</summary>
                      <form method="GET" action="/admin/pages" style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:flex-end;margin-bottom:0.85rem;">
                        <input type="hidden" name="tab" value="pages">
                        <input type="hidden" name="id" value="${escapeHtml(selectedPage.page_id)}">
                        <div class="field" style="margin:0;"><label for="cmp-reva">Base Rev</label>
                          <select id="cmp-reva" name="revA">
                            ${revisions.map((r) => `<option value="${r.revision_number}"${revCompare?.revA?.revision_number === r.revision_number ? ' selected' : ''}>v${r.revision_number}</option>`).join('')}
                          </select>
                        </div>
                        <div class="field" style="margin:0;"><label for="cmp-revb">Compare Rev</label>
                          <select id="cmp-revb" name="revB">
                            ${revisions.map((r) => `<option value="${r.revision_number}"${revCompare?.revB?.revision_number === r.revision_number ? ' selected' : ''}>v${r.revision_number}</option>`).join('')}
                          </select>
                        </div>
                        <button type="submit" class="btn btn--secondary btn--compact">Compare Revisions</button>
                      </form>
                      ${revCompare
              ? `<div class="table-scroll" tabindex="0" role="region" aria-label="Revision Comparison Table" style="margin-bottom:1rem;">
                              <table class="data-table" style="font-size:0.82rem;">
                                <thead><tr><th>Field</th><th>v${escapeHtml(revCompare.revA.revision_number)}</th><th>v${escapeHtml(revCompare.revB.revision_number)}</th><th>Status</th></tr></thead>
                                <tbody>
                                  ${compareFields
                .map((f) => {
                  const a = String(revCompare.revA[f.key] || '');
                  const b = String(revCompare.revB[f.key] || '');
                  const changed = a !== b;
                  return `<tr>
                                        <td><strong>${escapeHtml(f.label)}</strong></td>
                                        <td>${escapeHtml(a.slice(0, 120))}${a.length > 120 ? '...' : ''}</td>
                                        <td>${escapeHtml(b.slice(0, 120))}${b.length > 120 ? '...' : ''}</td>
                                        <td><span class="badge ${changed ? 'badge--warn' : 'badge--live'}">${changed ? 'Changed' : 'Same'}</span></td>
                                      </tr>`;
                })
                .join('')}
                                </tbody>
                              </table>
                            </div>`
              : ''
            }
                      <div class="table-scroll" tabindex="0" role="region" aria-label="Revision History Table">
                        <table class="data-table" style="font-size:0.84rem;">
                          <thead><tr><th>Rev</th><th>State</th><th>Created</th>${canPublish ? '<th>Action</th>' : ''}</tr></thead>
                          <tbody>
                            ${revisions
              .map(
                (r) => `<tr>
                                  <td>v${escapeHtml(r.revision_number)}</td>
                                  <td>${escapeHtml(r.editorial_state)}</td>
                                  <td>${escapeHtml(formatPhoenixDateTime(r.created_at, false))}</td>
                                  ${canPublish
                    ? `<td><button type="button" class="btn btn--secondary btn--compact js-restore-rev" data-url="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/restore" data-rev="${escapeHtml(r.revision_number)}">Restore to Draft</button></td>`
                    : ''
                  }
                                </tr>`
              )
              .join('')}
                          </tbody>
                        </table>
                      </div>
                    </details>
                  </section>`;
        })()
        : '<section id="page-editor-section" class="admin-card"><div class="admin-empty-state">Select a page to edit copy, inspect SEO fields, or compare revisions.</div></section>'
      }
        </div>`
      : ''
    }

  ${tab === 'articles'
      ? `<section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Insights Articles</h2>
              <p class="muted" style="margin:0;font-size:0.84rem;">Editorial guidance pages linked to Greater Phoenix commercial services.</p>
            </div>
          </div>
          <div class="admin-desktop-only">
            <div class="table-scroll" tabindex="0" role="region" aria-label="Articles Table">
              <table class="data-table" style="font-size:0.85rem;">
                <thead><tr><th>Title &amp; Slug</th><th>State</th>${canEdit || canPublish ? '<th>Actions</th>' : ''}</tr></thead>
                <tbody>
                  ${articles.length === 0
        ? `<tr><td colspan="${canEdit || canPublish ? 3 : 2}" class="muted">No articles yet.</td></tr>`
        : articles
          .map(
            (a) => `<tr>
                              <td><a href="/admin/pages?tab=articles&article=${encodeURIComponent(a.article_id)}"><strong>${escapeHtml(a.title)}</strong></a><br><small class="muted"><code>/insights/${escapeHtml(a.slug)}/</code> &middot; ${escapeHtml(a.buyer_target)}</small></td>
                              <td><span class="badge">${escapeHtml(a.editorial_state)}</span> <span class="badge ${a.activation_state === 'Live' ? 'badge--live' : 'badge--warn'}">${escapeHtml(a.activation_state)}</span></td>
                              ${canEdit || canPublish
                ? `<td><div class="admin-action-group">
                                      ${canEdit && a.editorial_state === 'Draft' ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/articles/${escapeHtml(a.article_id)}/submit-review">Submit Review</button>` : ''}
                                      ${canPublish && a.activation_state !== 'Live' ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/articles/${escapeHtml(a.article_id)}/publish" data-confirm-title="Publish Article Live?" data-confirm="Publish &quot;${escapeHtml(a.title)}&quot; to /insights/${escapeHtml(a.slug)}/?">Publish</button>` : ''}
                                      ${canPublish && a.activation_state === 'Live' ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/articles/${escapeHtml(a.article_id)}/archive" data-confirm-title="Archive Article?" data-confirm="Archive &quot;${escapeHtml(a.title)}&quot; and remove it from public listings?">Archive</button>` : ''}
                                    </div></td>`
                : ''
              }
                            </tr>`
          )
          .join('')
      }
                </tbody>
              </table>
            </div>
          </div>
          <div class="admin-mobile-cards">
            ${articles.length === 0
        ? '<div class="admin-empty-state">No articles yet.</div>'
        : articles
          .map(
            (a) => `<div class="admin-mobile-card">
                        <div class="admin-mobile-card__top"><span class="admin-mobile-card__title">${escapeHtml(a.title)}</span><span class="badge ${a.activation_state === 'Live' ? 'badge--live' : 'badge--warn'}">${escapeHtml(a.editorial_state)} / ${escapeHtml(a.activation_state)}</span></div>
                        <div class="admin-mobile-card__meta"><code>/insights/${escapeHtml(a.slug)}/</code> &middot; ${escapeHtml(a.buyer_target)}</div>
                        ${canEdit || canPublish
                ? `<div class="admin-mobile-card__actions">
                                ${canEdit ? `<a href="/admin/pages?tab=articles&article=${encodeURIComponent(a.article_id)}" class="btn btn--secondary btn--compact">Edit</a>` : ''}
                                ${canPublish && a.activation_state !== 'Live' ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/articles/${escapeHtml(a.article_id)}/publish" data-confirm-title="Publish Article Live?" data-confirm="Publish &quot;${escapeHtml(a.title)}&quot; live?">Publish</button>` : ''}
                              </div>`
                : ''
              }
                      </div>`
          )
          .join('')
      }
          </div>

          ${canEdit
        ? `<details class="admin-accordion"${selectedArticle ? ' open' : ''}>
                  <summary>${selectedArticle ? `Edit Article: ${escapeHtml(selectedArticle.title)}` : '+ Create New Article Draft'}</summary>
                  <form method="POST" action="${selectedArticle ? `/admin/api/articles/${escapeHtml(selectedArticle.article_id)}` : '/admin/api/articles'}" class="js-ajax-form">
                    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                    <div class="grid-2">
                      <div class="field"><label for="art-title">Title</label><input id="art-title" name="title" value="${escapeHtml(selectedArticle?.title || '')}" required></div>
                      ${selectedArticle
          ? `<div class="field"><label for="art-slug">Slug (Immutable)</label><input id="art-slug" value="${escapeHtml(selectedArticle.slug)}" disabled></div>`
          : `<div class="field"><label for="art-slug">Slug (/insights/{slug}/)</label><input id="art-slug" name="slug" pattern="[a-z0-9-]+" required></div>`
        }
                    </div>
                    <div class="grid-2">
                      <div class="field"><label for="art-buyer">Buyer Target</label><input id="art-buyer" name="buyer_target" value="${escapeHtml(selectedArticle?.buyer_target || 'Commercial property managers')}" required></div>
                      <div class="field"><label for="art-rel">Related Service Slug</label><input id="art-rel" name="related_service" value="${escapeHtml(selectedArticle?.related_service || '')}" placeholder="day-porter"></div>
                    </div>
                    <div class="field"><label for="art-sum">Summary</label><textarea id="art-sum" name="summary" style="min-height:3.5rem;" required>${escapeHtml(selectedArticle?.summary || '')}</textarea></div>
                    <div class="field"><label for="art-body">Body HTML (Sanitized)</label><textarea id="art-body" name="body_html" style="min-height:5rem;" required>${escapeHtml(selectedArticle?.body_html || '<p></p>')}</textarea></div>
                    <div class="field"><label for="art-src">Sources &amp; Review Note</label><input id="art-src" name="sources_note" value="${escapeHtml(selectedArticle?.sources_note || '')}" required></div>
                    <div class="admin-action-group">
                      <button type="submit" class="btn btn--primary">${selectedArticle ? 'Save Article Revision' : 'Create Article Draft'}</button>
                      ${selectedArticle ? '<a href="/admin/pages?tab=articles" class="btn btn--secondary">Cancel Edit</a>' : ''}
                    </div>
                  </form>
                </details>`
        : ''
      }
        </section>`
      : ''
    }

  ${tab === 'claims'
      ? `<section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Fact, Claim &amp; Testimonial Evidence Register</h2>
              <p class="muted" style="margin:0;font-size:0.84rem;">Approved facts and client testimonials referenced across public pages.</p>
            </div>
          </div>
          <div class="admin-desktop-only">
            <div class="table-scroll" tabindex="0" role="region" aria-label="Claims and Testimonials Table">
              <table class="data-table" style="font-size:0.85rem;">
                <thead><tr><th>Title &amp; Wording</th><th>Status</th>${canApprove || canPublish ? '<th>Actions</th>' : ''}</tr></thead>
                <tbody>
                  ${claims
        .map(
          (c) => `<tr>
                        <td><a href="/admin/pages?tab=claims&claim=${encodeURIComponent(c.claim_id)}"><strong>${escapeHtml(c.title)}</strong></a><br><span class="muted">${escapeHtml(c.exact_text)}</span><br><small class="muted">${escapeHtml(c.claim_type)} &middot; Source: ${escapeHtml(c.evidence_source)}</small></td>
                        <td><span class="badge ${c.status === 'withdrawn' ? 'badge--err' : c.status === 'established company fact' || c.status === 'approved for publication' ? 'badge--live' : 'badge--warn'}">${escapeHtml(c.status)}</span></td>
                        ${canApprove || canPublish
              ? `<td><div class="admin-action-group">
                                ${canApprove && c.status !== 'approved for publication' && c.status !== 'established company fact' ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/claims/${escapeHtml(c.claim_id)}/approve">Approve</button>` : ''}
                                ${canPublish && c.status !== 'withdrawn' ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/claims/${escapeHtml(c.claim_id)}/withdraw" data-confirm-title="Withdraw Factual Claim / Testimonial?" data-confirm="Withdrawing immediately stops public display of &quot;${escapeHtml(c.title)}&quot;.">Withdraw</button>` : ''}
                              </div></td>`
              : ''
            }
                      </tr>`
        )
        .join('')}
                </tbody>
              </table>
            </div>
          </div>
          <div class="admin-mobile-cards">
            ${claims
        .map(
          (c) => `<div class="admin-mobile-card">
                  <div class="admin-mobile-card__top"><span class="admin-mobile-card__title">${escapeHtml(c.title)}</span><span class="badge ${c.status === 'withdrawn' ? 'badge--err' : c.status === 'approved for publication' || c.status === 'established company fact' ? 'badge--live' : 'badge--warn'}">${escapeHtml(c.status)}</span></div>
                  <div class="admin-mobile-card__meta">${escapeHtml(c.exact_text)}<br><small>${escapeHtml(c.claim_type)} &middot; ${escapeHtml(c.evidence_source)}</small></div>
                  ${canApprove || canPublish
              ? `<div class="admin-mobile-card__actions">
                          ${canApprove && c.status !== 'approved for publication' && c.status !== 'established company fact' ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/claims/${escapeHtml(c.claim_id)}/approve">Approve</button>` : ''}
                          ${canPublish && c.status !== 'withdrawn' ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/claims/${escapeHtml(c.claim_id)}/withdraw" data-confirm-title="Withdraw Claim?" data-confirm="Withdraw &quot;${escapeHtml(c.title)}&quot;?">Withdraw</button>` : ''}
                        </div>`
              : ''
            }
                </div>`
        )
        .join('')}
          </div>

          ${canEdit
        ? `<details class="admin-accordion"${selectedClaim ? ' open' : ''}>
                  <summary>${selectedClaim ? `Edit Claim: ${escapeHtml(selectedClaim.title)}` : '+ Add Fact / Testimonial Record'}</summary>
                  <form method="POST" action="${selectedClaim ? `/admin/api/claims/${escapeHtml(selectedClaim.claim_id)}` : '/admin/api/claims'}" class="js-ajax-form">
                    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                    <div class="grid-2">
                      <div class="field"><label for="cl-title">Title</label><input id="cl-title" name="title" value="${escapeHtml(selectedClaim?.title || '')}" required></div>
                      <div class="field"><label for="cl-type">Type</label>
                        <select id="cl-type" name="claim_type">
                          ${['testimonial', 'fact', 'certification'].map((t) => `<option value="${t}"${selectedClaim?.claim_type === t ? ' selected' : ''}>${t}</option>`).join('')}
                        </select>
                      </div>
                    </div>
                    <div class="field"><label for="cl-text">Exact Approved Wording</label><textarea id="cl-text" name="exact_text" style="min-height:3.5rem;" required>${escapeHtml(selectedClaim?.exact_text || '')}</textarea></div>
                    <div class="grid-2">
                      <div class="field"><label for="cl-attr">Attribution</label><input id="cl-attr" name="attribution" value="${escapeHtml(selectedClaim?.attribution || '')}" required></div>
                      <div class="field"><label for="cl-src">Evidence Source</label><input id="cl-src" name="evidence_source" value="${escapeHtml(selectedClaim?.evidence_source || '')}" required></div>
                    </div>
                    <div class="admin-action-group">
                      <button type="submit" class="btn btn--secondary">${selectedClaim ? 'Save Claim Wording' : 'Add Claim for Review'}</button>
                      ${selectedClaim ? '<a href="/admin/pages?tab=claims" class="btn btn--secondary">Cancel Edit</a>' : ''}
                    </div>
                  </form>
                </details>`
        : ''
      }
        </section>`
      : ''
    }

  ${tab === 'redirects'
      ? `<section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>URL Redirects (Loop/Chain Validated)</h2>
              <p class="muted" style="margin:0;font-size:0.84rem;">Legacy routes permanently mapped to canonical destinations.</p>
            </div>
          </div>
          <div class="table-scroll" tabindex="0" role="region" aria-label="URL Redirects Table">
            <table class="data-table" style="font-size:0.85rem;">
              <thead><tr><th>Old Path</th><th>Destination</th><th>Code</th><th>Reason</th></tr></thead>
              <tbody>
                ${redirects
        .map(
          (r) => `<tr><td><code>${escapeHtml(r.old_path)}</code></td><td><code>${escapeHtml(r.destination_path)}</code></td><td>${escapeHtml(r.status_code)}</td><td>${escapeHtml(r.reason)}</td></tr>`
        )
        .join('')}
              </tbody>
            </table>
          </div>
          ${canEdit
        ? `<details class="admin-accordion">
                  <summary>+ Add 301 Redirect</summary>
                  <form method="POST" action="/admin/api/redirects" class="js-ajax-form" style="display:flex;flex-wrap:wrap;gap:0.65rem;align-items:flex-end;">
                    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                    <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="rd-old">Old path</label><input id="rd-old" name="old_path" placeholder="/old-page" required></div>
                    <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="rd-dest">Destination</label><input id="rd-dest" name="destination_path" placeholder="/services/" required></div>
                    <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="rd-reason">Reason</label><input id="rd-reason" name="reason" required></div>
                    <button type="submit" class="btn btn--primary">Add Redirect</button>
                  </form>
                </details>`
        : ''
      }
        </section>`
      : ''
    }`;
}

function renderPhoenixCalendarHtml(allCampaigns, monthParam) {
  const [yrStr, moStr] = monthParam.split('-');
  const year = Number(yrStr) || new Date().getUTCFullYear();
  const month = Number(moStr) || new Date().getUTCMonth() + 1;
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const firstDow = new Date(Date.UTC(year, month - 1, 1)).getUTCDay();

  const prevDate = new Date(Date.UTC(year, month - 2, 1));
  const nextDate = new Date(Date.UTC(year, month, 1));
  const fmtYm = (d) => `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;

  const cells = [];
  for (let i = 0; i < firstDow; i++) cells.push('<div class="cal-cell cal-cell--empty"></div>');

  const monthScheduleSummary = [];
  for (let day = 1; day <= daysInMonth; day++) {
    const dayStr = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    // Compare using Phoenix midday (19:00 UTC) so whole day transitions show clearly
    const dayMidMs = new Date(`${dayStr}T19:00:00Z`).getTime();
    const activeOnDay = allCampaigns.filter((c) => {
      if (c.activation_state === 'Archived' || c.activation_state === 'Draft') return false;
      const s = new Date(c.start_at).getTime();
      const e = c.is_evergreen ? Number.POSITIVE_INFINITY : new Date(c.end_at || 0).getTime();
      return s <= dayMidMs && dayMidMs < e;
    });
    if (activeOnDay.length > 0) {
      monthScheduleSummary.push({ dayStr, campaigns: activeOnDay });
    }
    cells.push(
      `<div class="cal-cell">
        <div class="cal-cell__day">${day}</div>
        ${activeOnDay
        .slice(0, 3)
        .map(
          (c) =>
            `<div class="cal-pill ${c.equalPriorityConflicts?.length ? 'cal-pill--conflict' : ''}">${escapeHtml(c.internal_title)} (P${escapeHtml(c.priority)})</div>`
        )
        .join('')}
      </div>`
    );
  }

  return `
  <div style="display:flex;justify-content:space-between;align-items:center;gap:0.75rem;flex-wrap:wrap;margin:1rem 0;">
    <h3 style="margin:0;">Phoenix Schedule Calendar: ${escapeHtml(monthParam)}</h3>
    <div style="display:flex;gap:0.5rem;">
      <a href="/admin/campaigns?view=calendar&month=${encodeURIComponent(fmtYm(prevDate))}" class="btn btn--secondary btn--compact">&larr; ${escapeHtml(fmtYm(prevDate))}</a>
      <a href="/admin/campaigns?view=calendar&month=${encodeURIComponent(fmtYm(nextDate))}" class="btn btn--secondary btn--compact">${escapeHtml(fmtYm(nextDate))} &rarr;</a>
    </div>
  </div>
  <div class="cal-grid" role="region" aria-label="Monthly Campaign Calendar">
    <div class="cal-head">Sun</div><div class="cal-head">Mon</div><div class="cal-head">Tue</div><div class="cal-head">Wed</div><div class="cal-head">Thu</div><div class="cal-head">Fri</div><div class="cal-head">Sat</div>
    ${cells.join('')}
  </div>
  <h3 style="margin-top:1.25rem;">Accessible Calendar Schedule List (${escapeHtml(monthParam)})</h3>
  ${monthScheduleSummary.length === 0
      ? '<p class="muted">No scheduled or live campaigns fall within this month.</p>'
      : `<ul style="font-size:0.88rem;">${allCampaigns
        .filter((c) => c.activation_state !== 'Archived')
        .map(
          (c) => `<li><strong>${escapeHtml(c.internal_title)}</strong> [<code>${escapeHtml(c.placement_slot)}</code>, P${escapeHtml(c.priority)}, ${escapeHtml(c.activation_state)}] — ${escapeHtml(formatPhoenixDateTime(c.start_at, false))} &rarr; ${c.is_evergreen ? 'Evergreen' : escapeHtml(formatPhoenixDateTime(c.end_at, false))}${c.warnings?.length ? ` <span class="badge badge--err">${escapeHtml(c.warnings.join('; '))}</span>` : ''}</li>`
        )
        .join('')}</ul>`
    }`;
}

export function renderAdminCampaignsView({
  campaigns,
  campaignsMeta,
  allCampaigns = campaigns,
  selectedCampaign = null,
  assets,
  viewMode = 'list',
  monthParam = '',
  filters = {},
  user,
  csrfToken,
}) {
  const canPublish = hasPermission(user, PERMISSIONS.PUBLISH_CAMPAIGNS);
  const canEdit = hasPermission(user, PERMISSIONS.MANAGE_CAMPAIGNS);

  let selectedTargets = '';
  if (selectedCampaign) {
    try {
      selectedTargets = JSON.parse(selectedCampaign.target_service_slugs_json || '[]').join(', ');
    } catch {
      selectedTargets = '';
    }
  }

  return `
  <section class="admin-card">
    <div class="admin-card__header">
      <div>
        <h2>Seasonal Website Campaigns</h2>
        <p class="muted" style="margin:0;font-size:0.86rem;">Notice Strip, Homepage Feature &amp; Contextual Service Slots in <strong>America/Phoenix</strong>.</p>
      </div>
      <div class="admin-action-group">
        <a href="/admin/campaigns?view=list" class="btn ${viewMode === 'list' ? 'btn--primary' : 'btn--secondary'}">List View</a>
        <a href="/admin/campaigns?view=calendar&month=${encodeURIComponent(monthParam)}" class="btn ${viewMode === 'calendar' ? 'btn--primary' : 'btn--secondary'}">Calendar</a>
        <button type="button" class="btn btn--secondary js-action-btn" data-url="/admin/api/campaigns/run-scheduler">Run Scheduler</button>
      </div>
    </div>

    <details class="admin-accordion" style="margin-top:0;margin-bottom:1rem;">
      <summary>Preview Website at Future America/Phoenix Date &amp; Time</summary>
      <form method="GET" action="/admin/preview" target="_blank" style="display:flex;flex-wrap:wrap;gap:0.75rem;align-items:flex-end;">
        <div class="field" style="margin:0;min-width:12rem;"><label for="prev-path">Target Page</label>
          <select id="prev-path" name="path">
            <option value="/">Home (/)</option>
            <option value="/services/exterior-site-maintenance/">Exterior &amp; Site Maintenance</option>
            <option value="/services/day-porter/">Day Porter Services</option>
            <option value="/services/warehouse-repairs/">Warehouse Repairs</option>
          </select>
        </div>
        <div class="field" style="margin:0;"><label for="prev-asof">As-Of Date/Time (America/Phoenix)</label>
          <input type="datetime-local" id="prev-asof" name="asOf" value="${escapeHtml(utcIsoToPhoenixInput(new Date().toISOString()))}">
        </div>
        <div class="field" style="margin:0;"><label for="prev-vp">Viewport</label>
          <select id="prev-vp" name="viewport">
            <option value="desktop">Desktop</option>
            <option value="mobile">Mobile (390px)</option>
          </select>
        </div>
        <button type="submit" class="btn btn--secondary">Open Preview</button>
      </form>
    </details>

    <form method="GET" action="/admin/campaigns" class="admin-filter-bar">
      <input type="hidden" name="view" value="${escapeHtml(viewMode)}">
      <div class="field" style="flex:1;min-width:12rem;"><label for="cp-q">Search campaigns</label><input id="cp-q" name="q" type="search" value="${escapeHtml(filters.q || '')}"></div>
      <div class="field"><label for="cp-fslot">Slot</label>
        <select id="cp-fslot" name="slot">
          <option value="">All slots</option>
          <option value="homepage_feature"${filters.slot === 'homepage_feature' ? ' selected' : ''}>homepage_feature</option>
          <option value="notice_strip"${filters.slot === 'notice_strip' ? ' selected' : ''}>notice_strip</option>
          <option value="service_contextual"${filters.slot === 'service_contextual' ? ' selected' : ''}>service_contextual</option>
        </select>
      </div>
      <div class="field"><label for="cp-fstate">State</label>
        <select id="cp-fstate" name="state">
          <option value="">All states</option>
          ${['Unpublished', 'Scheduled', 'Live', 'Paused', 'Ended', 'Archived']
      .map((st) => `<option value="${st}"${filters.state === st ? ' selected' : ''}>${st}</option>`)
      .join('')}
        </select>
      </div>
      <div class="admin-action-group">
        <button type="submit" class="btn btn--secondary">Filter</button>
        ${filters.q || filters.slot || filters.state ? '<a href="/admin/campaigns" class="btn btn--secondary">Clear</a>' : ''}
      </div>
    </form>

    ${viewMode === 'calendar'
      ? renderPhoenixCalendarHtml(allCampaigns, monthParam)
      : `
          <div class="admin-desktop-only">
            <div class="table-scroll" style="margin-top:1rem;" tabindex="0" role="region" aria-label="Seasonal Campaigns Table">
              <table class="data-table">
                <thead>
                  <tr><th>Campaign &amp; Diagnostics</th><th>Slot / Prio</th><th>Start &rarr; End (Phoenix)</th><th>State</th><th>Actions</th></tr>
                </thead>
                <tbody>
                  ${campaigns.length === 0
        ? '<tr><td colspan="5" class="muted">No campaigns matching current filter.</td></tr>'
        : campaigns
          .map(
            (c) => `<tr>
                              <td>
                                <strong>${escapeHtml(c.internal_title)}</strong> (rev ${escapeHtml(c.content_revision)})<br>
                                <small class="muted"><code>/lp/${escapeHtml(c.slug)}/</code> &rarr; ${escapeHtml(c.cta_destination)}</small>
                                ${c.warnings && c.warnings.length > 0
                ? `<div style="margin-top:0.3rem;">${c.warnings.map((w) => `<span class="badge badge--err">${escapeHtml(w)}</span>`).join(' ')}</div>`
                : ''
              }
                              </td>
                              <td><code>${escapeHtml(c.placement_slot)}</code><br><small>P${escapeHtml(c.priority)}</small></td>
                              <td>${escapeHtml(formatPhoenixDateTime(c.start_at, false))}<br>&rarr; ${c.is_evergreen ? 'Evergreen' : escapeHtml(formatPhoenixDateTime(c.end_at, false))}</td>
                              <td><span class="badge">${escapeHtml(c.editorial_state)}</span> <span class="badge ${c.activation_state === 'Live' ? 'badge--live' : c.activation_state === 'Archived' ? 'badge--err' : 'badge--warn'}">${escapeHtml(c.activation_state)}</span></td>
                              <td>
                                <div class="admin-action-group">
                                  ${canEdit && c.activation_state !== 'Archived' ? `<a href="/admin/campaigns?edit=${encodeURIComponent(c.campaign_id)}#campaign-editor-panel" class="btn btn--secondary btn--compact">Edit</a>` : ''}
                                  ${canPublish && c.activation_state !== 'Live' && c.activation_state !== 'Archived'
                ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/approve-schedule">Approve &amp; Schedule</button>`
                : ''
              }
                                  ${canPublish && c.activation_state === 'Live'
                ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/pause">Pause</button>`
                : ''
              }
                                  ${canPublish && c.activation_state === 'Paused'
                ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/resume">Resume</button>`
                : ''
              }
                                  ${canPublish && c.activation_state !== 'Archived'
                ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/archive" data-confirm-title="Archive Campaign?" data-confirm="Archive &quot;${escapeHtml(c.internal_title)}&quot;? Archived campaigns cannot be edited further.">Archive</button>`
                : ''
              }
                                </div>
                              </td>
                            </tr>`
          )
          .join('')
      }
                </tbody>
              </table>
            </div>
          </div>
          <div class="admin-mobile-cards">
            ${campaigns.length === 0
        ? '<div class="admin-empty-state">No campaigns matching current filter.</div>'
        : campaigns
          .map(
            (c) => `<div class="admin-mobile-card">
                        <div class="admin-mobile-card__top">
                          <span class="admin-mobile-card__title">${escapeHtml(c.internal_title)}</span>
                          <span class="badge ${c.activation_state === 'Live' ? 'badge--live' : c.activation_state === 'Archived' ? 'badge--err' : 'badge--warn'}">${escapeHtml(c.activation_state)}</span>
                        </div>
                        <div class="admin-mobile-card__meta"><code>${escapeHtml(c.placement_slot)}</code> &middot; Priority ${escapeHtml(c.priority)}<br>${escapeHtml(formatPhoenixDateTime(c.start_at, false))} &rarr; ${c.is_evergreen ? 'Evergreen' : escapeHtml(formatPhoenixDateTime(c.end_at, false))}</div>
                        ${c.warnings && c.warnings.length > 0
                ? `<div>${c.warnings.map((w) => `<span class="badge badge--err">${escapeHtml(w)}</span>`).join(' ')}</div>`
                : ''
              }
                        <div class="admin-mobile-card__actions">
                          ${canEdit && c.activation_state !== 'Archived' ? `<a href="/admin/campaigns?edit=${encodeURIComponent(c.campaign_id)}#campaign-editor-panel" class="btn btn--secondary btn--compact">Edit Campaign</a>` : ''}
                          ${canPublish && c.activation_state !== 'Live' && c.activation_state !== 'Archived' ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/approve-schedule">Approve &amp; Schedule</button>` : ''}
                          ${canPublish && c.activation_state === 'Live' ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/pause">Pause</button>` : ''}
                        </div>
                      </div>`
          )
          .join('')
      }
          </div>
          ${renderPaginationNav('/admin/campaigns', campaignsMeta, { view: viewMode, ...filters })}`
    }
  </section>

  ${canEdit
      ? `<details id="campaign-editor-panel" class="admin-accordion"${selectedCampaign ? ' open' : ''}>
          <summary>${selectedCampaign ? `Edit Campaign: ${escapeHtml(selectedCampaign.internal_title)}` : '+ Create Seasonal Campaign'}</summary>
          <form method="POST" action="${selectedCampaign ? `/admin/api/campaigns/${escapeHtml(selectedCampaign.campaign_id)}` : '/admin/api/campaigns'}" class="js-ajax-form form-stack">
            <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
            <div class="grid-2">
              <div class="field"><label for="cp-title">Internal Title</label><input id="cp-title" name="internal_title" value="${escapeHtml(selectedCampaign?.internal_title || '')}" required></div>
              ${selectedCampaign
        ? `<div class="field"><label for="cp-slug">Landing Slug (Immutable)</label><input id="cp-slug" value="${escapeHtml(selectedCampaign.slug)}" disabled></div>`
        : `<div class="field"><label for="cp-slug">Landing Slug (/lp/{slug}/)</label><input id="cp-slug" name="slug" pattern="[a-z0-9-]+" required></div>`
      }
            </div>
            <div class="grid-2">
              <div class="field"><label for="cp-slot">Placement Slot</label>
                <select id="cp-slot" name="placement_slot">
                  ${[
        { v: 'homepage_feature', l: 'Homepage Seasonal Feature' },
        { v: 'notice_strip', l: 'Promotional Notice Strip' },
        { v: 'service_contextual', l: 'Contextual Service Page Module' },
      ]
        .map((o) => `<option value="${o.v}"${selectedCampaign?.placement_slot === o.v ? ' selected' : ''}>${o.l}</option>`)
        .join('')}
                </select>
              </div>
              <div class="field"><label for="cp-prio">Numeric Priority (higher wins overlap)</label><input type="number" id="cp-prio" name="priority" value="${escapeHtml(selectedCampaign?.priority ?? 20)}" required></div>
            </div>
            <div class="grid-2">
              <div class="field"><label for="cp-start">Start (America/Phoenix)</label><input type="datetime-local" id="cp-start" name="start_phoenix" value="${selectedCampaign ? escapeHtml(utcIsoToPhoenixInput(selectedCampaign.start_at)) : ''}" required></div>
              <div class="field"><label for="cp-end">End (America/Phoenix, required unless evergreen)</label><input type="datetime-local" id="cp-end" name="end_phoenix" value="${selectedCampaign?.end_at ? escapeHtml(utcIsoToPhoenixInput(selectedCampaign.end_at)) : ''}"></div>
            </div>
            <div class="field"><label for="cp-heading">Public Heading</label><input id="cp-heading" name="heading" value="${escapeHtml(selectedCampaign?.heading || '')}" required></div>
            <div class="field"><label for="cp-summary">Public Summary</label><textarea id="cp-summary" name="summary" style="min-height:4rem;" required>${escapeHtml(selectedCampaign?.summary || '')}</textarea></div>
            <div class="grid-2">
              <div class="field"><label for="cp-cta-label">CTA Label</label><input id="cp-cta-label" name="cta_label" value="${escapeHtml(selectedCampaign?.cta_label || 'Request a property assessment')}" required></div>
              <div class="field"><label for="cp-cta-dest">CTA Destination (internal route)</label><input id="cp-cta-dest" name="cta_destination" value="${escapeHtml(selectedCampaign?.cta_destination || '/request-proposal/')}" required></div>
            </div>
            <div class="field"><label for="cp-targets">Target Service Slugs (comma-separated for service_contextual)</label><input id="cp-targets" name="target_service_slugs" value="${escapeHtml(selectedTargets)}" placeholder="/services/exterior-site-maintenance/"></div>
            <div class="field"><label for="cp-asset">Approved Media Asset (optional)</label>
              <select id="cp-asset" name="asset_id">
                <option value="">No image (text-only fallback)</option>
                ${assets.filter((a) => a.rights_status === 'approved').map((a) => `<option value="${escapeHtml(a.asset_id)}"${selectedCampaign?.asset_id === a.asset_id ? ' selected' : ''}>${escapeHtml(a.original_filename)}</option>`).join('')}
              </select>
            </div>
            <div class="admin-action-group">
              <button type="submit" class="btn btn--primary">${selectedCampaign ? 'Save Campaign Revision Draft' : 'Save Campaign Draft'}</button>
              ${selectedCampaign ? '<a href="/admin/campaigns" class="btn btn--secondary">Cancel Edit</a>' : ''}
            </div>
          </form>
        </details>`
      : ''
    }`;
}

function renderAdminPageHeader({ title, subtitle = '', actionsHtml = '' }) {
  return `<div class="admin-section-head">
    <div>
      <h2 style="margin:0 0 0.2rem;border:0;padding:0;font-size:1.35rem;">${escapeHtml(title)}</h2>
      ${subtitle ? `<p class="muted" style="margin:0;font-size:0.88rem;">${escapeHtml(subtitle)}</p>` : ''}
    </div>
    ${actionsHtml ? `<div class="admin-action-group">${actionsHtml}</div>` : ''}
  </div>`;
}

function renderAdminKpiStrip(cards = []) {
  if (!cards.length) return '';
  return `<div class="kpi-grid">${cards
    .map(
      (c) => `<div class="kpi-card${c.accent ? ' kpi-card--accent' : ''}">
        <span class="kpi-card__num">${escapeHtml(c.value)}</span>
        <span class="kpi-card__label">${escapeHtml(c.label)}</span>
        ${c.hint ? `<span class="kpi-card__hint">${escapeHtml(c.hint)}</span>` : ''}
      </div>`
    )
    .join('')}</div>`;
}

function renderAdminEmptyState({ title, description, ctaHtml = '' }) {
  return `<div class="admin-empty-card">
    <h3>${escapeHtml(title)}</h3>
    <p class="muted">${escapeHtml(description)}</p>
    ${ctaHtml ? `<div style="margin-top:0.9rem;">${ctaHtml}</div>` : ''}
  </div>`;
}

function renderProjectStatusTracker(project, checks = [], isContributor = false) {
  if (!project) return '';
  const isApprovedLive = project.editorial_state === 'Approved' && project.activation_state === 'Live';
  const isInReview = project.editorial_state === 'In review';
  const isDraft = project.editorial_state === 'Draft';
  const isArchived = project.activation_state === 'Archived';
  const allChecksPass = checks.length > 0 && checks.every((c) => c.passed);
  const failedChecks = checks.filter((c) => !c.passed);
  const contributorChecksPass = checks.length > 0 && checks.every((c) => c.key === 'media_rights' ? true : c.passed);
  const failedContributorChecks = checks.filter((c) => c.key !== 'media_rights' && !c.passed);

  // Stepper states: Draft -> Details & Evidence -> Photo Review -> In Review -> Live
  let s1State = 'done';
  let s2State = 'upcoming';
  let s3State = 'upcoming';
  let s4State = 'upcoming';
  let s5State = 'upcoming';

  if (isArchived) {
    s1State = 'done';
    s2State = 'done';
    s3State = 'done';
    s4State = 'done';
    s5State = 'done';
  } else if (isApprovedLive) {
    s1State = 'done';
    s2State = 'done';
    s3State = 'done';
    s4State = 'done';
    s5State = 'done';
  } else if (isInReview) {
    s1State = 'done';
    s2State = 'done';
    s3State = 'done';
    s4State = 'active';
  } else {
    // Draft
    const hasDetails = checks.find((c) => c.key === 'details')?.passed;
    const hasEvidence = checks.find((c) => c.key === 'evidence')?.passed && checks.find((c) => c.key === 'permission')?.passed;
    const hasPhotos = checks.find((c) => c.key === 'photos_exist')?.passed;
    const rightsApproved = checks.find((c) => c.key === 'media_rights')?.passed;

    if (!hasDetails || !hasEvidence) {
      s2State = 'active';
    } else if (!hasPhotos) {
      s2State = 'done';
      s3State = 'active';
    } else {
      s2State = 'done';
      s3State = 'done';
      s4State = 'upcoming';
    }
  }

  let nextActionText = '';
  if (isArchived) {
    nextActionText = 'This project is archived and removed from public listings.';
  } else if (isApprovedLive) {
    nextActionText = 'This project is live on the public website. You can view the live case study or update details at any time.';
  } else if (isInReview) {
    nextActionText = isContributor
      ? 'Awaiting Publisher Review: Your project has been submitted. An Approver & Publisher will review checklist items and publish it live.'
      : 'Awaiting Publisher Review: Review checklist items below and Approve & Publish live, or Return to Draft if edits are needed.';
  } else if (isContributor && contributorChecksPass) {
    nextActionText = 'All contributor requirements complete! Click "Submit for Review" below to send this project to the publisher.';
  } else if (allChecksPass) {
    nextActionText = isContributor
      ? 'All evidence and details documented! Open Step 5 to Submit for Publisher Review.'
      : 'All publishing requirements satisfied. Ready to Approve & Publish Live.';
  } else if (isContributor) {
    nextActionText = `${failedContributorChecks.length} requirement(s) pending: ${failedContributorChecks.map((f) => f.label).join('; ')}.`;
  } else {
    nextActionText = `${failedChecks.length} requirement(s) pending: ${failedChecks.map((f) => f.label).join('; ')}.`;
  }

  // Friendly human badge label
  const friendlyStatus = isArchived
    ? 'Archived'
    : isApprovedLive
      ? 'Live on Website'
      : isInReview
        ? 'Awaiting Publisher Review'
        : 'Draft (In Progress)';

  return `
    <div class="project-lifecycle-box" role="region" aria-label="Project Lifecycle Tracker">
      <div class="project-lifecycle-head">
        <div style="display:flex;align-items:center;gap:0.6rem;flex-wrap:wrap;">
          <span style="font-size:0.8rem;text-transform:uppercase;letter-spacing:0.06em;font-weight:700;color:var(--text-subtle);">Current Stage:</span>
          <span class="badge ${isApprovedLive ? 'badge--live' : isInReview ? 'badge--info' : isArchived ? 'badge--err' : 'badge--warn'}">
            ${escapeHtml(friendlyStatus)}
          </span>
          ${project.is_private_test ? '<span class="badge badge--err">Private Test Record (Not Public)</span>' : ''}
        </div>
        <div class="project-lifecycle-next">
          <strong>Next Action:</strong> ${escapeHtml(nextActionText)}
        </div>
      </div>
      <ol class="wizard-stepper wizard-stepper--compact" aria-label="Project lifecycle steps">
        <li class="wizard-stepper__item" data-state="${s1State}"><span class="wizard-stepper__num">1</span><span>Draft Created</span></li>
        <li class="wizard-stepper__item" data-state="${s2State}"><span class="wizard-stepper__num">2</span><span>Work &amp; Evidence</span></li>
        <li class="wizard-stepper__item" data-state="${s3State}"><span class="wizard-stepper__num">3</span><span>Before/After Photos</span></li>
        <li class="wizard-stepper__item" data-state="${s4State}"><span class="wizard-stepper__num">4</span><span>Publisher Review</span></li>
        <li class="wizard-stepper__item" data-state="${s5State}"><span class="wizard-stepper__num">5</span><span>Live on Website</span></li>
      </ol>
    </div>
  `;
}

function renderReadinessChecklist(checks = [], isContributor = false) {
  return `<ul class="readiness-list">
    ${checks
      .map(
        (chk) => {
          const isRightsCheck = chk.key === 'media_rights';
          const showAsPendingPublisher = isContributor && isRightsCheck && !chk.passed;

          return `<li class="readiness-item ${chk.passed ? 'is-pass' : showAsPendingPublisher ? 'is-publisher-pending' : 'is-fail'}">
            <span class="readiness-item__icon" aria-hidden="true">${chk.passed ? '&#10003;' : showAsPendingPublisher ? '&#9679;' : '!'}</span>
            <div style="flex:1;min-width:0;">
              <strong>${escapeHtml(chk.label)}</strong>
              ${showAsPendingPublisher
                ? `<div class="readiness-item__hint muted" style="margin-top:0.2rem;font-size:0.83rem;">Publisher will review and approve photo rights upon submission. Does not block submitting for review.</div>`
                : (!chk.passed && chk.blocker ? `<div class="readiness-item__blocker">${escapeHtml(chk.blocker)}</div>` : '')
              }
            </div>
            ${!chk.passed && chk.fixTab && !showAsPendingPublisher
              ? `<button type="button" class="btn btn--secondary btn--compact js-switch-project-tab" data-target-tab="${escapeHtml(chk.fixTab)}">Fix</button>`
              : ''
            }
          </li>`;
        }
      )
      .join('')}
  </ul>`;
}

export function renderAdminProjectsView({
  view = 'overview',
  tab = 'overview',
  projects = [],
  projectCounts = {},
  selectedProject = null,
  pairs = [],
  galleryItems = [],
  assets = [],
  assetUsageMap = {},
  publishChecks = [],
  filters = {},
  user,
  csrfToken,
}) {
  const canPublish = hasPermission(user, PERMISSIONS.PUBLISH_PROJECTS);
  const canEdit = hasPermission(user, PERMISSIONS.EDIT_PROJECTS);
  const canUploadMedia = hasPermission(user, PERMISSIONS.UPLOAD_PROJECT_MEDIA) || canEdit;
  const assetById = Object.fromEntries(assets.map((a) => [a.asset_id, a]));

  const totalCount = projects.length;
  const liveCount = projects.filter((p) => p.activation_state === 'Live').length;
  const draftCount = projects.filter((p) => p.activation_state !== 'Live' && p.activation_state !== 'Archived').length;
  const approvedMediaCount = assets.filter((a) => a.rights_status === 'approved').length;

  const renderMediaUploaderCard = ({ idPrefix = 'media', title = 'Upload Project Photos', subtitle = 'Drag and drop photos or browse from your computer or phone. EXIF/GPS location data is stripped automatically.', showRoleHint = false, projectId = '' } = {}) => `
    <section class="admin-card">
      ${renderAdminPageHeader({ title, subtitle })}
      <form id="${escapeHtml(idPrefix)}-upload-form" method="POST" action="/admin/api/media/upload" enctype="multipart/form-data" class="js-media-dropzone-form" data-project-id="${escapeHtml(projectId)}">
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
        ${showRoleHint
      ? `<div class="grid-2" style="margin-bottom:0.85rem;">
                <div class="field" style="margin:0;">
                  <label for="${escapeHtml(idPrefix)}-role">Photo Type</label>
                  <select id="${escapeHtml(idPrefix)}-role" name="photo_role">
                    <option value="general">General Project Photo</option>
                    <option value="before">Before Photo (Pre-Work)</option>
                    <option value="after">After Photo (Completed Work)</option>
                  </select>
                </div>
                <div class="field" style="margin:0;">
                  <label for="${escapeHtml(idPrefix)}-alt">Photo Description (Alt Text)</label>
                  <input id="${escapeHtml(idPrefix)}-alt" name="alt_text" placeholder="e.g. Warehouse loading dock repair in Tempe" required>
                </div>
              </div>`
      : `<div class="field">
                <label for="${escapeHtml(idPrefix)}-alt">Photo Description (Alt Text)</label>
                <span class="hint">Describe what is shown in the photo for screen readers and search engines.</span>
                <input id="${escapeHtml(idPrefix)}-alt" name="alt_text" placeholder="e.g. Completed retail storefront repaint in Phoenix" required>
              </div>`
    }
        <div class="field">
          <label for="${escapeHtml(idPrefix)}-rights">Rights Owner / Permission Source</label>
          <input id="${escapeHtml(idPrefix)}-rights" name="rights_owner" value="Service Maintenance / Client Approved" required>
        </div>

        <div class="dropzone-box" data-dropzone-for="${escapeHtml(idPrefix)}-files" tabindex="0" role="button" aria-label="Choose or drop photos to upload">
          <input type="file" id="${escapeHtml(idPrefix)}-files" name="photos" multiple accept="image/jpeg,image/png,image/webp,image/heic,.jpg,.jpeg,.png,.webp,.heic" class="dropzone-input">
          <div class="dropzone-box__content">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            <strong>Drag &amp; drop photos here, or click to browse</strong>
            <span>Supports JPEG, PNG, WebP, and HEIC &middot; Up to 20 files, 20 MB each (64 MP max) &middot; Originals stay private</span>
          </div>
        </div>
        <div id="${escapeHtml(idPrefix)}-previews" class="dropzone-previews" hidden></div>
        <div class="admin-action-group" style="margin-top:0.85rem;">
          <button type="submit" class="btn btn--primary" id="${escapeHtml(idPrefix)}-submit-btn">Upload Photos</button>
          <span id="${escapeHtml(idPrefix)}-upload-feedback" class="hint" aria-live="polite" style="margin:0;"></span>
        </div>
      </form>
    </section>
  `;

  // ==========================================================
  // VIEW 2: GUIDED 4-STEP CREATE PROJECT (?view=create)
  // ==========================================================
  if (view === 'create') {
    if (!canEdit) {
      return renderAdminEmptyState({
        title: 'Create Project Restricted',
        description: 'Your role can view or upload media, but creating new project case studies requires Content Editor or Project Contributor permission.',
        ctaHtml: '<a href="/admin/projects" class="btn btn--secondary">&larr; Back to Projects</a>',
      });
    }
    return `
    <div class="admin-card">
      ${renderAdminPageHeader({
      title: 'Create New Project',
      subtitle: 'Follow the 4 guided steps below to document a completed commercial project. You can save a draft from Step 2 onward.',
      actionsHtml: '<a href="/admin/projects" class="btn btn--secondary">&larr; Back to Projects</a>',
    })}

      <ol class="wizard-stepper" id="project-create-stepper" aria-label="Create project steps">
        <li class="wizard-stepper__item" data-wiz-ind="1" data-state="active" aria-current="step"><span class="wizard-stepper__num">1</span><span>Basic Info</span></li>
        <li class="wizard-stepper__item" data-wiz-ind="2" data-state="upcoming"><span class="wizard-stepper__num">2</span><span>Work Details</span></li>
        <li class="wizard-stepper__item" data-wiz-ind="3" data-state="upcoming"><span class="wizard-stepper__num">3</span><span>Before &amp; After Photos</span></li>
        <li class="wizard-stepper__item" data-wiz-ind="4" data-state="upcoming"><span class="wizard-stepper__num">4</span><span>Review &amp; Save</span></li>
      </ol>

      <div id="project-create-error" class="admin-inline-alert admin-inline-alert--error" hidden role="alert">
        <span id="project-create-error-text"></span>
      </div>

      <form id="project-create-wizard" class="form-stack form-stack--wide" method="POST" action="/admin/api/projects" novalidate>
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">

        <!-- Step 1: Basic Information -->
        <section class="wizard-step" data-wiz-step="1" aria-labelledby="wiz-s1-title">
          <h3 id="wiz-s1-title" style="margin-top:0;">Step 1: Basic Project Information</h3>
          <p class="muted" style="font-size:0.88rem;margin-bottom:1rem;">Start with the property name, type, location, and when the work was completed.</p>
          <div class="grid-2">
            <div class="field">
              <label for="wiz-title">Project Title <span aria-hidden="true">*</span></label>
              <span class="hint">Plain-English title shown on the website (e.g. Warehouse Dock &amp; Interior Refresh &mdash; Tempe).</span>
              <input id="wiz-title" name="title" required placeholder="e.g. Industrial Warehouse Door &amp; Lighting Upgrade">
            </div>
            <div class="field">
              <label for="wiz-prop">Property Type <span aria-hidden="true">*</span></label>
              <span class="hint">Category of commercial property serviced.</span>
              <select id="wiz-prop" name="property_type" required>
                <option value="Industrial / Warehouse">Industrial / Warehouse</option>
                <option value="Retail Center">Retail Center</option>
                <option value="Commercial Office">Commercial Office</option>
                <option value="Multi-Tenant Portfolio">Multi-Tenant Portfolio</option>
              </select>
            </div>
          </div>
          <div class="grid-2">
            <div class="field">
              <label for="wiz-city">Location (City / Region) <span aria-hidden="true">*</span></label>
              <input id="wiz-city" name="city_region" value="Phoenix / Greater Phoenix" required>
            </div>
            <div class="field">
              <label for="wiz-comp">Completion Date <span aria-hidden="true">*</span></label>
              <input type="date" id="wiz-comp" name="completion_date" required>
            </div>
          </div>
          <details class="admin-accordion" style="margin-bottom:1rem;">
            <summary>Advanced: Website URL Slug (auto-generated from title)</summary>
            <div class="field" style="margin-bottom:0;">
              <label for="wiz-slug">URL Slug <span aria-hidden="true">*</span></label>
              <span class="hint">Lowercase letters, numbers, and hyphens only. Example: <code>tempe-warehouse-refresh</code></span>
              <input id="wiz-slug" name="slug" pattern="[a-z0-9]+(-[a-z0-9]+)*" required>
            </div>
          </details>
          <div class="wizard-actions wizard-actions--space">
            <a href="/admin/projects" class="btn btn--secondary">&larr; Cancel</a>
            <div class="admin-action-group">
              <button type="button" class="btn btn--secondary" id="wiz-save-draft-step1">Save as Draft</button>
              <button type="button" class="btn btn--primary" data-wiz-next="2">Continue to Work Details &rarr;</button>
            </div>
          </div>
        </section>

        <!-- Step 2: Work Details -->
        <section class="wizard-step" data-wiz-step="2" hidden aria-labelledby="wiz-s2-title">
          <h3 id="wiz-s2-title" style="margin-top:0;">Step 2: Work Details</h3>
          <p class="muted" style="font-size:0.88rem;margin-bottom:1rem;">Explain what needed attention, the agreed scope, and what was completed.</p>
          <div class="field">
            <label for="wiz-chal">Customer Challenge <span aria-hidden="true">*</span></label>
            <span class="hint">What issue or property need did the client bring to us?</span>
            <textarea id="wiz-chal" name="challenge" style="min-height:4.5rem;" required></textarea>
          </div>
          <div class="field">
            <label for="wiz-scope">Agreed Scope <span aria-hidden="true">*</span></label>
            <span class="hint">Clear summary of what was included in the written scope.</span>
            <textarea id="wiz-scope" name="agreed_scope" style="min-height:4.5rem;" required></textarea>
          </div>
          <div class="grid-2">
            <div class="field">
              <label for="wiz-work">Work Completed <span aria-hidden="true">*</span></label>
              <textarea id="wiz-work" name="completed_work" style="min-height:4.5rem;" required></textarea>
            </div>
            <div class="field">
              <label for="wiz-res">Verified Result</label>
              <textarea id="wiz-res" name="verified_result" style="min-height:4.5rem;" placeholder="e.g. Suite turned over cleanly on schedule with zero punch-list items remaining."></textarea>
            </div>
          </div>
          <details class="admin-accordion" style="margin-bottom:1rem;">
            <summary>Optional: Trade Attribution &amp; Related Services</summary>
            <div class="grid-3">
              <div class="field"><label for="wiz-self">Self-Performed Elements</label><input id="wiz-self" name="self_performed_notes" value="In-house work"></div>
              <div class="field"><label for="wiz-coord">Coordinated Trades</label><input id="wiz-coord" name="coordinated_notes" value="Coordinated trades where applicable"></div>
              <div class="field"><label for="wiz-rel">Related Service Slugs</label><input id="wiz-rel" name="related_services" placeholder="warehouse-repairs, day-porter"></div>
            </div>
          </details>
          <div class="wizard-actions">
            <button type="button" class="btn btn--secondary" data-wiz-prev="1">&larr; Back</button>
            <div class="admin-action-group">
              <button type="button" class="btn btn--secondary" id="wiz-save-draft-early">Save Draft Now</button>
              <button type="button" class="btn btn--primary" data-wiz-next="3">Continue to Photos &rarr;</button>
            </div>
          </div>
        </section>

        <!-- Step 3: Photos (Before & After) -->
        <section class="wizard-step" data-wiz-step="3" hidden aria-labelledby="wiz-s3-title">
          <h3 id="wiz-s3-title" style="margin-top:0;">Step 3: Before &amp; After Photos (Optional for Draft)</h3>
          <p class="muted" style="font-size:0.88rem;margin-bottom:1rem;">Upload clear <strong>Before</strong> and <strong>After</strong> photos to automatically create a visual comparison, or skip and add photos later. JPEG, PNG, WebP, HEIC up to 20 MB each; EXIF/GPS metadata is stripped automatically.</p>

          <div class="grid-2" style="margin-bottom:1rem;">
            <div class="panel panel--light">
              <h4 style="margin-top:0;">Before Photo (Pre-Work)</h4>
              <div class="dropzone-box dropzone-box--compact" data-dropzone-for="wiz-before-file" tabindex="0" role="button" aria-label="Select Before photo">
                <input type="file" id="wiz-before-file" accept="image/jpeg,image/png,image/webp,image/heic,.jpg,.jpeg,.png,.webp,.heic" class="dropzone-input">
                <div class="dropzone-box__content">
                  <strong>Drop Before photo or click to browse</strong>
                  <span>Condition before work began</span>
                </div>
              </div>
              <div id="wiz-before-preview" class="dropzone-previews" hidden></div>
              <div class="field" style="margin-top:0.75rem;margin-bottom:0;">
                <label for="wiz-before-cap">Before Caption</label>
                <input id="wiz-before-cap" placeholder="e.g. Damaged dock seal prior to replacement">
              </div>
            </div>

            <div class="panel panel--light">
              <h4 style="margin-top:0;">After Photo (Completed Work)</h4>
              <div class="dropzone-box dropzone-box--compact" data-dropzone-for="wiz-after-file" tabindex="0" role="button" aria-label="Select After photo">
                <input type="file" id="wiz-after-file" accept="image/jpeg,image/png,image/webp,image/heic,.jpg,.jpeg,.png,.webp,.heic" class="dropzone-input">
                <div class="dropzone-box__content">
                  <strong>Drop After photo or click to browse</strong>
                  <span>Finished commercial result</span>
                </div>
              </div>
              <div id="wiz-after-preview" class="dropzone-previews" hidden></div>
              <div class="field" style="margin-top:0.75rem;margin-bottom:0;">
                <label for="wiz-after-cap">After Caption</label>
                <input id="wiz-after-cap" placeholder="e.g. New weather-tight seal installed">
              </div>
            </div>
          </div>

          <div class="field">
            <label for="wiz-pair-title">Comparison Title (used if both Before &amp; After photos are added)</label>
            <input id="wiz-pair-title" placeholder="e.g. Loading Dock Restoration">
          </div>

          <div class="wizard-actions">
            <button type="button" class="btn btn--secondary" data-wiz-prev="2">&larr; Back</button>
            <button type="button" class="btn btn--primary" data-wiz-next="4">Review &amp; Save &rarr;</button>
          </div>
        </section>

        <!-- Step 4: Review & Save -->
        <section class="wizard-step" data-wiz-step="4" hidden aria-labelledby="wiz-s4-title">
          <h3 id="wiz-s4-title" style="margin-top:0;">Step 4: Review, Permissions &amp; Save</h3>
          <p class="muted" style="font-size:0.88rem;margin-bottom:1rem;">Confirm the project details and client permissions below before saving.</p>

          <div id="wiz-review-box" class="review-summary" style="margin-bottom:1rem;"></div>

          <div class="panel panel--light" style="margin-bottom:1rem;">
            <h4 style="margin-top:0;">Evidence &amp; Client Permissions</h4>
            <div class="field">
              <label for="wiz-naming">Client Naming Decision</label>
              <select id="wiz-naming" name="naming_decision">
                <option value="anonymized">Anonymized (keep client name private)</option>
                <option value="named">Named (explicit written client permission obtained)</option>
              </select>
            </div>
            <div class="choice-row"><input type="checkbox" id="wiz-doc" name="completion_documented"><label for="wiz-doc">Actual completion evidence documented</label></div>
            <div class="choice-row"><input type="checkbox" id="wiz-perm" name="client_permission_verified"><label for="wiz-perm">Client naming/anonymity &amp; photo permission verified</label></div>
            <div class="choice-row"><input type="checkbox" id="wiz-test" name="is_private_test"><label for="wiz-test">Private Staging/Test Record (blocks public display)</label></div>
          </div>

          <div class="wizard-actions">
            <button type="button" class="btn btn--secondary" data-wiz-prev="3">&larr; Back</button>
            <div class="admin-action-group">
              <button type="submit" class="btn btn--primary" id="wiz-submit-btn">Save Project Draft</button>
            </div>
          </div>
        </section>
      </form>
    </div>`;
  }

  // ==========================================================
  // VIEW 3: MEDIA LIBRARY & PHOTO UPLOAD (?view=media)
  // ==========================================================
  if (view === 'media') {
    const backProjectId = '';
    return `
    <div style="margin-bottom:1rem;">
      <a href="/admin/projects" class="btn btn--secondary">&larr; Back to Projects Overview</a>
    </div>
    ${canUploadMedia
        ? renderMediaUploaderCard({
          idPrefix: 'media',
          title: 'Upload Project Photos',
          subtitle: 'Upload Before, After, or general site photos. Originals are stored privately and all GPS/EXIF metadata is stripped automatically.',
          showRoleHint: true,
          projectId: backProjectId,
        })
        : ''
      }
    <section class="admin-card">
      ${renderAdminPageHeader({
        title: `Media Library & Rights Registry (${assets.length})`,
        subtitle: 'Preview uploaded photos, adjust focal-point framing, and manage publication rights.',
      })}
      ${assets.length === 0
        ? renderAdminEmptyState({
          title: 'No project photography uploaded yet',
          description: 'Use the upload box above to add JPEG, PNG, WebP, or HEIC project photos.',
        })
        : `<div class="media-thumb-grid">
              ${assets
          .map((a) => {
            const usage = assetUsageMap[a.asset_id] || { total: 0 };
            const rightsLabel = a.rights_status === 'approved' ? 'Approved' : a.rights_status === 'withdrawn' ? 'Withdrawn' : 'Pending Rights';
            return `<article class="media-card">
                    <img src="/admin/api/media/preview/${escapeHtml(a.asset_id)}" alt="${escapeHtml(a.alt_text || a.original_filename)}" style="object-position:${escapeHtml(a.focal_x ?? 50)}% ${escapeHtml(a.focal_y ?? 50)}%;">
                    <div style="font-size:0.84rem;">
                      <strong style="word-break:break-word;">${escapeHtml(a.original_filename)}</strong>
                      <div style="margin-top:0.25rem;display:flex;flex-wrap:wrap;gap:0.35rem;align-items:center;">
                        <span class="badge ${a.rights_status === 'approved' ? 'badge--live' : a.rights_status === 'withdrawn' ? 'badge--err' : 'badge--warn'}">${rightsLabel}</span>
                        <span class="muted">${escapeHtml(a.width)}&times;${escapeHtml(a.height)}</span>
                      </div>
                      <div class="muted" style="font-size:0.78rem;margin-top:0.25rem;">Used in ${escapeHtml(usage.total)} placement(s)</div>
                      ${canUploadMedia
                ? `<form method="POST" action="/admin/api/media/${escapeHtml(a.asset_id)}/focal-point" class="js-ajax-form" style="margin-top:0.55rem;display:flex;gap:0.35rem;flex-wrap:wrap;align-items:center;">
                              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                              <label for="fx-${escapeHtml(a.asset_id)}" class="visually-hidden">Focal X percent</label>
                              <input id="fx-${escapeHtml(a.asset_id)}" type="number" min="0" max="100" name="focal_x" value="${escapeHtml(a.focal_x ?? 50)}" aria-label="Focal X%" style="width:66px;min-height:38px;padding:0.25rem;font-size:0.82rem;">
                              <label for="fy-${escapeHtml(a.asset_id)}" class="visually-hidden">Focal Y percent</label>
                              <input id="fy-${escapeHtml(a.asset_id)}" type="number" min="0" max="100" name="focal_y" value="${escapeHtml(a.focal_y ?? 50)}" aria-label="Focal Y%" style="width:66px;min-height:38px;padding:0.25rem;font-size:0.82rem;">
                              <button type="submit" class="btn btn--secondary btn--compact">Save Crop</button>
                            </form>`
                : ''
              }
                      <div class="admin-action-group" style="margin-top:0.55rem;">
                        ${canPublish && a.rights_status !== 'approved'
                ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/media/${escapeHtml(a.asset_id)}/approve-rights">Approve Rights</button>`
                : ''
              }
                        ${canPublish && a.rights_status !== 'withdrawn'
                ? `<button type="button" class="btn btn--secondary btn--compact js-withdraw-media-btn" data-usage-url="/admin/api/media/${escapeHtml(a.asset_id)}/usage" data-withdraw-url="/admin/api/media/${escapeHtml(a.asset_id)}/withdraw" data-filename="${escapeHtml(a.original_filename)}">Withdraw Rights</button>`
                : ''
              }
                      </div>
                    </div>
                  </article>`;
          })
          .join('')}
            </div>`
      }
    </section>`;
  }

  // ==========================================================
  // VIEW 4: 5-TAB EDIT PROJECT (?view=edit&id=...)
  // ==========================================================
  if (view === 'edit' && selectedProject) {
    let selectedServices = '';
    try {
      selectedServices = JSON.parse(selectedProject.related_services_json || '[]').join(', ');
    } catch {
      selectedServices = '';
    }
    const activeTab = ['overview', 'details', 'photos', 'permissions', 'publish'].includes(tab) ? tab : 'overview';
    const allChecksPass = publishChecks.length > 0 && publishChecks.every((c) => c.passed);

    return `
    <div class="sticky-edit-bar">
      <div style="min-width:0;">
        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:0.45rem;">
          <a href="/admin/projects" class="btn btn--secondary btn--compact">&larr; All Projects</a>
          <span class="badge ${selectedProject.activation_state === 'Live' ? 'badge--live' : selectedProject.editorial_state === 'In review' ? 'badge--info' : 'badge--warn'}">
            ${selectedProject.activation_state === 'Live' ? 'Live on Website' : selectedProject.editorial_state === 'In review' ? 'Awaiting Publisher Review' : 'Draft (In Progress)'}
          </span>
          ${selectedProject.is_private_test ? '<span class="badge badge--err">Private Test Record (Not Public)</span>' : ''}
          <span id="project-dirty-badge" class="dirty-pill" hidden>Unsaved changes</span>
        </div>
        <h2 style="margin:0.45rem 0 0.1rem;border:0;padding:0;font-size:1.35rem;">${escapeHtml(selectedProject.title)}</h2>
        <small class="muted">Public URL: <code>/projects/${escapeHtml(selectedProject.slug)}/</code></small>
      </div>
      <div class="admin-action-group">
        ${selectedProject.activation_state === 'Live'
          ? `<a href="/projects/${encodeURIComponent(selectedProject.slug)}/" target="_blank" class="btn btn--primary btn--compact">View Live Project &rarr;</a>`
          : ''
        }
        <a href="/admin/preview?project=${encodeURIComponent(selectedProject.slug)}&viewport=desktop" target="_blank" class="btn btn--secondary btn--compact">Preview</a>
        ${canEdit ? '<button type="submit" form="project-edit-form" class="btn btn--primary">Save Changes</button>' : ''}
      </div>
    </div>

    ${renderProjectStatusTracker(selectedProject, publishChecks, !canPublish)}

    <nav class="admin-tabs" id="project-edit-tabs" aria-label="Edit project sections">
      <button type="button" class="admin-tab${activeTab === 'overview' ? ' is-active' : ''}" data-project-tab="overview">1. Overview</button>
      <button type="button" class="admin-tab${activeTab === 'details' ? ' is-active' : ''}" data-project-tab="details">2. Work Details</button>
      <button type="button" class="admin-tab${activeTab === 'photos' ? ' is-active' : ''}" data-project-tab="photos">3. Photos &amp; Gallery (${galleryItems.length + pairs.length})</button>
      <button type="button" class="admin-tab${activeTab === 'permissions' ? ' is-active' : ''}" data-project-tab="permissions">4. Permissions &amp; Evidence</button>
      <button type="button" class="admin-tab${activeTab === 'publish' ? ' is-active' : ''}" data-project-tab="publish">5. Preview &amp; Publishing</button>
    </nav>

    <form id="project-edit-form" method="POST" action="/admin/api/projects/${escapeHtml(selectedProject.project_id)}" class="js-ajax-form" data-dirty-guard="1">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">

      <!-- Tab 1: Overview -->
      <section class="admin-card project-tab-panel" data-project-panel="overview"${activeTab === 'overview' ? '' : ' hidden'}>
        ${renderAdminPageHeader({ title: 'Project Overview', subtitle: 'Basic identifying details and cover image shown on the public Projects showcase.' })}
        <div class="grid-2">
          <div class="field"><label for="sp-title">Project Title</label><input id="sp-title" name="title" value="${escapeHtml(selectedProject.title)}" required ${canEdit ? '' : 'disabled'}></div>
          <div class="field"><label for="sp-prop">Property Type</label><input id="sp-prop" name="property_type" value="${escapeHtml(selectedProject.property_type)}" required ${canEdit ? '' : 'disabled'}></div>
        </div>
        <div class="grid-2">
          <div class="field"><label for="sp-city">Location (City / Region)</label><input id="sp-city" name="city_region" value="${escapeHtml(selectedProject.city_region)}" required ${canEdit ? '' : 'disabled'}></div>
          <div class="field"><label for="sp-comp">Completion Date</label><input type="date" id="sp-comp" name="completion_date" value="${escapeHtml(selectedProject.completion_date || '')}" ${canEdit ? '' : 'disabled'}></div>
        </div>
        <div class="grid-2" style="align-items:start;">
          <div class="field">
            <label for="sp-cover">Cover Photo</label>
            <span class="hint">Main photo shown on the Projects archive and homepage showcase.</span>
            <select id="sp-cover" name="cover_asset_id" ${canEdit ? '' : 'disabled'}>
              <option value="">No cover photo selected</option>
              ${assets.map((a) => `<option value="${escapeHtml(a.asset_id)}"${selectedProject.cover_asset_id === a.asset_id ? ' selected' : ''}>${escapeHtml(a.original_filename)} (${escapeHtml(a.rights_status)})</option>`).join('')}
            </select>
          </div>
          <div class="panel panel--light" style="display:flex;align-items:center;gap:0.85rem;">
            <img id="sp-cover-preview" src="${selectedProject.cover_asset_id ? `/admin/api/media/preview/${escapeHtml(selectedProject.cover_asset_id)}` : '/assets/brand-mark.svg'}" alt="Cover preview" class="project-thumb" style="width:88px;height:66px;">
            <div style="font-size:0.84rem;">
              <strong>Cover Thumbnail</strong><br>
              <span class="muted">Updates live when you choose a photo.</span>
            </div>
          </div>
        </div>
        <div class="choice-row"><input type="checkbox" id="sp-feat" name="featured_on_home"${selectedProject.featured_on_home ? ' checked' : ''} ${canEdit ? '' : 'disabled'}><label for="sp-feat">Feature on Homepage Selected Work</label></div>
      </section>

      <!-- Tab 2: Work Details -->
      <section class="admin-card project-tab-panel" data-project-panel="details"${activeTab === 'details' ? '' : ' hidden'}>
        ${renderAdminPageHeader({ title: 'Work Details & Trades', subtitle: 'Describe the client challenge, agreed scope, completed work, and verified outcome.' })}
        <div class="grid-2">
          <div class="field"><label for="sp-chal">Customer Challenge</label><textarea id="sp-chal" name="challenge" style="min-height:4.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(selectedProject.challenge)}</textarea></div>
          <div class="field"><label for="sp-scope">Agreed Scope</label><textarea id="sp-scope" name="agreed_scope" style="min-height:4.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(selectedProject.agreed_scope)}</textarea></div>
        </div>
        <div class="grid-2">
          <div class="field"><label for="sp-work">Completed Work</label><textarea id="sp-work" name="completed_work" style="min-height:4.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(selectedProject.completed_work)}</textarea></div>
          <div class="field"><label for="sp-res">Verified Result</label><textarea id="sp-res" name="verified_result" style="min-height:4.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(selectedProject.verified_result)}</textarea></div>
        </div>
        <div class="grid-3">
          <div class="field"><label for="sp-self">Self-Performed Elements</label><input id="sp-self" name="self_performed_notes" value="${escapeHtml(selectedProject.self_performed_notes)}" ${canEdit ? '' : 'disabled'}></div>
          <div class="field"><label for="sp-coord">Coordinated Trades</label><input id="sp-coord" name="coordinated_notes" value="${escapeHtml(selectedProject.coordinated_notes)}" ${canEdit ? '' : 'disabled'}></div>
          <div class="field"><label for="sp-rel">Related Service Slugs</label><input id="sp-rel" name="related_services" value="${escapeHtml(selectedServices)}" placeholder="warehouse-repairs, day-porter" ${canEdit ? '' : 'disabled'}></div>
        </div>
      </section>

      <!-- Tab 4: Permissions & Evidence -->
      <section class="admin-card project-tab-panel" data-project-panel="permissions"${activeTab === 'permissions' ? '' : ' hidden'}>
        ${renderAdminPageHeader({ title: 'Permissions & Evidence', subtitle: 'Required compliance confirmations before this project can be published on the public website.' })}
        <div class="field" style="max-width:28rem;">
          <label for="sp-naming">Client Naming Decision</label>
          <span class="hint">Keep anonymized unless written client naming permission is verified.</span>
          <select id="sp-naming" name="naming_decision" ${canEdit ? '' : 'disabled'}>
            <option value="anonymized"${selectedProject.naming_decision === 'anonymized' ? ' selected' : ''}>Anonymized (recommended when naming unapproved)</option>
            <option value="named"${selectedProject.naming_decision === 'named' ? ' selected' : ''}>Named (requires explicit client permission)</option>
          </select>
        </div>
        <div class="panel panel--light" style="display:flex;flex-direction:column;gap:0.65rem;">
          <div class="choice-row"><input type="checkbox" id="sp-doc" name="completion_documented"${selectedProject.completion_documented ? ' checked' : ''} ${canEdit ? '' : 'disabled'}><label for="sp-doc"><strong>Actual completion evidence documented</strong> (work orders, sign-off, or verified completion photos)</label></div>
          <div class="choice-row"><input type="checkbox" id="sp-perm" name="client_permission_verified"${selectedProject.client_permission_verified ? ' checked' : ''} ${canEdit ? '' : 'disabled'}><label for="sp-perm"><strong>Client naming/anonymity &amp; photo permission verified</strong></label></div>
          <div class="choice-row"><input type="checkbox" id="sp-test" name="is_private_test"${selectedProject.is_private_test ? ' checked' : ''} ${canEdit ? '' : 'disabled'}><label for="sp-test"><strong>Private Staging / Training Test Record</strong> (blocks live publication to the public website)</label></div>
        </div>
      </section>
    </form>

    <!-- Tab 3: Photos & Gallery (outside main form so nested upload/pair forms work independently) -->
    <div class="project-tab-panel" data-project-panel="photos"${activeTab === 'photos' ? '' : ' hidden'}>
      ${canUploadMedia
        ? renderMediaUploaderCard({
          idPrefix: 'proj-media',
          title: 'Upload Photos for This Project',
          subtitle: 'Upload Before or After photos here, then add them to the Gallery or pair them below.',
          showRoleHint: true,
          projectId: selectedProject.project_id,
        })
        : ''
      }

      <section class="admin-card">
        ${renderAdminPageHeader({ title: `Project Gallery (${galleryItems.length})`, subtitle: 'Ordered photos displayed in the project case study gallery.' })}
        <div id="gallery-list">
          ${galleryItems.length === 0
        ? '<div class="admin-empty-state">No gallery photos added yet. Choose an uploaded photo below to add it.</div>'
        : galleryItems
          .map(
            (g, idx) => `<div class="panel panel--light" style="margin-bottom:0.65rem;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;">
                      <div style="display:flex;align-items:center;gap:0.75rem;">
                        <img src="/admin/api/media/preview/${escapeHtml(g.asset_id)}" alt="${escapeHtml(g.alt_text || g.original_filename)}" class="project-thumb" style="width:72px;height:54px;">
                        <div>
                          <strong>${idx + 1}. ${escapeHtml(g.original_filename)}</strong> <span class="badge ${g.rights_status === 'approved' ? 'badge--live' : 'badge--warn'}">${escapeHtml(g.rights_status)}</span><br>
                          <small class="muted">${escapeHtml(g.caption || 'No caption')} &middot; Alt: ${escapeHtml(g.alt_text || 'Default')}</small>
                        </div>
                      </div>
                      ${canEdit
                ? `<div class="admin-action-group">
                              <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/gallery/${escapeHtml(g.item_id)}/move?dir=up">Move Up</button>
                              <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/gallery/${escapeHtml(g.item_id)}/move?dir=down">Move Down</button>
                              <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/gallery/${escapeHtml(g.item_id)}/delete">Remove</button>
                            </div>`
                : ''
              }
                    </div>`
          )
          .join('')
      }
        </div>
        ${canEdit && assets.length >= 1
        ? `<form method="POST" action="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/gallery" class="js-ajax-form" style="margin-top:0.9rem;display:flex;flex-wrap:wrap;gap:0.55rem;align-items:flex-end;">
                <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                <div class="field" style="margin:0;min-width:13rem;"><label for="gal-asset">Add Existing Photo to Gallery</label>
                  <select id="gal-asset" name="asset_id" required>
                    ${assets.filter((a) => a.rights_status !== 'withdrawn').map((a) => `<option value="${escapeHtml(a.asset_id)}">${escapeHtml(a.original_filename)} (${escapeHtml(a.rights_status)})</option>`).join('')}
                  </select>
                </div>
                <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="gal-cap">Caption</label><input id="gal-cap" name="caption"></div>
                <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="gal-alt">Alt Text</label><input id="gal-alt" name="alt_text"></div>
                <button type="submit" class="btn btn--primary">Add to Gallery</button>
              </form>`
        : ''
      }
      </section>

      <section class="admin-card">
        ${renderAdminPageHeader({ title: `Before & After Comparisons (${pairs.length})`, subtitle: 'Pair pre-work and completed photos side by side so clients can clearly see the improvement.' })}
        <div id="pairs-list">
          ${pairs.length === 0
        ? '<div class="admin-empty-state">No Before/After comparisons added yet. Pair two uploaded photos below.</div>'
        : pairs
          .map((pr, idx) => {
            const bAsset = assetById[pr.before_asset_id];
            const aAsset = assetById[pr.after_asset_id];
            return `<div class="pair-visual-card">
                      <div class="pair-visual-card__head">
                        <strong>${idx + 1}. ${escapeHtml(pr.pair_title)}</strong>
                        ${canEdit
                ? `<div class="admin-action-group">
                                <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/pairs/${escapeHtml(pr.pair_id)}/move?dir=up">Move Up</button>
                                <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/pairs/${escapeHtml(pr.pair_id)}/move?dir=down">Move Down</button>
                                <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/pairs/${escapeHtml(pr.pair_id)}/swap">Swap Before/After</button>
                              </div>`
                : ''
              }
                      </div>
                      <div class="pair-visual-card__thumbs">
                        <div class="pair-thumb-box">
                          <span class="badge">Before</span>
                          <img src="/admin/api/media/preview/${escapeHtml(pr.before_asset_id)}" alt="${escapeHtml(pr.before_caption || 'Before')}" class="project-thumb">
                          <small class="muted">${escapeHtml(bAsset?.original_filename || pr.before_asset_id.slice(0, 8))} &mdash; ${escapeHtml(pr.before_caption || '')}</small>
                        </div>
                        <div class="pair-thumb-box">
                          <span class="badge badge--live">After</span>
                          <img src="/admin/api/media/preview/${escapeHtml(pr.after_asset_id)}" alt="${escapeHtml(pr.after_caption || 'After')}" class="project-thumb">
                          <small class="muted">${escapeHtml(aAsset?.original_filename || pr.after_asset_id.slice(0, 8))} &mdash; ${escapeHtml(pr.after_caption || '')}</small>
                        </div>
                      </div>
                    </div>`;
          })
          .join('')
      }
        </div>

        ${canEdit && assets.length >= 2
        ? `<form method="POST" action="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/pairs" class="js-ajax-form" style="margin-top:1.15rem;padding-top:1rem;border-top:1px solid var(--border-subtle);">
                <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                <h3 style="margin-top:0;">Create Before &amp; After Comparison</h3>
                <div class="field"><label for="pair-title">Comparison Title</label><input id="pair-title" name="pair_title" placeholder="e.g. Loading Dock Restoration" required></div>
                <div class="grid-2">
                  <div class="panel panel--light">
                    <div class="field"><label for="pair-before">Before Image</label>
                      <select id="pair-before" name="before_asset_id" class="js-pair-preview-sel" data-preview-target="pair-before-img" required>
                        ${assets.map((a) => `<option value="${escapeHtml(a.asset_id)}">${escapeHtml(a.original_filename)} (${escapeHtml(a.rights_status)})</option>`).join('')}
                      </select>
                    </div>
                    <img id="pair-before-img" src="/admin/api/media/preview/${escapeHtml(assets[0].asset_id)}" alt="Before preview" class="project-thumb" style="width:100%;height:140px;margin-bottom:0.65rem;">
                    <div class="field" style="margin-bottom:0;"><label for="pair-bcap">Before Caption</label><input id="pair-bcap" name="before_caption" placeholder="Condition before work" required></div>
                  </div>
                  <div class="panel panel--light">
                    <div class="field"><label for="pair-after">After Image</label>
                      <select id="pair-after" name="after_asset_id" class="js-pair-preview-sel" data-preview-target="pair-after-img" required>
                        ${assets.map((a, i) => `<option value="${escapeHtml(a.asset_id)}"${i === 1 ? ' selected' : ''}>${escapeHtml(a.original_filename)} (${escapeHtml(a.rights_status)})</option>`).join('')}
                      </select>
                    </div>
                    <img id="pair-after-img" src="/admin/api/media/preview/${escapeHtml((assets[1] || assets[0]).asset_id)}" alt="After preview" class="project-thumb" style="width:100%;height:140px;margin-bottom:0.65rem;">
                    <div class="field" style="margin-bottom:0;"><label for="pair-acap">After Caption</label><input id="pair-acap" name="after_caption" placeholder="Completed result" required></div>
                  </div>
                </div>
                <button type="submit" class="btn btn--primary" style="margin-top:0.85rem;">Add Before / After Pair</button>
              </form>`
        : canEdit
          ? '<p class="muted" style="margin-top:0.85rem;">Upload at least 2 photos above to create a Before &amp; After comparison.</p>'
          : ''
      }
      </section>
    </div>

    <!-- Tab 5: Preview & Publishing -->
    <section class="admin-card project-tab-panel" data-project-panel="publish"${activeTab === 'publish' ? '' : ' hidden'}>
      ${renderAdminPageHeader({
        title: canPublish ? 'Publishing & Editorial Review' : 'Review & Publishing Readiness',
        subtitle: 'All compliance, evidence, and photo rights requirements must pass before a project can go live on the public website.',
      })}

      ${!canPublish && selectedProject.activation_state !== 'Live'
        ? `<div class="admin-inline-alert" style="margin-bottom:1.15rem;background:#F0FDF4;border:1px solid #BBF7D0;color:#166534;border-radius:var(--radius);padding:0.75rem 0.95rem;font-size:0.88rem;">
            <strong>Contributor Publishing Notice:</strong> Your project is not live yet. Once all required work details, evidence, and photos are completed below, click <strong>"Submit for Review"</strong>. An authorized Approver &amp; Publisher will review the evidence and publish it live to the public site.
          </div>`
        : ''
      }

      ${renderReadinessChecklist(publishChecks, !canPublish)}

      <div class="panel panel--light" style="margin-top:1.25rem;">
        <h4 style="margin:0 0 0.35rem 0;">Lifecycle Transitions &amp; Actions</h4>
        <p class="muted" style="margin-bottom:0.85rem;font-size:0.86rem;">
          ${selectedProject.activation_state === 'Live'
            ? 'This project is live on the public site. You can view the live page, inspect responsive previews, or archive it if no longer displayed.'
            : selectedProject.editorial_state === 'In review'
              ? (canPublish
                  ? 'This project is currently awaiting publisher review. As an Approver &amp; Publisher, you can approve and publish it live, or return it to Draft.'
                  : 'This project is currently awaiting publisher review. An Approver &amp; Publisher will review checklist items and publish it live.'
                )
              : canPublish
                ? 'As an Approver &amp; Publisher, you can approve and publish this project live as soon as all checklist items pass, or submit it for review.'
                : 'Save your draft changes and submit the project for publisher review once all evidence and photos are documented.'
          }
        </p>
        <div class="admin-action-group">
          ${selectedProject.activation_state === 'Live'
            ? `<a href="/projects/${encodeURIComponent(selectedProject.slug)}/" target="_blank" class="btn btn--primary">View Live Project &rarr;</a>`
            : ''
          }
          <a href="/admin/preview?project=${encodeURIComponent(selectedProject.slug)}&viewport=desktop" target="_blank" class="btn btn--secondary">Preview Case Study</a>

          ${canEdit && selectedProject.editorial_state === 'Draft'
            ? (() => {
                const contributorChecksPass = publishChecks.every((c) => c.key === 'media_rights' ? true : c.passed);
                return `<button type="button" class="btn ${contributorChecksPass ? 'btn--primary' : 'btn--secondary'} js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/submit-review" data-confirm-title="Submit Project for Review?" data-confirm="Submit &quot;${escapeHtml(selectedProject.title)}&quot; for Approver &amp; Publisher review?">Submit for Review</button>`;
              })()
            : ''
          }

          ${!canPublish && selectedProject.editorial_state === 'In review'
            ? `<span class="badge badge--info" style="align-self:center;padding:0.45rem 0.75rem;font-size:0.86rem;">Awaiting Publisher Review</span>`
            : ''
          }

          ${canPublish && selectedProject.editorial_state === 'In review'
            ? `<button type="button" class="btn btn--secondary js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/return-draft" data-confirm-title="Return Project to Draft?" data-confirm="Return &quot;${escapeHtml(selectedProject.title)}&quot; to Draft status for further changes?">Return to Draft</button>`
            : ''
          }

          ${canPublish && selectedProject.activation_state !== 'Live'
            ? `<button type="button" class="btn btn--primary js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/publish" data-confirm-title="Publish Completed Project?" data-confirm="Publish &quot;${escapeHtml(selectedProject.title)}&quot; and its approved derivatives live to /projects/?"${allChecksPass ? '' : ' disabled aria-disabled="true" title="Resolve all checklist blockers above first"'}>Approve &amp; Publish Project</button>`
            : ''
          }

          ${canPublish && selectedProject.activation_state === 'Live'
            ? `<button type="button" class="btn btn--secondary js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/archive" data-confirm-title="Archive Completed Project?" data-confirm="Remove &quot;${escapeHtml(selectedProject.title)}&quot; from public project archives?">Archive Project</button>`
            : ''
          }

          ${!canPublish && selectedProject.activation_state !== 'Live' && selectedProject.editorial_state !== 'In review'
            ? '<span class="muted" style="font-size:0.86rem;align-self:center;">Only an Approver &amp; Publisher can approve and publish live.</span>'
            : ''
          }
        </div>
      </div>
    </section>`;
  }

  // ==========================================================
  // VIEW 1: PROJECTS OVERVIEW (DEFAULT ?view=overview)
  // ==========================================================
  const overviewActions = [
    canUploadMedia ? '<a href="/admin/projects?view=media" class="btn btn--secondary">Upload &amp; Manage Photos</a>' : '',
    canEdit ? '<a href="/admin/projects?view=create" class="btn btn--primary">+ Create Project</a>' : '',
  ]
    .filter(Boolean)
    .join('');

  return `
  ${renderAdminKpiStrip([
    { value: totalCount, label: 'Total Projects', hint: 'Commercial case studies' },
    { value: liveCount, label: 'Live on Website', hint: 'Published public proof', accent: true },
    { value: draftCount, label: 'Drafts & In Review', hint: 'In progress or awaiting approval' },
    { value: approvedMediaCount, label: 'Approved Photos', hint: `${assets.length} total in Media Library` },
  ])}

  <section class="admin-card">
    ${renderAdminPageHeader({
    title: 'Completed Projects',
    subtitle: 'Select a project to edit details, upload Before/After photos, or check publishing readiness.',
    actionsHtml: overviewActions,
  })}

    <form method="GET" action="/admin/projects" class="admin-filter-bar">
      <div class="field" style="flex:1;min-width:13rem;">
        <label for="prj-q">Search projects by title, property type, or city</label>
        <input id="prj-q" name="q" type="search" value="${escapeHtml(filters.q || '')}" placeholder="Search completed projects...">
      </div>
      <div class="field" style="min-width:11rem;">
        <label for="prj-state">Status</label>
        <select id="prj-state" name="state">
          <option value="">All statuses</option>
          ${['Draft', 'In review', 'Approved', 'Live', 'Unpublished', 'Archived']
      .map((st) => `<option value="${st}"${filters.state === st ? ' selected' : ''}>${st}</option>`)
      .join('')}
        </select>
      </div>
      <div class="admin-action-group">
        <button type="submit" class="btn btn--secondary">Apply Filter</button>
        ${filters.q || filters.state ? '<a href="/admin/projects" class="btn btn--secondary">Clear</a>' : ''}
      </div>
    </form>

    ${projects.length === 0
      ? renderAdminEmptyState({
        title: 'No projects found',
        description: filters.q || filters.state
          ? 'No projects match your current search or status filter.'
          : 'Create your first completed-project case study to document commercial work and upload Before/After photos.',
        ctaHtml: canEdit ? '<a href="/admin/projects?view=create" class="btn btn--primary">+ Create Project</a>' : '',
      })
      : `<div class="project-overview-list" role="region" aria-label="Completed Projects List">
            ${projects
        .map((p) => {
          const counts = projectCounts[p.project_id] || { photos: 0, pairs: 0 };
          return `<article class="project-overview-card">
                  <div class="project-overview-card__main">
                    <img src="${p.cover_asset_id ? `/admin/api/media/preview/${escapeHtml(p.cover_asset_id)}` : '/assets/brand-mark.svg'}" alt="" class="project-thumb project-thumb--overview">
                    <div class="project-overview-card__text">
                      <div class="project-overview-card__title-row">
                        <strong class="project-overview-card__title" title="${escapeHtml(p.title)}" aria-label="${escapeHtml(p.title)}">${escapeHtml(p.title)}</strong>
                        ${p.is_private_test ? '<span class="badge badge--err">TEST</span>' : ''}
                      </div>
                      <div class="muted project-overview-card__sub">
                        ${escapeHtml(p.property_type)} &middot; ${escapeHtml(p.city_region)} &middot; ${escapeHtml(p.completion_date || 'Date not set')}
                      </div>
                    </div>
                  </div>
                  <div class="project-overview-card__status">
                    <span class="badge ${p.activation_state === 'Live' ? 'badge--live' : 'badge--warn'}">${escapeHtml(p.editorial_state)} &middot; ${escapeHtml(p.activation_state)}</span>
                    <span class="muted" style="font-size:0.8rem;">${escapeHtml(counts.photos)} photo(s) &middot; ${escapeHtml(counts.pairs)} pair(s)</span>
                  </div>
                  <div class="project-overview-card__actions">
                    <a href="/admin/projects?view=edit&id=${encodeURIComponent(p.project_id)}" class="btn btn--primary btn--compact">Edit</a>
                    <a href="/admin/projects?view=edit&tab=photos&id=${encodeURIComponent(p.project_id)}" class="btn btn--secondary btn--compact">Photos</a>
                    <a href="/admin/preview?project=${encodeURIComponent(p.slug)}&viewport=desktop" target="_blank" class="btn btn--secondary btn--compact">Preview</a>
                  </div>
                </article>`;
        })
        .join('')}
          </div>`
    }
  </section>`;
}

export function renderAdminJobsView({
  jobs,
  selectedJob = null,
  applications,
  appsMeta = null,
  filters = {},
  selectedApp,
  reviewers,
  user,
  csrfToken,
  tab = 'vacancies',
  totalScopedAppsCount = 0,
}) {
  const isOwner = hasPermission(user, PERMISSIONS.MANAGE_VACANCIES);
  const canExport = hasPermission(user, PERMISSIONS.EXPORT_APPLICATIONS);
  const pendingCount = totalScopedAppsCount;

  return `
  <nav class="admin-tabs" aria-label="Careers workspace" style="margin-bottom:1.25rem;">
    <a href="/admin/jobs?tab=vacancies" class="admin-tab${tab === 'vacancies' ? ' is-active' : ''}">Job Openings (${jobs.length})</a>
    <a href="/admin/jobs?tab=applications" class="admin-tab${tab === 'applications' ? ' is-active' : ''}">Applicant Inbox${pendingCount > 0 ? ` <span class="badge badge--warn">${pendingCount}</span>` : ''}</a>
  </nav>

  ${tab === 'vacancies' ? `
  <section class="admin-card">
    <div class="admin-card__header">
      <div>
        <h2>Job Openings</h2>
        <p class="muted" style="margin:0;font-size:0.85rem;">Opening schedules run in <strong>America/Phoenix</strong> time. Requisition IDs and cycle references are read-only.</p>
      </div>
      ${canExport
        ? `<a href="/admin/api/applications/export.csv" class="btn btn--secondary">Export Applicant List (CSV)</a>`
        : ''
      }
    </div>

    <div class="admin-desktop-only">
      <div class="table-scroll" tabindex="0" role="region" aria-label="Vacancies Table">
        <table class="data-table">
          <thead><tr><th>Req / Cycle</th><th>Title</th><th>Status &amp; Schedule</th><th>Work Area</th><th>Actions</th></tr></thead>
          <tbody>
            ${jobs
        .map(
          (j) => `<tr>
                  <td><code>${escapeHtml(j.requisition_id)}</code><br><small class="muted">${escapeHtml(j.opening_cycle_id)}</small></td>
                  <td><strong>${escapeHtml(j.title)}</strong>${j.is_private_test ? ' <span class="badge badge--warn">PRIVATE TEST</span>' : ''}</td>
                  <td>
                    <span class="badge ${j.status === 'Open' ? 'badge--live' : 'badge--warn'}">${escapeHtml(j.status)}</span>
                    ${j.publish_at ? `<br><small class="muted">Publish: ${escapeHtml(formatPhoenixDateTime(j.publish_at, false))}</small>` : ''}
                    ${j.close_at ? `<br><small class="muted">Close: ${escapeHtml(formatPhoenixDateTime(j.close_at, false))}</small>` : ''}
                  </td>
                  <td>${escapeHtml(j.work_area)}</td>
                  <td>
                    <div class="admin-action-group">
                      ${isOwner ? `<a href="/admin/jobs?job=${encodeURIComponent(j.requisition_id)}#job-editor-box" class="btn btn--secondary btn--compact">Edit / Schedule</a>` : ''}
                      ${isOwner && (j.status === 'Draft' || j.status === 'Paused' || j.status === 'Scheduled')
              ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/open">Open Role</button>`
              : ''
            }
                      ${isOwner && j.status === 'Open'
              ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/pause">Pause</button>
                             <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/close" data-confirm-title="Close Job Vacancy?" data-confirm="Closing &quot;${escapeHtml(j.title)}&quot; immediately blocks new applications while preserving submitted applicant records.">Close Role</button>`
              : ''
            }
                      ${isOwner && j.status === 'Closed'
              ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/reopen">Reopen</button>`
              : ''
            }
                    </div>
                  </td>
                </tr>`
        )
        .join('')}
          </tbody>
        </table>
      </div>
    </div>
    <div class="admin-mobile-cards">
      ${jobs
        .map(
          (j) => `<div class="admin-mobile-card">
            <div class="admin-mobile-card__top"><span class="admin-mobile-card__title">${escapeHtml(j.title)}</span><span class="badge ${j.status === 'Open' ? 'badge--live' : 'badge--warn'}">${escapeHtml(j.status)}</span></div>
            <div class="admin-mobile-card__meta"><code>${escapeHtml(j.requisition_id)}</code> &middot; ${escapeHtml(j.work_area)}</div>
            <div class="admin-mobile-card__actions">
              ${isOwner ? `<a href="/admin/jobs?job=${encodeURIComponent(j.requisition_id)}#job-editor-box" class="btn btn--secondary btn--compact">Edit / Schedule</a>` : ''}
              ${isOwner && (j.status === 'Draft' || j.status === 'Paused' || j.status === 'Scheduled') ? `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/open">Open Role</button>` : ''}
              ${isOwner && j.status === 'Open' ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/close" data-confirm-title="Close Job Vacancy?" data-confirm="Closing &quot;${escapeHtml(j.title)}&quot; blocks new applications.">Close Role</button>` : ''}
            </div>
          </div>`
        )
        .join('')}
    </div>

    ${isOwner && selectedJob
        ? `<div id="job-editor-box" class="panel panel--light" style="margin-top:1.25rem;">
            <h3>Edit Vacancy: ${escapeHtml(selectedJob.title)} (<code>${escapeHtml(selectedJob.requisition_id)}</code>)</h3>
            <form method="POST" action="/admin/api/jobs/${escapeHtml(selectedJob.requisition_id)}" class="js-ajax-form">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <div class="grid-3">
                <div class="field"><label for="ej-title">Title</label><input id="ej-title" name="title" value="${escapeHtml(selectedJob.title)}" required></div>
                <div class="field"><label for="ej-type">Employment Type</label>
                  <select id="ej-type" name="employment_type">
                    ${['Full-time', 'Part-time', 'Seasonal'].map((et) => `<option value="${et}"${selectedJob.employment_type === et ? ' selected' : ''}>${et}</option>`).join('')}
                  </select>
                </div>
                <div class="field"><label for="ej-area">Work Area</label><input id="ej-area" name="work_area" value="${escapeHtml(selectedJob.work_area)}" required></div>
              </div>
              <div class="grid-3">
                <div class="field"><label for="ej-sched">Schedule Text</label><input id="ej-sched" name="schedule_text" value="${escapeHtml(selectedJob.schedule_text)}" required></div>
                <div class="field"><label for="ej-pay">Approved Pay Info</label><input id="ej-pay" name="pay_info" value="${escapeHtml(selectedJob.pay_info)}" required></div>
                <div class="field"><label for="ej-res">Resume Policy</label>
                  <select id="ej-res" name="resume_policy">
                    <option value="optional"${selectedJob.resume_policy === 'optional' ? ' selected' : ''}>Optional (experience substitute)</option>
                    <option value="required"${selectedJob.resume_policy === 'required' ? ' selected' : ''}>Required</option>
                  </select>
                </div>
              </div>
              <div class="grid-2">
                <div class="field"><label for="ej-resp">Responsibilities HTML</label><textarea id="ej-resp" name="responsibilities_html" style="min-height:4rem;" required>${escapeHtml(selectedJob.responsibilities_html)}</textarea></div>
                <div class="field"><label for="ej-qual">Qualifications HTML</label><textarea id="ej-qual" name="qualifications_html" style="min-height:4rem;" required>${escapeHtml(selectedJob.qualifications_html)}</textarea></div>
              </div>
              <div class="admin-action-group">
                <button type="submit" class="btn btn--primary">Save Vacancy Changes</button>
                <a href="/admin/jobs" class="btn btn--secondary">Done Editing</a>
              </div>
            </form>

            <h4 style="margin-top:1.25rem;">Schedule Publish / Close Window (America/Phoenix)</h4>
            <form method="POST" action="/admin/api/jobs/${escapeHtml(selectedJob.requisition_id)}/schedule" class="js-ajax-form" style="display:flex;flex-wrap:wrap;gap:0.75rem;align-items:flex-end;">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <div class="field" style="margin:0;"><label for="sj-pub">Publish At (Phoenix)</label><input type="datetime-local" id="sj-pub" name="publish_phoenix" value="${selectedJob.publish_at ? escapeHtml(utcIsoToPhoenixInput(selectedJob.publish_at)) : ''}" required></div>
              <div class="field" style="margin:0;"><label for="sj-cls">Auto-Close At (Optional Phoenix)</label><input type="datetime-local" id="sj-cls" name="close_phoenix" value="${selectedJob.close_at ? escapeHtml(utcIsoToPhoenixInput(selectedJob.close_at)) : ''}"></div>
              <button type="submit" class="btn btn--secondary">Save Schedule</button>
            </form>
          </div>`
        : ''
      }

    ${isOwner
        ? `<details class="admin-accordion">
            <summary>+ Create New Draft Vacancy</summary>
            <form method="POST" action="/admin/api/jobs" class="js-ajax-form">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <div class="grid-2">
                <div class="field"><label for="jb-title">Role Title</label><input id="jb-title" name="title" required></div>
                <div class="field"><label for="jb-slug">Slug (/careers/{slug}/)</label><input id="jb-slug" name="slug" pattern="[a-z0-9-]+" required></div>
              </div>
              <div class="grid-3">
                <div class="field"><label for="jb-family">Role Family</label><input id="jb-family" name="role_family" value="Maintenance Technician" required></div>
                <div class="field"><label for="jb-type">Employment Type</label><select id="jb-type" name="employment_type"><option value="Full-time">Full-time</option><option value="Part-time">Part-time</option></select></div>
                <div class="field"><label for="jb-area">Work Area</label><input id="jb-area" name="work_area" value="Greater Phoenix" required></div>
              </div>
              <div class="grid-2">
                <div class="field"><label for="jb-sched">Schedule</label><input id="jb-sched" name="schedule_text" value="Monday - Friday, 7:00 AM - 3:30 PM (America/Phoenix)" required></div>
                <div class="field"><label for="jb-pay">Owner-Approved Pay Info</label><input id="jb-pay" name="pay_info" required></div>
              </div>
              <div class="field"><label for="jb-resp">Responsibilities</label><textarea id="jb-resp" name="responsibilities_html" style="min-height:4rem;" required></textarea></div>
              <div class="field"><label for="jb-qual">Qualifications</label><textarea id="jb-qual" name="qualifications_html" style="min-height:4rem;" required></textarea></div>
              <button type="submit" class="btn btn--primary">Create Draft Vacancy</button>
            </form>
          </details>`
        : ''
      }
  </section>
  ` : ''}

  ${tab === 'applications' ? `
  <div class="admin-split">
    <section class="admin-card">
      <h2>Applicant Inbox</h2>
      <form method="GET" action="/admin/jobs" class="admin-filter-bar">
        <div class="field" style="flex:1;min-width:10rem;"><label for="app-q">Search applicant / ID</label><input id="app-q" name="q" type="search" value="${escapeHtml(filters.q || '')}"></div>
        <div class="field"><label for="app-req">Vacancy</label>
          <select id="app-req" name="req">
            <option value="">All scoped roles</option>
            ${jobs.map((j) => `<option value="${escapeHtml(j.requisition_id)}"${filters.req === j.requisition_id ? ' selected' : ''}>${escapeHtml(j.title)}</option>`).join('')}
          </select>
        </div>
        <div class="field"><label for="app-stf">Stage</label>
          <select id="app-stf" name="stage">
            <option value="">All stages</option>
            ${['Received', 'Under review', 'Contacting', 'Interview', 'Offer', 'Hired', 'Not selected', 'Withdrawn', 'Duplicate', 'Unable to contact']
        .map((st) => `<option value="${escapeHtml(st)}"${filters.stage === st ? ' selected' : ''}>${escapeHtml(st)}</option>`)
        .join('')}
          </select>
        </div>
        <div class="admin-action-group">
          <button type="submit" class="btn btn--secondary">Filter</button>
          ${filters.q || filters.req || filters.stage ? '<a href="/admin/jobs" class="btn btn--secondary">Clear</a>' : ''}
        </div>
      </form>
      ${applications.length === 0
        ? '<div class="admin-empty-state">No applications matching your authorized recruiting scope and filters.</div>'
        : `<div class="admin-desktop-only">
              <div class="table-scroll" tabindex="0" role="region" aria-label="Protected Applicant Inbox Table">
                <table class="data-table">
                  <thead><tr><th>Applicant</th><th>Role</th><th>Stage</th><th>Action</th></tr></thead>
                  <tbody>
                    ${applications
          .map(
            (a) => `<tr class="${selectedApp?.application_id === a.application_id ? 'is-selected' : ''}">
                          <td><strong>${escapeHtml(a.applicant_name)}</strong>${a.possible_duplicate_of ? ' <span class="badge badge--warn">Duplicate?</span>' : ''}<br><small class="muted">${escapeHtml(formatPhoenixDateTime(a.received_at, false))}</small></td>
                          <td>${escapeHtml(a.job_title)}</td>
                          <td><span class="badge">${escapeHtml(a.stage)}</span></td>
                          <td><a href="/admin/jobs?app=${encodeURIComponent(a.application_id)}#app-detail-panel" class="btn btn--secondary btn--compact">Review</a></td>
                        </tr>`
          )
          .join('')}
                  </tbody>
                </table>
              </div>
            </div>
            <div class="admin-mobile-cards">
              ${applications
          .map(
            (a) => `<div class="admin-mobile-card${selectedApp?.application_id === a.application_id ? ' is-selected' : ''}">
                    <div class="admin-mobile-card__top"><span class="admin-mobile-card__title">${escapeHtml(a.applicant_name)}</span><span class="badge">${escapeHtml(a.stage)}</span></div>
                    <div class="admin-mobile-card__meta">${escapeHtml(a.job_title)} &middot; ${escapeHtml(formatPhoenixDateTime(a.received_at, false))}</div>
                    <div class="admin-mobile-card__actions"><a href="/admin/jobs?app=${encodeURIComponent(a.application_id)}#app-detail-panel" class="btn btn--secondary btn--compact">Review Application</a></div>
                  </div>`
          )
          .join('')}
            </div>`
      }
      ${renderPaginationNav('/admin/jobs', appsMeta, filters)}
    </section>

    ${selectedApp
        ? `<section id="app-detail-panel" class="admin-card">
            <h2>Application Detail: ${escapeHtml(selectedApp.applicant_name)}</h2>
            <p><strong>Application ID:</strong> <code>${escapeHtml(selectedApp.application_id)}</code><br>
            <strong>Requisition / Cycle:</strong> <code>${escapeHtml(selectedApp.requisition_id)}</code> / <code>${escapeHtml(selectedApp.opening_cycle_id)}</code><br>
            <strong>Contact (${escapeHtml(selectedApp.preferred_method)}):</strong> ${escapeHtml(selectedApp.email_normalized || selectedApp.phone_normalized || '—')}<br>
            <strong>City / ZIP:</strong> ${escapeHtml(selectedApp.city_or_zip || '—')}</p>

            <h3>Immutable Submitted Snapshot &amp; Answers</h3>
            <div class="panel panel--light" style="font-size:0.9rem;">
              <p><strong>Role Shown at Submission:</strong> ${escapeHtml(selectedApp.snapshot?.job_title)} (${escapeHtml(selectedApp.snapshot?.pay_info)})</p>
              <p><strong>Relevant Experience:</strong><br>${escapeHtml(selectedApp.answers?.relevant_experience || '—')}</p>
              <p><strong>Availability:</strong> ${escapeHtml(selectedApp.answers?.availability || '—')}</p>
            </div>

            ${selectedApp.attachments.length > 0
          ? `<h3 style="margin-top:1rem;">Protected Attachments</h3>
                   <ul>${selectedApp.attachments
            .map(
              (att) => `<li style="margin-bottom:0.75rem;">
                         ${escapeHtml(att.original_display_name)} (${escapeHtml(att.scan_state)}) — ${att.scan_state === 'clean'
                  ? `<a href="/admin/api/applications/${escapeHtml(selectedApp.application_id)}/attachments/${escapeHtml(att.attachment_id)}">Authenticated Download</a>`
                  : '<span class="badge badge--err">Quarantined / Blocked</span>'
                }
                         ${isOwner
                  ? `<div class="admin-action-group" style="margin-top:0.45rem;">
                                 <form method="POST" action="/admin/api/applications/${escapeHtml(selectedApp.application_id)}/attachments/${escapeHtml(att.attachment_id)}/replace" enctype="multipart/form-data" class="js-multipart-form admin-action-group">
                                   <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                                   <input type="file" name="resume" accept=".pdf,.docx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" required aria-label="Replacement resume PDF or DOCX" style="max-width:210px;font-size:0.84rem;">
                                   <button type="submit" class="btn btn--secondary btn--compact">Replace Resume</button>
                                 </form>
                                 <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/applications/${escapeHtml(selectedApp.application_id)}/attachments/${escapeHtml(att.attachment_id)}/delete">Delete Resume</button>
                               </div>`
                  : ''
                }
                       </li>`
            )
            .join('')}</ul>`
          : ''
        }

            <form method="POST" action="/admin/api/applications/${escapeHtml(selectedApp.application_id)}/review" class="js-ajax-form" style="margin-top:1.25rem;">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <div class="grid-2">
                <div class="field"><label for="app-stage">Manual Stage</label>
                  <select id="app-stage" name="stage">
                    ${['Received', 'Under review', 'Contacting', 'Interview', 'Offer', 'Hired', 'Not selected', 'Withdrawn', 'Duplicate', 'Unable to contact']
          .map((st) => `<option value="${escapeHtml(st)}"${selectedApp.stage === st ? ' selected' : ''}>${escapeHtml(st)}</option>`)
          .join('')}
                  </select>
                </div>
                ${isOwner
          ? `<div class="field"><label for="app-rev">Assign Reviewer</label>
                        <select id="app-rev" name="assigned_reviewer_id">
                          <option value="">Unassigned</option>
                          ${reviewers.map((r) => `<option value="${escapeHtml(r.user_id)}"${selectedApp.assigned_reviewer_id === r.user_id ? ' selected' : ''}>${escapeHtml(r.full_name)}</option>`).join('')}
                        </select>
                      </div>`
          : ''
        }
              </div>
              <div class="field"><label for="app-note">Factual Job-Related Reviewer Note (Internal Only)</label>
                <textarea id="app-note" name="note_text" style="min-height:4rem;" placeholder="Record factual review notes (does not email candidate)..."></textarea>
              </div>
              <button type="submit" class="btn btn--primary">Update Stage / Save Note</button>
            </form>

            ${selectedApp.notes.length > 0
          ? `<h3 style="margin-top:1.25rem;">Internal Review Notes</h3>
                   <ul>${selectedApp.notes
            .map((n) => `<li><strong>${escapeHtml(n.author_name)}</strong> (${escapeHtml(formatPhoenixDateTime(n.created_at, false))}): ${escapeHtml(n.note_text)}</li>`)
            .join('')}</ul>`
          : ''
        }
          </section>`
        : '<section class="admin-card"><div class="admin-empty-state">Select an application from the inbox to inspect its snapshot, resume attachment, and review controls.</div></section>'
      }
  </div>
  ` : ''}`;
}

export function renderAdminLeadsView({
  tab = 'inquiries',
  inquiries,
  inquiriesMeta = null,
  allInquiriesCount = 0,
  inquiryAttachments = {},
  filters = {},
  crmQueue = [],
  notifications = [],
  crmFaultMode,
  csrfToken,
}) {
  const queueAlertCount =
    crmQueue.filter((q) => q.status === 'failed_review' || q.status === 'pending').length +
    notifications.filter((n) => n.status !== 'sent').length;

  const KIND_LABELS = {
    new_business: 'New Proposal',
    existing_service: 'Service Request',
  };
  const STAGE_LABELS = {
    received: 'Received',
    qualified: 'Qualified',
    proposal_sent: 'Proposal Sent',
    closed_won: 'Closed Won',
    disqualified: 'Disqualified',
  };
  const CLASS_LABELS = {
    valid: 'Valid Lead',
    existing_service: 'Existing Service',
    spam: 'Spam',
    job: 'Job Inquiry',
    vendor: 'Vendor',
    out_of_area: 'Out of Area',
    test: 'Test',
  };
  const formatSlug = (s) =>
    String(s || '')
      .replace(/[-_]+/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());

  const parseLeadPayload = (inq) => {
    try {
      return JSON.parse(inq.payload_json || '{}');
    } catch {
      return {};
    }
  };

  return `
  <nav class="admin-tabs" aria-label="Leads & CRM sections">
    <a href="/admin/leads?tab=inquiries" class="admin-tab${tab === 'inquiries' ? ' is-active' : ''}"${tab === 'inquiries' ? ' aria-current="page"' : ''}>Commercial Inquiries (${allInquiriesCount})</a>
    <a href="/admin/leads?tab=queues" class="admin-tab${tab === 'queues' ? ' is-active' : ''}"${tab === 'queues' ? ' aria-current="page"' : ''}>CRM &amp; Email Queues ${queueAlertCount > 0 ? `<span class="badge badge--warn">${queueAlertCount}</span>` : ''}</a>
  </nav>

  ${tab === 'inquiries'
      ? `<section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Commercial Inquiries &amp; Operations Requests</h2>
              <p class="muted" style="margin:0;font-size:0.86rem;">Review incoming proposals and service requests, inspect customer contact details, update pipeline stages, or download attachments.</p>
            </div>
            ${ENV.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'production'
        ? `<div class="admin-action-group">
                    <span class="badge ${crmFaultMode === 'none' ? 'badge--live' : 'badge--err'}">CRM Fault Sim: ${escapeHtml(crmFaultMode)}</span>
                    <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/crm/fault-mode?mode=${crmFaultMode === 'none' ? 'outage_503' : 'none'}">${crmFaultMode === 'none' ? 'Simulate Outage' : 'Restore Normal'}</button>
                  </div>`
        : ''
      }
          </div>

          <form method="GET" action="/admin/leads" class="admin-filter-bar">
            <input type="hidden" name="tab" value="inquiries">
            <div class="field" style="flex:1.4;min-width:13rem;"><label for="ld-q">Search company, location, or ID</label><input id="ld-q" name="q" type="search" placeholder="e.g. Phoenix, company name, or ID..." value="${escapeHtml(filters.q || '')}"></div>
            <div class="field" style="min-width:11.5rem;"><label for="ld-cls">Classification</label>
              <select id="ld-cls" name="classification">
                <option value="">All classifications</option>
                ${['valid', 'existing_service', 'spam', 'job', 'vendor', 'out_of_area', 'test'].map((c) => `<option value="${c}"${filters.classification === c ? ' selected' : ''}>${escapeHtml(CLASS_LABELS[c] || c)}</option>`).join('')}
              </select>
            </div>
            <div class="field" style="min-width:10.5rem;"><label for="ld-st">Stage</label>
              <select id="ld-st" name="status">
                <option value="">All stages</option>
                ${['received', 'qualified', 'proposal_sent', 'closed_won', 'disqualified'].map((s) => `<option value="${s}"${filters.status === s ? ' selected' : ''}>${escapeHtml(STAGE_LABELS[s] || s)}</option>`).join('')}
              </select>
            </div>
            <div class="admin-action-group">
              <button type="submit" class="btn btn--primary btn--compact">Apply Filter</button>
              ${filters.q || filters.classification || filters.status ? '<a href="/admin/leads?tab=inquiries" class="btn btn--secondary btn--compact">Clear</a>' : ''}
            </div>
          </form>

          <div class="admin-desktop-only">
            <div class="table-scroll" tabindex="0" role="region" aria-label="Commercial Inquiries Table">
              <table class="data-table">
                <thead><tr><th>Company &amp; Contact</th><th>Service &amp; Attachments</th><th>Stage &amp; Classification</th><th>Received</th><th>Pipeline Update</th></tr></thead>
                <tbody>
                  ${inquiries.length === 0
        ? '<tr><td colspan="5" class="muted">No inquiries matching filter criteria.</td></tr>'
        : inquiries
          .map((inq) => {
            const atts = inquiryAttachments[inq.inquiry_id] || [];
            const payload = parseLeadPayload(inq);
            const leadDetail = {
              inquiry_id: inq.inquiry_id,
              org_name: inq.org_name,
              prop_loc: inq.prop_loc || payload.property_city_or_zip || payload.property || '',
              kind: KIND_LABELS[inq.inquiry_kind] || formatSlug(inq.inquiry_kind),
              service: formatSlug(inq.service_family),
              classification: CLASS_LABELS[inq.classification] || inq.classification,
              status: STAGE_LABELS[inq.status] || inq.status,
              received_at: formatPhoenixDateTime(inq.received_at, false),
              name: payload.name || '',
              email: payload.email || '',
              telephone: payload.telephone || '',
              preferred_contact_method: payload.preferred_contact_method || '',
              property_type: payload.property_type || '',
              desired_timing: payload.desired_timing || '',
              description: payload.description || '',
            };
            return `<tr>
                              <td>
                                <strong>${escapeHtml(inq.org_name)}</strong>
                                ${payload.name ? `<div style="font-size:0.84rem;color:var(--color-carbon);margin-top:0.15rem;">${escapeHtml(payload.name)}</div>` : ''}
                                <small class="muted"><code>${escapeHtml(inq.inquiry_id.slice(0, 8))}</code> &middot; ${escapeHtml(inq.prop_loc || '—')}</small>
                                <div style="margin-top:0.45rem;">
                                  <button type="button" class="btn btn--secondary btn--compact js-lead-detail-btn" data-lead="${escapeHtml(JSON.stringify(leadDetail))}" style="min-height:34px;padding:0.25rem 0.65rem;font-size:0.79rem;">View Details</button>
                                </div>
                              </td>
                              <td>
                                <span style="font-weight:600;">${escapeHtml(KIND_LABELS[inq.inquiry_kind] || formatSlug(inq.inquiry_kind))}</span><br>
                                <small class="muted">${escapeHtml(formatSlug(inq.service_family))}</small>
                                ${atts.length > 0
                ? `<div style="margin-top:0.35rem;font-size:0.8rem;">${atts
                  .map((att) =>
                    att.scan_state === 'clean'
                      ? `<a href="/admin/api/inquiries/${escapeHtml(inq.inquiry_id)}/attachments/${escapeHtml(att.attachment_id)}">Download: ${escapeHtml(att.original_name)}</a>`
                      : `<span class="badge badge--err">${escapeHtml(att.original_name)} (${escapeHtml(att.scan_state)})</span>`
                  )
                  .join('<br>')}</div>`
                : ''
              }
                              </td>
                              <td>
                                <div style="display:flex;flex-wrap:wrap;gap:0.3rem;">
                                  <span class="badge">${escapeHtml(CLASS_LABELS[inq.classification] || inq.classification)}</span>
                                  <span class="badge badge--live">${escapeHtml(STAGE_LABELS[inq.status] || inq.status)}</span>
                                </div>
                                ${inq.crm_deal_id ? `<small class="muted" style="display:block;margin-top:0.3rem;">Deal: ${escapeHtml(inq.crm_deal_id)}</small>` : ''}
                              </td>
                              <td style="white-space:nowrap;">${escapeHtml(formatPhoenixDateTime(inq.received_at, false))}</td>
                              <td>
                                <form method="POST" action="/admin/api/inquiries/${escapeHtml(inq.inquiry_id)}/status" class="js-ajax-form admin-lead-form">
                                  <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                                  <select name="classification" aria-label="Classification">
                                    ${['valid', 'existing_service', 'spam', 'job', 'vendor', 'out_of_area', 'test'].map((c) => `<option value="${c}"${inq.classification === c ? ' selected' : ''}>${escapeHtml(CLASS_LABELS[c] || c)}</option>`).join('')}
                                  </select>
                                  <select name="status" aria-label="Pipeline status">
                                    ${['received', 'qualified', 'proposal_sent', 'closed_won', 'disqualified'].map((s) => `<option value="${s}"${inq.status === s ? ' selected' : ''}>${escapeHtml(STAGE_LABELS[s] || s)}</option>`).join('')}
                                  </select>
                                  <input type="number" step="0.01" min="0" name="deal_value" aria-label="Deal value USD" placeholder="Value $" value="${inq.deal_value != null ? escapeHtml(inq.deal_value) : ''}">
                                  <button type="submit" class="btn btn--primary btn--compact">Save</button>
                                </form>
                              </td>
                            </tr>`;
          })
          .join('')
      }
                </tbody>
              </table>
            </div>
          </div>
          <div class="admin-mobile-cards">
            ${inquiries.length === 0
        ? '<div class="admin-empty-state">No inquiries matching filter criteria.</div>'
        : inquiries
          .map((inq) => {
            const payload = parseLeadPayload(inq);
            const leadDetail = {
              inquiry_id: inq.inquiry_id,
              org_name: inq.org_name,
              prop_loc: inq.prop_loc || payload.property_city_or_zip || payload.property || '',
              kind: KIND_LABELS[inq.inquiry_kind] || formatSlug(inq.inquiry_kind),
              service: formatSlug(inq.service_family),
              classification: CLASS_LABELS[inq.classification] || inq.classification,
              status: STAGE_LABELS[inq.status] || inq.status,
              received_at: formatPhoenixDateTime(inq.received_at, false),
              name: payload.name || '',
              email: payload.email || '',
              telephone: payload.telephone || '',
              preferred_contact_method: payload.preferred_contact_method || '',
              property_type: payload.property_type || '',
              desired_timing: payload.desired_timing || '',
              description: payload.description || '',
            };
            return `<div class="admin-mobile-card">
                        <div class="admin-mobile-card__top"><span class="admin-mobile-card__title">${escapeHtml(inq.org_name)}</span><span class="badge badge--live">${escapeHtml(STAGE_LABELS[inq.status] || inq.status)}</span></div>
                        <div class="admin-mobile-card__meta">${payload.name ? `<strong>${escapeHtml(payload.name)}</strong> &middot; ` : ''}${escapeHtml(formatSlug(inq.service_family))} &middot; ${escapeHtml(inq.prop_loc || '—')}<br>${escapeHtml(formatPhoenixDateTime(inq.received_at, false))}</div>
                        <div style="margin-bottom:0.5rem;">
                          <button type="button" class="btn btn--secondary btn--compact js-lead-detail-btn" data-lead="${escapeHtml(JSON.stringify(leadDetail))}">View Details</button>
                        </div>
                        <form method="POST" action="/admin/api/inquiries/${escapeHtml(inq.inquiry_id)}/status" class="js-ajax-form admin-mobile-card__actions">
                          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                          <select name="status" aria-label="Pipeline status" style="min-height:44px;flex:1;">
                            ${['received', 'qualified', 'proposal_sent', 'closed_won', 'disqualified'].map((s) => `<option value="${s}"${inq.status === s ? ' selected' : ''}>${escapeHtml(STAGE_LABELS[s] || s)}</option>`).join('')}
                          </select>
                          <button type="submit" class="btn btn--primary btn--compact">Save</button>
                        </form>
                      </div>`;
          })
          .join('')
      }
          </div>
          ${renderPaginationNav('/admin/leads', inquiriesMeta, { tab: 'inquiries', ...filters })}

          <dialog id="admin-lead-dialog" aria-labelledby="lead-dialog-title">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.75rem;margin-bottom:0.85rem;">
              <div>
                <span class="eyebrow" id="lead-dialog-kind" style="margin-bottom:0.2rem;">Inquiry</span>
                <h2 id="lead-dialog-title" style="margin:0;border:0;padding:0;font-size:1.35rem;">Inquiry Details</h2>
              </div>
              <button type="button" id="lead-dialog-close" class="btn btn--secondary btn--compact">Close</button>
            </div>
            <dl id="lead-dialog-dl" class="lead-detail-dl"></dl>
          </dialog>
        </section>`
      : `<div class="grid-2" style="align-items:start;">
          <section class="admin-card">
            <h2>Freshsales CRM Delivery Queue</h2>
            ${crmQueue.length === 0
        ? '<div class="admin-empty-state">No CRM delivery records queued yet.</div>'
        : `<div class="table-scroll" tabindex="0" role="region" aria-label="Freshsales CRM Delivery Queue">
                    <table class="data-table" style="font-size:0.84rem;">
                      <thead><tr><th>Inquiry</th><th>Status</th><th>Attempts</th><th>External ID / Error</th><th>Action</th></tr></thead>
                      <tbody>
                        ${crmQueue
          .map(
            (q) => `<tr>
                              <td><code>${escapeHtml(q.inquiry_id.slice(0, 8))}</code></td>
                              <td><span class="badge ${q.status === 'delivered' ? 'badge--live' : q.status === 'failed_review' ? 'badge--err' : 'badge--warn'}">${escapeHtml(q.status)}</span></td>
                              <td>${escapeHtml(q.attempts)}</td>
                              <td>${escapeHtml(q.external_record_id || q.last_error || 'Pending')}</td>
                              <td>${q.status === 'failed_review' || q.status === 'pending'
                ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/crm/replay/${escapeHtml(q.delivery_id)}">Replay</button>`
                : '—'
              }</td>
                            </tr>`
          )
          .join('')}
                      </tbody>
                    </table>
                  </div>`
      }
          </section>

          <section class="admin-card">
            <h2>M365 Notification Dispatch Queue</h2>
            ${notifications.length === 0
        ? '<div class="admin-empty-state">No notification dispatches recorded yet.</div>'
        : `<div class="table-scroll" tabindex="0" role="region" aria-label="M365 Notification Dispatch Queue">
                    <table class="data-table" style="font-size:0.84rem;">
                      <thead><tr><th>Recipient</th><th>Status</th><th>Attempts</th><th>Provider ID / Error</th><th>Action</th></tr></thead>
                      <tbody>
                        ${notifications
          .map(
            (n) => `<tr>
                              <td><strong>${escapeHtml(n.recipient_target)}</strong><br><small class="muted">${escapeHtml(n.domain)} &middot; ${escapeHtml(n.subject)}</small></td>
                              <td><span class="badge ${n.status === 'sent' ? 'badge--live' : n.status === 'failed_review' ? 'badge--err' : 'badge--warn'}">${escapeHtml(n.status)}</span></td>
                              <td>${escapeHtml(n.attempts)}</td>
                              <td>${escapeHtml(n.provider_message_id || n.last_error || 'Pending')}</td>
                              <td>${n.status !== 'sent'
                ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/notifications/replay/${escapeHtml(n.notification_id)}">Replay</button>`
                : '—'
              }</td>
                            </tr>`
          )
          .join('')}
                      </tbody>
                    </table>
                  </div>`
      }
          </section>
        </div>`
    }`;
}

export function renderAdminAnalyticsView({ summary, user = null, range = summary.range || 'all' }) {
  const leads = summary.leadsByService || [];
  const events = summary.eventCounts || [];
  const camps = summary.campaignPerformance || [];
  const projReady = summary.projectReadiness || [];
  const channels = summary.channelBreakdown || [];
  const hiringActivity = summary.hiringActivity || [];
  const showHiring = hiringActivity.length > 0 && user && (hasPermission(user, PERMISSIONS.MANAGE_VACANCIES) || hasPermission(user, PERMISSIONS.REVIEW_APPLICATIONS));

  const rangeLabels = { '7d': 'Last 7 Days', '30d': 'Last 30 Days', '90d': 'Last 90 Days', 'all': 'All Time' };

  return `
  <nav class="admin-tabs" aria-label="Analytics date range" style="margin-bottom:1rem;">
    ${['7d', '30d', '90d', 'all'].map((r) => `<a href="/admin/analytics?range=${r}" class="admin-tab${range === r ? ' is-active' : ''}">${rangeLabels[r]}</a>`).join('')}
  </nav>
  <p class="muted" style="margin-bottom:1.15rem;"><strong>Data boundary:</strong> Reports non-identifying first-party events and durable inquiry totals only. Applicant names, emails, and resume filenames are never shown here. Snapshot reflects stored records as of page load.</p>
  <section class="admin-card">
    <h2>Inquiry Funnel by Service</h2>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Durable Inquiries Summary">
      <table class="data-table" style="font-size:0.86rem;">
        <thead><tr><th>Service Family</th><th>Total</th><th>New Biz</th><th>Qualified</th><th>Proposals</th><th>Won</th><th>Existing / Excluded</th></tr></thead>
        <tbody>
          ${leads.length === 0
      ? '<tr><td colspan="7" class="muted">No commercial inquiries recorded yet.</td></tr>'
      : leads
        .map(
          (r) =>
            `<tr><td>${escapeHtml(r.service_family)}</td><td>${escapeHtml(r.total_inquiries)}</td><td>${escapeHtml(r.accepted_new_business)}</td><td>${escapeHtml(r.qualified_opportunities)}</td><td>${escapeHtml(r.proposals_sent)}</td><td>${escapeHtml(r.closed_won)}</td><td>${escapeHtml(r.existing_service_requests)} / ${escapeHtml(r.excluded_non_sales)}</td></tr>`
        )
        .join('')
    }
        </tbody>
      </table>
    </div>
  </section>

  <div class="grid-2" style="align-items:start;">
    <section class="admin-card">
      <h2>First-Party Event Totals (PII-Scrubbed)</h2>
      <div class="table-scroll" tabindex="0" role="region" aria-label="First-Party Event Totals">
        <table class="data-table" style="font-size:0.85rem;">
          <thead><tr><th>Event Name</th><th>Count</th></tr></thead>
          <tbody>
            ${events.length === 0
      ? '<tr><td colspan="2" class="muted">No analytics events recorded yet.</td></tr>'
      : events.map((e) => `<tr><td><code>${escapeHtml(e.event_name)}</code></td><td>${escapeHtml(e.total)}</td></tr>`).join('')
    }
          </tbody>
        </table>
      </div>
    </section>

    <section class="admin-card">
      <h2>Project Publication &amp; Rights Readiness</h2>
      <div class="table-scroll" tabindex="0" role="region" aria-label="Project Readiness Summary">
        <table class="data-table" style="font-size:0.85rem;">
          <thead><tr><th>Activation</th><th>Editorial</th><th>Total</th><th>Private Test</th></tr></thead>
          <tbody>
            ${projReady
      .map(
        (p) => `<tr><td>${escapeHtml(p.activation_state)}</td><td>${escapeHtml(p.editorial_state)}</td><td>${escapeHtml(p.total)}</td><td>${escapeHtml(p.test_records)}</td></tr>`
      )
      .join('')}
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <section class="admin-card">
    <h2>Inquiry Channels (UTM Source / Medium)</h2>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Inquiry Channels Summary">
      <table class="data-table" style="font-size:0.85rem;">
        <thead><tr><th>Source</th><th>Medium</th><th>Accepted Leads</th><th>Total Events</th></tr></thead>
        <tbody>
          ${channels.length === 0
      ? '<tr><td colspan="4" class="muted">No channel attribution events recorded for this period.</td></tr>'
      : channels
        .map(
          (ch) => `<tr><td>${escapeHtml(ch.source)}</td><td>${escapeHtml(ch.medium)}</td><td>${escapeHtml(ch.accepted_leads)}</td><td>${escapeHtml(ch.events_total)}</td></tr>`
        )
        .join('')
    }
        </tbody>
      </table>
    </div>
  </section>

  <section class="admin-card">
    <h2>On-Site Seasonal Campaign Placement Performance</h2>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Campaign Placement Performance">
      <table class="data-table" style="font-size:0.85rem;">
        <thead><tr><th>Campaign</th><th>Slot</th><th>State</th><th>Views (50% &ge; 1s)</th><th>CTA Clicks</th></tr></thead>
        <tbody>
          ${camps
      .map(
        (c) => `<tr><td>${escapeHtml(c.internal_title)}</td><td><code>${escapeHtml(c.placement_slot)}</code></td><td>${escapeHtml(c.activation_state)}</td><td>${escapeHtml(c.views)}</td><td>${escapeHtml(c.clicks)}</td></tr>`
      )
      .join('')}
        </tbody>
      </table>
    </div>
  </section>

  ${showHiring
      ? `<section class="admin-card">
          <h2>Role-Scoped Hiring Activity</h2>
          <p class="muted" style="margin-top:0;font-size:0.85rem;">Shows aggregate counts only for job openings within your authorized hiring scope. No applicant PII appears here.</p>
          <div class="table-scroll" tabindex="0" role="region" aria-label="Role-Scoped Hiring Activity">
            <table class="data-table" style="font-size:0.85rem;">
              <thead><tr><th>Requisition</th><th>Role Title</th><th>Status</th><th>Applications</th><th>Pending Review</th><th>Avg Review Hours</th></tr></thead>
              <tbody>
                ${hiringActivity
        .map(
          (h) => `<tr><td><code>${escapeHtml(h.requisition_id)}</code></td><td>${escapeHtml(h.title)}</td><td><span class="badge ${h.status === 'Open' ? 'badge--live' : 'badge--warn'}">${escapeHtml(h.status)}</span></td><td>${escapeHtml(h.total)}</td><td>${escapeHtml(h.pendingReview)}</td><td>${h.avgReviewHours !== null ? `${escapeHtml(h.avgReviewHours)}h` : '&mdash;'}</td></tr>`
        )
        .join('')}
              </tbody>
            </table>
          </div>
        </section>`
      : ''
    }`;
}

export function renderAdminReviewsView({ pendingItems = [], logs = [], logsMeta = null, filters = {} }) {
  return `
  <section class="admin-card">
    <div class="admin-card__header">
      <div>
        <h2>Editorial &amp; Publication Review Queue</h2>
        <p class="muted" style="margin:0;font-size:0.85rem;">Items marked <strong>In review</strong> or awaiting factual evidence approval. Click any item to inspect or publish.</p>
      </div>
      <span class="badge ${pendingItems.length > 0 ? 'badge--warn' : 'badge--live'}">${pendingItems.length} pending</span>
    </div>
    ${pendingItems.length === 0
      ? '<div class="admin-empty-state">All website pages, articles, claims, and projects have cleared review.</div>'
      : `<div class="table-scroll admin-desktop-only" tabindex="0" role="region" aria-label="Pending Review Queue">
            <table class="data-table">
              <thead><tr><th scope="col">Type</th><th scope="col">Title / Route</th><th scope="col">Owner</th><th scope="col">Updated (Phoenix)</th><th scope="col">Action</th></tr></thead>
              <tbody>
                ${pendingItems
        .map(
          (it) => `<tr>
                      <td><span class="badge badge--warn">${escapeHtml(it.type)}</span></td>
                      <td><strong>${escapeHtml(it.title)}</strong></td>
                      <td>${escapeHtml(it.owner)}</td>
                      <td>${escapeHtml(formatPhoenixDateTime(it.updated_at, false))}</td>
                      <td><a href="${escapeHtml(it.href)}" class="btn btn--secondary btn--compact">Open Review &rarr;</a></td>
                    </tr>`
        )
        .join('')}
              </tbody>
            </table>
          </div>
          <div class="admin-mobile-cards" aria-label="Pending Review Queue Cards">
            ${pendingItems
        .map(
          (it) => `<article class="admin-mobile-card">
                  <div class="admin-mobile-card__head">
                    <div>
                      <strong>${escapeHtml(it.title)}</strong>
                      <div class="muted" style="font-size:0.85rem;">Owner: ${escapeHtml(it.owner)} &middot; ${escapeHtml(formatPhoenixDateTime(it.updated_at, false))}</div>
                    </div>
                    <span class="badge badge--warn">${escapeHtml(it.type)}</span>
                  </div>
                  <div class="admin-mobile-card__actions">
                    <a href="${escapeHtml(it.href)}" class="btn btn--secondary btn--compact">Open Review &rarr;</a>
                  </div>
                </article>`
        )
        .join('')}
          </div>`
    }
  </section>

  <section class="admin-card">
    <div class="admin-card__header">
      <div>
        <h2>Audit Trail (Non-Hiring Operations)</h2>
        <p class="muted" style="margin:0;font-size:0.85rem;">Recruiting and private applicant logs remain strictly isolated from this operational feed.</p>
      </div>
    </div>
    <form method="GET" action="/admin/reviews" class="admin-filter-bar">
      <div class="field" style="flex:1;min-width:13rem;">
        <label for="aud-q">Search actor, action, or object</label>
        <input id="aud-q" name="q" type="search" value="${escapeHtml(filters.q || '')}" placeholder="Filter audit trail...">
      </div>
      <div class="field" style="min-width:11rem;">
        <label for="aud-domain">Domain</label>
        <select id="aud-domain" name="domain">
          <option value="">All domains</option>
          ${['auth', 'users', 'content', 'campaigns', 'projects', 'media', 'crm', 'notifications', 'settings', 'ops']
      .map((d) => `<option value="${d}"${filters.domain === d ? ' selected' : ''}>${d}</option>`)
      .join('')}
        </select>
      </div>
      <div class="admin-action-group">
        <button type="submit" class="btn btn--secondary">Filter</button>
        ${filters.domain || filters.q ? '<a href="/admin/reviews" class="btn btn--secondary">Clear</a>' : ''}
      </div>
    </form>
    ${logs.length === 0
      ? '<div class="admin-empty-state">No non-hiring audit events match your filter criteria.</div>'
      : `<div class="table-scroll admin-desktop-only" tabindex="0" role="region" aria-label="Audit Trail Table">
            <table class="data-table" style="font-size:0.875rem;">
              <thead><tr><th scope="col">Time (Phoenix)</th><th scope="col">Actor</th><th scope="col">Domain</th><th scope="col">Action</th><th scope="col">Object</th><th scope="col">Details</th></tr></thead>
              <tbody>
                ${logs
        .map(
          (l) => `<tr>
                      <td>${escapeHtml(formatPhoenixDateTime(l.created_at, false))}</td>
                      <td>${escapeHtml(l.actor_name)}<br><small class="muted">${escapeHtml(l.actor_role)}</small></td>
                      <td><span class="badge">${escapeHtml(l.domain)}</span></td>
                      <td>${escapeHtml(l.action)}</td>
                      <td><code>${escapeHtml(l.object_type)}:${escapeHtml(l.object_id)}</code></td>
                      <td><small class="muted">${escapeHtml(l.details_json)}</small></td>
                    </tr>`
        )
        .join('')}
              </tbody>
            </table>
          </div>
          <div class="admin-mobile-cards" aria-label="Audit Trail Cards">
            ${logs
        .map(
          (l) => `<article class="admin-mobile-card">
                  <div class="admin-mobile-card__head">
                    <div>
                      <strong>${escapeHtml(l.action)}</strong>
                      <div class="muted" style="font-size:0.85rem;">${escapeHtml(l.actor_name)} (${escapeHtml(l.actor_role)})</div>
                    </div>
                    <span class="badge">${escapeHtml(l.domain)}</span>
                  </div>
                  <div class="admin-mobile-card__meta">
                    <span>Time: <strong>${escapeHtml(formatPhoenixDateTime(l.created_at, false))}</strong></span>
                    <span>Object: <code>${escapeHtml(l.object_type)}:${escapeHtml(l.object_id)}</code></span>
                  </div>
                  ${l.details_json ? `<div class="muted" style="font-size:0.82rem;word-break:break-word;">${escapeHtml(l.details_json)}</div>` : ''}
                </article>`
        )
        .join('')}
          </div>`
    }
    ${renderPaginationNav('/admin/reviews', logsMeta, filters)}
  </section>`;
}

export function renderAdminUsersView({
  tab = 'directory',
  actionMode = '',
  users = [],
  allUsers = [],
  filters = {},
  selectedUser = null,
  selectedRoleName = '',
  userAuditLogs = [],
  activeSessionsMap = {},
  lastLoginMap = {},
  rolePermissionMap = {},
  m365Status = { configured: false, senderDomain: null },
  user,
  csrfToken,
}) {
  const canManageUsers = hasPermission(user, PERMISSIONS.MANAGE_USERS);
  const allRoleNames = Object.values(ROLES);
  const permLabelByKey = Object.fromEntries(PERMISSION_META.map((p) => [p.key, p.label]));

  const activeCount = allUsers.filter((u) => Boolean(u.active)).length;
  const mfaEnrolledCount = allUsers.filter((u) => Boolean(u.mfa_enabled && u.mfa_enrolled)).length;
  const totalSessions = Object.values(activeSessionsMap).reduce((sum, n) => sum + Number(n || 0), 0);

  const roleAssignedCounts = Object.fromEntries(allRoleNames.map((r) => [r, 0]));
  for (const u of allUsers) {
    for (const r of getUserRoles(u)) {
      if (roleAssignedCounts[r] !== undefined) roleAssignedCounts[r] += 1;
    }
  }

  const activeRoleDetail = allRoleNames.includes(selectedRoleName) ? selectedRoleName : allRoleNames[0];
  const roleUsers = allUsers.filter((u) => getUserRoles(u).includes(activeRoleDetail));

  const renderRoleCheckboxes = (idPrefix, selectedExtraRoles = [], currentPrimaryRole = '') => `
    <div class="role-checkbox-grid">
      ${allRoleNames
      .map((roleName, idx) => {
        const checked = selectedExtraRoles.includes(roleName);
        const isPrimary = currentPrimaryRole === roleName;
        const cid = `${idPrefix}-${idx}`;
        return `<label class="role-checkbox-card" for="${escapeHtml(cid)}">
            <input type="checkbox" id="${escapeHtml(cid)}" name="extra_roles" value="${escapeHtml(roleName)}" data-checkbox-array="true"${checked ? ' checked' : ''}>
            <span>
              <span class="role-checkbox-card__title">${escapeHtml(getRoleDisplayLabel(roleName))}${isPrimary ? ' <span class="badge">Primary</span>' : ''}</span>
              <span class="role-checkbox-card__desc">${escapeHtml((ROLE_DESCRIPTIONS[roleName] || '').slice(0, 74))}...</span>
            </span>
          </label>`;
      })
      .join('')}
    </div>`;

  return `
  <div class="kpi-grid">
    <div class="kpi-card"><span class="kpi-card__num">${allUsers.length}</span><span class="kpi-card__label">Total Users</span><span class="kpi-card__hint">${activeCount} active &middot; ${allUsers.length - activeCount} revoked</span></div>
    <div class="kpi-card"><span class="kpi-card__num">${totalSessions}</span><span class="kpi-card__label">Live Sessions</span><span class="kpi-card__hint">Active signed-in devices</span></div>
    <div class="kpi-card kpi-card--accent"><span class="kpi-card__num">${mfaEnrolledCount}</span><span class="kpi-card__label">MFA Enrolled</span><span class="kpi-card__hint">${allUsers.length - mfaEnrolledCount} pending setup</span></div>
    <div class="kpi-card"><span class="kpi-card__num">${allRoleNames.length}</span><span class="kpi-card__label">Staff Roles</span><span class="kpi-card__hint">Least-privilege access</span></div>
  </div>

  <div class="admin-tabs" style="justify-content:space-between;align-items:center;">
    <div class="admin-action-group">
      <a href="/admin/users?tab=directory" class="admin-tab${tab === 'directory' ? ' is-active' : ''}"${tab === 'directory' ? ' aria-current="page"' : ''}>Staff Directory (${allUsers.length})</a>
      <a href="/admin/users?tab=roles" class="admin-tab${tab === 'roles' ? ' is-active' : ''}"${tab === 'roles' ? ' aria-current="page"' : ''}>Roles &amp; Permissions</a>
    </div>
    <div class="admin-action-group">
      ${canManageUsers
      ? `<a href="/admin/users?tab=directory&action=create#create-staff-panel" class="btn btn--primary">+ Add User</a>`
      : ''
    }
      <a href="/admin/mfa-setup" class="btn btn--secondary">My MFA Settings</a>
    </div>
  </div>

  ${tab === 'directory'
      ? `
        ${canManageUsers && actionMode === 'create'
        ? `<section id="create-staff-panel" class="admin-card">
                <div class="admin-card__header">
                  <div>
                    <h2>Add Staff Account</h2>
                    <p class="muted" style="margin:0;font-size:0.84rem;">Provision a named account with a primary role and optional additional roles.</p>
                  </div>
                  <a href="/admin/users?tab=directory" class="btn btn--secondary btn--compact">Close</a>
                </div>
                <form id="create-user-form" method="POST" action="/admin/api/users" class="js-ajax-form" data-success-msg="Staff account created cleanly.">
                  <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                  <div class="grid-3">
                    <div class="field"><label for="nu-name">Full Name</label><input type="text" id="nu-name" name="full_name" required></div>
                    <div class="field"><label for="nu-email">Staff Email</label><input type="email" id="nu-email" name="email" required></div>
                    <div class="field"><label for="nu-role">Primary Role</label>
                      <select id="nu-role" name="role">
                        ${allRoleNames.map((r) => `<option value="${escapeHtml(r)}">${escapeHtml(getRoleDisplayLabel(r))}</option>`).join('')}
                      </select>
                    </div>
                  </div>
                  <fieldset class="admin-fieldset">
                    <legend>Onboarding Method (Staff Sets Their Own Password &amp; Google Authenticator)</legend>
                    <div class="grid-2">
                      <label class="role-checkbox-card" for="nu-mode-manual">
                        <input type="radio" id="nu-mode-manual" name="onboarding_mode" value="manual" checked>
                        <span>
                          <span class="role-checkbox-card__title">Manual Invitation (Copy Setup Link)</span>
                          <span class="role-checkbox-card__desc">Generates a single-use 60-minute link to share securely.</span>
                        </span>
                      </label>
                      <label class="role-checkbox-card" for="nu-mode-email" style="${m365Status.configured ? '' : 'opacity:0.65;'}">
                        <input type="radio" id="nu-mode-email" name="onboarding_mode" value="email"${m365Status.configured ? '' : ' disabled'}>
                        <span>
                          <span class="role-checkbox-card__title">Email Invitation (Microsoft 365)${m365Status.configured ? '' : ' <span class="badge badge--warn">Unavailable</span>'}</span>
                          <span class="role-checkbox-card__desc">${m365Status.configured ? 'Emails a single-use 24-hour onboarding link via Microsoft 365.' : 'Microsoft 365 email is not configured. Use Manual Invitation.'}</span>
                        </span>
                      </label>
                    </div>
                  </fieldset>
                  <fieldset class="admin-fieldset">
                    <legend>Additional Roles (Optional Multi-Role)</legend>
                    ${renderRoleCheckboxes('nu-extra', [], '')}
                  </fieldset>
                  <div class="admin-action-group">
                    <button type="submit" class="btn btn--primary">Create &amp; Issue Invitation</button>
                    <a href="/admin/users?tab=directory" class="btn btn--secondary">Cancel</a>
                  </div>
                </form>
                <div id="onboarding-link-box" class="panel panel--light" hidden style="margin-top:1rem;">
                  <h3 style="margin-top:0;">Single-Use Onboarding Link Ready</h3>
                  <p id="onboarding-link-meta" class="muted" style="font-size:0.86rem;margin-bottom:0.5rem;"></p>
                  <div style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;">
                    <input type="text" id="onboarding-link-input" readonly style="flex:1;min-width:16rem;font-family:monospace;font-size:0.84rem;" aria-label="Single-use onboarding setup link">
                    <button type="button" id="btn-copy-onboarding-link" class="btn btn--primary btn--compact">Copy Setup Link</button>
                  </div>
                </div>
              </section>`
        : ''
      }

        ${selectedUser
        ? (() => {
          let extra = [];
          try { extra = JSON.parse(selectedUser.extra_roles_json || '[]'); } catch { }
          const combinedRoles = getUserRoles(selectedUser);
          const effectivePerms = Array.from(new Set(combinedRoles.flatMap((r) => rolePermissionMap[r] || [])));
          const sessCount = activeSessionsMap[selectedUser.user_id] || 0;
          const lastLogin = lastLoginMap[selectedUser.user_id];
          return `<section id="user-details-panel" class="admin-card">
                  <div class="admin-card__header">
                    <div>
                      <h2>Edit User: ${escapeHtml(selectedUser.full_name)}</h2>
                      <p class="muted" style="margin:0;font-size:0.84rem;"><code>${escapeHtml(selectedUser.email)}</code> &middot; ID <code>${escapeHtml(selectedUser.user_id)}</code> &middot; ${sessCount} session(s)</p>
                    </div>
                    <div class="admin-action-group">
                      <span class="badge ${selectedUser.active ? 'badge--live' : 'badge--err'}">${selectedUser.active ? 'Active' : 'Revoked'}</span>
                      <a href="/admin/users?tab=directory" class="btn btn--secondary btn--compact">Close Editor</a>
                    </div>
                  </div>

                  <p class="muted" style="font-size:0.85rem;margin-bottom:1rem;">
                    <strong>Last Login (Phoenix):</strong> ${lastLogin ? escapeHtml(formatPhoenixDateTime(lastLogin, false)) : 'No login recorded'} &middot;
                    <strong>MFA:</strong> ${selectedUser.mfa_enabled ? (selectedUser.mfa_enrolled ? 'Enrolled (TOTP)' : 'Pending Setup') : 'Off'}
                  </p>

                  <form id="edit-user-form" method="POST" action="/admin/api/users/${escapeHtml(selectedUser.user_id)}" data-orig-name="${escapeHtml(selectedUser.full_name)}" data-orig-role="${escapeHtml(selectedUser.role)}" data-orig-extra="${escapeHtml(JSON.stringify(extra))}" data-orig-active="${selectedUser.active ? '1' : '0'}">
                    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                    <div class="grid-3">
                      <div class="field">
                        <label for="eu-name">Full Name</label>
                        <input type="text" id="eu-name" name="full_name" value="${escapeHtml(selectedUser.full_name)}" required ${canManageUsers ? '' : 'disabled'}>
                      </div>
                      <div class="field">
                        <label for="eu-status">Account Status</label>
                        <select id="eu-status" name="active" ${canManageUsers ? '' : 'disabled'}>
                          <option value="1"${selectedUser.active ? ' selected' : ''}>Active (Allowed to sign in)</option>
                          <option value="0"${!selectedUser.active ? ' selected' : ''}>Revoked / Deactivated</option>
                        </select>
                      </div>
                      <div class="field">
                        <label for="eu-role">Primary Role</label>
                        <select id="eu-role" name="role" ${canManageUsers ? '' : 'disabled'}>
                          ${allRoleNames.map((r) => `<option value="${escapeHtml(r)}"${selectedUser.role === r ? ' selected' : ''}>${escapeHtml(getRoleDisplayLabel(r))}</option>`).join('')}
                        </select>
                      </div>
                    </div>

                    <fieldset class="admin-fieldset">
                      <legend>Additional Assigned Roles (Multi-Role Checkboxes)</legend>
                      ${renderRoleCheckboxes(`eu-extra-${selectedUser.user_id}`, extra, selectedUser.role)}
                    </fieldset>

                    <details class="admin-accordion" style="margin-top:0;margin-bottom:1rem;">
                      <summary>Optional Password Reset (Minimum 10 Characters)</summary>
                      <div class="field" style="margin-bottom:0;">
                        <label for="eu-new-pass">New Password (leave blank to keep current password)</label>
                        <input type="password" id="eu-new-pass" name="new_password" minlength="10" autocomplete="new-password" placeholder="Leave blank unless resetting password..." ${canManageUsers ? '' : 'disabled'}>
                      </div>
                    </details>

                    <div class="admin-action-group" style="justify-content:space-between;">
                      <button type="submit" class="btn btn--primary" ${canManageUsers ? '' : 'disabled'}>Save User Changes</button>
                      ${canManageUsers
              ? `<div class="admin-action-group">
                              <button type="button" class="btn btn--secondary btn--compact js-invite-btn" data-url="/admin/api/users/${encodeURIComponent(selectedUser.user_id)}/mfa-recovery-token" data-delivery="manual">Copy New Setup Link</button>
                              <button type="button" class="btn btn--secondary btn--compact js-invite-btn" data-url="/admin/api/users/${encodeURIComponent(selectedUser.user_id)}/mfa-recovery-token" data-delivery="email"${m365Status.configured ? '' : ' disabled title="Microsoft 365 email is not configured"'}>Email Setup Link${m365Status.configured ? '' : ' (M365 Unavailable)'}</button>
                              <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/users/${encodeURIComponent(selectedUser.user_id)}/revoke-sessions" data-confirm-title="Revoke All Active Sessions?" data-confirm="Sign out ${escapeHtml(selectedUser.full_name)} immediately from all browsers?">Revoke Sessions</button>
                              ${selectedUser.active
                ? `<button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/users/${encodeURIComponent(selectedUser.user_id)}/deactivate" data-confirm-title="Deactivate Staff Account?" data-confirm="Deactivating ${escapeHtml(selectedUser.full_name)} immediately revokes access and clears all active sessions.">Deactivate</button>`
                : `<button type="button" class="btn btn--primary btn--compact js-action-btn" data-url="/admin/api/users/${encodeURIComponent(selectedUser.user_id)}/activate" data-confirm-title="Reactivate Staff Account?" data-confirm="Allow ${escapeHtml(selectedUser.full_name)} to sign in again with existing role assignments?">Activate</button>`
              }
                            </div>`
              : ''
            }
                    </div>
                  </form>
                  <div id="edit-onboarding-link-box" class="panel panel--light" hidden style="margin-top:1rem;">
                    <h3 style="margin-top:0;">Single-Use Setup / Recovery Link</h3>
                    <p id="edit-onboarding-link-meta" class="muted" style="font-size:0.86rem;margin-bottom:0.5rem;"></p>
                    <div style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;">
                      <input type="text" id="edit-onboarding-link-input" readonly style="flex:1;min-width:16rem;font-family:monospace;font-size:0.84rem;" aria-label="Single-use setup or recovery link">
                      <button type="button" id="btn-copy-edit-onboarding-link" class="btn btn--primary btn--compact">Copy Setup Link</button>
                    </div>
                  </div>

                  <details class="admin-accordion">
                    <summary>Effective Permissions (${effectivePerms.length}) &amp; Activity History (${userAuditLogs.length})</summary>
                    <h3 style="margin-top:0;">Effective Server-Side Permissions</h3>
                    <div class="perm-chip-list" style="margin-bottom:1rem;">
                      ${effectivePerms.length === 0
              ? '<span class="muted">No permissions assigned.</span>'
              : effectivePerms.map((p) => `<span class="perm-chip" title="${escapeHtml(p)}">${escapeHtml(permLabelByKey[p] || p)}</span>`).join('')
            }
                    </div>
                    <h3>Recent Non-Hiring Activity</h3>
                    ${userAuditLogs.length === 0
              ? '<div class="admin-empty-state">No recorded non-hiring activity for this user yet.</div>'
              : `<div class="table-scroll" tabindex="0" role="region" aria-label="User Audit Activity">
                            <table class="data-table" style="font-size:0.82rem;">
                              <thead><tr><th scope="col">Time (Phoenix)</th><th scope="col">Domain</th><th scope="col">Action</th><th scope="col">Object</th></tr></thead>
                              <tbody>
                                ${userAuditLogs
                .map(
                  (al) => `<tr><td>${escapeHtml(formatPhoenixDateTime(al.created_at, false))}</td><td><span class="badge">${escapeHtml(al.domain)}</span></td><td>${escapeHtml(al.action)}</td><td><code>${escapeHtml(al.object_type)}:${escapeHtml(al.object_id)}</code></td></tr>`
                )
                .join('')}
                              </tbody>
                            </table>
                          </div>`
            }
                  </details>
                </section>`;
        })()
        : ''
      }

        <section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Staff Directory</h2>
              <p class="muted" style="margin:0;font-size:0.84rem;">Select <strong>Edit User</strong> to update name, status, roles, password, or MFA controls.</p>
            </div>
          </div>

          <form method="GET" action="/admin/users" class="admin-filter-bar">
            <input type="hidden" name="tab" value="directory">
            <div class="field" style="flex:1;min-width:13rem;">
              <label for="usr-q">Search by name or email</label>
              <input id="usr-q" name="q" type="search" value="${escapeHtml(filters.q || '')}" placeholder="Search staff member...">
            </div>
            <div class="field" style="min-width:12rem;">
              <label for="usr-role-filter">Role</label>
              <select id="usr-role-filter" name="role">
                <option value="">All Staff Roles</option>
                ${allRoleNames.map((r) => `<option value="${escapeHtml(r)}"${filters.role === r ? ' selected' : ''}>${escapeHtml(getRoleDisplayLabel(r))}</option>`).join('')}
              </select>
            </div>
            <div class="field" style="min-width:10rem;">
              <label for="usr-status-filter">Status</label>
              <select id="usr-status-filter" name="status">
                <option value="">All statuses</option>
                <option value="active"${filters.status === 'active' ? ' selected' : ''}>Active only</option>
                <option value="revoked"${filters.status === 'revoked' ? ' selected' : ''}>Revoked only</option>
              </select>
            </div>
            <div class="admin-action-group">
              <button type="submit" class="btn btn--secondary">Filter</button>
              ${filters.q || filters.role || filters.status ? '<a href="/admin/users?tab=directory" class="btn btn--secondary">Clear</a>' : ''}
            </div>
          </form>

          ${users.length === 0
        ? '<div class="admin-empty-state">No staff accounts match your search or role filters.</div>'
        : `<div class="admin-desktop-only">
                  <div class="table-scroll" tabindex="0" role="region" aria-label="Staff Accounts Directory">
                    <table class="data-table" style="font-size:0.86rem;">
                      <thead>
                        <tr>
                          <th scope="col">Staff Member</th>
                          <th scope="col">Assigned Roles</th>
                          <th scope="col">Status &amp; MFA</th>
                          <th scope="col">Last Login (Phoenix)</th>
                          <th scope="col">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        ${users
          .map((u) => {
            let extra = [];
            try { extra = JSON.parse(u.extra_roles_json || '[]'); } catch { }
            const sessCount = activeSessionsMap[u.user_id] || 0;
            const lastLogin = lastLoginMap[u.user_id];
            const isSelf = u.user_id === user.user_id;
            return `<tr class="${selectedUser?.user_id === u.user_id ? 'is-selected' : ''}">
                              <td>
                                <strong>${escapeHtml(u.full_name)}</strong>${isSelf ? ' <span class="badge">You</span>' : ''}<br>
                                <small class="muted"><code>${escapeHtml(u.email)}</code></small>
                              </td>
                              <td>
                                <div class="admin-action-group">
                                  <span class="badge badge--oxide">${escapeHtml(getRoleDisplayLabel(u.role))}</span>
                                  ${extra.map((er) => `<span class="badge">${escapeHtml(getRoleDisplayLabel(er))}</span>`).join('')}
                                </div>
                              </td>
                              <td>
                                <div class="admin-action-group">
                                  <span class="badge ${u.active ? 'badge--live' : 'badge--err'}">${u.active ? 'Active' : 'Revoked'}</span>
                                  <span class="badge ${u.mfa_enabled && u.mfa_enrolled ? 'badge--live' : 'badge--warn'}">${u.mfa_enabled ? (u.mfa_enrolled ? 'MFA Enrolled' : 'MFA Pending') : 'MFA Off'}</span>
                                </div>
                                <small class="muted">${sessCount} active session(s)</small>
                              </td>
                              <td>${lastLogin ? escapeHtml(formatPhoenixDateTime(lastLogin, false)) : '<span class="muted">Never</span>'}</td>
                              <td>
                                <a href="/admin/users?tab=directory&user=${encodeURIComponent(u.user_id)}#user-details-panel" class="btn btn--secondary btn--compact">Edit User</a>
                              </td>
                            </tr>`;
          })
          .join('')}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div class="admin-mobile-cards">
                  ${users
          .map((u) => {
            let extra = [];
            try { extra = JSON.parse(u.extra_roles_json || '[]'); } catch { }
            const sessCount = activeSessionsMap[u.user_id] || 0;
            const lastLogin = lastLoginMap[u.user_id];
            const isSelf = u.user_id === user.user_id;
            return `<div class="admin-mobile-card${selectedUser?.user_id === u.user_id ? ' is-selected' : ''}">
                        <div class="admin-mobile-card__top">
                          <span class="admin-mobile-card__title">${escapeHtml(u.full_name)}${isSelf ? ' <span class="badge">You</span>' : ''}</span>
                          <span class="badge ${u.active ? 'badge--live' : 'badge--err'}">${u.active ? 'Active' : 'Revoked'}</span>
                        </div>
                        <div class="admin-mobile-card__meta">
                          <code>${escapeHtml(u.email)}</code><br>
                          Last login: ${lastLogin ? escapeHtml(formatPhoenixDateTime(lastLogin, false)) : 'Never'} &middot; ${sessCount} session(s)
                        </div>
                        <div class="admin-action-group">
                          <span class="badge badge--oxide">${escapeHtml(getRoleDisplayLabel(u.role))}</span>
                          ${extra.map((er) => `<span class="badge">${escapeHtml(getRoleDisplayLabel(er))}</span>`).join('')}
                          <span class="badge ${u.mfa_enabled && u.mfa_enrolled ? 'badge--live' : 'badge--warn'}">${u.mfa_enabled ? (u.mfa_enrolled ? 'MFA Enrolled' : 'MFA Pending') : 'MFA Off'}</span>
                        </div>
                        <div class="admin-mobile-card__actions">
                          <a href="/admin/users?tab=directory&user=${encodeURIComponent(u.user_id)}#user-details-panel" class="btn btn--secondary">Edit User</a>
                        </div>
                      </div>`;
          })
          .join('')}
                </div>`
      }
        </section>
      `
      : `
        <section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Staff Roles &amp; Access Boundaries</h2>
              <p class="muted" style="margin:0;font-size:0.85rem;">Select any role below to see what the employee can do, what is restricted, and which modules they open.</p>
            </div>
          </div>

          <div class="role-card-grid">
            ${allRoleNames
        .map((r) => {
          const perms = rolePermissionMap[r] || [];
          const count = roleAssignedCounts[r] || 0;
          const isSelected = r === activeRoleDetail;
          return `<a href="/admin/users?tab=roles&roleDetail=${encodeURIComponent(r)}#role-detail-inspector" class="role-summary-card${isSelected ? ' is-selected' : ''}">
                  <div>
                    <strong>${escapeHtml(getRoleDisplayLabel(r))}</strong>
                    <p class="muted" style="font-size:0.8rem;margin:0.35rem 0 0;line-height:1.4;">${escapeHtml(ROLE_DESCRIPTIONS[r] || '')}</p>
                  </div>
                  <div class="admin-action-group" style="margin-top:0.4rem;">
                    <span class="badge">${count} user(s)</span>
                    <span class="badge badge--live">${perms.length} capability rule(s)</span>
                  </div>
                </a>`;
        })
        .join('')}
          </div>

          ${(() => {
        const guide = ROLE_GUIDE[activeRoleDetail] || { purpose: ROLE_DESCRIPTIONS[activeRoleDetail] || '', canDo: [], cannotDo: [], modules: [], extraPerms: '' };
        return `<div id="role-detail-inspector" class="panel panel--light" style="margin-bottom:1.35rem;">
              <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;margin-bottom:0.75rem;">
                <h3 style="margin:0;border:0;padding:0;">${escapeHtml(getRoleDisplayLabel(activeRoleDetail))}</h3>
                <span class="badge badge--oxide">${roleUsers.length} Assigned Staff Member(s)</span>
              </div>
              <p style="font-size:0.92rem;margin-bottom:0.85rem;"><strong>What This Role Is For:</strong> ${escapeHtml(guide.purpose)}</p>
              <div class="grid-2" style="margin-bottom:0.85rem;">
                <div>
                  <strong style="font-size:0.86rem;display:block;margin-bottom:0.3rem;">What the Employee Can Do</strong>
                  <ul style="margin:0;padding-left:1.15rem;font-size:0.85rem;">
                    ${guide.canDo.map((c) => `<li style="margin-bottom:0.25rem;">${escapeHtml(c)}</li>`).join('')}
                  </ul>
                </div>
                <div>
                  <strong style="font-size:0.86rem;display:block;margin-bottom:0.3rem;">What the Employee Cannot Do</strong>
                  <ul style="margin:0;padding-left:1.15rem;font-size:0.85rem;">
                    ${guide.cannotDo.map((c) => `<li style="margin-bottom:0.25rem;">${escapeHtml(c)}</li>`).join('')}
                  </ul>
                </div>
              </div>
              <p style="font-size:0.85rem;margin-bottom:0.5rem;"><strong>Available Dashboard Modules:</strong> ${guide.modules.map((m) => `<span class="badge">${escapeHtml(m)}</span>`).join(' ')}</p>
              <p style="font-size:0.85rem;margin-bottom:0.75rem;"><strong>Extra Permission Note:</strong> <span class="muted">${escapeHtml(guide.extraPerms)}</span></p>
              <div>
                <strong style="font-size:0.84rem;display:block;margin-bottom:0.3rem;">Assigned Staff Members:</strong>
                ${roleUsers.length === 0
            ? '<span class="muted" style="font-size:0.85rem;">No staff users currently assigned to this role.</span>'
            : `<div class="admin-action-group">${roleUsers.map((ru) => `<a href="/admin/users?tab=directory&user=${encodeURIComponent(ru.user_id)}#user-details-panel" class="badge">${escapeHtml(ru.full_name)}</a>`).join('')}</div>`
          }
              </div>
            </div>`;
      })()}

          <details class="admin-accordion">
            <summary>Advanced: Full Role Capability Matrix</summary>
            <p class="muted" style="font-size:0.84rem;margin-bottom:0.75rem;">Server-enforced permission matrix across all 7 staff roles. Use for technical security review.</p>
            <div class="admin-desktop-only">
              <div class="table-scroll" tabindex="0" role="region" aria-label="Full Role Permission Matrix">
                <table class="data-table matrix-table" style="font-size:0.82rem;">
                  <thead>
                    <tr>
                      <th scope="col">Capability</th>
                      ${allRoleNames.map((r) => `<th scope="col">${escapeHtml(getRoleDisplayLabel(r))}</th>`).join('')}
                    </tr>
                  </thead>
                  <tbody>
                    ${PERMISSION_META.map(
        (pm) => `<tr>
                        <th scope="row">${escapeHtml(pm.label)}<br><small class="muted"><code>${escapeHtml(pm.key)}</code></small></th>
                        ${allRoleNames
            .map((r) => {
              const granted = (rolePermissionMap[r] || []).includes(pm.key);
              return `<td class="${granted ? 'matrix-cell--yes' : 'matrix-cell--no'}" aria-label="${granted ? 'Granted' : 'Not granted'}">${granted ? '&#10003;' : '&mdash;'}</td>`;
            })
            .join('')}
                      </tr>`
      ).join('')}
                  </tbody>
                </table>
              </div>
            </div>
            <div class="admin-mobile-cards">
              ${allRoleNames
        .map(
          (r) => `<details class="admin-accordion">
                    <summary>${escapeHtml(getRoleDisplayLabel(r))} (${(rolePermissionMap[r] || []).length})</summary>
                    <div class="perm-chip-list">
                      ${(rolePermissionMap[r] || []).map((p) => `<span class="perm-chip">${escapeHtml(permLabelByKey[p] || p)}</span>`).join('')}
                    </div>
                  </details>`
        )
        .join('')}
            </div>
          </details>
        </section>
      `
    }`;
}

export function renderAdminSettingsView({
  settings,
  users,
  activeSessionsMap = {},
  rolePermissionMap = {},
  backupRuns = [],
  retentionPolicies = [],
  user,
  csrfToken,
}) {
  const canManageUsers = hasPermission(user, PERMISSIONS.MANAGE_USERS);
  const canManageSettings = hasPermission(user, PERMISSIONS.MANAGE_SETTINGS);
  const canManageBackups = hasPermission(user, PERMISSIONS.MANAGE_BACKUPS);
  const allRoleNames = Object.values(ROLES);
  const activeUsersCount = users.filter((u) => Boolean(u.active)).length;
  const activeSessionsTotal = Object.values(activeSessionsMap).reduce((sum, n) => sum + Number(n || 0), 0);

  return `
  ${canManageUsers
      ? `<section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Staff Access Summary</h2>
              <p class="muted" style="margin:0;font-size:0.85rem;">${users.length} total accounts (${activeUsersCount} active) &middot; ${activeSessionsTotal} live session(s) across ${allRoleNames.length} staff roles.</p>
            </div>
            <div class="admin-action-group">
              <a href="/admin/users" class="btn btn--primary">Open Users &amp; Roles</a>
              <a href="/admin/mfa-setup" class="btn btn--secondary">My MFA Settings</a>
            </div>
          </div>
        </section>`
      : ''
    }

  ${canManageSettings
      ? `<section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Company Contact &amp; Credential Profile</h2>
              <p class="muted" style="margin:0;font-size:0.85rem;">Shared across public headers, footers, structured schema, and procurement credentials.</p>
            </div>
          </div>
          <form method="POST" action="/admin/api/settings" class="js-ajax-form" data-success-msg="Business settings saved and applied across public templates.">
            <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
            <div class="grid-2">
              <div class="field"><label for="bs-trading">Trading Name</label><input type="text" id="bs-trading" name="trading_name" value="${escapeHtml(settings.trading_name)}" required></div>
              <div class="field"><label for="bs-legal">Legal Entity</label><input type="text" id="bs-legal" name="legal_entity" value="${escapeHtml(settings.legal_entity)}" required></div>
            </div>
            <div class="grid-2">
              <div class="field"><label for="bs-phone">Phone Display</label><input type="text" id="bs-phone" name="phone_display" value="${escapeHtml(settings.phone_display)}" required></div>
              <div class="field"><label for="bs-hours">Hours (America/Phoenix)</label><input type="text" id="bs-hours" name="hours_display" value="${escapeHtml(settings.hours_display)}" required></div>
            </div>
            <div class="grid-2">
              <div class="field"><label for="bs-addr">Office Address Reference</label><input type="text" id="bs-addr" name="address_display" value="${escapeHtml(settings.address_display)}" required></div>
              <div class="field"><label for="bs-roc">Arizona ROC Numbers</label><input type="text" id="bs-roc" name="roc_numbers" value="${escapeHtml(settings.roc_numbers)}" required></div>
            </div>
            <div class="field"><label for="bs-ins">Insurance Statement</label><input type="text" id="bs-ins" name="insurance_statement" value="${escapeHtml(settings.insurance_statement)}" required></div>
            <button type="submit" class="btn btn--primary">Save Business Settings</button>
          </form>
        </section>`
      : ''
    }

  ${canManageBackups
      ? `<section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Backups &amp; Data Export</h2>
              <p class="muted" style="margin:0;font-size:0.85rem;">Portable JSON snapshot plus checksummed full backups with SHA-256 verification and re-evaluated restore.</p>
            </div>
            <div class="admin-action-group">
              <a href="/admin/api/backup/export.json" class="btn btn--secondary">Export JSON</a>
              <button type="button" class="btn btn--primary js-action-btn" data-url="/admin/api/backups/create">Create Verified Backup</button>
            </div>
          </div>
          ${backupRuns.length > 0
        ? `<div class="table-scroll" tabindex="0" role="region" aria-label="Full Backup Runs">
                   <table class="data-table" style="font-size:0.85rem;">
                     <thead><tr><th scope="col">Backup ID / Reason</th><th scope="col">Created (Phoenix)</th><th scope="col">Files</th><th scope="col">Status</th><th scope="col">Actions</th></tr></thead>
                     <tbody>
                       ${backupRuns
          .map(
            (b) => `<tr>
                             <td><code>${escapeHtml(b.backup_id.slice(0, 8))}</code> (${escapeHtml(b.reason)})</td>
                             <td>${escapeHtml(formatPhoenixDateTime(b.created_at, false))}</td>
                             <td>${escapeHtml(b.file_count)}</td>
                             <td><span class="badge ${b.status === 'verified' ? 'badge--live' : b.status === 'corrupted' ? 'badge--err' : 'badge--warn'}">${escapeHtml(b.status)}</span></td>
                             <td>
                               <div class="admin-action-group">
                                 <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/backups/${escapeHtml(b.backup_id)}/verify">Verify SHA-256</button>
                                 <button type="button" class="btn btn--secondary btn--compact js-action-btn" data-url="/admin/api/backups/${escapeHtml(b.backup_id)}/restore" data-confirm-title="Restore From Backup Snapshot?" data-confirm="Restore content and media associations from backup ${escapeHtml(b.backup_id.slice(0, 8))}? Intervening inquiries and deletion records will be preserved and dates re-evaluated.">Restore</button>
                               </div>
                             </td>
                           </tr>`
          )
          .join('')}
                     </tbody>
                   </table>
                 </div>`
        : '<div class="admin-empty-state">No full filesystem backups recorded yet.</div>'
      }
        </section>`
      : ''
    }

  ${canManageBackups
      ? `<section class="admin-card">
          <div class="admin-card__header">
            <div>
              <h2>Data Retention Schedule</h2>
              <p class="muted" style="margin:0;font-size:0.85rem;">Policies marked <strong>Pending Client Approval</strong> never auto-delete data until approved.</p>
            </div>
            <button type="button" class="btn btn--secondary js-action-btn" data-url="/admin/api/retention/run" data-confirm-title="Run Retention Purge Sweep?" data-confirm="Execute deletion across explicitly approved retention categories only? Unapproved or legal-hold records remain protected.">Run Retention Sweep</button>
          </div>
          <div class="table-scroll" tabindex="0" role="region" aria-label="Retention Policies Table">
            <table class="data-table" style="font-size:0.84rem;">
              <thead><tr><th scope="col">Data Category</th><th scope="col">Approval Status</th><th scope="col">Retention Period &amp; Action</th><th scope="col">Last Sweep</th></tr></thead>
              <tbody>
                ${retentionPolicies
        .map(
          (p) => `<tr>
                      <td><strong>${escapeHtml(p.label)}</strong><br><small class="muted">${escapeHtml(p.prd_reference)}</small></td>
                      <td><span class="badge ${p.approved_by_client ? 'badge--live' : 'badge--warn'}">${p.approved_by_client ? `Approved (${escapeHtml(p.approved_by_user || 'Client')})` : 'Pending Client Approval'}</span></td>
                      <td>
                        <form method="POST" action="/admin/api/retention/policies/${escapeHtml(p.policy_key)}" class="js-ajax-form admin-action-group" data-confirm-title="Approve Retention Schedule?" data-confirm="Save and approve automated retention rule for ${escapeHtml(p.label)}?">
                          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                          <input type="hidden" name="approved" value="true">
                          <input type="number" name="retention_days" min="1" max="3650" value="${p.retention_days ?? ''}" placeholder="Days (TBD)" aria-label="Retention days for ${escapeHtml(p.policy_key)}" style="width:96px;" required>
                          <button type="submit" class="btn btn--secondary btn--compact">Approve &amp; Save</button>
                        </form>
                      </td>
                      <td>${p.last_run_at ? escapeHtml(formatPhoenixDateTime(p.last_run_at, false)) : 'Never run'}</td>
                    </tr>`
        )
        .join('')}
              </tbody>
            </table>
          </div>
        </section>`
      : ''
    }

  <details class="admin-accordion">
    <summary>Role Access Overview (${allRoleNames.length} Roles)</summary>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Role Permission Matrix">
      <table class="data-table" style="font-size:0.83rem;">
        <thead><tr><th scope="col">Role</th><th scope="col">Granted Server-Side Permissions</th></tr></thead>
        <tbody>
          ${allRoleNames
      .map(
        (r) => `<tr><td><strong>${escapeHtml(getRoleDisplayLabel(r))}</strong></td><td><div class="perm-chip-list">${(rolePermissionMap[r] || []).map((p) => `<span class="perm-chip">${escapeHtml(p)}</span>`).join('')}</div></td></tr>`
      )
      .join('')}
        </tbody>
      </table>
    </div>
  </details>`;
}
