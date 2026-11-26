import { ENV, isAdminMfaRequired, ROLES } from '../config.js';
import { escapeHtml } from '../lib/sanitize.js';
import { formatPhoenixDateTime, utcIsoToPhoenixInput } from '../lib/time.js';
import { hasPermission, PERMISSIONS } from '../services/auth.js';

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
      ${
        meta.page > 1
          ? `<a href="${escapeHtml(makeHref(meta.page - 1))}" class="btn btn--secondary" style="min-height:38px;padding:0.3rem 0.75rem;">Previous</a>`
          : '<span class="btn btn--secondary" aria-disabled="true" style="min-height:38px;padding:0.3rem 0.75rem;opacity:0.45;pointer-events:none;">Previous</span>'
      }
      ${
        meta.page < meta.totalPages
          ? `<a href="${escapeHtml(makeHref(meta.page + 1))}" class="btn btn--secondary" style="min-height:38px;padding:0.3rem 0.75rem;">Next</a>`
          : '<span class="btn btn--secondary" aria-disabled="true" style="min-height:38px;padding:0.3rem 0.75rem;opacity:0.45;pointer-events:none;">Next</span>'
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
  <link rel="stylesheet" href="/css/tokens.css">
  <link rel="stylesheet" href="/css/main.css">
  <link rel="stylesheet" href="/css/admin.css">
</head>
<body>
  <main id="main-content" class="section">
    <div class="container" style="max-width:34rem;">
      <span class="eyebrow">Protected Operations Workspace</span>
      <h1>Staff Dashboard Sign In</h1>
      <p class="muted">${
        mfaRequired
          ? 'Individual company identity and 6-digit MFA verification required. No shared administrator accounts.'
          : 'Individual company identity required. Multi-factor authentication is temporarily disabled (Email + Password mode).'
      }</p>

      ${
        !mfaRequired
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
        ${
          mfaRequired
            ? `<div class="field">
                <label for="login-totp">6-Digit Authenticator MFA Code ${requireMfa ? '(Required)' : ''}</label>
                <span class="hint">Time-based TOTP authenticator code.</span>
                <input type="text" id="login-totp" name="totp_code" inputmode="numeric" pattern="\\d{6}" maxlength="6" autocomplete="one-time-code" required>
              </div>`
            : ''
        }
        <button type="submit" class="btn btn--primary" style="width:100%;">${mfaRequired ? 'Sign in with MFA' : 'Sign in with Email & Password'}</button>
      </form>

      ${
        mfaRequired
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
  <link rel="stylesheet" href="/css/tokens.css">
  <link rel="stylesheet" href="/css/main.css">
  <link rel="stylesheet" href="/css/admin.css">
</head>
<body>
  <main id="main-content" class="section">
    <div class="container" style="max-width:40rem;">
      <span class="eyebrow">Authorized Multi-Factor Authentication</span>
      <h1>Google Authenticator Setup &amp; Recovery</h1>
      <p class="muted">Connecting or rotating MFA requires identity verification and live 6-digit TOTP confirmation. Unauthorized users cannot initiate setup.</p>

      ${error ? `<div class="status-banner status-banner--error" role="alert">${escapeHtml(error)}</div>` : ''}
      ${info ? `<div class="status-banner status-banner--success" role="status">${escapeHtml(info)}</div>` : ''}

      ${
        stage === 'verify_identity'
          ? `<form method="POST" action="/admin/mfa-setup" class="admin-card">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <input type="hidden" name="step" value="begin">
              <h2 style="font-size:1.25rem;">Step 1: Verify Identity &amp; Authorization</h2>
              <div class="field">
                <label for="mfa-email">Staff Email</label>
                <input type="email" id="mfa-email" name="email" value="${escapeHtml(email)}" required autocomplete="username" autocorrect="off" autocapitalize="none" spellcheck="false">
              </div>
              <div class="field">
                <label for="mfa-pass">Account Password</label>
                <input type="password" id="mfa-pass" name="password" required autocomplete="current-password">
              </div>

              ${
                signedInUser
                  ? `<div class="field">
                      <label for="mfa-current-totp">Current 6-Digit Authenticator Code (if already enrolled)</label>
                      <span class="hint">Confirm your current authenticator device before rotating to a new QR code.</span>
                      <input type="text" id="mfa-current-totp" name="current_totp" inputmode="numeric" pattern="\\d{6}" maxlength="6" autocomplete="one-time-code">
                    </div>`
                  : setupToken
                    ? `<input type="hidden" name="setup_token" value="${escapeHtml(setupToken)}">
                       <p class="muted" style="font-size:0.86rem;">Authorization mode: <strong>${escapeHtml(tokenPurpose === 'recovery' ? 'Administrator Recovery Token' : 'First-Time Enrollment Token')}</strong></p>`
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

export function renderAdminShell({ title, user, csrfToken, currentSection, bodyHtml, nonce = '', flash = '' }) {
  const nav = [
    { id: 'overview', href: '/admin/', label: 'Overview', show: true },
    { id: 'pages', href: '/admin/pages', label: 'Website & Pages', show: hasPermission(user, PERMISSIONS.EDIT_CONTENT) || hasPermission(user, PERMISSIONS.MANAGE_SETTINGS) },
    { id: 'campaigns', href: '/admin/campaigns', label: 'Seasonal Campaigns', show: hasPermission(user, PERMISSIONS.MANAGE_CAMPAIGNS) },
    { id: 'projects', href: '/admin/projects', label: 'Projects & Media', show: hasPermission(user, PERMISSIONS.EDIT_PROJECTS) },
    { id: 'jobs', href: '/admin/jobs', label: 'Jobs & Applications', show: hasPermission(user, PERMISSIONS.MANAGE_VACANCIES) || hasPermission(user, PERMISSIONS.REVIEW_APPLICATIONS) },
    { id: 'leads', href: '/admin/leads', label: 'Leads & CRM Queue', show: hasPermission(user, PERMISSIONS.MANAGE_LEADS_CRM) },
    { id: 'reviews', href: '/admin/reviews', label: 'Reviews & Activity', show: hasPermission(user, PERMISSIONS.PUBLISH_CONTENT) || hasPermission(user, PERMISSIONS.VIEW_AUDIT) },
    { id: 'analytics', href: '/admin/analytics', label: 'Analytics & Reports', show: hasPermission(user, PERMISSIONS.VIEW_ANALYTICS) || hasPermission(user, PERMISSIONS.MANAGE_LEADS_CRM) },
    { id: 'settings', href: '/admin/settings', label: 'Users, Settings & Backups', show: hasPermission(user, PERMISSIONS.MANAGE_USERS) || hasPermission(user, PERMISSIONS.MANAGE_SETTINGS) },
  ].filter((n) => n.show);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} | Staff Dashboard | Service Maintenance</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/svg+xml" href="/assets/brand-mark.svg">
  <link rel="stylesheet" href="/css/tokens.css">
  <link rel="stylesheet" href="/css/main.css">
  <link rel="stylesheet" href="/css/admin.css">
</head>
<body data-csrf="${escapeHtml(csrfToken)}">
  <a href="#admin-main" class="skip-link">Skip to dashboard content</a>
  <div class="admin-shell">
    <aside class="admin-sidebar">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;">
        <div>
          <div class="admin-sidebar__brand">Service Maintenance</div>
          <div class="admin-sidebar__role">
            <strong>${escapeHtml(user.full_name)}</strong><br>
            <span>${escapeHtml(user.role)}</span>
          </div>
        </div>
        <button type="button" id="admin-nav-toggle" class="btn btn--ghost-light admin-mobile-toggle" aria-expanded="false" aria-controls="admin-nav-panel">Menu</button>
      </div>
      <nav id="admin-nav-panel" class="admin-nav-panel" aria-label="Staff dashboard navigation">
        <ul class="admin-nav">
          ${nav
            .map(
              (n) =>
                `<li><a href="${escapeHtml(n.href)}"${currentSection === n.id ? ' aria-current="page"' : ''}>${escapeHtml(n.label)}</a></li>`
            )
            .join('')}
        </ul>
      </nav>
      <div style="margin-top:2rem;padding-top:1rem;border-top:1px solid rgba(244,240,232,0.2);display:flex;flex-direction:column;gap:0.5rem;">
        <a href="/" style="color:#EAE4D9;font-size:0.88rem;min-height:44px;display:inline-flex;align-items:center;">View Public Site &rarr;</a>
        <form method="POST" action="/admin/logout">
          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
          <button type="submit" class="btn btn--ghost-light" style="width:100%;font-size:0.85rem;">Sign out</button>
        </form>
      </div>
    </aside>

    <main id="admin-main" class="admin-main" tabindex="-1">
      <div class="admin-topbar">
        <h1 style="margin:0;font-size:clamp(1.4rem,2.4vw,2rem);">${escapeHtml(title)}</h1>
        <span class="muted" style="font-size:0.85rem;">Business Timezone: America/Phoenix &middot; Snapshot ${escapeHtml(formatPhoenixDateTime(new Date(), false))}</span>
      </div>
      <div id="admin-toast-region" role="region" aria-label="Notifications">
        <div id="admin-inline-alert" class="admin-inline-alert" hidden tabindex="-1" role="status" aria-live="polite">
          <span id="admin-inline-alert-text"></span>
          <button type="button" id="admin-inline-alert-close" class="btn btn--secondary" style="min-height:36px;padding:0.2rem 0.65rem;font-size:0.8rem;" aria-label="Dismiss notification">Dismiss</button>
        </div>
      </div>
      ${
        !isAdminMfaRequired()
          ? `<div class="status-banner status-banner--warning" role="status"><strong>Temporary Auth Deviation:</strong> Staff MFA enforcement is currently disabled (<code>ADMIN_MFA_REQUIRED=false</code>). Re-enable <code>ADMIN_MFA_REQUIRED=true</code> in environment configuration for PRD compliance.</div>`
          : ''
      }
      ${flash ? `<div class="status-banner status-banner--success" role="status">${escapeHtml(flash)}</div>` : ''}
      ${bodyHtml}
    </main>
  </div>

  <dialog id="admin-confirm-dialog" aria-labelledby="admin-confirm-title">
    <h2 id="admin-confirm-title" style="margin-top:0;">Confirm Action</h2>
    <p id="admin-confirm-message" style="margin-bottom:0.75rem;"></p>
    <div id="admin-confirm-details" class="panel panel--light" style="margin-bottom:1rem;font-size:0.88rem;" hidden></div>
    <div style="display:flex;justify-content:flex-end;gap:0.65rem;flex-wrap:wrap;">
      <button type="button" id="admin-confirm-cancel" class="btn btn--secondary" autofocus>Cancel</button>
      <button type="button" id="admin-confirm-proceed" class="btn btn--primary">Confirm &amp; Proceed</button>
    </div>
  </dialog>

  <div id="admin-announcer" aria-live="polite" class="visually-hidden"></div>
  <script nonce="${escapeHtml(nonce)}" src="/js/admin.js" defer></script>
</body>
</html>`;
}

export function renderAdminOverview({ user, stats, schedulerHealth, recentAudit, pendingReviews }) {
  return `
  <div class="kpi-grid">
    ${
      stats.showContent
        ? `<div class="kpi-card"><span class="kpi-card__num">${stats.livePages}</span><span class="kpi-card__label">Live Public Pages</span></div>
           <div class="kpi-card"><span class="kpi-card__num">${stats.inReviewCount}</span><span class="kpi-card__label">Items In Review</span></div>`
        : ''
    }
    ${
      stats.showCampaigns
        ? `<div class="kpi-card"><span class="kpi-card__num">${stats.liveCampaigns}</span><span class="kpi-card__label">Live Seasonal Campaigns</span></div>`
        : ''
    }
    ${
      stats.showProjects
        ? `<div class="kpi-card"><span class="kpi-card__num">${stats.liveProjects}</span><span class="kpi-card__label">Published Projects</span></div>`
        : ''
    }
    ${
      stats.showHiring
        ? `<div class="kpi-card"><span class="kpi-card__num">${stats.openJobs}</span><span class="kpi-card__label">Open Vacancies</span></div>
           <div class="kpi-card"><span class="kpi-card__num">${stats.unassignedApps}</span><span class="kpi-card__label">Applications Awaiting Review</span></div>`
        : ''
    }
    ${
      stats.showLeads
        ? `<div class="kpi-card"><span class="kpi-card__num">${stats.newInquiries}</span><span class="kpi-card__label">Total Inquiries</span></div>
           <div class="kpi-card"><span class="kpi-card__num">${stats.crmFailed}</span><span class="kpi-card__label">CRM Delivery Failures</span></div>`
        : ''
    }
  </div>

  <div class="grid-2">
    <section class="admin-card">
      <h2>Scheduler &amp; Delivery Health</h2>
      <p><strong>Scheduler Status:</strong> <span class="badge ${schedulerHealth?.status === 'healthy' ? 'badge--live' : 'badge--warn'}">${escapeHtml(schedulerHealth?.status || 'ready')}</span></p>
      <p><strong>Last Successful Sweep:</strong> ${escapeHtml(formatPhoenixDateTime(schedulerHealth?.last_success_at))}</p>
      <p class="muted" style="font-size:0.86rem;margin-bottom:0;">Note: Reporting widgets reflect stored database state as of page render (not real-time streaming).</p>
    </section>

    <section class="admin-card">
      <h2>Role Scope &amp; Boundaries</h2>
      <p>Signed in as <strong>${escapeHtml(user.role)}</strong>.</p>
      <ul style="font-size:0.9rem;">
        <li>All permissions are enforced server-side on every route, record, export, and download.</li>
        <li>${stats.showHiring ? 'You have authorized access to assigned recruiting records.' : 'Hiring records and applicant resumes are isolated and restricted from your role.'}</li>
      </ul>
    </section>
  </div>

  ${
    pendingReviews.length > 0
      ? `<section class="admin-card">
          <h2>Items Awaiting Review</h2>
          <div class="table-scroll" tabindex="0" role="region" aria-label="Items Awaiting Review">
            <table class="data-table">
              <thead><tr><th>Type</th><th>Title</th><th>Owner</th><th>Updated</th></tr></thead>
              <tbody>
                ${pendingReviews
                  .map(
                    (r) => `<tr><td>${escapeHtml(r.type)}</td><td><a href="${escapeHtml(r.href)}">${escapeHtml(r.title)}</a></td><td>${escapeHtml(r.owner)}</td><td>${escapeHtml(formatPhoenixDateTime(r.updated_at, false))}</td></tr>`
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </section>`
      : ''
  }

  ${
    recentAudit.length > 0
      ? `<section class="admin-card">
          <h2>Recent Non-Hiring Activity</h2>
          <div class="table-scroll" tabindex="0" role="region" aria-label="Recent Non-Hiring Activity">
            <table class="data-table">
              <thead><tr><th>Time (Phoenix)</th><th>Actor</th><th>Domain</th><th>Action</th><th>Object</th></tr></thead>
              <tbody>
                ${recentAudit
                  .map(
                    (a) => `<tr><td>${escapeHtml(formatPhoenixDateTime(a.created_at, false))}</td><td>${escapeHtml(a.actor_name)}</td><td>${escapeHtml(a.domain)}</td><td>${escapeHtml(a.action)}</td><td><code>${escapeHtml(a.object_type)}:${escapeHtml(a.object_id.slice(0, 12))}</code></td></tr>`
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </section>`
      : ''
  }`;
}

export function renderAdminPagesView({
  pages,
  pagesMeta,
  filters = {},
  selectedPage,
  revisions,
  revCompare,
  articles = [],
  selectedArticle,
  claims,
  selectedClaim,
  redirects,
  user,
  csrfToken,
}) {
  const canPublish = hasPermission(user, PERMISSIONS.PUBLISH_CONTENT);
  const canEdit = hasPermission(user, PERMISSIONS.EDIT_CONTENT);

  return `
  <section class="admin-card">
    <form method="GET" action="/admin/pages" style="display:flex;flex-wrap:wrap;gap:0.65rem;align-items:flex-end;">
      <div class="field" style="margin:0;flex:1;min-width:13rem;">
        <label for="cms-q">Search pages, articles &amp; claims</label>
        <input id="cms-q" name="q" type="search" value="${escapeHtml(filters.q || '')}" placeholder="Search slug, title, text...">
      </div>
      <div class="field" style="margin:0;min-width:11rem;">
        <label for="cms-state">Page State</label>
        <select id="cms-state" name="state">
          <option value="">All states</option>
          ${['Draft', 'In review', 'Approved', 'Live', 'Unpublished']
            .map((st) => `<option value="${st}"${filters.state === st ? ' selected' : ''}>${st}</option>`)
            .join('')}
        </select>
      </div>
      <button type="submit" class="btn btn--secondary">Filter</button>
      ${filters.q || filters.state ? '<a href="/admin/pages" class="btn btn--secondary">Clear</a>' : ''}
    </form>
  </section>

  <div class="admin-split">
    <section class="admin-card">
      <h2>Website Pages</h2>
      ${
        pages.length === 0
          ? '<p class="muted">No pages match your search/filter.</p>'
          : `<div class="table-scroll" tabindex="0" role="region" aria-label="Website Pages Table">
              <table class="data-table">
                <thead><tr><th>Route</th><th>Editorial</th><th>Public State</th><th>Rev</th></tr></thead>
                <tbody>
                  ${pages
                    .map(
                      (p) => `<tr>
                        <td><a href="/admin/pages?id=${encodeURIComponent(p.page_id)}">${escapeHtml(p.slug)}</a></td>
                        <td><span class="badge">${escapeHtml(p.editorial_state)}</span></td>
                        <td><span class="badge ${p.activation_state === 'Live' ? 'badge--live' : 'badge--warn'}">${escapeHtml(p.activation_state)}</span></td>
                        <td>v${escapeHtml(p.current_revision)} (pub: ${p.published_revision ? `v${p.published_revision}` : 'none'})</td>
                      </tr>`
                    )
                    .join('')}
                </tbody>
              </table>
            </div>`
      }
      ${renderPaginationNav('/admin/pages', pagesMeta, { q: filters.q, state: filters.state, id: selectedPage?.page_id })}
    </section>

    ${
      selectedPage && revisions.length > 0
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
            return `<section class="admin-card">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap;">
                <h2 style="margin:0;">Edit: ${escapeHtml(selectedPage.slug)}</h2>
                <span id="autosave-status" class="autosave-pill">Idle</span>
              </div>
              <p class="muted" style="font-size:0.86rem;">Current revision: v${escapeHtml(selectedPage.current_revision)} | Published revision: ${selectedPage.published_revision ? `v${selectedPage.published_revision}` : 'Unpublished'}</p>

              <form id="page-editor-form" data-autosave-url="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/draft">
                <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                <input type="hidden" name="expected_revision" value="${escapeHtml(selectedPage.current_revision)}">

                <div class="field">
                  <label for="pg-title">Page Title</label>
                  <input type="text" id="pg-title" name="title" value="${escapeHtml(latest.title)}" required ${canEdit ? '' : 'disabled'}>
                </div>
                <div class="field">
                  <label for="pg-meta-title">SEO Meta Title</label>
                  <input type="text" id="pg-meta-title" name="meta_title" value="${escapeHtml(latest.meta_title)}" required ${canEdit ? '' : 'disabled'}>
                </div>
                <div class="field">
                  <label for="pg-meta-desc">SEO Meta Description</label>
                  <textarea id="pg-meta-desc" name="meta_description" style="min-height:4.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(latest.meta_description)}</textarea>
                </div>
                <div class="field">
                  <label for="pg-headline">Hero Headline</label>
                  <input type="text" id="pg-headline" name="hero_headline" value="${escapeHtml(latest.hero_headline)}" required ${canEdit ? '' : 'disabled'}>
                </div>
                <div class="field">
                  <label for="pg-summary">Hero Summary</label>
                  <textarea id="pg-summary" name="hero_summary" style="min-height:4.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(latest.hero_summary)}</textarea>
                </div>
                <div class="field">
                  <label for="pg-cta">Primary CTA Label</label>
                  <input type="text" id="pg-cta" name="cta_label" value="${escapeHtml(latest.cta_label)}" ${canEdit ? '' : 'disabled'}>
                </div>
                <div class="field">
                  <label for="pg-body">Body Content (Sanitized Rich HTML)</label>
                  <textarea id="pg-body" name="body_html" style="min-height:10rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(latest.body_html)}</textarea>
                </div>

                <div style="display:flex;flex-wrap:wrap;gap:0.6rem;">
                  ${
                    canEdit
                      ? `<button type="button" class="btn btn--secondary" id="btn-save-draft">Save Draft</button>
                         <button type="button" class="btn btn--secondary" id="btn-submit-review" data-url="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/submit-review">Submit for Review</button>`
                      : ''
                  }
                  <a href="/admin/preview?path=${encodeURIComponent(selectedPage.slug)}&rev=${encodeURIComponent(latest.revision_number)}&viewport=desktop" target="_blank" class="btn btn--secondary">Preview Desktop</a>
                  <a href="/admin/preview?path=${encodeURIComponent(selectedPage.slug)}&rev=${encodeURIComponent(latest.revision_number)}&viewport=mobile" target="_blank" class="btn btn--secondary">Preview Mobile (390px)</a>
                  ${
                    canPublish
                      ? `<button type="button" class="btn btn--primary" id="btn-publish-page" data-url="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/publish">Approve &amp; Publish Live</button>`
                      : ''
                  }
                </div>
              </form>

              <h3 style="margin-top:1.75rem;">Revision Comparison</h3>
              <form method="GET" action="/admin/pages" style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:flex-end;margin-bottom:0.75rem;">
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
                <button type="submit" class="btn btn--secondary" style="min-height:40px;">Compare Revisions</button>
              </form>
              ${
                revCompare
                  ? `<div class="table-scroll" tabindex="0" role="region" aria-label="Revision Comparison Table">
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
                                <td>${escapeHtml(a.slice(0, 140))}${a.length > 140 ? '...' : ''}</td>
                                <td>${escapeHtml(b.slice(0, 140))}${b.length > 140 ? '...' : ''}</td>
                                <td><span class="badge ${changed ? 'badge--warn' : 'badge--live'}">${changed ? 'Changed' : 'Same'}</span></td>
                              </tr>`;
                            })
                            .join('')}
                        </tbody>
                      </table>
                    </div>`
                  : ''
              }

              <h3 style="margin-top:1.75rem;">Revision History &amp; Safe Restore</h3>
              <div class="table-scroll" tabindex="0" role="region" aria-label="Revision History Table">
                <table class="data-table" style="font-size:0.85rem;">
                  <thead><tr><th>Rev</th><th>State</th><th>Created</th><th>Action</th></tr></thead>
                  <tbody>
                    ${revisions
                      .map(
                        (r) => `<tr>
                          <td>v${escapeHtml(r.revision_number)}</td>
                          <td>${escapeHtml(r.editorial_state)}</td>
                          <td>${escapeHtml(formatPhoenixDateTime(r.created_at, false))}</td>
                          <td>${
                            canPublish
                              ? `<button type="button" class="btn btn--secondary js-restore-rev" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/pages/${escapeHtml(selectedPage.page_id)}/restore" data-rev="${escapeHtml(r.revision_number)}">Restore to Draft</button>`
                              : 'View only'
                          }</td>
                        </tr>`
                      )
                      .join('')}
                  </tbody>
                </table>
              </div>
            </section>`;
          })()
        : '<section class="admin-card"><p>Select a page from the table to edit or preview revisions.</p></section>'
    }
  </div>

  <div class="admin-split">
    <section class="admin-card">
      <h2>Insights Articles</h2>
      <div class="table-scroll" tabindex="0" role="region" aria-label="Articles Table">
        <table class="data-table" style="font-size:0.84rem;">
          <thead><tr><th>Title &amp; Slug</th><th>State</th><th>Actions</th></tr></thead>
          <tbody>
            ${
              articles.length === 0
                ? '<tr><td colspan="3" class="muted">No articles yet. Create one below.</td></tr>'
                : articles
                    .map(
                      (a) => `<tr>
                        <td><a href="/admin/pages?article=${encodeURIComponent(a.article_id)}">${escapeHtml(a.title)}</a><br><small class="muted"><code>/insights/${escapeHtml(a.slug)}/</code> &middot; ${escapeHtml(a.buyer_target)}</small></td>
                        <td><span class="badge">${escapeHtml(a.editorial_state)}</span> <span class="badge ${a.activation_state === 'Live' ? 'badge--live' : 'badge--warn'}">${escapeHtml(a.activation_state)}</span></td>
                        <td style="display:flex;gap:0.35rem;flex-wrap:wrap;">
                          ${canEdit && a.editorial_state === 'Draft' ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:34px;padding:0.2rem 0.5rem;font-size:0.78rem;" data-url="/admin/api/articles/${escapeHtml(a.article_id)}/submit-review">Submit Review</button>` : ''}
                          ${canPublish && a.activation_state !== 'Live' ? `<button type="button" class="btn btn--primary js-action-btn" style="min-height:34px;padding:0.2rem 0.5rem;font-size:0.78rem;" data-url="/admin/api/articles/${escapeHtml(a.article_id)}/publish">Publish</button>` : ''}
                          ${canPublish && a.activation_state === 'Live' ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:34px;padding:0.2rem 0.5rem;font-size:0.78rem;" data-url="/admin/api/articles/${escapeHtml(a.article_id)}/archive">Archive</button>` : ''}
                        </td>
                      </tr>`
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>

      ${
        canEdit
          ? `<form method="POST" action="${selectedArticle ? `/admin/api/articles/${escapeHtml(selectedArticle.article_id)}` : '/admin/api/articles'}" class="js-ajax-form" style="margin-top:1rem;">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <h3 style="margin:0 0 0.6rem;">${selectedArticle ? `Edit Article: ${escapeHtml(selectedArticle.title)}` : 'Create New Article Draft'}</h3>
              <div class="grid-2">
                <div class="field"><label for="art-title">Title</label><input id="art-title" name="title" value="${escapeHtml(selectedArticle?.title || '')}" required></div>
                ${
                  selectedArticle
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
              <div style="display:flex;gap:0.5rem;">
                <button type="submit" class="btn btn--primary">${selectedArticle ? 'Save Article Revision' : 'Create Article Draft'}</button>
                ${selectedArticle ? '<a href="/admin/pages" class="btn btn--secondary">New Article</a>' : ''}
              </div>
            </form>`
          : ''
      }
    </section>

    <section class="admin-card">
      <h2>Fact, Claim &amp; Testimonial Evidence Register</h2>
      <div class="table-scroll" tabindex="0" role="region" aria-label="Claims and Testimonials Table">
        <table class="data-table" style="font-size:0.84rem;">
          <thead><tr><th>Title &amp; Wording</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            ${claims
              .map(
                (c) => `<tr>
                  <td><a href="/admin/pages?claim=${encodeURIComponent(c.claim_id)}"><strong>${escapeHtml(c.title)}</strong></a><br><span class="muted">${escapeHtml(c.exact_text)}</span><br><small class="muted">${escapeHtml(c.claim_type)} &middot; Source: ${escapeHtml(c.evidence_source)}</small></td>
                  <td><span class="badge ${c.status === 'withdrawn' ? 'badge--err' : c.status === 'established company fact' || c.status === 'approved for publication' ? 'badge--live' : 'badge--warn'}">${escapeHtml(c.status)}</span></td>
                  <td style="display:flex;gap:0.35rem;flex-wrap:wrap;">
                    ${canPublish && c.status !== 'approved for publication' && c.status !== 'established company fact' ? `<button type="button" class="btn btn--primary js-action-btn" style="min-height:34px;padding:0.2rem 0.5rem;font-size:0.78rem;" data-url="/admin/api/claims/${escapeHtml(c.claim_id)}/approve">Approve</button>` : ''}
                    ${canPublish && c.status !== 'withdrawn' ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:34px;padding:0.2rem 0.5rem;font-size:0.78rem;" data-url="/admin/api/claims/${escapeHtml(c.claim_id)}/withdraw">Withdraw</button>` : ''}
                  </td>
                </tr>`
              )
              .join('')}
          </tbody>
        </table>
      </div>

      ${
        canEdit
          ? `<form method="POST" action="${selectedClaim ? `/admin/api/claims/${escapeHtml(selectedClaim.claim_id)}` : '/admin/api/claims'}" class="js-ajax-form" style="margin-top:1rem;">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <h3 style="margin:0 0 0.6rem;">${selectedClaim ? `Edit Claim: ${escapeHtml(selectedClaim.title)}` : 'Add Fact / Testimonial Record'}</h3>
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
              <div style="display:flex;gap:0.5rem;">
                <button type="submit" class="btn btn--secondary">${selectedClaim ? 'Save Claim Wording' : 'Add Claim for Review'}</button>
                ${selectedClaim ? '<a href="/admin/pages" class="btn btn--secondary">Cancel Edit</a>' : ''}
              </div>
            </form>`
          : ''
      }
    </section>
  </div>

  <section class="admin-card">
    <h2>URL Redirects (Loop/Chain Validated)</h2>
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
    ${
      canEdit
        ? `<form method="POST" action="/admin/api/redirects" class="js-ajax-form" style="margin-top:1rem;display:flex;flex-wrap:wrap;gap:0.5rem;align-items:flex-end;">
            <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
            <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="rd-old">Old path</label><input id="rd-old" name="old_path" placeholder="/old-page" required></div>
            <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="rd-dest">Destination</label><input id="rd-dest" name="destination_path" placeholder="/services/" required></div>
            <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="rd-reason">Reason</label><input id="rd-reason" name="reason" required></div>
            <button type="submit" class="btn btn--secondary">Add 301 Redirect</button>
          </form>`
        : ''
    }
  </section>`;
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
      <a href="/admin/campaigns?view=calendar&month=${encodeURIComponent(fmtYm(prevDate))}" class="btn btn--secondary" style="min-height:36px;padding:0.25rem 0.65rem;">&larr; ${escapeHtml(fmtYm(prevDate))}</a>
      <a href="/admin/campaigns?view=calendar&month=${encodeURIComponent(fmtYm(nextDate))}" class="btn btn--secondary" style="min-height:36px;padding:0.25rem 0.65rem;">${escapeHtml(fmtYm(nextDate))} &rarr;</a>
    </div>
  </div>
  <div class="cal-grid" role="region" aria-label="Monthly Campaign Calendar">
    <div class="cal-head">Sun</div><div class="cal-head">Mon</div><div class="cal-head">Tue</div><div class="cal-head">Wed</div><div class="cal-head">Thu</div><div class="cal-head">Fri</div><div class="cal-head">Sat</div>
    ${cells.join('')}
  </div>
  <h3 style="margin-top:1.25rem;">Accessible Calendar Schedule List (${escapeHtml(monthParam)})</h3>
  ${
    monthScheduleSummary.length === 0
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
    <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;">
      <div>
        <h2 style="margin:0;">Seasonal Website Campaigns &amp; Highlights</h2>
        <p class="muted" style="margin:0;font-size:0.88rem;">Website placements only (Notice Strip, Homepage Feature, Contextual Service Module). All schedule times are in <strong>America/Phoenix</strong>.</p>
      </div>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
        <a href="/admin/campaigns?view=list" class="btn ${viewMode === 'list' ? 'btn--primary' : 'btn--secondary'}">Accessible List View</a>
        <a href="/admin/campaigns?view=calendar&month=${encodeURIComponent(monthParam)}" class="btn ${viewMode === 'calendar' ? 'btn--primary' : 'btn--secondary'}">Phoenix Calendar View</a>
        <button type="button" class="btn btn--secondary js-action-btn" data-url="/admin/api/campaigns/run-scheduler">Run Scheduler Sweep Now</button>
      </div>
    </div>

    <div class="panel panel--light" style="margin-top:1rem;">
      <form method="GET" action="/admin/preview" target="_blank" style="display:flex;flex-wrap:wrap;gap:0.75rem;align-items:flex-end;">
        <div class="field" style="margin:0;"><label for="prev-path">Target Page</label>
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
        <button type="submit" class="btn btn--secondary">Preview As Of Future Phoenix Time</button>
      </form>
    </div>

    <form method="GET" action="/admin/campaigns" style="display:flex;flex-wrap:wrap;gap:0.65rem;align-items:flex-end;margin-top:1rem;">
      <input type="hidden" name="view" value="${escapeHtml(viewMode)}">
      <div class="field" style="margin:0;flex:1;min-width:12rem;"><label for="cp-q">Search campaigns</label><input id="cp-q" name="q" type="search" value="${escapeHtml(filters.q || '')}"></div>
      <div class="field" style="margin:0;"><label for="cp-fslot">Slot</label>
        <select id="cp-fslot" name="slot">
          <option value="">All slots</option>
          <option value="homepage_feature"${filters.slot === 'homepage_feature' ? ' selected' : ''}>homepage_feature</option>
          <option value="notice_strip"${filters.slot === 'notice_strip' ? ' selected' : ''}>notice_strip</option>
          <option value="service_contextual"${filters.slot === 'service_contextual' ? ' selected' : ''}>service_contextual</option>
        </select>
      </div>
      <div class="field" style="margin:0;"><label for="cp-fstate">State</label>
        <select id="cp-fstate" name="state">
          <option value="">All states</option>
          ${['Unpublished', 'Scheduled', 'Live', 'Paused', 'Ended', 'Archived']
            .map((st) => `<option value="${st}"${filters.state === st ? ' selected' : ''}>${st}</option>`)
            .join('')}
        </select>
      </div>
      <button type="submit" class="btn btn--secondary">Filter</button>
      ${filters.q || filters.slot || filters.state ? '<a href="/admin/campaigns" class="btn btn--secondary">Clear</a>' : ''}
    </form>

    ${
      viewMode === 'calendar'
        ? renderPhoenixCalendarHtml(allCampaigns, monthParam)
        : `<div class="table-scroll" style="margin-top:1.25rem;" tabindex="0" role="region" aria-label="Seasonal Campaigns Table">
            <table class="data-table">
              <thead>
                <tr><th>Campaign &amp; Diagnostics</th><th>Slot</th><th>Priority</th><th>Start &rarr; End (America/Phoenix)</th><th>Editorial / State</th><th>Actions</th></tr>
              </thead>
              <tbody>
                ${
                  campaigns.length === 0
                    ? '<tr><td colspan="6" class="muted">No campaigns matching current filter.</td></tr>'
                    : campaigns
                        .map(
                          (c) => `<tr>
                            <td>
                              <strong>${escapeHtml(c.internal_title)}</strong> (rev ${escapeHtml(c.content_revision)})<br>
                              <small class="muted"><code>/lp/${escapeHtml(c.slug)}/</code> &rarr; ${escapeHtml(c.cta_destination)}</small>
                              ${
                                c.warnings && c.warnings.length > 0
                                  ? `<div style="margin-top:0.3rem;">${c.warnings.map((w) => `<span class="badge badge--err">${escapeHtml(w)}</span>`).join(' ')}</div>`
                                  : ''
                              }
                            </td>
                            <td><code>${escapeHtml(c.placement_slot)}</code></td>
                            <td>${escapeHtml(c.priority)}</td>
                            <td>${escapeHtml(formatPhoenixDateTime(c.start_at, false))}<br>&rarr; ${c.is_evergreen ? 'Evergreen' : escapeHtml(formatPhoenixDateTime(c.end_at, false))}</td>
                            <td><span class="badge">${escapeHtml(c.editorial_state)}</span> <span class="badge ${c.activation_state === 'Live' ? 'badge--live' : c.activation_state === 'Archived' ? 'badge--err' : 'badge--warn'}">${escapeHtml(c.activation_state)}</span></td>
                            <td style="display:flex;flex-wrap:wrap;gap:0.4rem;">
                              ${canEdit && c.activation_state !== 'Archived' ? `<a href="/admin/campaigns?edit=${encodeURIComponent(c.campaign_id)}" class="btn btn--secondary" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;">Edit</a>` : ''}
                              ${
                                canPublish && c.activation_state !== 'Live' && c.activation_state !== 'Archived'
                                  ? `<button type="button" class="btn btn--primary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/approve-schedule">Approve &amp; Schedule</button>`
                                  : ''
                              }
                              ${
                                canPublish && c.activation_state === 'Live'
                                  ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/pause">Pause</button>`
                                  : ''
                              }
                              ${
                                canPublish && c.activation_state === 'Paused'
                                  ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/resume">Resume</button>`
                                  : ''
                              }
                              ${
                                canPublish && c.activation_state !== 'Archived'
                                  ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/campaigns/${escapeHtml(c.campaign_id)}/archive">Archive</button>`
                                  : ''
                              }
                            </td>
                          </tr>`
                        )
                        .join('')
                }
              </tbody>
            </table>
          </div>
          ${renderPaginationNav('/admin/campaigns', campaignsMeta, { view: viewMode, ...filters })}`
    }
  </section>

  ${
    canEdit
      ? `<section class="admin-card">
          <h2>${selectedCampaign ? `Edit Campaign: ${escapeHtml(selectedCampaign.internal_title)}` : 'Create Seasonal Campaign'}</h2>
          <form method="POST" action="${selectedCampaign ? `/admin/api/campaigns/${escapeHtml(selectedCampaign.campaign_id)}` : '/admin/api/campaigns'}" class="js-ajax-form form-stack">
            <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
            <div class="grid-2">
              <div class="field"><label for="cp-title">Internal Title</label><input id="cp-title" name="internal_title" value="${escapeHtml(selectedCampaign?.internal_title || '')}" required></div>
              ${
                selectedCampaign
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
            <div style="display:flex;gap:0.6rem;flex-wrap:wrap;">
              <button type="submit" class="btn btn--primary">${selectedCampaign ? 'Save Campaign Revision Draft' : 'Save Campaign Draft'}</button>
              ${selectedCampaign ? '<a href="/admin/campaigns" class="btn btn--secondary">Cancel Edit</a>' : ''}
            </div>
          </form>
        </section>`
      : ''
  }`;
}

export function renderAdminProjectsView({ projects, selectedProject, pairs, galleryItems = [], assets, assetUsageMap = {}, user, csrfToken }) {
  const canPublish = hasPermission(user, PERMISSIONS.PUBLISH_PROJECTS);
  const canEdit = hasPermission(user, PERMISSIONS.EDIT_PROJECTS);

  let selectedServices = '';
  if (selectedProject) {
    try {
      selectedServices = JSON.parse(selectedProject.related_services_json || '[]').join(', ');
    } catch {
      selectedServices = '';
    }
  }

  return `
  <div class="admin-split">
    <section class="admin-card">
      <h2>Completed Projects</h2>
      <div class="table-scroll" tabindex="0" role="region" aria-label="Completed Projects Table">
        <table class="data-table">
          <thead><tr><th>Title</th><th>Property</th><th>State</th></tr></thead>
          <tbody>
            ${projects
              .map(
                (p) => `<tr>
                  <td><a href="/admin/projects?id=${encodeURIComponent(p.project_id)}">${escapeHtml(p.title)}</a>${p.is_private_test ? ' <span class="badge badge--warn">TEST RECORD</span>' : ''}</td>
                  <td>${escapeHtml(p.property_type)}</td>
                  <td><span class="badge ${p.activation_state === 'Live' ? 'badge--live' : 'badge--warn'}">${escapeHtml(p.editorial_state)} / ${escapeHtml(p.activation_state)}</span></td>
                </tr>`
              )
              .join('')}
          </tbody>
        </table>
      </div>

      ${
        canEdit
          ? `<details style="margin-top:1.25rem;">
              <summary style="cursor:pointer;font-weight:700;">+ Create New Completed Project Draft</summary>
              <form method="POST" action="/admin/api/projects" class="js-ajax-form" style="margin-top:1rem;">
                <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                <div class="field"><label for="np-title">Project Title</label><input id="np-title" name="title" required></div>
                <div class="field"><label for="np-slug">URL Slug</label><input id="np-slug" name="slug" pattern="[a-z0-9-]+" required></div>
                <div class="field"><label for="np-prop">Property Type</label>
                  <select id="np-prop" name="property_type">
                    <option value="Industrial / Warehouse">Industrial / Warehouse</option>
                    <option value="Retail Center">Retail Center</option>
                    <option value="Commercial Office">Commercial Office</option>
                  </select>
                </div>
                <div class="field"><label for="np-city">City / Region</label><input id="np-city" name="city_region" value="Phoenix / Greater Phoenix" required></div>
                <div class="field"><label for="np-comp">Completion Date</label><input type="date" id="np-comp" name="completion_date" required></div>
                <div class="field"><label for="np-chal">Challenge</label><textarea id="np-chal" name="challenge" style="min-height:4rem;" required></textarea></div>
                <div class="field"><label for="np-scope">Agreed Scope</label><textarea id="np-scope" name="agreed_scope" style="min-height:4rem;" required></textarea></div>
                <div class="field"><label for="np-work">Completed Work &amp; Verified Result</label><textarea id="np-work" name="completed_work" style="min-height:4rem;" required></textarea></div>
                <button type="submit" class="btn btn--primary">Create Project Draft</button>
              </form>
            </details>`
          : ''
      }
    </section>

    <section class="admin-card">
      <h2>Authenticated Project Photo Upload &amp; Rights Registry</h2>
      <p class="muted" style="font-size:0.86rem;">Up to 20 files/batch, 20 MB/image, 64 MP max. Adjust focal points (0–100%) and inspect usages before withdrawing rights.</p>
      ${
        canEdit
          ? `<form id="media-upload-form" method="POST" action="/admin/api/media/upload" enctype="multipart/form-data">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <div class="field">
                <label for="media-files">Select desktop or phone photos</label>
                <input type="file" id="media-files" name="photos" multiple accept="image/jpeg,image/png,image/webp,image/heic,.jpg,.jpeg,.png,.webp,.heic" capture="environment">
              </div>
              <div class="grid-2">
                <div class="field"><label for="media-rights">Rights Owner</label><input id="media-rights" name="rights_owner" value="Service Maintenance / Client Approved" required></div>
                <div class="field"><label for="media-alt">Default Alt Text</label><input id="media-alt" name="alt_text" required></div>
              </div>
              <button type="submit" class="btn btn--primary">Upload &amp; Strip Metadata</button>
              <div id="media-upload-feedback" class="hint" style="margin-top:0.5rem;" aria-live="polite"></div>
            </form>`
          : ''
      }

      <div class="media-thumb-grid" style="margin-top:1.25rem;">
        ${assets
          .map((a) => {
            const usage = assetUsageMap[a.asset_id] || { total: 0 };
            return `<div class="media-card">
              <img src="/admin/api/media/preview/${escapeHtml(a.asset_id)}" alt="${escapeHtml(a.alt_text || a.original_filename)}" style="object-position:${escapeHtml(a.focal_x ?? 50)}% ${escapeHtml(a.focal_y ?? 50)}%;">
              <div style="font-size:0.82rem;">
                <strong>${escapeHtml(a.original_filename)}</strong><br>
                <span>${escapeHtml(a.width)}&times;${escapeHtml(a.height)} &middot; <span class="badge ${a.rights_status === 'approved' ? 'badge--live' : a.rights_status === 'withdrawn' ? 'badge--err' : 'badge--warn'}">${escapeHtml(a.rights_status)}</span></span>
                <div class="muted" style="font-size:0.76rem;margin-top:0.2rem;">Focal: ${escapeHtml(a.focal_x ?? 50)}%, ${escapeHtml(a.focal_y ?? 50)}% &middot; Used in ${escapeHtml(usage.total)} placement(s)</div>
                ${
                  canEdit
                    ? `<form method="POST" action="/admin/api/media/${escapeHtml(a.asset_id)}/focal-point" class="js-ajax-form" style="margin-top:0.45rem;display:flex;gap:0.3rem;flex-wrap:wrap;align-items:center;">
                        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                        <label for="fx-${escapeHtml(a.asset_id)}" class="visually-hidden">Focal X percent</label>
                        <input id="fx-${escapeHtml(a.asset_id)}" type="number" min="0" max="100" name="focal_x" value="${escapeHtml(a.focal_x ?? 50)}" aria-label="Focal X%" style="width:58px;min-height:32px;padding:0.2rem;font-size:0.78rem;">
                        <label for="fy-${escapeHtml(a.asset_id)}" class="visually-hidden">Focal Y percent</label>
                        <input id="fy-${escapeHtml(a.asset_id)}" type="number" min="0" max="100" name="focal_y" value="${escapeHtml(a.focal_y ?? 50)}" aria-label="Focal Y%" style="width:58px;min-height:32px;padding:0.2rem;font-size:0.78rem;">
                        <button type="submit" class="btn btn--secondary" style="min-height:32px;padding:0.2rem 0.5rem;font-size:0.75rem;">Save Crop</button>
                      </form>`
                    : ''
                }
                <div style="display:flex;gap:0.35rem;margin-top:0.45rem;flex-wrap:wrap;">
                  ${
                    canPublish && a.rights_status !== 'approved'
                      ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:32px;padding:0.2rem 0.5rem;font-size:0.76rem;" data-url="/admin/api/media/${escapeHtml(a.asset_id)}/approve-rights">Approve Rights</button>`
                      : ''
                  }
                  ${
                    canPublish && a.rights_status !== 'withdrawn'
                      ? `<button type="button" class="btn btn--secondary js-withdraw-media-btn" style="min-height:32px;padding:0.2rem 0.5rem;font-size:0.76rem;" data-usage-url="/admin/api/media/${escapeHtml(a.asset_id)}/usage" data-withdraw-url="/admin/api/media/${escapeHtml(a.asset_id)}/withdraw" data-filename="${escapeHtml(a.original_filename)}">Withdraw Rights</button>`
                      : ''
                  }
                </div>
              </div>
            </div>`;
          })
          .join('')}
      </div>
    </section>
  </div>

  ${
    selectedProject
      ? `<section class="admin-card">
          <h2>Editing Project: ${escapeHtml(selectedProject.title)}</h2>
          <form method="POST" action="/admin/api/projects/${escapeHtml(selectedProject.project_id)}" class="js-ajax-form">
            <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
            <div class="grid-3">
              <div class="field"><label for="sp-title">Project Title</label><input id="sp-title" name="title" value="${escapeHtml(selectedProject.title)}" required ${canEdit ? '' : 'disabled'}></div>
              <div class="field"><label for="sp-prop">Property Type</label><input id="sp-prop" name="property_type" value="${escapeHtml(selectedProject.property_type)}" required ${canEdit ? '' : 'disabled'}></div>
              <div class="field"><label for="sp-city">City / Region</label><input id="sp-city" name="city_region" value="${escapeHtml(selectedProject.city_region)}" required ${canEdit ? '' : 'disabled'}></div>
            </div>
            <div class="grid-2">
              <div class="field"><label for="sp-chal">Challenge</label><textarea id="sp-chal" name="challenge" style="min-height:3.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(selectedProject.challenge)}</textarea></div>
              <div class="field"><label for="sp-scope">Agreed Scope</label><textarea id="sp-scope" name="agreed_scope" style="min-height:3.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(selectedProject.agreed_scope)}</textarea></div>
            </div>
            <div class="grid-2">
              <div class="field"><label for="sp-work">Completed Work</label><textarea id="sp-work" name="completed_work" style="min-height:3.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(selectedProject.completed_work)}</textarea></div>
              <div class="field"><label for="sp-res">Verified Result</label><textarea id="sp-res" name="verified_result" style="min-height:3.5rem;" ${canEdit ? '' : 'disabled'}>${escapeHtml(selectedProject.verified_result)}</textarea></div>
            </div>
            <div class="grid-3">
              <div class="field"><label for="sp-self">Self-Performed Elements</label><input id="sp-self" name="self_performed_notes" value="${escapeHtml(selectedProject.self_performed_notes)}" ${canEdit ? '' : 'disabled'}></div>
              <div class="field"><label for="sp-coord">Coordinated Trades</label><input id="sp-coord" name="coordinated_notes" value="${escapeHtml(selectedProject.coordinated_notes)}" ${canEdit ? '' : 'disabled'}></div>
              <div class="field"><label for="sp-rel">Related Service Slugs (comma-sep)</label><input id="sp-rel" name="related_services" value="${escapeHtml(selectedServices)}" placeholder="warehouse-repairs, day-porter" ${canEdit ? '' : 'disabled'}></div>
            </div>
            <div class="grid-3">
              <div class="field"><label for="sp-comp">Completion Date</label><input type="date" id="sp-comp" name="completion_date" value="${escapeHtml(selectedProject.completion_date || '')}" ${canEdit ? '' : 'disabled'}></div>
              <div class="field"><label for="sp-naming">Client Naming Decision</label>
                <select id="sp-naming" name="naming_decision">
                  <option value="anonymized"${selectedProject.naming_decision === 'anonymized' ? ' selected' : ''}>Anonymized (recommended when naming unapproved)</option>
                  <option value="named"${selectedProject.naming_decision === 'named' ? ' selected' : ''}>Named (requires explicit client permission)</option>
                </select>
              </div>
              <div class="field"><label for="sp-cover">Approved Cover Asset</label>
                <select id="sp-cover" name="cover_asset_id">
                  <option value="">None</option>
                  ${assets.map((a) => `<option value="${escapeHtml(a.asset_id)}"${selectedProject.cover_asset_id === a.asset_id ? ' selected' : ''}>${escapeHtml(a.original_filename)} (${escapeHtml(a.rights_status)})</option>`).join('')}
                </select>
              </div>
            </div>
            <div class="choice-row"><input type="checkbox" id="sp-doc" name="completion_documented"${selectedProject.completion_documented ? ' checked' : ''}><label for="sp-doc">Actual completion evidence documented</label></div>
            <div class="choice-row"><input type="checkbox" id="sp-perm" name="client_permission_verified"${selectedProject.client_permission_verified ? ' checked' : ''}><label for="sp-perm">Client naming/anonymity &amp; photo permission verified</label></div>
            <div class="choice-row"><input type="checkbox" id="sp-feat" name="featured_on_home"${selectedProject.featured_on_home ? ' checked' : ''}><label for="sp-feat">Feature on Homepage Selected Work</label></div>
            <div class="choice-row"><input type="checkbox" id="sp-test" name="is_private_test"${selectedProject.is_private_test ? ' checked' : ''}><label for="sp-test">Private Staging/Training Test Record (blocks public display)</label></div>

            <div style="display:flex;gap:0.6rem;flex-wrap:wrap;margin-top:1rem;">
              <button type="submit" class="btn btn--secondary">Save Project Details</button>
              <a href="/admin/preview?project=${encodeURIComponent(selectedProject.slug)}&viewport=desktop" target="_blank" class="btn btn--secondary">Preview Desktop</a>
              <a href="/admin/preview?project=${encodeURIComponent(selectedProject.slug)}&viewport=mobile" target="_blank" class="btn btn--secondary">Preview Mobile (390px)</a>
              ${
                canPublish
                  ? `<button type="button" class="btn btn--primary js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/publish">Approve &amp; Publish Project</button>
                     <button type="button" class="btn btn--secondary js-action-btn" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/archive">Archive Project</button>`
                  : ''
              }
            </div>
          </form>

          <h3 style="margin-top:1.75rem;">Project Gallery Order (Keyboard Reorderable)</h3>
          <div id="gallery-list">
            ${
              galleryItems.length === 0
                ? '<p class="muted">No gallery items added yet.</p>'
                : galleryItems
                    .map(
                      (g, idx) => `<div class="panel panel--light" style="margin-bottom:0.65rem;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;">
                        <div>
                          <strong>${idx + 1}. ${escapeHtml(g.original_filename)}</strong> (${escapeHtml(g.rights_status)})<br>
                          <small class="muted">${escapeHtml(g.caption || 'No caption')} &middot; Alt: ${escapeHtml(g.alt_text || 'Default')}</small>
                        </div>
                        <div style="display:flex;gap:0.4rem;flex-wrap:wrap;">
                          <button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/gallery/${escapeHtml(g.item_id)}/move?dir=up">Move earlier</button>
                          <button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/gallery/${escapeHtml(g.item_id)}/move?dir=down">Move later</button>
                          <button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/gallery/${escapeHtml(g.item_id)}/delete">Remove</button>
                        </div>
                      </div>`
                    )
                    .join('')
            }
          </div>
          ${
            canEdit && assets.length >= 1
              ? `<form method="POST" action="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/gallery" class="js-ajax-form" style="margin-top:0.85rem;display:flex;flex-wrap:wrap;gap:0.5rem;align-items:flex-end;">
                  <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                  <div class="field" style="margin:0;min-width:12rem;"><label for="gal-asset">Add Image</label>
                    <select id="gal-asset" name="asset_id" required>
                      ${assets.filter((a) => a.rights_status !== 'withdrawn').map((a) => `<option value="${escapeHtml(a.asset_id)}">${escapeHtml(a.original_filename)} (${escapeHtml(a.rights_status)})</option>`).join('')}
                    </select>
                  </div>
                  <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="gal-cap">Caption</label><input id="gal-cap" name="caption"></div>
                  <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="gal-alt">Alt Text</label><input id="gal-alt" name="alt_text"></div>
                  <button type="submit" class="btn btn--secondary">Add to Gallery</button>
                </form>`
              : ''
          }

          <h3 style="margin-top:1.75rem;">Explicit Before &amp; After Pairing (Keyboard Reorderable)</h3>
          <div id="pairs-list">
            ${pairs
              .map(
                (pr, idx) => `<div class="panel panel--light" style="margin-bottom:0.85rem;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;">
                  <div>
                    <strong>${idx + 1}. ${escapeHtml(pr.pair_title)}</strong><br>
                    <span class="muted" style="font-size:0.85rem;">Before: <code>${escapeHtml(pr.before_asset_id.slice(0, 8))}</code> | After: <code>${escapeHtml(pr.after_asset_id.slice(0, 8))}</code></span>
                  </div>
                  <div style="display:flex;gap:0.4rem;">
                    <button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/pairs/${escapeHtml(pr.pair_id)}/move?dir=up">Move earlier</button>
                    <button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/pairs/${escapeHtml(pr.pair_id)}/move?dir=down">Move later</button>
                    <button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/pairs/${escapeHtml(pr.pair_id)}/swap">Swap Before/After</button>
                  </div>
                </div>`
              )
              .join('')}
          </div>

          ${
            canEdit && assets.length >= 2
              ? `<form method="POST" action="/admin/api/projects/${escapeHtml(selectedProject.project_id)}/pairs" class="js-ajax-form" style="margin-top:1rem;">
                  <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                  <div class="grid-3">
                    <div class="field"><label for="pair-title">Pair Title</label><input id="pair-title" name="pair_title" required></div>
                    <div class="field"><label for="pair-before">Before Image</label>
                      <select id="pair-before" name="before_asset_id" required>
                        ${assets.map((a) => `<option value="${escapeHtml(a.asset_id)}">${escapeHtml(a.original_filename)}</option>`).join('')}
                      </select>
                    </div>
                    <div class="field"><label for="pair-after">After Image</label>
                      <select id="pair-after" name="after_asset_id" required>
                        ${assets.map((a) => `<option value="${escapeHtml(a.asset_id)}">${escapeHtml(a.original_filename)}</option>`).join('')}
                      </select>
                    </div>
                  </div>
                  <div class="grid-2">
                    <div class="field"><label for="pair-bcap">Before Caption</label><input id="pair-bcap" name="before_caption" required></div>
                    <div class="field"><label for="pair-acap">After Caption</label><input id="pair-acap" name="after_caption" required></div>
                  </div>
                  <button type="submit" class="btn btn--secondary">Add Before/After Pair</button>
                </form>`
              : ''
          }
        </section>`
      : ''
  }`;
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
}) {
  const isOwner = hasPermission(user, PERMISSIONS.MANAGE_VACANCIES);
  const canExport = hasPermission(user, PERMISSIONS.EXPORT_APPLICATIONS);

  return `
  <section class="admin-card">
    <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;">
      <div>
        <h2 style="margin:0;">Vacancies (Isolated Recruiting Domain)</h2>
        <p class="muted" style="margin:0;font-size:0.85rem;">Requisition IDs and Opening Cycles are immutable. Publishing &amp; closing schedules evaluate in <strong>America/Phoenix</strong>.</p>
      </div>
      ${
        canExport
          ? `<a href="/admin/api/applications/export.csv" class="btn btn--secondary">Export Permitted Applications (CWE-1236 Protected CSV)</a>`
          : ''
      }
    </div>

    <div class="table-scroll" style="margin-top:1rem;" tabindex="0" role="region" aria-label="Vacancies Table">
      <table class="data-table">
        <thead><tr><th>Req / Cycle</th><th>Title</th><th>Status &amp; Schedule (Phoenix)</th><th>Work Area</th><th>Actions</th></tr></thead>
        <tbody>
          ${jobs
            .map(
              (j) => `<tr>
                <td><code>${escapeHtml(j.requisition_id)}</code><br><small class="muted">${escapeHtml(j.opening_cycle_id)}</small></td>
                <td>${escapeHtml(j.title)}${j.is_private_test ? ' <span class="badge badge--warn">PRIVATE TEST</span>' : ''}</td>
                <td>
                  <span class="badge ${j.status === 'Open' ? 'badge--live' : 'badge--warn'}">${escapeHtml(j.status)}</span>
                  ${j.publish_at ? `<br><small class="muted">Publish: ${escapeHtml(formatPhoenixDateTime(j.publish_at, false))}</small>` : ''}
                  ${j.close_at ? `<br><small class="muted">Close: ${escapeHtml(formatPhoenixDateTime(j.close_at, false))}</small>` : ''}
                </td>
                <td>${escapeHtml(j.work_area)}</td>
                <td style="display:flex;gap:0.4rem;flex-wrap:wrap;">
                  ${isOwner ? `<a href="/admin/jobs?job=${encodeURIComponent(j.requisition_id)}" class="btn btn--secondary" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;">Edit / Schedule</a>` : ''}
                  ${
                    isOwner && (j.status === 'Draft' || j.status === 'Paused' || j.status === 'Scheduled')
                      ? `<button type="button" class="btn btn--primary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/open">Open Role</button>`
                      : ''
                  }
                  ${
                    isOwner && j.status === 'Open'
                      ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/pause">Pause</button>
                         <button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/close">Close Role</button>`
                      : ''
                  }
                  ${
                    isOwner && j.status === 'Closed'
                      ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/jobs/${escapeHtml(j.requisition_id)}/reopen">Reopen (New Cycle)</button>`
                      : ''
                  }
                </td>
              </tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>

    ${
      isOwner && selectedJob
        ? `<div class="panel panel--light" style="margin-top:1.25rem;">
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
              <div style="display:flex;gap:0.6rem;flex-wrap:wrap;">
                <button type="submit" class="btn btn--primary">Save Vacancy Changes</button>
                <a href="/admin/jobs" class="btn btn--secondary">Done Editing</a>
              </div>
            </form>

            <h4 style="margin-top:1.25rem;">Schedule Publish / Close Window (America/Phoenix)</h4>
            <form method="POST" action="/admin/api/jobs/${escapeHtml(selectedJob.requisition_id)}/schedule" class="js-ajax-form" style="display:flex;flex-wrap:wrap;gap:0.75rem;align-items:flex-end;">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <div class="field" style="margin:0;"><label for="sj-pub">Publish At (Phoenix)</label><input type="datetime-local" id="sj-pub" name="publish_phoenix" value="${selectedJob.publish_at ? escapeHtml(utcIsoToPhoenixInput(selectedJob.publish_at)) : ''}" required></div>
              <div class="field" style="margin:0;"><label for="sj-cls">Auto-Close At (Optional Phoenix)</label><input type="datetime-local" id="sj-cls" name="close_phoenix" value="${selectedJob.close_at ? escapeHtml(utcIsoToPhoenixInput(selectedJob.close_at)) : ''}"></div>
              <button type="submit" class="btn btn--secondary">Save &amp; Schedule Vacancy</button>
            </form>
          </div>`
        : ''
    }

    ${
      isOwner
        ? `<details style="margin-top:1.25rem;">
            <summary style="cursor:pointer;font-weight:700;">+ Create New Vacancy</summary>
            <form method="POST" action="/admin/api/jobs" class="js-ajax-form" style="margin-top:1rem;">
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

  <div class="admin-split">
    <section class="admin-card">
      <h2>Protected Applicant Inbox</h2>
      <form method="GET" action="/admin/jobs" style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:flex-end;margin-bottom:1rem;">
        <div class="field" style="margin:0;flex:1;min-width:10rem;"><label for="app-q">Search applicant / email / ID</label><input id="app-q" name="q" type="search" value="${escapeHtml(filters.q || '')}"></div>
        <div class="field" style="margin:0;"><label for="app-req">Vacancy</label>
          <select id="app-req" name="req">
            <option value="">All scoped roles</option>
            ${jobs.map((j) => `<option value="${escapeHtml(j.requisition_id)}"${filters.req === j.requisition_id ? ' selected' : ''}>${escapeHtml(j.title)}</option>`).join('')}
          </select>
        </div>
        <div class="field" style="margin:0;"><label for="app-stf">Stage</label>
          <select id="app-stf" name="stage">
            <option value="">All stages</option>
            ${['Received', 'Under review', 'Contacting', 'Interview', 'Offer', 'Hired', 'Not selected', 'Withdrawn', 'Duplicate', 'Unable to contact']
              .map((st) => `<option value="${escapeHtml(st)}"${filters.stage === st ? ' selected' : ''}>${escapeHtml(st)}</option>`)
              .join('')}
          </select>
        </div>
        <button type="submit" class="btn btn--secondary">Filter</button>
        ${filters.q || filters.req || filters.stage ? '<a href="/admin/jobs" class="btn btn--secondary">Clear</a>' : ''}
      </form>
      ${
        applications.length === 0
          ? '<p class="muted">No applications matching your authorized recruiting scope and filters.</p>'
          : `<div class="table-scroll" tabindex="0" role="region" aria-label="Protected Applicant Inbox Table">
              <table class="data-table">
                <thead><tr><th>Applicant</th><th>Role</th><th>Stage</th><th>Received (Phoenix)</th></tr></thead>
                <tbody>
                  ${applications
                    .map(
                      (a) => `<tr>
                        <td><a href="/admin/jobs?app=${encodeURIComponent(a.application_id)}">${escapeHtml(a.applicant_name)}</a>${a.possible_duplicate_of ? ' <span class="badge badge--warn">Possible Duplicate</span>' : ''}</td>
                        <td>${escapeHtml(a.job_title)}</td>
                        <td><span class="badge">${escapeHtml(a.stage)}</span></td>
                        <td>${escapeHtml(formatPhoenixDateTime(a.received_at, false))}</td>
                      </tr>`
                    )
                    .join('')}
                </tbody>
              </table>
            </div>`
      }
      ${renderPaginationNav('/admin/jobs', appsMeta, filters)}
    </section>

    ${
      selectedApp
        ? `<section class="admin-card">
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

            ${
              selectedApp.attachments.length > 0
                ? `<h3 style="margin-top:1rem;">Protected Attachments</h3>
                   <ul>${selectedApp.attachments
                     .map(
                       (att) => `<li style="margin-bottom:0.65rem;">
                         ${escapeHtml(att.original_display_name)} (${escapeHtml(att.scan_state)}) — ${
                           att.scan_state === 'clean'
                             ? `<a href="/admin/api/applications/${escapeHtml(selectedApp.application_id)}/attachments/${escapeHtml(att.attachment_id)}">Authenticated Download</a>`
                             : '<span class="badge badge--err">Quarantined / Blocked</span>'
                         }
                         ${
                           isOwner
                             ? `<div style="margin-top:0.4rem;display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
                                 <form method="POST" action="/admin/api/applications/${escapeHtml(selectedApp.application_id)}/attachments/${escapeHtml(att.attachment_id)}/replace" enctype="multipart/form-data" class="js-multipart-form" style="display:inline-flex;gap:0.35rem;align-items:center;flex-wrap:wrap;">
                                   <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                                   <input type="file" name="resume" accept=".pdf,.docx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" required aria-label="Replacement resume PDF or DOCX" style="max-width:210px;font-size:0.78rem;">
                                   <button type="submit" class="btn btn--secondary" style="min-height:32px;padding:0.2rem 0.5rem;font-size:0.78rem;">Replace Resume</button>
                                 </form>
                                 <button type="button" class="btn btn--secondary js-action-btn" style="min-height:32px;padding:0.2rem 0.5rem;font-size:0.78rem;" data-url="/admin/api/applications/${escapeHtml(selectedApp.application_id)}/attachments/${escapeHtml(att.attachment_id)}/delete">Delete Resume</button>
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
                ${
                  isOwner
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

            ${
              selectedApp.notes.length > 0
                ? `<h3 style="margin-top:1.25rem;">Internal Review Notes</h3>
                   <ul>${selectedApp.notes
                     .map((n) => `<li><strong>${escapeHtml(n.author_name)}</strong> (${escapeHtml(formatPhoenixDateTime(n.created_at, false))}): ${escapeHtml(n.note_text)}</li>`)
                     .join('')}</ul>`
                : ''
            }
          </section>`
        : '<section class="admin-card"><p>Select an application to inspect its immutable snapshot, resume attachment, and review controls.</p></section>'
    }
  </div>`;
}

export function renderAdminLeadsView({
  inquiries,
  inquiriesMeta = null,
  inquiryAttachments = {},
  filters = {},
  crmQueue,
  notifications,
  crmFaultMode,
  csrfToken,
}) {
  return `
  <section class="admin-card">
    <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;">
      <div>
        <h2 style="margin:0;">Commercial Inquiries &amp; Operations Requests</h2>
        <p class="muted" style="margin:0;font-size:0.86rem;">Separated from Recruiting. Replays failed Freshsales deliveries and provides audited private downloads for inquiry attachments.</p>
      </div>
      ${
        ENV.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'production'
          ? `<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
              <span class="badge ${crmFaultMode === 'none' ? 'badge--live' : 'badge--err'}">CRM Fault Sim: ${escapeHtml(crmFaultMode)}</span>
              <button type="button" class="btn btn--secondary js-action-btn" style="min-height:36px;padding:0.25rem 0.6rem;font-size:0.8rem;" data-url="/admin/api/crm/fault-mode?mode=${crmFaultMode === 'none' ? 'outage_503' : 'none'}">${crmFaultMode === 'none' ? 'Simulate CRM Outage' : 'Restore CRM Normal'}</button>
            </div>`
          : ''
      }
    </div>

    <form method="GET" action="/admin/leads" style="display:flex;flex-wrap:wrap;gap:0.65rem;align-items:flex-end;margin-top:1rem;">
      <div class="field" style="margin:0;flex:1;min-width:12rem;"><label for="ld-q">Search company, location, or ID</label><input id="ld-q" name="q" type="search" value="${escapeHtml(filters.q || '')}"></div>
      <div class="field" style="margin:0;"><label for="ld-cls">Classification</label>
        <select id="ld-cls" name="classification">
          <option value="">All classifications</option>
          ${['valid', 'existing_service', 'spam', 'job', 'vendor', 'out_of_area', 'test'].map((c) => `<option value="${c}"${filters.classification === c ? ' selected' : ''}>${c}</option>`).join('')}
        </select>
      </div>
      <div class="field" style="margin:0;"><label for="ld-st">Stage</label>
        <select id="ld-st" name="status">
          <option value="">All stages</option>
          ${['received', 'qualified', 'proposal_sent', 'closed_won', 'disqualified'].map((s) => `<option value="${s}"${filters.status === s ? ' selected' : ''}>${s}</option>`).join('')}
        </select>
      </div>
      <button type="submit" class="btn btn--secondary">Filter</button>
      ${filters.q || filters.classification || filters.status ? '<a href="/admin/leads" class="btn btn--secondary">Clear</a>' : ''}
    </form>

    <div class="table-scroll" style="margin-top:1rem;" tabindex="0" role="region" aria-label="Commercial Inquiries Table">
      <table class="data-table">
        <thead><tr><th>Inquiry ID</th><th>Kind / Service</th><th>Company, Property &amp; Attachments</th><th>Classification / Stage</th><th>Received (Phoenix)</th><th>Actions</th></tr></thead>
        <tbody>
          ${
            inquiries.length === 0
              ? '<tr><td colspan="6" class="muted">No inquiries matching filter criteria.</td></tr>'
              : inquiries
                  .map((inq) => {
                    const atts = inquiryAttachments[inq.inquiry_id] || [];
                    return `<tr>
                      <td><code>${escapeHtml(inq.inquiry_id.slice(0, 8))}</code></td>
                      <td>${escapeHtml(inq.inquiry_kind)}<br><small>${escapeHtml(inq.service_family)}</small></td>
                      <td>
                        <strong>${escapeHtml(inq.org_name)}</strong><br>
                        <small class="muted">${escapeHtml(inq.prop_loc || '—')} &middot; ${escapeHtml(inq.routing_queue)}</small>
                        ${
                          atts.length > 0
                            ? `<div style="margin-top:0.35rem;font-size:0.78rem;">${atts
                                .map((att) =>
                                  att.scan_state === 'clean'
                                    ? `<a href="/admin/api/inquiries/${escapeHtml(inq.inquiry_id)}/attachments/${escapeHtml(att.attachment_id)}">Download: ${escapeHtml(att.original_name)}</a>`
                                    : `<span class="badge badge--err">${escapeHtml(att.original_name)} (${escapeHtml(att.scan_state)})</span>`
                                )
                                .join('<br>')}</div>`
                            : ''
                        }
                      </td>
                      <td><span class="badge">${escapeHtml(inq.classification)}</span> <span class="badge badge--live">${escapeHtml(inq.status)}</span>${inq.crm_deal_id ? `<br><small class="muted">Deal: ${escapeHtml(inq.crm_deal_id)}</small>` : ''}</td>
                      <td>${escapeHtml(formatPhoenixDateTime(inq.received_at, false))}</td>
                      <td>
                        <form method="POST" action="/admin/api/inquiries/${escapeHtml(inq.inquiry_id)}/status" class="js-ajax-form" style="display:flex;gap:0.35rem;flex-wrap:wrap;">
                          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                          <select name="classification" aria-label="Classification" style="font-size:0.8rem;min-height:34px;">
                            ${['valid', 'existing_service', 'spam', 'job', 'vendor', 'out_of_area', 'test'].map((c) => `<option value="${c}"${inq.classification === c ? ' selected' : ''}>${c}</option>`).join('')}
                          </select>
                          <select name="status" aria-label="Pipeline status" style="font-size:0.8rem;min-height:34px;">
                            ${['received', 'qualified', 'proposal_sent', 'closed_won', 'disqualified'].map((s) => `<option value="${s}"${inq.status === s ? ' selected' : ''}>${s}</option>`).join('')}
                          </select>
                          <input type="number" step="0.01" min="0" name="deal_value" aria-label="Deal value USD" placeholder="Value $" value="${inq.deal_value != null ? escapeHtml(inq.deal_value) : ''}" style="font-size:0.8rem;min-height:34px;width:88px;">
                          <button type="submit" class="btn btn--secondary" style="min-height:34px;padding:0.2rem 0.55rem;font-size:0.8rem;">Update</button>
                        </form>
                      </td>
                    </tr>`;
                  })
                  .join('')
          }
        </tbody>
      </table>
    </div>
    ${renderPaginationNav('/admin/leads', inquiriesMeta, filters)}
  </section>

  <section class="admin-card">
    <h2>Freshsales CRM Delivery Queue</h2>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Freshsales CRM Delivery Queue">
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
                <td>${
                  q.status === 'failed_review' || q.status === 'pending'
                    ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:34px;padding:0.2rem 0.55rem;font-size:0.78rem;" data-url="/admin/api/crm/replay/${escapeHtml(q.delivery_id)}">Replay</button>`
                    : '—'
                }</td>
              </tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>
  </section>

  <section class="admin-card">
    <h2>M365 Notification Dispatch Queue</h2>
    <div class="table-scroll" tabindex="0" role="region" aria-label="M365 Notification Dispatch Queue">
      <table class="data-table" style="font-size:0.84rem;">
        <thead><tr><th>Domain</th><th>Recipient</th><th>Subject</th><th>Status</th><th>Attempts</th><th>Provider ID / Error</th><th>Action</th></tr></thead>
        <tbody>
          ${notifications
            .map(
              (n) => `<tr>
                <td>${escapeHtml(n.domain)}</td>
                <td>${escapeHtml(n.recipient_target)}</td>
                <td>${escapeHtml(n.subject)}</td>
                <td><span class="badge ${n.status === 'sent' ? 'badge--live' : n.status === 'failed_review' ? 'badge--err' : 'badge--warn'}">${escapeHtml(n.status)}</span></td>
                <td>${escapeHtml(n.attempts)}</td>
                <td>${escapeHtml(n.provider_message_id || n.last_error || 'Pending')}</td>
                <td>${
                  n.status !== 'sent'
                    ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:34px;padding:0.2rem 0.55rem;font-size:0.78rem;" data-url="/admin/api/notifications/replay/${escapeHtml(n.notification_id)}">Replay</button>`
                    : '—'
                }</td>
              </tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>
  </section>`;
}

export function renderAdminAnalyticsView({ summary }) {
  const leads = summary.leadsByService || [];
  const events = summary.eventCounts || [];
  const camps = summary.campaignPerformance || [];
  const projReady = summary.projectReadiness || [];

  return `
  <p class="muted" style="margin-bottom:1.15rem;"><strong>Data Integrity Boundary:</strong> Reports non-identifying first-party events and durable inquiry totals only. Applicant names, emails, telephones, and resume filenames are never present here. Snapshot reflects stored database records as of page load.</p>
  <section class="admin-card">
    <h2>Durable Inquiries by Service Family (Commercial Funnel)</h2>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Durable Inquiries Summary">
      <table class="data-table" style="font-size:0.86rem;">
        <thead><tr><th>Service Family</th><th>Total</th><th>New Biz</th><th>Qualified</th><th>Proposals</th><th>Won</th><th>Existing / Excluded</th></tr></thead>
        <tbody>
          ${
            leads.length === 0
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
            ${
              events.length === 0
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
  </section>`;
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

  return `
  <section class="admin-card">
    <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;margin-bottom:0.85rem;">
      <div>
        <h2 style="border:0;padding:0;margin:0 0 0.25rem;">Staff Accounts, Roles &amp; Session Controls</h2>
        <p class="muted" style="font-size:0.86rem;margin:0;">Deactivating a staff user or changing their role immediately revokes all active sessions server-side.</p>
      </div>
      <a href="/admin/mfa-setup" class="btn btn--secondary" style="min-height:38px;padding:0.4rem 0.9rem;font-size:0.84rem;">Manage / Rotate My MFA &rarr;</a>
    </div>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Staff Accounts Table">
      <table class="data-table" style="font-size:0.86rem;">
        <thead><tr><th>Staff Member</th><th>Role &amp; Extra Roles</th><th>MFA / Sessions</th><th>Status &amp; Actions</th></tr></thead>
        <tbody>
          ${users
            .map((u) => {
              let extra = [];
              try { extra = JSON.parse(u.extra_roles_json || '[]'); } catch {}
              const sessCount = activeSessionsMap[u.user_id] || 0;
              return `<tr>
                <td style="min-width:190px;"><strong>${escapeHtml(u.full_name)}</strong><br><small class="muted">${escapeHtml(u.email)}</small></td>
                <td style="min-width:250px;">
                  ${
                    canManageUsers
                      ? `<form method="POST" action="/admin/api/users/${escapeHtml(u.user_id)}" class="js-ajax-form" style="display:flex;flex-direction:column;gap:0.4rem;">
                          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                          <div style="display:flex;gap:0.4rem;flex-wrap:wrap;">
                            <select name="role" aria-label="Primary role for ${escapeHtml(u.email)}" style="flex:1;min-width:165px;">
                              ${allRoleNames.map((r) => `<option value="${escapeHtml(r)}"${u.role === r ? ' selected' : ''}>${escapeHtml(r)}</option>`).join('')}
                            </select>
                            <button type="submit" class="btn btn--secondary" style="min-height:36px;padding:0.25rem 0.7rem;font-size:0.8rem;">Save Role</button>
                          </div>
                          <input type="text" name="extra_roles" value="${escapeHtml(extra.join(', '))}" aria-label="Extra roles comma-separated" placeholder="Extra roles (comma-separated)">
                        </form>`
                      : `${escapeHtml(u.role)}${extra.length ? `<br><small class="muted">+ ${escapeHtml(extra.join(', '))}</small>` : ''}`
                  }
                </td>
                <td style="min-width:165px;">
                  <span class="badge ${u.mfa_enabled && u.mfa_enrolled ? 'badge--live' : 'badge--warn'}">${u.mfa_enabled ? (u.mfa_enrolled ? 'Enrolled (TOTP)' : 'Setup Pending (TOTP)') : 'Off'}</span>
                  <div class="muted" style="font-size:0.8rem;margin-top:0.35rem;">${sessCount} active session(s)</div>
                </td>
                <td style="min-width:265px;">
                  <div class="admin-action-group">
                    <span class="badge ${u.active ? 'badge--live' : 'badge--err'}">${u.active ? 'Active' : 'Revoked'}</span>
                    ${
                      canManageUsers
                        ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:34px;padding:0.25rem 0.65rem;font-size:0.78rem;" data-url="/admin/api/users/${escapeHtml(u.user_id)}/mfa-recovery-token">Issue MFA Setup Link</button>
                           <button type="button" class="btn btn--secondary js-action-btn" style="min-height:34px;padding:0.25rem 0.65rem;font-size:0.78rem;" data-url="/admin/api/users/${escapeHtml(u.user_id)}/revoke-sessions">Revoke Sessions</button>
                           ${
                             u.active
                               ? `<button type="button" class="btn btn--secondary js-action-btn" style="min-height:34px;padding:0.25rem 0.65rem;font-size:0.78rem;" data-url="/admin/api/users/${escapeHtml(u.user_id)}/deactivate">Deactivate</button>`
                               : `<button type="button" class="btn btn--primary js-action-btn" style="min-height:34px;padding:0.25rem 0.65rem;font-size:0.78rem;" data-url="/admin/api/users/${escapeHtml(u.user_id)}/activate">Activate</button>`
                           }`
                        : ''
                    }
                  </div>
                </td>
              </tr>`;
            })
            .join('')}
        </tbody>
      </table>
    </div>
  </section>

  ${
    canManageSettings
      ? `<section class="admin-card">
          <h2>Canonical Business Settings</h2>
          <form method="POST" action="/admin/api/settings" class="js-ajax-form">
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
            <button type="submit" class="btn btn--primary">Save Canonical Business Settings</button>
          </form>
        </section>`
      : ''
  }

  <div class="grid-2" style="align-items:start;">
    ${
      canManageUsers
        ? `<section class="admin-card">
            <h2>Create Staff Account</h2>
            <form method="POST" action="/admin/api/users" class="js-ajax-form">
              <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
              <div class="grid-2">
                <div class="field"><label for="nu-name">Full Name</label><input type="text" id="nu-name" name="full_name" required></div>
                <div class="field"><label for="nu-email">Staff Email</label><input type="email" id="nu-email" name="email" required></div>
              </div>
              <div class="grid-2">
                <div class="field"><label for="nu-role">Primary Role</label>
                  <select id="nu-role" name="role">
                    ${allRoleNames.map((r) => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`).join('')}
                  </select>
                </div>
                <div class="field"><label for="nu-extra">Additional Roles (comma-separated, optional)</label><input type="text" id="nu-extra" name="extra_roles" placeholder="e.g. Analyst"></div>
              </div>
              <div class="field"><label for="nu-pass">Initial Password (min 10 chars)</label><input type="password" id="nu-pass" name="password" minlength="10" required></div>
              <button type="submit" class="btn btn--primary">Create Staff Account</button>
            </form>
          </section>`
        : ''
    }

    ${
      canManageBackups
        ? `<section class="admin-card">
            <h2>Company-Owned Backup &amp; Export (OPS-01 / OPS-03)</h2>
            <p class="muted" style="font-size:0.86rem;">Generates a portable JSON snapshot plus checksummed full backups with SHA-256 verification and re-evaluated restore.</p>
            <div class="admin-action-group" style="margin-bottom:1rem;">
              <a href="/admin/api/backup/export.json" class="btn btn--secondary">Download Portable JSON Export</a>
              <button type="button" class="btn btn--primary js-action-btn" data-url="/admin/api/backups/create">Create Verified Full Backup Now</button>
            </div>
            ${
              backupRuns.length > 0
                ? `<div class="table-scroll" tabindex="0" role="region" aria-label="Full Backup Runs">
                     <table class="data-table" style="font-size:0.82rem;">
                       <thead><tr><th>Backup ID / Reason</th><th>Created (Phoenix)</th><th>Files</th><th>Status</th><th>Actions</th></tr></thead>
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
                                   <button type="button" class="btn btn--secondary js-action-btn" style="min-height:32px;padding:0.2rem 0.55rem;font-size:0.76rem;" data-url="/admin/api/backups/${escapeHtml(b.backup_id)}/verify">Verify SHA-256</button>
                                   <button type="button" class="btn btn--secondary js-action-btn" style="min-height:32px;padding:0.2rem 0.55rem;font-size:0.76rem;" data-url="/admin/api/backups/${escapeHtml(b.backup_id)}/restore">Restore</button>
                                 </div>
                               </td>
                             </tr>`
                           )
                           .join('')}
                       </tbody>
                     </table>
                   </div>`
                : '<p class="muted" style="font-size:0.84rem;">No full filesystem backups recorded yet.</p>'
            }
          </section>`
        : ''
    }
  </div>

  ${
    canManageBackups
      ? `<section class="admin-card">
          <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;margin-bottom:0.85rem;">
            <div>
              <h2 style="margin:0;">Retention &amp; Automated Deletion Policies (PRD 17.09 &amp; 21.03)</h2>
              <p class="muted" style="margin:0;font-size:0.85rem;">Policies marked <strong>Pending Client Approval</strong> never auto-delete data until an administrator saves an approved retention period.</p>
            </div>
            <button type="button" class="btn btn--secondary js-action-btn" data-url="/admin/api/retention/run">Run Approved Retention Sweep</button>
          </div>
          <div class="table-scroll" tabindex="0" role="region" aria-label="Retention Policies Table">
            <table class="data-table" style="font-size:0.82rem;">
              <thead><tr><th>Data Category &amp; PRD Rule</th><th>Approval Status</th><th>Retention Days &amp; Action</th><th>Last Sweep</th></tr></thead>
              <tbody>
                ${retentionPolicies
                  .map(
                    (p) => `<tr>
                      <td><strong>${escapeHtml(p.label)}</strong><br><small class="muted">${escapeHtml(p.prd_reference)}</small></td>
                      <td><span class="badge ${p.approved_by_client ? 'badge--live' : 'badge--warn'}">${p.approved_by_client ? `Approved (${escapeHtml(p.approved_by_user || 'Client')})` : 'Pending Client Approval'}</span></td>
                      <td>
                        <form method="POST" action="/admin/api/retention/policies/${escapeHtml(p.policy_key)}" class="js-ajax-form" style="display:flex;gap:0.35rem;align-items:center;flex-wrap:wrap;">
                          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
                          <input type="hidden" name="approved" value="true">
                          <input type="number" name="retention_days" min="1" max="3650" value="${p.retention_days ?? ''}" placeholder="Days (TBD)" aria-label="Retention days for ${escapeHtml(p.policy_key)}" style="width:92px;min-height:34px;font-size:0.8rem;" required>
                          <button type="submit" class="btn btn--secondary" style="min-height:34px;padding:0.2rem 0.55rem;font-size:0.78rem;">Approve &amp; Save</button>
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

  <section class="admin-card">
    <h2>Server-Side Role &amp; Permission Matrix</h2>
    <div class="table-scroll" tabindex="0" role="region" aria-label="Role Permission Matrix">
      <table class="data-table" style="font-size:0.82rem;">
        <thead><tr><th>Role</th><th>Granted Server-Side Permissions</th></tr></thead>
        <tbody>
          ${allRoleNames
            .map(
              (r) => `<tr><td><strong>${escapeHtml(r)}</strong></td><td>${(rolePermissionMap[r] || []).map((p) => `<code>${escapeHtml(p)}</code>`).join(' ')}</td></tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>
  </section>`;
}
