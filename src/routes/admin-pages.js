import { DEMO_USERS } from '../db/seed.js';
import { parseRequestBody } from '../lib/multipart.js';
import { escapeHtml } from '../lib/sanitize.js';
import { formatPhoenixDateTime, phoenixLocalToUtcIso } from '../lib/time.js';
import {
  authenticateSession,
  buildSessionCookie,
  canAccessApplicationRecord,
  canAccessJobRecord,
  checkRateLimit,
  clearSessionCookie,
  createPendingOrVerifiedSession,
  hasPermission,
  PERMISSIONS,
  recordAudit,
  ROLE_PERMISSION_MAP,
} from '../services/auth.js';
import { getAnalyticsSummary } from '../services/analytics.js';
import { detectCampaignSlotConflicts, resolveActiveCampaigns } from '../services/campaign-engine.js';
import { getCrmFaultMode } from '../services/crm-adapter.js';
import * as AdminViews from '../views/admin-views.js';
import { renderPublicLayout } from '../views/layout.js';
import * as PublicPages from '../views/public-pages.js';
import { getCanonicalSettings } from './public.js';

function sendHtml(res, status, html, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(html);
}

function redirect(res, loc, headers = {}) {
  res.writeHead(302, { Location: loc, ...headers });
  res.end();
}

function forbidden(res, user, csrfToken, nonce) {
  sendHtml(
    res,
    403,
    AdminViews.renderAdminShell({
      title: 'Access Denied (403)',
      user,
      csrfToken,
      currentSection: 'overview',
      nonce,
      bodyHtml: `<div class="status-banner status-banner--error"><strong>403 Forbidden:</strong> Your role (${escapeHtml(user.role)}) does not have permission to access this workspace or record.</div><a href="/admin/" class="btn btn--secondary">Return to Overview</a>`,
    })
  );
}

function paginateRows(rows, pageParam, pageSize = 15) {
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.max(1, Math.min(totalPages, Number(pageParam) || 1));
  const start = (page - 1) * pageSize;
  return {
    items: rows.slice(start, start + pageSize),
    page,
    pageSize,
    total,
    totalPages,
  };
}

export async function handleAdminPages(req, res, db, urlObj, nonce) {
  const pathname = urlObj.pathname;
  if (!pathname.startsWith('/admin')) return false;

  // 1. Login / Logout
  if (pathname === '/admin/login') {
    if (req.method === 'GET') {
      sendHtml(res, 200, AdminViews.renderAdminLoginPage({ demoAccounts: DEMO_USERS, nonce }));
      return true;
    }
    if (req.method === 'POST') {
      const ip = req.socket?.remoteAddress || 'unknown';
      const rl = checkRateLimit(`login:${ip}`, 15, 60_000);
      if (!rl.allowed) {
        sendHtml(res, 429, AdminViews.renderAdminLoginPage({ error: 'Too many login attempts. Please wait 60 seconds.', demoAccounts: DEMO_USERS, nonce }));
        return true;
      }
      const { fields } = await parseRequestBody(req, 64 * 1024);
      const authRes = await createPendingOrVerifiedSession(db, {
        email: fields.email,
        password: fields.password,
        totpCode: fields.totp_code,
        ip,
      });
      if (!authRes.ok) {
        sendHtml(
          res,
          401,
          AdminViews.renderAdminLoginPage({
            error: authRes.error,
            requireMfa: authRes.requireMfa,
            email: fields.email || '',
            demoAccounts: DEMO_USERS,
            nonce,
          })
        );
        return true;
      }
      redirect(res, '/admin/', { 'Set-Cookie': buildSessionCookie(authRes.sessionId) });
      return true;
    }
  }

  // Authenticate all other /admin routes server-side
  const session = await authenticateSession(db, req);
  if (!session) {
    redirect(res, '/admin/login');
    return true;
  }

  if (pathname === '/admin/logout' && req.method === 'POST') {
    const { fields } = await parseRequestBody(req, 16 * 1024);
    if (fields.csrf_token !== session.csrf_token) {
      res.writeHead(403);
      res.end('Invalid CSRF token');
      return true;
    }
    await db.prepare('DELETE FROM sessions WHERE session_id = ?').run(session.session_id);
    await recordAudit(db, session, 'auth', 'logout', 'session', session.session_id);
    redirect(res, '/admin/login', {
      'Set-Cookie': clearSessionCookie(),
      'Clear-Site-Data': '"cookies", "storage"',
    });
    return true;
  }

  const renderShell = (opts) =>
    AdminViews.renderAdminShell({
      user: session,
      csrfToken: session.csrf_token,
      nonce,
      ...opts,
    });

  // 2. Staff Preview Mode (/admin/preview) — Desktop / Mobile (390px) & As-Of Phoenix time without firing analytics!
  if (pathname === '/admin/preview') {
    const settings = await getCanonicalSettings(db);
    const asOfParam = urlObj.searchParams.get('asOf');
    const asOfIso = asOfParam ? phoenixLocalToUtcIso(asOfParam) : null;
    const projectSlug = urlObj.searchParams.get('project');
    const viewport = urlObj.searchParams.get('viewport') === 'mobile' ? 'mobile' : 'desktop';

    const buildViewportUrls = () => {
      const d = new URLSearchParams(urlObj.searchParams);
      d.set('viewport', 'desktop');
      const m = new URLSearchParams(urlObj.searchParams);
      m.set('viewport', 'mobile');
      return {
        desktopUrl: `/admin/preview?${d.toString()}`,
        mobileUrl: `/admin/preview?${m.toString()}`,
      };
    };
    const vpUrls = buildViewportUrls();

    if (projectSlug && hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      const project = await db.prepare('SELECT * FROM projects WHERE slug = ?').get(projectSlug);
      if (project) {
        const pairs = await db
          .prepare(
            `SELECT p.*, b.width as before_width, b.height as before_height, b.focal_x as before_focal_x, b.focal_y as before_focal_y,
                    a.width as after_width, a.height as after_height, a.focal_x as after_focal_x, a.focal_y as after_focal_y
             FROM project_before_after_pairs p
             JOIN media_assets b ON b.asset_id = p.before_asset_id
             JOIN media_assets a ON a.asset_id = p.after_asset_id
             WHERE p.project_id = ? ORDER BY p.sort_order ASC`
          )
          .all(project.project_id);
        const gallery = await db
          .prepare(`SELECT g.*, m.width, m.height, m.focal_x, m.focal_y FROM project_gallery_items g JOIN media_assets m ON m.asset_id = g.asset_id WHERE g.project_id = ? ORDER BY g.sort_order ASC`)
          .all(project.project_id);

        sendHtml(
          res,
          200,
          renderPublicLayout({
            title: `[PREVIEW] ${project.title}`,
            metaDescription: 'Draft project preview',
            canonicalPath: `/projects/${project.slug}/`,
            noindex: true,
            settings,
            previewInfo: { label: `Project Draft (${project.slug})`, viewport, ...vpUrls },
            nonce,
            bodyHtml: PublicPages.renderProjectDetailPage({ project, pairs, gallery, isPreview: true }),
          })
        );
        return true;
      }
    }

    const targetPath = urlObj.searchParams.get('path') || '/';
    const page = await db.prepare('SELECT * FROM pages WHERE slug = ?').get(targetPath);
    if (!page) {
      sendHtml(res, 404, 'Page not found');
      return true;
    }
    const reqRev = Number(urlObj.searchParams.get('rev') || page.current_revision);
    const rev =
      (await db.prepare('SELECT * FROM page_revisions WHERE page_id = ? AND revision_number = ?').get(page.page_id, reqRev)) ||
      (await db.prepare('SELECT * FROM page_revisions WHERE page_id = ? ORDER BY revision_number DESC LIMIT 1').get(page.page_id));

    const resolved = await resolveActiveCampaigns(db, { asOfIso });

    let bodyHtml = '';
    if (page.template === 'home') {
      const approvedProjects = await db
        .prepare(`SELECT p.*, m.public_derivative_key as cover_derivative_key, m.alt_text as cover_alt, m.focal_x as cover_focal_x, m.focal_y as cover_focal_y FROM projects p LEFT JOIN media_assets m ON m.asset_id = p.cover_asset_id WHERE p.editorial_state = 'Approved' AND p.activation_state = 'Live' AND p.is_private_test = 0`)
        .all();
      bodyHtml = PublicPages.renderHomePage({
        rev,
        settings,
        approvedProjects,
        seasonalFeature: resolved.homepageFeature,
        buildingEngineerLive: false,
      });
    } else if (page.template === 'service') {
      bodyHtml = PublicPages.renderServiceDetailPage({
        page,
        rev,
        contextualCampaign: resolved.serviceModules.get(page.slug) || null,
        relatedProjects: [],
        settings,
      });
    } else {
      bodyHtml = `<section class="section"><div class="container"><h1>${escapeHtml(rev.hero_headline)}</h1><p>${escapeHtml(rev.hero_summary)}</p>${rev.body_html}</div></section>`;
    }

    sendHtml(
      res,
      200,
      renderPublicLayout({
        title: `[PREVIEW] ${rev.meta_title}`,
        metaDescription: rev.meta_description,
        canonicalPath: page.slug,
        noindex: true,
        settings,
        noticeStrip: resolved.noticeStrip,
        previewInfo: { label: `${page.slug} (v${rev.revision_number})`, asOf: asOfParam || '', viewport, ...vpUrls },
        nonce,
        bodyHtml,
      })
    );
    return true;
  }

  // 3. Overview (/admin/)
  if (pathname === '/admin/' || pathname === '/admin') {
    const showContent = hasPermission(session, PERMISSIONS.EDIT_CONTENT);
    const showCampaigns = hasPermission(session, PERMISSIONS.MANAGE_CAMPAIGNS);
    const showProjects = hasPermission(session, PERMISSIONS.EDIT_PROJECTS);
    const showHiring = hasPermission(session, PERMISSIONS.MANAGE_VACANCIES) || hasPermission(session, PERMISSIONS.REVIEW_APPLICATIONS);
    const showLeads = hasPermission(session, PERMISSIONS.MANAGE_LEADS_CRM);

    const stats = {
      showContent,
      showCampaigns,
      showProjects,
      showHiring,
      showLeads,
      livePages: showContent ? (await db.prepare(`SELECT COUNT(*) as c FROM pages WHERE activation_state = 'Live'`).get()).c : 0,
      inReviewCount: showContent ? (await db.prepare(`SELECT COUNT(*) as c FROM pages WHERE editorial_state = 'In review'`).get()).c : 0,
      liveCampaigns: showCampaigns ? (await db.prepare(`SELECT COUNT(*) as c FROM campaigns WHERE activation_state = 'Live'`).get()).c : 0,
      liveProjects: showProjects ? (await db.prepare(`SELECT COUNT(*) as c FROM projects WHERE activation_state = 'Live' AND is_private_test = 0`).get()).c : 0,
      openJobs: showHiring ? (await db.prepare(`SELECT COUNT(*) as c FROM jobs WHERE status = 'Open'`).get()).c : 0,
      unassignedApps: showHiring ? (await db.prepare(`SELECT COUNT(*) as c FROM applications WHERE stage = 'Received'`).get()).c : 0,
      newInquiries: showLeads ? (await db.prepare(`SELECT COUNT(*) as c FROM inquiries`).get()).c : 0,
      crmFailed: showLeads ? (await db.prepare(`SELECT COUNT(*) as c FROM crm_delivery_queue WHERE status = 'failed_review'`).get()).c : 0,
    };

    const schedulerHealth = await db.prepare('SELECT * FROM scheduler_health WHERE id = 1').get();
    const recentAudit = hasPermission(session, PERMISSIONS.VIEW_AUDIT)
      ? await db.prepare(`SELECT * FROM audit_log WHERE domain != 'hiring' ORDER BY created_at DESC LIMIT 12`).all()
      : [];

    const pendingReviews = [];
    if (showContent) {
      const pgs = await db.prepare(`SELECT page_id, slug, owner_name, updated_at FROM pages WHERE editorial_state = 'In review'`).all();
      for (const p of pgs) pendingReviews.push({ type: 'Page', title: p.slug, owner: p.owner_name, updated_at: p.updated_at, href: `/admin/pages?id=${p.page_id}` });
    }
    if (showProjects) {
      const projs = await db.prepare(`SELECT project_id, title, owner_id, updated_at FROM projects WHERE editorial_state = 'In review'`).all();
      for (const p of projs) pendingReviews.push({ type: 'Project', title: p.title, owner: p.owner_id || 'Contributor', updated_at: p.updated_at, href: `/admin/projects?id=${p.project_id}` });
    }

    sendHtml(
      res,
      200,
      renderShell({
        title: 'Dashboard Overview',
        currentSection: 'overview',
        bodyHtml: AdminViews.renderAdminOverview({ user: session, stats, schedulerHealth, recentAudit, pendingReviews }),
      })
    );
    return true;
  }

  // 4. Website & Pages (with search, pagination, revision diff, articles & claims)
  if (pathname === '/admin/pages') {
    if (!hasPermission(session, PERMISSIONS.EDIT_CONTENT) && !hasPermission(session, PERMISSIONS.MANAGE_SETTINGS)) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }
    const q = String(urlObj.searchParams.get('q') || '').trim().toLowerCase();
    const stateFilter = String(urlObj.searchParams.get('state') || '').trim();
    const pageNum = urlObj.searchParams.get('page') || '1';

    const allPages = await db.prepare('SELECT * FROM pages ORDER BY slug ASC').all();
    const filteredPages = allPages.filter((p) => {
      if (stateFilter && p.editorial_state !== stateFilter && p.activation_state !== stateFilter) return false;
      if (q && !`${p.slug} ${p.title} ${p.owner_name}`.toLowerCase().includes(q)) return false;
      return true;
    });
    const pagedPages = paginateRows(filteredPages, pageNum, 10);

    const selId = urlObj.searchParams.get('id') || filteredPages[0]?.page_id || allPages[0]?.page_id;
    const selectedPage = allPages.find((p) => p.page_id === selId) || null;
    const revisions = selectedPage
      ? await db.prepare('SELECT * FROM page_revisions WHERE page_id = ? ORDER BY revision_number DESC').all(selectedPage.page_id)
      : [];

    const revANum = urlObj.searchParams.get('revA') ? Number(urlObj.searchParams.get('revA')) : revisions[1]?.revision_number || revisions[0]?.revision_number || null;
    const revBNum = urlObj.searchParams.get('revB') ? Number(urlObj.searchParams.get('revB')) : revisions[0]?.revision_number || null;
    const revA = revisions.find((r) => r.revision_number === revANum) || null;
    const revB = revisions.find((r) => r.revision_number === revBNum) || null;

    const allArticles = await db.prepare('SELECT * FROM articles ORDER BY updated_at DESC').all();
    const filteredArticles = q
      ? allArticles.filter((a) => `${a.title} ${a.slug} ${a.summary} ${a.buyer_target}`.toLowerCase().includes(q))
      : allArticles;
    const selectedArticle = allArticles.find((a) => a.article_id === urlObj.searchParams.get('article')) || null;

    const allClaims = await db.prepare('SELECT * FROM testimonials_claims ORDER BY updated_at DESC').all();
    const filteredClaims = q
      ? allClaims.filter((c) => `${c.title} ${c.exact_text} ${c.attribution}`.toLowerCase().includes(q))
      : allClaims;
    const selectedClaim = allClaims.find((c) => c.claim_id === urlObj.searchParams.get('claim')) || null;

    const redirects = await db.prepare('SELECT * FROM redirects ORDER BY old_path ASC').all();

    sendHtml(
      res,
      200,
      renderShell({
        title: 'Website & Content Operations',
        currentSection: 'pages',
        bodyHtml: AdminViews.renderAdminPagesView({
          pages: pagedPages.items,
          pagesMeta: pagedPages,
          filters: { q, state: stateFilter },
          selectedPage,
          revisions,
          revCompare: revA && revB ? { revA, revB } : null,
          articles: filteredArticles,
          selectedArticle,
          claims: filteredClaims,
          selectedClaim,
          redirects,
          user: session,
          csrfToken: session.csrf_token,
        }),
      })
    );
    return true;
  }

  // 5. Seasonal Campaigns (edit, archive, list + calendar view, conflict & fallback diagnostics)
  if (pathname === '/admin/campaigns') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_CAMPAIGNS)) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }
    const q = String(urlObj.searchParams.get('q') || '').trim().toLowerCase();
    const slotFilter = String(urlObj.searchParams.get('slot') || '').trim();
    const stateFilter = String(urlObj.searchParams.get('state') || '').trim();
    const viewMode = urlObj.searchParams.get('view') === 'calendar' ? 'calendar' : 'list';
    const monthParam = String(urlObj.searchParams.get('month') || formatPhoenixDateTime(new Date(), false).slice(0, 7)).slice(0, 7);

    const allCampaigns = await db.prepare('SELECT * FROM campaigns ORDER BY updated_at DESC').all();
    const assets = await db.prepare('SELECT * FROM media_assets ORDER BY created_at DESC').all();
    const assetById = new Map(assets.map((a) => [a.asset_id, a]));

    const enrichedCampaigns = [];
    for (const c of allCampaigns) {
      const { overlaps, equalPriorityConflicts } = await detectCampaignSlotConflicts(db, c);
      const warnings = [];
      if (equalPriorityConflicts.length > 0) {
        warnings.push(`Blocked: equal-priority overlap with "${equalPriorityConflicts[0].internal_title}"`);
      } else if (overlaps.length > 0) {
        const higher = overlaps.find((o) => Number(o.priority) > Number(c.priority));
        if (higher) {
          warnings.push(`Lower priority: overridden by "${higher.internal_title}" (P${higher.priority}) during overlap`);
        }
      }
      if (c.asset_id) {
        const asset = assetById.get(c.asset_id);
        if (!asset || asset.rights_status !== 'approved') {
          warnings.push('Fallback warning: attached image lacks approved rights (text-only fallback applies)');
        }
      }
      if (!c.is_evergreen && c.end_at && new Date(c.end_at).getTime() <= Date.now() && c.activation_state === 'Live') {
        warnings.push('Fallback warning: end time elapsed — awaiting scheduler expiry');
      }
      enrichedCampaigns.push({ ...c, warnings, equalPriorityConflicts, overlaps });
    }

    const filteredCampaigns = enrichedCampaigns.filter((c) => {
      if (slotFilter && c.placement_slot !== slotFilter) return false;
      if (stateFilter && c.activation_state !== stateFilter) return false;
      if (q && !`${c.internal_title} ${c.slug} ${c.heading}`.toLowerCase().includes(q)) return false;
      return true;
    });
    const pagedCampaigns = paginateRows(filteredCampaigns, urlObj.searchParams.get('page') || '1', 15);
    const selectedCampaign = allCampaigns.find((c) => c.campaign_id === urlObj.searchParams.get('edit')) || null;

    sendHtml(
      res,
      200,
      renderShell({
        title: 'Seasonal Campaigns & Highlights',
        currentSection: 'campaigns',
        bodyHtml: AdminViews.renderAdminCampaignsView({
          campaigns: pagedCampaigns.items,
          campaignsMeta: pagedCampaigns,
          allCampaigns: enrichedCampaigns,
          selectedCampaign,
          assets,
          viewMode,
          monthParam,
          filters: { q, slot: slotFilter, state: stateFilter },
          user: session,
          csrfToken: session.csrf_token,
        }),
      })
    );
    return true;
  }

  // 6. Projects & Media (description editing, gallery order, focal points, usage dependencies)
  if (pathname === '/admin/projects') {
    if (!hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }
    const projects = await db.prepare('SELECT * FROM projects ORDER BY updated_at DESC').all();
    const selId = urlObj.searchParams.get('id') || projects[0]?.project_id;
    const selectedProject = projects.find((p) => p.project_id === selId) || null;
    const pairs = selectedProject
      ? await db.prepare('SELECT * FROM project_before_after_pairs WHERE project_id = ? ORDER BY sort_order ASC').all(selectedProject.project_id)
      : [];
    const galleryItems = selectedProject
      ? await db
          .prepare(
            `SELECT g.*, m.original_filename, m.rights_status, m.focal_x, m.focal_y
             FROM project_gallery_items g
             JOIN media_assets m ON m.asset_id = g.asset_id
             WHERE g.project_id = ?
             ORDER BY g.sort_order ASC`
          )
          .all(selectedProject.project_id)
      : [];
    const assets = await db.prepare('SELECT * FROM media_assets ORDER BY created_at DESC').all();

    const assetUsageMap = {};
    for (const a of assets) {
      const covers = await db.prepare('SELECT project_id, title FROM projects WHERE cover_asset_id = ?').all(a.asset_id);
      const gal = await db
        .prepare('SELECT p.project_id, p.title FROM project_gallery_items g JOIN projects p ON p.project_id = g.project_id WHERE g.asset_id = ?')
        .all(a.asset_id);
      const pr = await db
        .prepare('SELECT DISTINCT p.project_id, p.title FROM project_before_after_pairs b JOIN projects p ON p.project_id = b.project_id WHERE b.before_asset_id = ? OR b.after_asset_id = ?')
        .all(a.asset_id, a.asset_id);
      const camps = await db.prepare('SELECT campaign_id, internal_title FROM campaigns WHERE asset_id = ?').all(a.asset_id);
      assetUsageMap[a.asset_id] = { covers, gal, pairs: pr, camps, total: covers.length + gal.length + pr.length + camps.length };
    }

    sendHtml(
      res,
      200,
      renderShell({
        title: 'Completed Projects & Before/After Media',
        currentSection: 'projects',
        bodyHtml: AdminViews.renderAdminProjectsView({
          projects,
          selectedProject,
          pairs,
          galleryItems,
          assets,
          assetUsageMap,
          user: session,
          csrfToken: session.csrf_token,
        }),
      })
    );
    return true;
  }

  // 7. Jobs & Protected Applications (Strict Hiring Isolation + search, filter & pagination!)
  if (pathname === '/admin/jobs') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_VACANCIES) && !hasPermission(session, PERMISSIONS.REVIEW_APPLICATIONS)) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }

    const allJobs = await db.prepare('SELECT * FROM jobs ORDER BY updated_at DESC').all();
    const jobs = allJobs.filter((j) => canAccessJobRecord(session, j));
    const selectedJob = jobs.find((j) => j.requisition_id === urlObj.searchParams.get('job')) || null;

    const allApps = await db
      .prepare(
        `SELECT a.*, ap.name as applicant_name, ap.email_normalized, ap.phone_normalized, ap.preferred_method, ap.city_or_zip,
                j.title as job_title,
                (SELECT COUNT(*) FROM application_attachments aa WHERE aa.application_id = a.application_id AND aa.deleted_at IS NULL) as att_count,
                (SELECT MAX(aa.scan_state) FROM application_attachments aa WHERE aa.application_id = a.application_id AND aa.deleted_at IS NULL) as att_scan_state
         FROM applications a
         JOIN applicants ap ON ap.applicant_id = a.applicant_id
         JOIN jobs j ON j.requisition_id = a.requisition_id
         ORDER BY a.received_at DESC`
      )
      .all();
    const scopedApps = [];
    for (const a of allApps) {
      if (await canAccessApplicationRecord(db, session, a)) scopedApps.push(a);
    }

    const q = String(urlObj.searchParams.get('q') || '').trim().toLowerCase();
    const reqFilter = String(urlObj.searchParams.get('req') || '').trim();
    const stageFilter = String(urlObj.searchParams.get('stage') || '').trim();
    const revFilter = String(urlObj.searchParams.get('reviewer') || '').trim();
    const attFilter = String(urlObj.searchParams.get('att') || '').trim();

    const filteredApps = scopedApps.filter((a) => {
      if (reqFilter && a.requisition_id !== reqFilter) return false;
      if (stageFilter && a.stage !== stageFilter) return false;
      if (revFilter === 'unassigned' && a.assigned_reviewer_id) return false;
      if (revFilter && revFilter !== 'unassigned' && a.assigned_reviewer_id !== revFilter) return false;
      if (attFilter === 'clean' && a.att_scan_state !== 'clean') return false;
      if (attFilter === 'none' && a.att_count > 0) return false;
      if (q) {
        const hay = `${a.applicant_name} ${a.email_normalized || ''} ${a.phone_normalized || ''} ${a.application_id} ${a.job_title}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    const pagedApps = paginateRows(filteredApps, urlObj.searchParams.get('page') || '1', 15);

    const selAppId = urlObj.searchParams.get('app');
    let selectedApp = scopedApps.find((a) => a.application_id === selAppId) || null;
    if (selAppId && !selectedApp) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }
    if (selectedApp) {
      let snapshot = {};
      let answers = {};
      try { snapshot = JSON.parse(selectedApp.snapshot_json || '{}'); } catch {}
      try { answers = JSON.parse(selectedApp.answers_json || '{}'); } catch {}
      const attachments = await db.prepare('SELECT * FROM application_attachments WHERE application_id = ? AND deleted_at IS NULL').all(selectedApp.application_id);
      const notes = await db.prepare('SELECT * FROM application_notes WHERE application_id = ? ORDER BY created_at DESC').all(selectedApp.application_id);
      selectedApp = { ...selectedApp, snapshot, answers, attachments, notes };
    }

    const reviewers = await db.prepare(`SELECT user_id, full_name, role FROM users WHERE active = 1 AND role IN ('Hiring Owner', 'Hiring Reviewer')`).all();

    sendHtml(
      res,
      200,
      renderShell({
        title: 'Hiring & Protected Applicant Workspace',
        currentSection: 'jobs',
        bodyHtml: AdminViews.renderAdminJobsView({
          jobs,
          selectedJob,
          applications: pagedApps.items,
          appsMeta: pagedApps,
          filters: { q, req: reqFilter, stage: stageFilter, reviewer: revFilter, att: attFilter },
          selectedApp,
          reviewers,
          user: session,
          csrfToken: session.csrf_token,
        }),
      })
    );
    return true;
  }

  // 8. Leads & CRM Operations (with search, filter, pagination & secure inquiry attachments)
  if (pathname === '/admin/leads') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_LEADS_CRM)) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }
    const q = String(urlObj.searchParams.get('q') || '').trim().toLowerCase();
    const classFilter = String(urlObj.searchParams.get('classification') || '').trim();
    const statusFilter = String(urlObj.searchParams.get('status') || '').trim();

    const allInquiries = await db
      .prepare(
        `SELECT i.*, a.organization_name as org_name, p.city_or_zip as prop_loc
         FROM inquiries i
         JOIN accounts a ON a.account_id = i.account_id
         LEFT JOIN properties p ON p.property_id = i.property_id
         ORDER BY i.received_at DESC`
      )
      .all();

    const filteredInquiries = allInquiries.filter((inq) => {
      if (classFilter && inq.classification !== classFilter) return false;
      if (statusFilter && inq.status !== statusFilter) return false;
      if (q && !`${inq.inquiry_id} ${inq.org_name} ${inq.prop_loc || ''} ${inq.service_family}`.toLowerCase().includes(q)) return false;
      return true;
    });
    const pagedInquiries = paginateRows(filteredInquiries, urlObj.searchParams.get('page') || '1', 20);

    const inquiryAttachments = {};
    for (const inq of pagedInquiries.items) {
      inquiryAttachments[inq.inquiry_id] = await db
        .prepare('SELECT attachment_id, inquiry_id, original_name, mime_type, byte_size, scan_state, created_at FROM inquiry_attachments WHERE inquiry_id = ?')
        .all(inq.inquiry_id);
    }

    const crmQueue = await db.prepare('SELECT * FROM crm_delivery_queue ORDER BY created_at DESC LIMIT 50').all();
    const notifications = await db.prepare(`SELECT * FROM notification_queue WHERE domain != 'hiring' ORDER BY created_at DESC LIMIT 50`).all();

    sendHtml(
      res,
      200,
      renderShell({
        title: 'Commercial Leads & CRM Delivery',
        currentSection: 'leads',
        bodyHtml: AdminViews.renderAdminLeadsView({
          inquiries: pagedInquiries.items,
          inquiriesMeta: pagedInquiries,
          inquiryAttachments,
          filters: { q, classification: classFilter, status: statusFilter },
          crmQueue,
          notifications,
          crmFaultMode: getCrmFaultMode(),
          csrfToken: session.csrf_token,
        }),
      })
    );
    return true;
  }

  // 9. Reviews & Activity
  if (pathname === '/admin/reviews') {
    if (!hasPermission(session, PERMISSIONS.PUBLISH_CONTENT) && !hasPermission(session, PERMISSIONS.VIEW_AUDIT)) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }
    const domainFilter = String(urlObj.searchParams.get('domain') || '').trim();
    const logsAll = await db.prepare(`SELECT * FROM audit_log WHERE domain != 'hiring' ORDER BY created_at DESC LIMIT 200`).all();
    const filteredLogs = domainFilter ? logsAll.filter((l) => l.domain === domainFilter) : logsAll;
    const pagedLogs = paginateRows(filteredLogs, urlObj.searchParams.get('page') || '1', 25);

    const html = `<section class="admin-card">
      <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0.75rem;margin-bottom:1rem;">
        <h2 style="margin:0;">Audit Trail (Non-Hiring Operations)</h2>
        <form method="GET" action="/admin/reviews" style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;">
          <label for="aud-domain" class="visually-hidden">Domain filter</label>
          <select id="aud-domain" name="domain" style="min-height:40px;">
            <option value="">All domains</option>
            ${['auth', 'users', 'content', 'campaigns', 'projects', 'media', 'crm', 'notifications', 'settings', 'ops']
              .map((d) => `<option value="${d}"${domainFilter === d ? ' selected' : ''}>${d}</option>`)
              .join('')}
          </select>
          <button type="submit" class="btn btn--secondary" style="min-height:40px;">Filter</button>
          ${domainFilter ? '<a href="/admin/reviews" class="btn btn--secondary" style="min-height:40px;">Clear</a>' : ''}
        </form>
      </div>
      <div class="table-scroll" tabindex="0" role="region" aria-label="Audit Trail Table">
        <table class="data-table">
          <thead><tr><th>Time (Phoenix)</th><th>Actor</th><th>Domain</th><th>Action</th><th>Object</th><th>Details</th></tr></thead>
          <tbody>${pagedLogs.items
            .map(
              (l) => `<tr><td>${escapeHtml(formatPhoenixDateTime(l.created_at, false))}</td><td>${escapeHtml(l.actor_name)} (${escapeHtml(l.actor_role)})</td><td>${escapeHtml(l.domain)}</td><td>${escapeHtml(l.action)}</td><td><code>${escapeHtml(l.object_type)}:${escapeHtml(l.object_id)}</code></td><td><small class="muted">${escapeHtml(l.details_json)}</small></td></tr>`
            )
            .join('')}</tbody>
        </table>
      </div>
      ${AdminViews.renderPaginationNav('/admin/reviews', pagedLogs, { domain: domainFilter })}
    </section>`;
    sendHtml(res, 200, renderShell({ title: 'Reviews & Activity Audit', currentSection: 'reviews', bodyHtml: html }));
    return true;
  }

  // 10. Analytics & Reporting
  if (pathname === '/admin/analytics') {
    if (!hasPermission(session, PERMISSIONS.VIEW_ANALYTICS) && !hasPermission(session, PERMISSIONS.MANAGE_LEADS_CRM)) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }
    const summary = await getAnalyticsSummary(db);
    sendHtml(
      res,
      200,
      renderShell({
        title: 'Analytics & Attribution Reporting',
        currentSection: 'analytics',
        bodyHtml: AdminViews.renderAdminAnalyticsView({ summary }),
      })
    );
    return true;
  }

  // 11. Settings, Users & Backups
  if (pathname === '/admin/settings') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_USERS) && !hasPermission(session, PERMISSIONS.MANAGE_SETTINGS)) {
      forbidden(res, session, session.csrf_token, nonce);
      return true;
    }
    const settings = await getCanonicalSettings(db);
    const users = await db
      .prepare('SELECT user_id, email, full_name, role, extra_roles_json, mfa_enabled, active, created_at, updated_at FROM users ORDER BY active DESC, role ASC, full_name ASC')
      .all();
    const sessionRows = await db
      .prepare('SELECT user_id, COUNT(*) as session_count FROM sessions WHERE expires_at > ? GROUP BY user_id')
      .all(new Date().toISOString());
    const activeSessionsMap = Object.fromEntries(sessionRows.map((r) => [r.user_id, r.session_count]));
    const backupRuns = hasPermission(session, PERMISSIONS.MANAGE_BACKUPS)
      ? await db.prepare('SELECT * FROM backup_runs ORDER BY created_at DESC LIMIT 20').all()
      : [];
    const retentionPolicies = hasPermission(session, PERMISSIONS.MANAGE_BACKUPS)
      ? await db.prepare('SELECT * FROM retention_policies ORDER BY policy_key ASC').all()
      : [];

    sendHtml(
      res,
      200,
      renderShell({
        title: 'Users, Settings & Backups',
        currentSection: 'settings',
        bodyHtml: AdminViews.renderAdminSettingsView({
          settings,
          users,
          activeSessionsMap,
          rolePermissionMap: ROLE_PERMISSION_MAP,
          backupRuns,
          retentionPolicies,
          user: session,
          csrfToken: session.csrf_token,
        }),
      })
    );
    return true;
  }

  return false;
}
