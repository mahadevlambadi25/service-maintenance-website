import path from 'node:path';
import { ENV, ROLES, STORAGE_PATHS, UPLOAD_LIMITS } from '../config.js';
import { generateTotpSecret, generateUuid, hashPassword } from '../lib/crypto.js';
import { processPrivateDocumentUploadAsync, processProjectImageUploadAsync } from '../lib/media-processor.js';
import { parseRequestBody } from '../lib/multipart.js';
import { buildSafeCsv, isSafeUrl, sanitizeRichHtml } from '../lib/sanitize.js';
import { isValidEmail } from '../lib/validation.js';
import { phoenixLocalToUtcIso } from '../lib/time.js';
import {
  authenticateSession,
  canAccessApplicationRecord,
  canAccessJobRecord,
  encryptMfaSecret,
  getUserRoles,
  hasPermission,
  issueMfaSetupToken,
  PERMISSIONS,
  recordAudit,
  revokeUserSessions,
  ROLE_PERMISSION_MAP,
} from '../services/auth.js';
import { bumpPublicCache, detectCampaignSlotConflicts, runScheduleEvaluation } from '../services/campaign-engine.js';
import { recordAnalyticsEvent } from '../services/analytics.js';
import { createFullBackup, restoreFromBackup, verifyBackupIntegrity } from '../services/backup-service.js';
import { setCrmFaultMode, syncDealMilestoneToFreshsales } from '../services/crm-adapter.js';
import { processDeliveryQueues } from '../services/delivery-worker.js';
import { createObjectStore } from '../services/object-store.js';
import { approveRetentionPolicy, runRetentionSweep } from '../services/retention-service.js';

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(data));
}

function verifyCsrf(session, req, fields) {
  const token = req.headers['x-csrf-token'] || fields?.csrf_token;
  return Boolean(token && token === session.csrf_token);
}

export async function handleAdminApi(req, res, db, urlObj, storagePaths = STORAGE_PATHS) {
  const pathname = urlObj.pathname;
  if (!pathname.startsWith('/admin/api/')) return false;

  const session = await authenticateSession(db, req);
  if (!session) {
    sendJson(res, 401, { ok: false, message: 'Authentication required.' });
    return true;
  }

  // ============================================================
  // 1. PROTECTED MEDIA PREVIEW, USAGE, INQUIRY & RESUME DOWNLOAD (GET)
  // ============================================================
  const mediaPreviewMatch = pathname.match(/^\/admin\/api\/media\/preview\/([a-zA-Z0-9-]+)$/);
  if (mediaPreviewMatch && req.method === 'GET') {
    if (
      !hasPermission(session, PERMISSIONS.EDIT_PROJECTS) &&
      !hasPermission(session, PERMISSIONS.UPLOAD_PROJECT_MEDIA) &&
      !hasPermission(session, PERMISSIONS.PUBLISH_PROJECTS) &&
      !hasPermission(session, PERMISSIONS.MANAGE_CAMPAIGNS)
    ) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const asset = await db.prepare('SELECT * FROM media_assets WHERE asset_id = ?').get(mediaPreviewMatch[1]);
    if (!asset) {
      res.writeHead(404);
      res.end('Not found');
      return true;
    }
    const store = createObjectStore(storagePaths);
    const mediaBuf = await store.getObjectBuffer({ area: 'publicMedia', key: asset.public_derivative_key });
    if (!mediaBuf) {
      res.writeHead(404);
      res.end('Not found');
      return true;
    }
    res.writeHead(200, {
      'Content-Type': asset.derivative_mime || 'image/jpeg',
      'Content-Length': mediaBuf.length,
      'Cache-Control': 'no-store',
    });
    res.end(mediaBuf);
    return true;
  }

  const mediaUsageMatch = pathname.match(/^\/admin\/api\/media\/([a-zA-Z0-9-]+)\/usage$/);
  if (mediaUsageMatch && req.method === 'GET') {
    if (
      !hasPermission(session, PERMISSIONS.EDIT_PROJECTS) &&
      !hasPermission(session, PERMISSIONS.UPLOAD_PROJECT_MEDIA) &&
      !hasPermission(session, PERMISSIONS.PUBLISH_PROJECTS) &&
      !hasPermission(session, PERMISSIONS.MANAGE_CAMPAIGNS)
    ) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const asset = await db.prepare('SELECT asset_id, original_filename, rights_status FROM media_assets WHERE asset_id = ?').get(mediaUsageMatch[1]);
    if (!asset) {
      sendJson(res, 404, { ok: false, message: 'Asset not found.' });
      return true;
    }
    const coverProjects = await db
      .prepare('SELECT project_id, title, slug, activation_state FROM projects WHERE cover_asset_id = ?')
      .all(asset.asset_id);
    const pairRefs = await db
      .prepare(
        `SELECT p.pair_id, p.pair_title, pr.project_id, pr.title as project_title, pr.activation_state
         FROM project_before_after_pairs p
         JOIN projects pr ON pr.project_id = p.project_id
         WHERE p.before_asset_id = ? OR p.after_asset_id = ?`
      )
      .all(asset.asset_id, asset.asset_id);
    const galleryRefs = await db
      .prepare(
        `SELECT g.item_id, pr.project_id, pr.title as project_title, pr.activation_state
         FROM project_gallery_items g
         JOIN projects pr ON pr.project_id = g.project_id
         WHERE g.asset_id = ?`
      )
      .all(asset.asset_id);
    const campaignRefs = await db
      .prepare('SELECT campaign_id, internal_title, slug, placement_slot, activation_state FROM campaigns WHERE asset_id = ?')
      .all(asset.asset_id);

    const totalAffected = coverProjects.length + pairRefs.length + galleryRefs.length + campaignRefs.length;
    sendJson(res, 200, {
      ok: true,
      asset,
      totalAffected,
      affected: {
        coverProjects,
        pairRefs,
        galleryRefs,
        campaignRefs,
      },
    });
    return true;
  }

  const pageCompareMatch = pathname.match(/^\/admin\/api\/pages\/([a-zA-Z0-9-]+)\/compare$/);
  if (pageCompareMatch && req.method === 'GET') {
    if (
      !hasPermission(session, PERMISSIONS.VIEW_CONTENT) &&
      !hasPermission(session, PERMISSIONS.EDIT_CONTENT) &&
      !hasPermission(session, PERMISSIONS.APPROVE_CONTENT) &&
      !hasPermission(session, PERMISSIONS.PUBLISH_CONTENT)
    ) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const page = await db.prepare('SELECT * FROM pages WHERE page_id = ?').get(pageCompareMatch[1]);
    if (!page) {
      sendJson(res, 404, { ok: false, message: 'Page not found.' });
      return true;
    }
    const revANum = Number(urlObj.searchParams.get('revA') || Math.max(1, page.current_revision - 1));
    const revBNum = Number(urlObj.searchParams.get('revB') || page.current_revision);
    const revA = await db.prepare('SELECT * FROM page_revisions WHERE page_id = ? AND revision_number = ?').get(page.page_id, revANum);
    const revB = await db.prepare('SELECT * FROM page_revisions WHERE page_id = ? AND revision_number = ?').get(page.page_id, revBNum);
    if (!revA || !revB) {
      sendJson(res, 404, { ok: false, message: 'Selected revisions not found.' });
      return true;
    }
    const compareFields = [
      { key: 'title', label: 'Page Title' },
      { key: 'meta_title', label: 'SEO Meta Title' },
      { key: 'meta_description', label: 'SEO Meta Description' },
      { key: 'hero_headline', label: 'Hero Headline' },
      { key: 'hero_summary', label: 'Hero Summary' },
      { key: 'cta_label', label: 'CTA Label' },
      { key: 'body_html', label: 'Body Content' },
    ];
    const diffs = compareFields.map((f) => ({
      field: f.key,
      label: f.label,
      changed: String(revA[f.key] || '') !== String(revB[f.key] || ''),
      before: String(revA[f.key] || ''),
      after: String(revB[f.key] || ''),
    }));
    sendJson(res, 200, { ok: true, page_id: page.page_id, revA: revANum, revB: revBNum, diffs });
    return true;
  }

  const inquiryAttachmentMatch = pathname.match(/^\/admin\/api\/inquiries\/([a-zA-Z0-9-]+)\/attachments\/([a-zA-Z0-9-]+)$/);
  if (inquiryAttachmentMatch && req.method === 'GET') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_LEADS_CRM)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Lead & CRM permission required.' });
      return true;
    }
    const [, inquiryId, attId] = inquiryAttachmentMatch;
    const inquiry = await db.prepare('SELECT inquiry_id FROM inquiries WHERE inquiry_id = ?').get(inquiryId);
    if (!inquiry) {
      sendJson(res, 404, { ok: false, message: 'Inquiry not found.' });
      return true;
    }
    const att = await db
      .prepare('SELECT * FROM inquiry_attachments WHERE attachment_id = ? AND inquiry_id = ?')
      .get(attId, inquiryId);
    if (!att || att.scan_state !== 'clean') {
      sendJson(res, 403, { ok: false, message: 'Attachment unavailable or quarantined.' });
      return true;
    }
    const store = createObjectStore(storagePaths);
    const attBuf = await store.getObjectBuffer({ area: 'quarantine', key: path.basename(att.storage_key) });
    if (!attBuf) {
      sendJson(res, 404, { ok: false, message: 'Attachment file missing from private storage.' });
      return true;
    }
    const inlineMode = urlObj.searchParams.get('inline') === '1';
    await recordAudit(db, session, 'crm', inlineMode ? 'view_inquiry_attachment' : 'download_inquiry_attachment', 'inquiry_attachment', att.attachment_id, {
      inquiry_id: inquiryId,
    });
    const safeFileName = att.original_name.replace(/["\r\n]/g, '');
    res.writeHead(200, {
      'Content-Type': att.mime_type,
      'Content-Length': attBuf.length,
      'Content-Disposition': `${inlineMode ? 'inline' : 'attachment'}; filename="${safeFileName}"`,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
      ...(inlineMode ? { 'Content-Security-Policy': "sandbox" } : {}),
    });
    res.end(attBuf);
    return true;
  }

  const resumeDownloadMatch = pathname.match(/^\/admin\/api\/applications\/([a-zA-Z0-9-]+)\/attachments\/([a-zA-Z0-9-]+)$/);
  if (resumeDownloadMatch && req.method === 'GET') {
    if (!hasPermission(session, PERMISSIONS.REVIEW_APPLICATIONS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: hiring permission required.' });
      return true;
    }
    const app = await db.prepare('SELECT * FROM applications WHERE application_id = ?').get(resumeDownloadMatch[1]);
    if (!app || !await canAccessApplicationRecord(db, session, app)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: outside assigned recruiting scope.' });
      return true;
    }
    const att = await db
      .prepare('SELECT * FROM application_attachments WHERE attachment_id = ? AND application_id = ? AND deleted_at IS NULL')
      .get(resumeDownloadMatch[2], app.application_id);
    if (!att || att.scan_state !== 'clean') {
      sendJson(res, 403, { ok: false, message: 'Attachment unavailable or quarantined.' });
      return true;
    }
    const store = createObjectStore(storagePaths);
    const resumeBuf = await store.getObjectBuffer({ area: 'resumes', key: path.basename(att.storage_key) });
    if (!resumeBuf) {
      res.writeHead(404);
      res.end('File missing');
      return true;
    }
    await recordAudit(db, session, 'hiring', 'download_resume', 'application_attachment', att.attachment_id, {
      application_id: app.application_id,
    });
    res.writeHead(200, {
      'Content-Type': att.mime_type,
      'Content-Length': resumeBuf.length,
      'Content-Disposition': `attachment; filename="${att.original_display_name.replace(/"/g, '')}"`,
      'Cache-Control': 'no-store',
    });
    res.end(resumeBuf);
    return true;
  }

  // ============================================================
  // 2. CWE-1236 SAFE CSV EXPORT OF APPLICATIONS (GET)
  // ============================================================
  if (pathname === '/admin/api/applications/export.csv' && req.method === 'GET') {
    if (!hasPermission(session, PERMISSIONS.EXPORT_APPLICATIONS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Hiring export privilege required.' });
      return true;
    }
    const allCandidateRows = await db
      .prepare(
        `SELECT a.application_id, a.requisition_id, a.opening_cycle_id, a.stage, a.received_at,
                ap.name, ap.preferred_method, ap.email_normalized, ap.phone_normalized, ap.city_or_zip,
                a.answers_json, j.title as job_title
         FROM applications a
         JOIN applicants ap ON ap.applicant_id = a.applicant_id
         JOIN jobs j ON j.requisition_id = a.requisition_id
         ORDER BY a.received_at DESC`
      )
      .all();
    const rows = [];
    for (const r of allCandidateRows) {
      if (await canAccessApplicationRecord(db, session, r)) rows.push(r);
    }

    const headers = ['Application ID', 'Requisition ID', 'Opening Cycle', 'Role', 'Stage', 'Received At', 'Applicant Name', 'Preferred Contact', 'Email', 'Phone', 'City/ZIP', 'Experience'];
    const csvRows = rows.map((r) => {
      let exp = '';
      try { exp = JSON.parse(r.answers_json || '{}').relevant_experience || ''; } catch {}
      return [
        r.application_id,
        r.requisition_id,
        r.opening_cycle_id,
        r.job_title,
        r.stage,
        r.received_at,
        r.name,
        r.preferred_method,
        r.email_normalized || '',
        r.phone_normalized || '',
        r.city_or_zip || '',
        exp,
      ];
    });

    const csv = buildSafeCsv(headers, csvRows);
    await recordAudit(db, session, 'hiring', 'export_applications_csv', 'applicant_export', generateUuid(), { row_count: rows.length });
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="applications-export.csv"',
      'Cache-Control': 'no-store',
    });
    res.end(csv);
    return true;
  }

  // ============================================================
  // 3. PORTABLE COMPANY DATA BACKUP EXPORT (GET)
  // ============================================================
  if (pathname === '/admin/api/backup/export.json' && req.method === 'GET') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_BACKUPS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: backup permission required.' });
      return true;
    }
    // Platform Administrator backup includes content/campaigns/projects/inquiries/redirects (no raw resume files)
    const snapshot = {
      exported_at: new Date().toISOString(),
      business_settings: (await db.prepare('SELECT * FROM business_settings WHERE id = 1').get()),
      pages: (await db.prepare('SELECT * FROM pages').all()),
      page_revisions: (await db.prepare('SELECT * FROM page_revisions').all()),
      campaigns: (await db.prepare('SELECT * FROM campaigns').all()),
      projects: (await db.prepare('SELECT * FROM projects').all()),
      project_before_after_pairs: (await db.prepare('SELECT * FROM project_before_after_pairs').all()),
      media_assets: (await db.prepare('SELECT * FROM media_assets').all()),
      redirects: (await db.prepare('SELECT * FROM redirects').all()),
      inquiries: (await db.prepare('SELECT * FROM inquiries').all()),
    };
    await recordAudit(db, session, 'ops', 'export_backup_json', 'backup', snapshot.exported_at);
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="service-maintenance-backup.json"',
      'Cache-Control': 'no-store',
    });
    res.end(JSON.stringify(snapshot, null, 2));
    return true;
  }

  // ============================================================
  // 3b. SAFE READ-ONLY STAFF USER & ROLE INSPECTION API (GET)
  // ============================================================
  if (pathname === '/admin/api/users' && req.method === 'GET') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_USERS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Platform Administrator required.' });
      return true;
    }
    const rows = await db
      .prepare('SELECT user_id, email, full_name, role, extra_roles_json, mfa_enabled, mfa_enrolled, last_login_at, active, created_at, updated_at FROM users ORDER BY active DESC, role ASC, full_name ASC')
      .all();
    const safeUsers = rows.map((u) => {
      const roles = getUserRoles(u);
      const permissions = Array.from(new Set(roles.flatMap((r) => ROLE_PERMISSION_MAP[r] || [])));
      return {
        user_id: u.user_id,
        email: u.email,
        full_name: u.full_name,
        role: u.role,
        roles,
        permissions,
        mfa_enabled: Boolean(u.mfa_enabled),
        mfa_enrolled: Boolean(u.mfa_enrolled),
        last_login_at: u.last_login_at || null,
        active: Boolean(u.active),
        created_at: u.created_at,
        updated_at: u.updated_at,
      };
    });
    sendJson(res, 200, { ok: true, users: safeUsers });
    return true;
  }

  const userGetDetailMatch = pathname.match(/^\/admin\/api\/users\/([a-zA-Z0-9-]+)$/);
  if (userGetDetailMatch && req.method === 'GET') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_USERS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Platform Administrator required.' });
      return true;
    }
    const targetUser = await db
      .prepare('SELECT user_id, email, full_name, role, extra_roles_json, mfa_enabled, mfa_enrolled, last_login_at, active, created_at, updated_at FROM users WHERE user_id = ?')
      .get(userGetDetailMatch[1]);
    if (!targetUser) {
      sendJson(res, 404, { ok: false, message: 'Staff user not found.' });
      return true;
    }
    const roles = getUserRoles(targetUser);
    const permissions = Array.from(new Set(roles.flatMap((r) => ROLE_PERMISSION_MAP[r] || [])));
    const recentActivity = await db
      .prepare(`SELECT audit_id, domain, action, object_type, object_id, created_at FROM audit_log WHERE domain != 'hiring' AND (actor_id = ? OR object_id = ?) ORDER BY created_at DESC LIMIT 20`)
      .all(targetUser.user_id, targetUser.user_id);
    sendJson(res, 200, {
      ok: true,
      user: {
        user_id: targetUser.user_id,
        email: targetUser.email,
        full_name: targetUser.full_name,
        role: targetUser.role,
        roles,
        permissions,
        mfa_enabled: Boolean(targetUser.mfa_enabled),
        mfa_enrolled: Boolean(targetUser.mfa_enrolled),
        last_login_at: targetUser.last_login_at || null,
        active: Boolean(targetUser.active),
        created_at: targetUser.created_at,
        updated_at: targetUser.updated_at,
      },
      recentActivity,
    });
    return true;
  }

  // All mutating endpoints below must be POST and verify CSRF
  if (req.method !== 'POST') return false;

  const isMultipart = String(req.headers['content-type'] || '').includes('multipart/form-data');
  let parsed;
  try {
    parsed = await parseRequestBody(req, isMultipart ? UPLOAD_LIMITS.projectMedia.maxBatchBytes + 2 * 1024 * 1024 : 2 * 1024 * 1024);
  } catch (err) {
    sendJson(res, err.statusCode || 400, { ok: false, message: err.message });
    return true;
  }
  const { fields, files } = parsed;

  if (!verifyCsrf(session, req, fields)) {
    sendJson(res, 403, { ok: false, message: 'Invalid CSRF token.' });
    return true;
  }

  const nowIso = new Date().toISOString();

  // ============================================================
  // 4. PAGES & CONTENT WORKFLOW (Draft, Concurrency Check, Review, Publish, Restore)
  // ============================================================
  const pageDraftMatch = pathname.match(/^\/admin\/api\/pages\/([a-zA-Z0-9-]+)\/draft$/);
  if (pageDraftMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const page = await db.prepare('SELECT * FROM pages WHERE page_id = ?').get(pageDraftMatch[1]);
    if (!page) {
      sendJson(res, 404, { ok: false, message: 'Page not found.' });
      return true;
    }
    const expectedRev = Number(fields.expected_revision);
    if (Number.isFinite(expectedRev) && expectedRev !== page.current_revision) {
      sendJson(res, 409, {
        ok: false,
        code: 'concurrent_edit_conflict',
        message: `Concurrent edit detected: expected v${expectedRev}, current is v${page.current_revision}. Reload to review newer changes.`,
      });
      return true;
    }
    const nextRev = page.current_revision + 1;
    const prev = await db.prepare('SELECT * FROM page_revisions WHERE page_id = ? AND revision_number = ?').get(page.page_id, page.current_revision);
    await db.prepare(
      `INSERT INTO page_revisions (
        revision_id, page_id, revision_number, title, meta_title, meta_description,
        hero_headline, hero_summary, cta_label, cta_route, body_html,
        scopes_json, faqs_json, claim_status, author_id, editorial_state, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed wording', ?, 'Draft', ?)`
    ).run(
      generateUuid(),
      page.page_id,
      nextRev,
      String(fields.title || prev.title).slice(0, 200),
      String(fields.meta_title || prev.meta_title).slice(0, 200),
      String(fields.meta_description || prev.meta_description).slice(0, 400),
      String(fields.hero_headline || prev.hero_headline).slice(0, 240),
      String(fields.hero_summary || prev.hero_summary).slice(0, 500),
      String(fields.cta_label || prev.cta_label).slice(0, 80),
      prev.cta_route,
      sanitizeRichHtml(fields.body_html ?? prev.body_html),
      prev.scopes_json,
      prev.faqs_json,
      session.user_id,
      nowIso
    );
    await db.prepare(`UPDATE pages SET current_revision = ?, editorial_state = 'Draft', updated_at = ? WHERE page_id = ?`).run(nextRev, nowIso, page.page_id);
    await recordAudit(db, session, 'content', 'save_page_draft', 'page', page.page_id, { revision: nextRev });
    sendJson(res, 200, { ok: true, revision_number: nextRev });
    return true;
  }

  const pageReviewMatch = pathname.match(/^\/admin\/api\/pages\/([a-zA-Z0-9-]+)\/submit-review$/);
  if (pageReviewMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const page = await db.prepare('SELECT * FROM pages WHERE page_id = ?').get(pageReviewMatch[1]);
    if (!page) {
      sendJson(res, 404, { ok: false, message: 'Page not found.' });
      return true;
    }
    (await db.prepare(`UPDATE pages SET editorial_state = 'In review', updated_at = ? WHERE page_id = ?`).run(nowIso, page.page_id));
    await db.prepare(`UPDATE page_revisions SET editorial_state = 'In review' WHERE page_id = ? AND revision_number = ?`).run(page.page_id, page.current_revision);
    await recordAudit(db, session, 'content', 'submit_page_review', 'page', page.page_id, { revision: page.current_revision });
    sendJson(res, 200, { ok: true });
    return true;
  }

  const pageReturnMatch = pathname.match(/^\/admin\/api\/pages\/([a-zA-Z0-9-]+)\/return-draft$/);
  if (pageReturnMatch) {
    if (!hasPermission(session, PERMISSIONS.APPROVE_CONTENT) && !hasPermission(session, PERMISSIONS.PUBLISH_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Approver and Publisher permission required to return revisions.' });
      return true;
    }
    const page = await db.prepare('SELECT * FROM pages WHERE page_id = ?').get(pageReturnMatch[1]);
    if (!page) {
      sendJson(res, 404, { ok: false, message: 'Page not found.' });
      return true;
    }
    const reviewComment = String(fields.review_comment || '').trim().slice(0, 500);
    if (!reviewComment) {
      sendJson(res, 422, { ok: false, message: 'Review comment is required when returning a revision to Draft.' });
      return true;
    }
    await db.prepare(`UPDATE pages SET editorial_state = 'Draft', updated_at = ? WHERE page_id = ?`).run(nowIso, page.page_id);
    await db
      .prepare(`UPDATE page_revisions SET editorial_state = 'Draft', review_comment = ?, approver_id = ? WHERE page_id = ? AND revision_number = ?`)
      .run(reviewComment, session.user_id, page.page_id, page.current_revision);
    await recordAudit(db, session, 'content', 'return_page_draft', 'page', page.page_id, {
      revision: page.current_revision,
      review_comment: reviewComment,
    });
    sendJson(res, 200, { ok: true, editorial_state: 'Draft', revision_number: page.current_revision, review_comment: reviewComment });
    return true;
  }

  const pagePublishMatch = pathname.match(/^\/admin\/api\/pages\/([a-zA-Z0-9-]+)\/publish$/);
  if (pagePublishMatch) {
    if (!hasPermission(session, PERMISSIONS.PUBLISH_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Approver and Publisher permission required.' });
      return true;
    }
    const page = await db.prepare('SELECT * FROM pages WHERE page_id = ?').get(pagePublishMatch[1]);
    if (!page) {
      sendJson(res, 404, { ok: false, message: 'Page not found.' });
      return true;
    }
    (await db.prepare(
      `UPDATE pages SET editorial_state = 'Approved', activation_state = 'Live', published_revision = current_revision, updated_at = ? WHERE page_id = ?`
    ).run(nowIso, page.page_id));
    await db.prepare(
      `UPDATE page_revisions SET editorial_state = 'Approved', approver_id = ? WHERE page_id = ? AND revision_number = ?`
    ).run(session.user_id, page.page_id, page.current_revision);
    await bumpPublicCache(db);
    await recordAudit(db, session, 'content', 'publish_page', 'page', page.page_id, { revision: page.current_revision });
    sendJson(res, 200, { ok: true, public_url: page.slug });
    return true;
  }

  const pageRestoreMatch = pathname.match(/^\/admin\/api\/pages\/([a-zA-Z0-9-]+)\/restore$/);
  if (pageRestoreMatch) {
    if (!hasPermission(session, PERMISSIONS.PUBLISH_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const page = await db.prepare('SELECT * FROM pages WHERE page_id = ?').get(pageRestoreMatch[1]);
    const rev = await db
      .prepare('SELECT * FROM page_revisions WHERE page_id = ? AND revision_number = ?')
      .get(pageRestoreMatch[1], Number(fields.revision_number));
    if (!page || !rev) {
      sendJson(res, 404, { ok: false, message: 'Revision not found.' });
      return true;
    }
    // Restore creates a reviewable Draft revision (does NOT silently publish or revive withdrawn claims)
    const nextRev = page.current_revision + 1;
    await db.prepare(
      `INSERT INTO page_revisions (
        revision_id, page_id, revision_number, title, meta_title, meta_description,
        hero_headline, hero_summary, cta_label, cta_route, body_html,
        scopes_json, faqs_json, claim_status, author_id, editorial_state, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed wording', ?, 'Draft', ?)`
    ).run(
      generateUuid(),
      page.page_id,
      nextRev,
      rev.title,
      rev.meta_title,
      rev.meta_description,
      rev.hero_headline,
      rev.hero_summary,
      rev.cta_label,
      rev.cta_route,
      rev.body_html,
      rev.scopes_json,
      rev.faqs_json,
      session.user_id,
      nowIso
    );
    await db.prepare(`UPDATE pages SET current_revision = ?, editorial_state = 'Draft', updated_at = ? WHERE page_id = ?`).run(nextRev, nowIso, page.page_id);
    await recordAudit(db, session, 'content', 'restore_revision_to_draft', 'page', page.page_id, { restored_from: rev.revision_number, new_revision: nextRev });
    sendJson(res, 200, { ok: true, revision_number: nextRev });
    return true;
  }

  // Redirects
  if (pathname === '/admin/api/redirects') {
    if (!hasPermission(session, PERMISSIONS.EDIT_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const oldPath = String(fields.old_path || '').trim();
    const destPath = String(fields.destination_path || '').trim();
    if (!oldPath.startsWith('/') || !isSafeUrl(destPath) || oldPath === destPath) {
      sendJson(res, 422, { ok: false, message: 'Invalid redirect path or loop detected.' });
      return true;
    }
    const reverse = await db.prepare('SELECT 1 FROM redirects WHERE old_path = ? AND destination_path = ?').get(destPath, oldPath);
    if (reverse) {
      sendJson(res, 409, { ok: false, message: 'Redirect chain/loop detected with existing rule.' });
      return true;
    }
    (await db.prepare(
      `INSERT INTO redirects (redirect_id, old_path, destination_path, status_code, reason, author_name, active, created_at, updated_at)
       VALUES (?, ?, ?, 301, ?, ?, 1, ?, ?)`
    ).run(generateUuid(), oldPath, destPath, String(fields.reason || 'Admin redirect'), session.full_name, nowIso, nowIso));
    await recordAudit(db, session, 'content', 'create_redirect', 'redirect', oldPath, { destination_path: destPath });
    sendJson(res, 201, { ok: true });
    return true;
  }

  // ============================================================
  // 4b. ARTICLES & TESTIMONIAL / CLAIM MANAGEMENT
  // ============================================================
  if (pathname === '/admin/api/articles') {
    if (!hasPermission(session, PERMISSIONS.EDIT_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const slug = String(fields.slug || '').toLowerCase().trim().replace(/[^a-z0-9-]/g, '-').replace(/^-|-$/g, '');
    const title = String(fields.title || '').trim();
    const buyerTarget = String(fields.buyer_target || '').trim();
    const summary = String(fields.summary || '').trim();
    const bodyHtml = sanitizeRichHtml(fields.body_html || '');
    const sourcesNote = String(fields.sources_note || '').trim();
    if (!slug || !title || !buyerTarget || !summary) {
      sendJson(res, 422, { ok: false, message: 'Slug, title, buyer target, and summary are required.' });
      return true;
    }
    const dupSlug = await db.prepare('SELECT 1 FROM articles WHERE slug = ?').get(slug);
    if (dupSlug) {
      sendJson(res, 409, { ok: false, message: `An article with slug "${slug}" already exists.` });
      return true;
    }
    const articleId = generateUuid();
    await db.prepare(
      `INSERT INTO articles (
        article_id, slug, title, buyer_target, related_service, summary, body_html,
        sources_note, author_name, editorial_state, activation_state, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', 'Unpublished', ?)`
    ).run(articleId, slug, title, buyerTarget, String(fields.related_service || '').trim() || null, summary, bodyHtml, sourcesNote, session.full_name, nowIso);
    await recordAudit(db, session, 'content', 'create_article_draft', 'article', articleId, { slug });
    sendJson(res, 201, { ok: true, article_id: articleId, slug });
    return true;
  }

  const articleLifecycleMatch = pathname.match(/^\/admin\/api\/articles\/([a-zA-Z0-9-]+)\/(submit-review|publish|archive)$/);
  if (articleLifecycleMatch) {
    const [, articleId, action] = articleLifecycleMatch;
    const neededPerm = action === 'submit-review' ? PERMISSIONS.EDIT_CONTENT : PERMISSIONS.PUBLISH_CONTENT;
    if (!hasPermission(session, neededPerm)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const article = await db.prepare('SELECT * FROM articles WHERE article_id = ?').get(articleId);
    if (!article) {
      sendJson(res, 404, { ok: false, message: 'Article not found.' });
      return true;
    }
    if (action === 'submit-review') {
      (await db.prepare(`UPDATE articles SET editorial_state = 'In review', updated_at = ? WHERE article_id = ?`).run(nowIso, articleId));
    } else if (action === 'publish') {
      (await db.prepare(
        `UPDATE articles SET editorial_state = 'Approved', activation_state = 'Live', reviewer_name = ?, published_at = COALESCE(published_at, ?), updated_at = ? WHERE article_id = ?`
      ).run(session.full_name, nowIso, nowIso, articleId));
      await bumpPublicCache(db);
    } else if (action === 'archive') {
      (await db.prepare(`UPDATE articles SET activation_state = 'Archived', updated_at = ? WHERE article_id = ?`).run(nowIso, articleId));
      await bumpPublicCache(db);
    }
    await recordAudit(db, session, 'content', `article_${action}`, 'article', articleId);
    sendJson(res, 200, { ok: true });
    return true;
  }

  const articleEditMatch = pathname.match(/^\/admin\/api\/articles\/([a-zA-Z0-9-]+)$/);
  if (articleEditMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const article = await db.prepare('SELECT * FROM articles WHERE article_id = ?').get(articleEditMatch[1]);
    if (!article) {
      sendJson(res, 404, { ok: false, message: 'Article not found.' });
      return true;
    }
    (await db.prepare(
      `UPDATE articles SET
        title = ?, buyer_target = ?, related_service = ?, summary = ?, body_html = ?, sources_note = ?,
        editorial_state = 'Draft', updated_at = ?
       WHERE article_id = ?`
    ).run(
      String(fields.title ?? article.title).trim(),
      String(fields.buyer_target ?? article.buyer_target).trim(),
      fields.related_service !== undefined ? (String(fields.related_service).trim() || null) : article.related_service,
      String(fields.summary ?? article.summary).trim(),
      fields.body_html !== undefined ? sanitizeRichHtml(fields.body_html) : article.body_html,
      String(fields.sources_note ?? article.sources_note).trim(),
      nowIso,
      article.article_id
    ));
    await recordAudit(db, session, 'content', 'edit_article_draft', 'article', article.article_id);
    sendJson(res, 200, { ok: true });
    return true;
  }

  if (pathname === '/admin/api/claims') {
    if (!hasPermission(session, PERMISSIONS.EDIT_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const claimType = ['testimonial', 'fact', 'certification'].includes(fields.claim_type) ? fields.claim_type : 'testimonial';
    const title = String(fields.title || '').trim();
    const exactText = String(fields.exact_text || '').trim();
    const attribution = String(fields.attribution || '').trim();
    const evidenceSource = String(fields.evidence_source || '').trim();
    if (!title || !exactText || !evidenceSource) {
      sendJson(res, 422, { ok: false, message: 'Title, exact text, and evidence source are required.' });
      return true;
    }
    const initialStatus = ['proposed wording', 'evidence needed'].includes(fields.status) ? fields.status : 'proposed wording';
    const claimId = generateUuid();
    const placements = String(fields.allowed_placements || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    await db.prepare(
      `INSERT INTO testimonials_claims (
        claim_id, claim_type, title, exact_text, attribution, evidence_source, owner_name,
        status, allowed_placements_json, review_date, expiry_date, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      claimId,
      claimType,
      title,
      exactText,
      attribution || 'Internal verified company record',
      evidenceSource,
      session.full_name,
      initialStatus,
      JSON.stringify(placements),
      fields.review_date || null,
      fields.expiry_date || null,
      nowIso
    );
    await recordAudit(db, session, 'content', 'create_claim', 'claim', claimId);
    sendJson(res, 201, { ok: true, claim_id: claimId });
    return true;
  }

  const claimActionMatch = pathname.match(/^\/admin\/api\/claims\/([a-zA-Z0-9-]+)\/(approve|withdraw)$/);
  if (claimActionMatch) {
    const [, claimId, action] = claimActionMatch;
    const neededClaimPerm = action === 'withdraw' ? PERMISSIONS.PUBLISH_CONTENT : PERMISSIONS.APPROVE_CONTENT;
    if (!hasPermission(session, neededClaimPerm)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Approver and Publisher permission required.' });
      return true;
    }
    const claim = await db.prepare('SELECT * FROM testimonials_claims WHERE claim_id = ?').get(claimId);
    if (!claim) {
      sendJson(res, 404, { ok: false, message: 'Claim or testimonial not found.' });
      return true;
    }
    const nextStatus =
      action === 'withdraw'
        ? 'withdrawn'
        : fields.status === 'established company fact'
          ? 'established company fact'
          : 'approved for publication';
    await db.prepare(`UPDATE testimonials_claims SET status = ?, updated_at = ? WHERE claim_id = ?`).run(nextStatus, nowIso, claimId);
    await bumpPublicCache(db);
    await recordAudit(db, session, 'content', `${action}_claim`, 'claim', claimId, { status: nextStatus });
    sendJson(res, 200, { ok: true, status: nextStatus });
    return true;
  }

  const claimEditMatch = pathname.match(/^\/admin\/api\/claims\/([a-zA-Z0-9-]+)$/);
  if (claimEditMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_CONTENT)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const claim = await db.prepare('SELECT * FROM testimonials_claims WHERE claim_id = ?').get(claimEditMatch[1]);
    if (!claim) {
      sendJson(res, 404, { ok: false, message: 'Claim not found.' });
      return true;
    }
    (await db.prepare(
      `UPDATE testimonials_claims SET
        title = ?, exact_text = ?, attribution = ?, evidence_source = ?,
        review_date = ?, expiry_date = ?, status = 'proposed wording', updated_at = ?
       WHERE claim_id = ?`
    ).run(
      String(fields.title ?? claim.title).trim(),
      String(fields.exact_text ?? claim.exact_text).trim(),
      String(fields.attribution ?? claim.attribution).trim(),
      String(fields.evidence_source ?? claim.evidence_source).trim(),
      fields.review_date !== undefined ? (fields.review_date || null) : claim.review_date,
      fields.expiry_date !== undefined ? (fields.expiry_date || null) : claim.expiry_date,
      nowIso,
      claim.claim_id
    ));
    await recordAudit(db, session, 'content', 'edit_claim', 'claim', claim.claim_id);
    sendJson(res, 200, { ok: true });
    return true;
  }

  // ============================================================
  // 5. SEASONAL CAMPAIGNS WORKFLOW
  // ============================================================
  if (pathname === '/admin/api/campaigns/run-scheduler') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_CAMPAIGNS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const resEval = await runScheduleEvaluation(db, new Date());
    sendJson(res, 200, { ok: true, ...resEval });
    return true;
  }

  if (pathname === '/admin/api/campaigns') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_CAMPAIGNS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const startIso = phoenixLocalToUtcIso(fields.start_phoenix);
    const isEvergreen = fields.is_evergreen === true || fields.is_evergreen === 'true' || fields.is_evergreen === 'on';
    const endIso = isEvergreen ? null : phoenixLocalToUtcIso(fields.end_phoenix);
    if (!startIso || (!isEvergreen && (!endIso || new Date(endIso) <= new Date(startIso)))) {
      sendJson(res, 422, { ok: false, message: 'Provide valid America/Phoenix start and end dates (end must be after start).' });
      return true;
    }
    const ctaDest = String(fields.cta_destination || '').trim();
    if (!ctaDest.startsWith('/')) {
      sendJson(res, 422, { ok: false, message: 'CTA destination must be a valid internal route starting with /.' });
      return true;
    }
    const targets = String(fields.target_service_slugs || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    const campId = generateUuid();
    await db.prepare(
      `INSERT INTO campaigns (
        campaign_id, slug, internal_title, service_family, owner_name, placement_slot,
        target_service_slugs_json, heading, summary, cta_label, cta_destination, asset_id,
        priority, start_at, end_at, is_evergreen, editorial_state, activation_state,
        landing_page_enabled, landing_page_noindex, content_revision, updated_at
      ) VALUES (?, ?, ?, 'general', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', 'Unpublished', 1, 1, 1, ?)`
    ).run(
      campId,
      String(fields.slug).toLowerCase().trim(),
      String(fields.internal_title).trim(),
      session.full_name,
      fields.placement_slot,
      JSON.stringify(targets),
      String(fields.heading).trim(),
      String(fields.summary).trim(),
      String(fields.cta_label).trim(),
      ctaDest,
      fields.asset_id || null,
      Number(fields.priority || 10),
      startIso,
      endIso,
      isEvergreen ? 1 : 0,
      nowIso
    );
    await recordAudit(db, session, 'campaigns', 'create_campaign_draft', 'campaign', campId);
    sendJson(res, 201, { ok: true, campaign_id: campId });
    return true;
  }

  const campApproveMatch = pathname.match(/^\/admin\/api\/campaigns\/([a-zA-Z0-9-]+)\/approve-schedule$/);
  if (campApproveMatch) {
    if (!hasPermission(session, PERMISSIONS.PUBLISH_CAMPAIGNS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Approver and Publisher permission required.' });
      return true;
    }
    const camp = await db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(campApproveMatch[1]);
    if (!camp) {
      sendJson(res, 404, { ok: false, message: 'Campaign not found.' });
      return true;
    }
    if (camp.asset_id) {
      const asset = await db.prepare('SELECT * FROM media_assets WHERE asset_id = ?').get(camp.asset_id);
      if (!asset || asset.rights_status !== 'approved') {
        sendJson(res, 422, { ok: false, message: 'Cannot activate campaign: attached media asset lacks approved rights.' });
        return true;
      }
    }
    // Conflict detection: block equal-priority overlaps in the same placement slot!
    const { equalPriorityConflicts } = await detectCampaignSlotConflicts(db, camp);
    if (equalPriorityConflicts.length > 0) {
      sendJson(res, 409, {
        ok: false,
        code: 'slot_priority_conflict',
        message: `Blocked: Equal-priority conflict in slot ${camp.placement_slot} with "${equalPriorityConflicts[0].internal_title}". Adjust priority, dates, or slot.`,
      });
      return true;
    }

    const nowMs = Date.now();
    const startMs = new Date(camp.start_at).getTime();
    const endMs = camp.is_evergreen ? Number.POSITIVE_INFINITY : new Date(camp.end_at || 0).getTime();
    if (!camp.is_evergreen && nowMs >= endMs) {
      sendJson(res, 422, { ok: false, message: 'Campaign end date has already elapsed.' });
      return true;
    }
    const nextActivation = nowMs >= startMs ? 'Live' : 'Scheduled';
    await db.prepare(
      `UPDATE campaigns SET editorial_state = 'Approved', activation_state = ?, approver_id = ?, updated_at = ? WHERE campaign_id = ?`
    ).run(nextActivation, session.user_id, nowIso, camp.campaign_id);
    if (camp.asset_id) {
      (await db.prepare('UPDATE media_assets SET is_public_published = 1 WHERE asset_id = ?').run(camp.asset_id));
    }
    await bumpPublicCache(db);
    await recordAudit(db, session, 'campaigns', 'approve_schedule_campaign', 'campaign', camp.campaign_id, { activation_state: nextActivation });
    sendJson(res, 200, { ok: true, activation_state: nextActivation });
    return true;
  }

  const campPauseMatch = pathname.match(/^\/admin\/api\/campaigns\/([a-zA-Z0-9-]+)\/(pause|resume|archive)$/);
  if (campPauseMatch) {
    if (!hasPermission(session, PERMISSIONS.PUBLISH_CAMPAIGNS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const camp = await db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(campPauseMatch[1]);
    if (!camp) {
      sendJson(res, 404, { ok: false, message: 'Campaign not found.' });
      return true;
    }
    const action = campPauseMatch[2];
    if (action === 'pause') {
      (await db.prepare(`UPDATE campaigns SET activation_state = 'Paused', updated_at = ? WHERE campaign_id = ?`).run(nowIso, camp.campaign_id));
    } else if (action === 'archive') {
      (await db.prepare(`UPDATE campaigns SET activation_state = 'Archived', updated_at = ? WHERE campaign_id = ?`).run(nowIso, camp.campaign_id));
    } else {
      if (camp.editorial_state !== 'Approved' || (!camp.is_evergreen && new Date(camp.end_at).getTime() <= Date.now())) {
        sendJson(res, 422, { ok: false, message: 'Cannot resume: campaign is unapproved or past its end date.' });
        return true;
      }
      (await db.prepare(`UPDATE campaigns SET activation_state = 'Live', updated_at = ? WHERE campaign_id = ?`).run(nowIso, camp.campaign_id));
    }
    await bumpPublicCache(db);
    await recordAudit(db, session, 'campaigns', `campaign_${action}`, 'campaign', camp.campaign_id);
    sendJson(res, 200, { ok: true });
    return true;
  }

  const campEditMatch = pathname.match(/^\/admin\/api\/campaigns\/([a-zA-Z0-9-]+)$/);
  if (campEditMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_CAMPAIGNS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const camp = await db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(campEditMatch[1]);
    if (!camp) {
      sendJson(res, 404, { ok: false, message: 'Campaign not found.' });
      return true;
    }
    if (camp.activation_state === 'Archived') {
      sendJson(res, 422, { ok: false, message: 'Archived campaigns cannot be edited directly.' });
      return true;
    }
    const isEvergreen =
      fields.is_evergreen !== undefined
        ? fields.is_evergreen === true || fields.is_evergreen === 'true' || fields.is_evergreen === 'on'
        : Boolean(camp.is_evergreen);
    const startIso = fields.start_phoenix ? phoenixLocalToUtcIso(fields.start_phoenix) : camp.start_at;
    const endIso = isEvergreen ? null : fields.end_phoenix ? phoenixLocalToUtcIso(fields.end_phoenix) : camp.end_at;
    if (!startIso || (!isEvergreen && (!endIso || new Date(endIso) <= new Date(startIso)))) {
      sendJson(res, 422, { ok: false, message: 'Provide valid America/Phoenix start and end dates (end must be after start).' });
      return true;
    }
    const ctaDest = String(fields.cta_destination ?? camp.cta_destination).trim();
    if (!ctaDest.startsWith('/')) {
      sendJson(res, 422, { ok: false, message: 'CTA destination must start with /.' });
      return true;
    }
    const targetsJson =
      fields.target_service_slugs !== undefined
        ? JSON.stringify(
            String(fields.target_service_slugs)
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          )
        : camp.target_service_slugs_json;

    const nextRevision = Number(camp.content_revision || 1) + 1;
    await db.prepare(
      `UPDATE campaigns SET
        internal_title = ?, placement_slot = ?, target_service_slugs_json = ?, heading = ?, summary = ?,
        cta_label = ?, cta_destination = ?, asset_id = ?, priority = ?, start_at = ?, end_at = ?, is_evergreen = ?,
        landing_expiry_policy = ?, content_revision = ?, editorial_state = 'Draft', activation_state = 'Unpublished', updated_at = ?
       WHERE campaign_id = ?`
    ).run(
      String(fields.internal_title ?? camp.internal_title).trim(),
      fields.placement_slot || camp.placement_slot,
      targetsJson,
      String(fields.heading ?? camp.heading).trim(),
      String(fields.summary ?? camp.summary).trim(),
      String(fields.cta_label ?? camp.cta_label).trim(),
      ctaDest,
      fields.asset_id !== undefined ? (fields.asset_id || null) : camp.asset_id,
      Number(fields.priority ?? camp.priority),
      startIso,
      endIso,
      isEvergreen ? 1 : 0,
      fields.landing_expiry_policy || camp.landing_expiry_policy || 'ended_notice',
      nextRevision,
      nowIso,
      camp.campaign_id
    );
    await bumpPublicCache(db);
    await recordAudit(db, session, 'campaigns', 'update_campaign', 'campaign', camp.campaign_id, { content_revision: nextRevision });
    sendJson(res, 200, { ok: true, content_revision: nextRevision });
    return true;
  }

  // ============================================================
  // 6. PROJECTS & AUTHENTICATED MEDIA PIPELINE
  // ============================================================
  if (pathname === '/admin/api/media/presign') {
    if (!hasPermission(session, PERMISSIONS.UPLOAD_PROJECT_MEDIA) && !hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const items = Array.isArray(fields.files) ? fields.files : [];
    if (items.length === 0 || items.length > UPLOAD_LIMITS.projectMedia.maxFiles) {
      sendJson(res, 422, { ok: false, message: 'Select 1 to 20 image files.' });
      return true;
    }
    const store = createObjectStore(storagePaths);
    if (store.mode !== 's3') {
      sendJson(res, 200, { ok: true, mode: 'direct_multipart', uploads: [] });
      return true;
    }
    const uploads = [];
    for (const item of items) {
      const byteSize = Number(item.size || 0);
      const mime = String(item.type || 'application/octet-stream').toLowerCase();
      const origName = path.basename(String(item.name || 'image.jpg')).slice(0, 140);
      if (byteSize <= 0 || byteSize > UPLOAD_LIMITS.projectMedia.maxFileBytes) {
        sendJson(res, 422, { ok: false, message: `${origName}: exceeds 20 MB per-file limit.` });
        return true;
      }
      if (!UPLOAD_LIMITS.projectMedia.allowedTypes.includes(mime)) {
        sendJson(res, 422, { ok: false, message: `${origName}: allowed formats are JPEG, PNG, WebP, HEIC.` });
        return true;
      }
      const stagingKey = `media/${session.user_id}/${generateUuid()}-${origName.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      const presigned = await store.createPresignedUpload({ key: stagingKey, contentType: mime, expiresIn: 600 });
      uploads.push({ originalName: origName, ...presigned });
    }
    sendJson(res, 200, { ok: true, mode: 's3_presigned_put', uploads });
    return true;
  }

  if (pathname === '/admin/api/media/finalize') {
    if (!hasPermission(session, PERMISSIONS.UPLOAD_PROJECT_MEDIA) && !hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const items = Array.isArray(fields.staged_files) ? fields.staged_files : [];
    if (items.length === 0 || items.length > UPLOAD_LIMITS.projectMedia.maxFiles) {
      sendJson(res, 422, { ok: false, message: 'Provide 1 to 20 staged media files.' });
      return true;
    }
    const store = createObjectStore(storagePaths);
    const accepted = [];
    const rejected = [];
    for (const item of items) {
      const stagingKey = String(item.stagingKey || '');
      const originalName = path.basename(String(item.originalName || 'upload')).slice(0, 140);
      if (!stagingKey.startsWith(`media/${session.user_id}/`)) {
        rejected.push({ name: originalName, code: 'invalid_staging_key', message: 'Invalid staged object reference.' });
        continue;
      }
      try {
        const buffer = await store.getObjectBuffer({ area: 'staging', key: stagingKey });
        if (!buffer) {
          rejected.push({ name: originalName, code: 'missing_staged_object', message: 'Uploaded object not found in staging.' });
          continue;
        }
        const proc = await processProjectImageUploadAsync({ buffer, originalName, storagePaths });
        if (!proc.ok) {
          rejected.push({ name: originalName, code: proc.errorCode, message: proc.message });
          continue;
        }
        const a = proc.asset;
        await db.prepare(
          `INSERT INTO media_assets (
            asset_id, original_filename, mime_type, derivative_mime, byte_size, width, height, orientation,
            alt_text, rights_owner, rights_status, private_original_key, public_derivative_key, variants_json,
            sha256, scan_state, is_public_published, uploaded_by, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, 0, ?, ?)`
        ).run(
          a.asset_id,
          a.original_filename,
          a.mime_type,
          a.derivative_mime,
          a.byte_size,
          a.width,
          a.height,
          a.orientation,
          String(fields.alt_text || a.original_filename).slice(0, 200),
          String(fields.rights_owner || 'Internal').slice(0, 120),
          a.private_original_key,
          a.public_derivative_key,
          a.variants ? JSON.stringify(a.variants) : null,
          a.sha256 || null,
          a.scan_state || 'clean',
          session.user_id,
          nowIso
        );
        accepted.push(a);
      } finally {
        await store.deleteObject({ area: 'staging', key: stagingKey });
      }
    }
    await recordAudit(db, session, 'media', 'batch_upload', 'media_asset', `${accepted.length}_files`, {
      rejected_count: rejected.length,
      transport: 's3_presigned_put',
    });
    sendJson(res, accepted.length > 0 ? 201 : 422, { ok: accepted.length > 0, accepted, rejected });
    return true;
  }

  if (pathname === '/admin/api/media/upload') {
    if (!hasPermission(session, PERMISSIONS.UPLOAD_PROJECT_MEDIA) && !hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    if (files.length === 0) {
      sendJson(res, 422, { ok: false, message: 'Select at least one image file.' });
      return true;
    }
    if (files.length > UPLOAD_LIMITS.projectMedia.maxFiles) {
      sendJson(res, 413, { ok: false, message: 'Maximum 20 files per batch.' });
      return true;
    }

    const accepted = [];
    const rejected = [];
    for (const f of files) {
      const proc = await processProjectImageUploadAsync({
        buffer: f.buffer,
        originalName: f.originalName,
        storagePaths,
      });
      if (!proc.ok) {
        rejected.push({ name: f.originalName, code: proc.errorCode, message: proc.message });
        continue;
      }
      const a = proc.asset;
      await db.prepare(
        `INSERT INTO media_assets (
          asset_id, original_filename, mime_type, derivative_mime, byte_size, width, height, orientation,
          alt_text, rights_owner, rights_status, private_original_key, public_derivative_key, variants_json,
          sha256, scan_state, is_public_published, uploaded_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, 0, ?, ?)`
      ).run(
        a.asset_id,
        a.original_filename,
        a.mime_type,
        a.derivative_mime,
        a.byte_size,
        a.width,
        a.height,
        a.orientation,
        String(fields.alt_text || a.original_filename).slice(0, 200),
        String(fields.rights_owner || 'Internal').slice(0, 120),
        a.private_original_key,
        a.public_derivative_key,
        a.variants ? JSON.stringify(a.variants) : null,
        a.sha256 || null,
        a.scan_state || 'clean',
        session.user_id,
        nowIso
      );
      accepted.push(a);
    }

    await recordAudit(db, session, 'media', 'batch_upload', 'media_asset', `${accepted.length}_files`, { rejected_count: rejected.length });
    sendJson(res, accepted.length > 0 ? 201 : 422, { ok: accepted.length > 0, accepted, rejected });
    return true;
  }

  const mediaFocalMatch = pathname.match(/^\/admin\/api\/media\/([a-zA-Z0-9-]+)\/focal-point$/);
  if (mediaFocalMatch) {
    if (!hasPermission(session, PERMISSIONS.UPLOAD_PROJECT_MEDIA) && !hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const asset = await db.prepare('SELECT * FROM media_assets WHERE asset_id = ?').get(mediaFocalMatch[1]);
    if (!asset) {
      sendJson(res, 404, { ok: false, message: 'Asset not found.' });
      return true;
    }
    const fx = Math.max(0, Math.min(100, Math.round(Number(fields.focal_x ?? asset.focal_x))));
    const fy = Math.max(0, Math.min(100, Math.round(Number(fields.focal_y ?? asset.focal_y))));
    if (!Number.isFinite(fx) || !Number.isFinite(fy)) {
      sendJson(res, 422, { ok: false, message: 'Focal point coordinates must be numbers between 0 and 100.' });
      return true;
    }
    const altText = fields.alt_text !== undefined ? String(fields.alt_text).trim().slice(0, 200) : asset.alt_text;
    const caption = fields.caption !== undefined ? String(fields.caption).trim().slice(0, 300) : asset.caption;
    await db.prepare(`UPDATE media_assets SET focal_x = ?, focal_y = ?, alt_text = ?, caption = ? WHERE asset_id = ?`).run(
      fx,
      fy,
      altText,
      caption,
      asset.asset_id
    );
    await bumpPublicCache(db);
    await recordAudit(db, session, 'media', 'update_focal_point', 'media_asset', asset.asset_id, { focal_x: fx, focal_y: fy });
    sendJson(res, 200, { ok: true, focal_x: fx, focal_y: fy });
    return true;
  }

  const mediaActionMatch = pathname.match(/^\/admin\/api\/media\/([a-zA-Z0-9-]+)\/(approve-rights|withdraw)$/);
  if (mediaActionMatch) {
    if (!hasPermission(session, PERMISSIONS.PUBLISH_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Publisher permission required for media rights.' });
      return true;
    }
    const asset = await db.prepare('SELECT * FROM media_assets WHERE asset_id = ?').get(mediaActionMatch[1]);
    if (!asset) {
      sendJson(res, 404, { ok: false, message: 'Asset not found.' });
      return true;
    }
    if (mediaActionMatch[2] === 'approve-rights') {
      (await db.prepare(`UPDATE media_assets SET rights_status = 'approved', client_approved = 1 WHERE asset_id = ?`).run(asset.asset_id));
      await recordAudit(db, session, 'media', 'approve_rights', 'media_asset', asset.asset_id);
      sendJson(res, 200, { ok: true });
      return true;
    }
    const affectedProjects = await db.prepare('SELECT project_id, title FROM projects WHERE cover_asset_id = ?').all(asset.asset_id);
    const affectedGallery = await db.prepare('SELECT item_id, project_id FROM project_gallery_items WHERE asset_id = ?').all(asset.asset_id);
    const affectedPairs = await db
      .prepare('SELECT pair_id, project_id FROM project_before_after_pairs WHERE before_asset_id = ? OR after_asset_id = ?')
      .all(asset.asset_id, asset.asset_id);
    const affectedCampaigns = await db.prepare('SELECT campaign_id, internal_title FROM campaigns WHERE asset_id = ?').all(asset.asset_id);

    // Withdrawal cascades immediately: disables public exposure, removes from covers/gallery/campaigns, removes public derivatives & bumps cache!
    (await db.prepare(`UPDATE media_assets SET rights_status = 'withdrawn', is_public_published = 0 WHERE asset_id = ?`).run(asset.asset_id));
    await db.prepare(`UPDATE projects SET cover_asset_id = NULL WHERE cover_asset_id = ?`).run(asset.asset_id);
    await db.prepare(`DELETE FROM project_gallery_items WHERE asset_id = ?`).run(asset.asset_id);
    await db.prepare(`UPDATE campaigns SET asset_id = NULL WHERE asset_id = ?`).run(asset.asset_id);
    const keysToRemove = new Set([asset.public_derivative_key].filter(Boolean));
    if (asset.variants_json) {
      try {
        const pv = JSON.parse(asset.variants_json);
        for (const k of [...Object.values(pv.webp || {}), ...Object.values(pv.jpeg || {})]) {
          if (k) keysToRemove.add(k);
        }
      } catch {}
    }
    const store = createObjectStore(storagePaths);
    for (const k of keysToRemove) {
      await store.deleteObject({ area: 'publicMedia', key: path.basename(k) });
    }
    await bumpPublicCache(db);
    await recordAudit(db, session, 'media', 'withdraw_rights', 'media_asset', asset.asset_id, {
      affected_covers: affectedProjects.length,
      affected_gallery: affectedGallery.length,
      affected_pairs: affectedPairs.length,
      affected_campaigns: affectedCampaigns.length,
    });
    sendJson(res, 200, {
      ok: true,
      affected: { affectedProjects, affectedGallery, affectedPairs, affectedCampaigns },
      message: 'Asset rights withdrawn and affected public placements invalidated.',
    });
    return true;
  }

  if (pathname === '/admin/api/projects') {
    if (!hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const projId = generateUuid();
    await db.prepare(
      `INSERT INTO projects (
        project_id, slug, title, is_private_test, naming_decision, property_type, city_region,
        completion_date, challenge, agreed_scope, delivery_role, self_performed_notes, coordinated_notes,
        operating_constraints, completed_work, verified_result, editorial_state, activation_state, owner_id, updated_at
      ) VALUES (?, ?, ?, 0, 'anonymized', ?, ?, ?, ?, ?, 'In-house plus coordinated trades', 'In-house work', 'Coordinated trades where applicable', 'Active commercial property access', ?, 'Completed agreed scope', 'Draft', 'Unpublished', ?, ?)`
    ).run(
      projId,
      String(fields.slug).toLowerCase().trim(),
      String(fields.title).trim(),
      fields.property_type,
      fields.city_region,
      fields.completion_date,
      fields.challenge,
      fields.agreed_scope,
      fields.completed_work,
      session.user_id,
      nowIso
    );
    await recordAudit(db, session, 'projects', 'create_project_draft', 'project', projId);
    sendJson(res, 201, { ok: true, project_id: projId });
    return true;
  }

  const projUpdateMatch = pathname.match(/^\/admin\/api\/projects\/([a-zA-Z0-9-]+)$/);
  if (projUpdateMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const proj = await db.prepare('SELECT * FROM projects WHERE project_id = ?').get(projUpdateMatch[1]);
    if (!proj) {
      sendJson(res, 404, { ok: false, message: 'Project not found.' });
      return true;
    }
    const relatedServicesJson =
      fields.related_services !== undefined
        ? JSON.stringify(
            Array.isArray(fields.related_services)
              ? fields.related_services
              : String(fields.related_services)
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean)
          )
        : proj.related_services_json;

    await db.prepare(
      `UPDATE projects SET
        title = ?, property_type = ?, city_region = ?, completion_date = ?,
        challenge = ?, agreed_scope = ?, delivery_role = ?, self_performed_notes = ?,
        coordinated_notes = ?, operating_constraints = ?, completed_work = ?, verified_result = ?,
        related_services_json = ?, meta_title = ?, meta_description = ?, featured_order = ?,
        naming_decision = ?, cover_asset_id = ?, completion_documented = ?,
        client_permission_verified = ?, featured_on_home = ?, is_private_test = ?, updated_at = ?
       WHERE project_id = ?`
    ).run(
      String(fields.title ?? proj.title).trim(),
      String(fields.property_type ?? proj.property_type).trim(),
      String(fields.city_region ?? proj.city_region).trim(),
      fields.completion_date !== undefined ? (fields.completion_date || null) : proj.completion_date,
      String(fields.challenge ?? proj.challenge).trim(),
      String(fields.agreed_scope ?? proj.agreed_scope).trim(),
      String(fields.delivery_role ?? proj.delivery_role).trim(),
      String(fields.self_performed_notes ?? proj.self_performed_notes).trim(),
      String(fields.coordinated_notes ?? proj.coordinated_notes).trim(),
      String(fields.operating_constraints ?? proj.operating_constraints).trim(),
      String(fields.completed_work ?? proj.completed_work).trim(),
      String(fields.verified_result ?? proj.verified_result).trim(),
      relatedServicesJson,
      String(fields.meta_title ?? proj.meta_title).trim(),
      String(fields.meta_description ?? proj.meta_description).trim(),
      Number.isFinite(Number(fields.featured_order)) ? Number(fields.featured_order) : proj.featured_order,
      fields.naming_decision !== undefined ? (fields.naming_decision === 'named' ? 'named' : 'anonymized') : proj.naming_decision,
      fields.cover_asset_id !== undefined ? (fields.cover_asset_id || null) : proj.cover_asset_id,
      fields.completion_documented !== undefined ? (fields.completion_documented ? 1 : 0) : proj.completion_documented,
      fields.client_permission_verified !== undefined ? (fields.client_permission_verified ? 1 : 0) : proj.client_permission_verified,
      fields.featured_on_home !== undefined ? (fields.featured_on_home ? 1 : 0) : proj.featured_on_home,
      fields.is_private_test !== undefined ? (fields.is_private_test ? 1 : 0) : proj.is_private_test,
      nowIso,
      proj.project_id
    );
    await bumpPublicCache(db);
    await recordAudit(db, session, 'projects', 'update_project', 'project', proj.project_id);
    sendJson(res, 200, { ok: true });
    return true;
  }

  const galleryAddMatch = pathname.match(/^\/admin\/api\/projects\/([a-zA-Z0-9-]+)\/gallery$/);
  if (galleryAddMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const projId = galleryAddMatch[1];
    const asset = await db.prepare('SELECT * FROM media_assets WHERE asset_id = ?').get(fields.asset_id);
    if (!asset || asset.rights_status === 'withdrawn') {
      sendJson(res, 422, { ok: false, message: 'Select a valid non-withdrawn media asset.' });
      return true;
    }
    const maxSort = (await db.prepare('SELECT COALESCE(MAX(sort_order), 0) as m FROM project_gallery_items WHERE project_id = ?').get(projId)).m;
    const itemId = generateUuid();
    await db.prepare(
      `INSERT INTO project_gallery_items (item_id, project_id, asset_id, caption, alt_text, sort_order)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(itemId, projId, asset.asset_id, String(fields.caption || '').trim(), String(fields.alt_text || asset.alt_text || '').trim(), maxSort + 1);
    await bumpPublicCache(db);
    await recordAudit(db, session, 'projects', 'add_gallery_item', 'project', projId, { item_id: itemId, asset_id: asset.asset_id });
    sendJson(res, 201, { ok: true, item_id: itemId });
    return true;
  }

  const galleryMoveMatch = pathname.match(/^\/admin\/api\/projects\/([a-zA-Z0-9-]+)\/gallery\/([a-zA-Z0-9-]+)\/(move|delete)$/);
  if (galleryMoveMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const [, projId, itemId, action] = galleryMoveMatch;
    if (action === 'delete') {
      (await db.prepare('DELETE FROM project_gallery_items WHERE item_id = ? AND project_id = ?').run(itemId, projId));
      await bumpPublicCache(db);
      await recordAudit(db, session, 'projects', 'delete_gallery_item', 'project', projId, { item_id: itemId });
      sendJson(res, 200, { ok: true });
      return true;
    }
    const dir = urlObj.searchParams.get('dir') === 'down' ? 1 : -1;
    const all = await db.prepare('SELECT * FROM project_gallery_items WHERE project_id = ? ORDER BY sort_order ASC').all(projId);
    const idx = all.findIndex((x) => x.item_id === itemId);
    const swapIdx = idx + dir;
    if (idx !== -1 && swapIdx >= 0 && swapIdx < all.length) {
      const a = all[idx];
      const b = all[swapIdx];
      await db.prepare('UPDATE project_gallery_items SET sort_order = ? WHERE item_id = ?').run(b.sort_order, a.item_id);
      await db.prepare('UPDATE project_gallery_items SET sort_order = ? WHERE item_id = ?').run(a.sort_order, b.item_id);
      await bumpPublicCache(db);
    }
    sendJson(res, 200, { ok: true });
    return true;
  }

  const projPublishMatch = pathname.match(/^\/admin\/api\/projects\/([a-zA-Z0-9-]+)\/(publish|archive)$/);
  if (projPublishMatch) {
    if (!hasPermission(session, PERMISSIONS.PUBLISH_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Approver and Publisher permission required.' });
      return true;
    }
    const proj = await db.prepare('SELECT * FROM projects WHERE project_id = ?').get(projPublishMatch[1]);
    if (!proj) {
      sendJson(res, 404, { ok: false, message: 'Project not found.' });
      return true;
    }
    if (projPublishMatch[2] === 'archive') {
      (await db.prepare(`UPDATE projects SET activation_state = 'Archived', updated_at = ? WHERE project_id = ?`).run(nowIso, proj.project_id));
      await bumpPublicCache(db);
      await recordAudit(db, session, 'projects', 'archive_project', 'project', proj.project_id);
      sendJson(res, 200, { ok: true });
      return true;
    }
    // Publish requires completion evidence + client permission verification + non-test flag (PROJ-02)
    if (!proj.completion_documented || !proj.client_permission_verified) {
      sendJson(res, 422, {
        ok: false,
        message: 'Cannot publish: actual completion evidence and client naming/photo permission must be verified first.',
      });
      return true;
    }
    if (proj.is_private_test) {
      sendJson(res, 422, { ok: false, message: 'Private test records cannot be published to the live public site.' });
      return true;
    }
    // Verify all paired and gallery assets have approved rights and expose derivatives publicly
    const pairs = await db.prepare('SELECT * FROM project_before_after_pairs WHERE project_id = ?').all(proj.project_id);
    const galleryItems = await db.prepare('SELECT * FROM project_gallery_items WHERE project_id = ?').all(proj.project_id);
    const assetIdsToPublish = new Set(
      [proj.cover_asset_id, ...pairs.map((p) => p.before_asset_id), ...pairs.map((p) => p.after_asset_id), ...galleryItems.map((g) => g.asset_id)].filter(Boolean)
    );
    for (const aid of assetIdsToPublish) {
      const a = await db.prepare('SELECT * FROM media_assets WHERE asset_id = ?').get(aid);
      if (!a || a.rights_status !== 'approved') {
        sendJson(res, 422, { ok: false, message: `Asset ${a?.original_filename || aid} does not have approved publication rights.` });
        return true;
      }
    }
    for (const aid of assetIdsToPublish) {
      (await db.prepare('UPDATE media_assets SET is_public_published = 1 WHERE asset_id = ?').run(aid));
    }
    (await db.prepare(`UPDATE projects SET editorial_state = 'Approved', activation_state = 'Live', approver_id = ?, updated_at = ? WHERE project_id = ?`).run(
      session.user_id,
      nowIso,
      proj.project_id
    ));
    await bumpPublicCache(db);
    await recordAudit(db, session, 'projects', 'publish_project', 'project', proj.project_id);
    sendJson(res, 200, { ok: true });
    return true;
  }

  const pairCreateMatch = pathname.match(/^\/admin\/api\/projects\/([a-zA-Z0-9-]+)\/pairs$/);
  if (pairCreateMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const maxSort = (await db.prepare('SELECT COALESCE(MAX(sort_order), 0) as m FROM project_before_after_pairs WHERE project_id = ?').get(pairCreateMatch[1])).m;
    await db.prepare(
      `INSERT INTO project_before_after_pairs (
        pair_id, project_id, pair_title, before_asset_id, after_asset_id,
        before_caption, after_caption, sort_order
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(generateUuid(), pairCreateMatch[1], fields.pair_title, fields.before_asset_id, fields.after_asset_id, fields.before_caption, fields.after_caption, maxSort + 1);
    sendJson(res, 201, { ok: true });
    return true;
  }

  const pairMoveMatch = pathname.match(/^\/admin\/api\/projects\/([a-zA-Z0-9-]+)\/pairs\/([a-zA-Z0-9-]+)\/(move|swap)$/);
  if (pairMoveMatch) {
    if (!hasPermission(session, PERMISSIONS.EDIT_PROJECTS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const [, projId, pairId, action] = pairMoveMatch;
    if (action === 'swap') {
      const p = await db.prepare('SELECT * FROM project_before_after_pairs WHERE pair_id = ? AND project_id = ?').get(pairId, projId);
      if (p) {
        (await db.prepare(
          `UPDATE project_before_after_pairs SET before_asset_id = ?, after_asset_id = ?, before_caption = ?, after_caption = ? WHERE pair_id = ?`
        ).run(p.after_asset_id, p.before_asset_id, p.after_caption, p.before_caption, pairId));
      }
      sendJson(res, 200, { ok: true });
      return true;
    }
    const dir = urlObj.searchParams.get('dir') === 'down' ? 1 : -1;
    const all = await db.prepare('SELECT * FROM project_before_after_pairs WHERE project_id = ? ORDER BY sort_order ASC').all(projId);
    const idx = all.findIndex((x) => x.pair_id === pairId);
    const swapIdx = idx + dir;
    if (idx !== -1 && swapIdx >= 0 && swapIdx < all.length) {
      const a = all[idx];
      const b = all[swapIdx];
      await db.prepare('UPDATE project_before_after_pairs SET sort_order = ? WHERE pair_id = ?').run(b.sort_order, a.pair_id);
      await db.prepare('UPDATE project_before_after_pairs SET sort_order = ? WHERE pair_id = ?').run(a.sort_order, b.pair_id);
    }
    sendJson(res, 200, { ok: true });
    return true;
  }

  // ============================================================
  // 7. HIRING & PROTECTED APPLICANT MANAGEMENT
  // ============================================================
  if (pathname === '/admin/api/jobs') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_VACANCIES)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Hiring Owner required.' });
      return true;
    }
    const publishIso = fields.publish_phoenix ? phoenixLocalToUtcIso(fields.publish_phoenix) : null;
    const closeIso = fields.close_phoenix ? phoenixLocalToUtcIso(fields.close_phoenix) : null;
    if (fields.publish_phoenix && !publishIso) {
      sendJson(res, 422, { ok: false, message: 'Invalid America/Phoenix publish schedule.' });
      return true;
    }
    if (fields.close_phoenix && !closeIso) {
      sendJson(res, 422, { ok: false, message: 'Invalid America/Phoenix close schedule.' });
      return true;
    }
    if (publishIso && closeIso && new Date(closeIso) <= new Date(publishIso)) {
      sendJson(res, 422, { ok: false, message: 'Close time must be after publish time.' });
      return true;
    }
    const reqId = `REQ-${Date.now().toString().slice(-6)}`;
    const cycleId = `CYCLE-${generateUuid().slice(0, 8)}`;
    await db.prepare(
      `INSERT INTO jobs (
        requisition_id, opening_cycle_id, slug, title, role_family, employment_type,
        work_area, schedule_text, travel_requirements, responsibilities_html, qualifications_html,
        pay_info, benefits_info, status, publish_at, close_at, resume_policy, form_revision,
        hiring_owner_id, backup_owner_id, assigned_reviewers_json, is_private_test, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Draft', ?, ?, ?, 1, ?, ?, ?, 0, ?)`
    ).run(
      reqId,
      cycleId,
      String(fields.slug).toLowerCase().trim(),
      String(fields.title).trim(),
      fields.role_family,
      fields.employment_type,
      fields.work_area,
      fields.schedule_text,
      String(fields.travel_requirements || '').trim(),
      sanitizeRichHtml(fields.responsibilities_html),
      sanitizeRichHtml(fields.qualifications_html),
      fields.pay_info,
      String(fields.benefits_info || 'Standard approved company benefits').trim(),
      publishIso,
      closeIso,
      fields.resume_policy === 'required' ? 'required' : 'optional',
      session.user_id,
      fields.backup_owner_id || session.user_id,
      JSON.stringify(
        fields.assigned_reviewers
          ? String(fields.assigned_reviewers).split(',').map((s) => s.trim()).filter(Boolean)
          : ['usr-hiring-reviewer-01']
      ),
      nowIso
    );
    await recordAudit(db, session, 'hiring', 'create_vacancy_draft', 'job', reqId);
    sendJson(res, 201, { ok: true, requisition_id: reqId, opening_cycle_id: cycleId });
    return true;
  }

  const jobScheduleMatch = pathname.match(/^\/admin\/api\/jobs\/([a-zA-Z0-9-]+)\/schedule$/);
  if (jobScheduleMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_VACANCIES)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const reqId = jobScheduleMatch[1];
    const job = await db.prepare('SELECT * FROM jobs WHERE requisition_id = ?').get(reqId);
    if (!job || !canAccessJobRecord(session, job)) {
      sendJson(res, 404, { ok: false, message: 'Vacancy not found.' });
      return true;
    }
    const publishIso = phoenixLocalToUtcIso(fields.publish_phoenix || fields.publish_at);
    const closeIso = fields.close_phoenix || fields.close_at ? phoenixLocalToUtcIso(fields.close_phoenix || fields.close_at) : null;
    if (!publishIso) {
      sendJson(res, 422, { ok: false, message: 'Valid America/Phoenix publish date/time is required.' });
      return true;
    }
    if ((fields.close_phoenix || fields.close_at) && !closeIso) {
      sendJson(res, 422, { ok: false, message: 'Invalid America/Phoenix closing date/time.' });
      return true;
    }
    if (closeIso && new Date(closeIso) <= new Date(publishIso)) {
      sendJson(res, 422, { ok: false, message: 'Closing time must be after publish time.' });
      return true;
    }
    (await db.prepare(`UPDATE jobs SET status = 'Scheduled', publish_at = ?, close_at = ?, updated_at = ? WHERE requisition_id = ?`).run(
      publishIso,
      closeIso,
      nowIso,
      reqId
    ));
    await bumpPublicCache(db);
    await recordAudit(db, session, 'hiring', 'schedule_vacancy', 'job', reqId, { publish_at: publishIso, close_at: closeIso });
    sendJson(res, 200, { ok: true, status: 'Scheduled', publish_at: publishIso, close_at: closeIso });
    return true;
  }

  const jobStateMatch = pathname.match(/^\/admin\/api\/jobs\/([a-zA-Z0-9-]+)\/(open|pause|close|reopen)$/);
  if (jobStateMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_VACANCIES)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const [, reqId, action] = jobStateMatch;
    const job = await db.prepare('SELECT * FROM jobs WHERE requisition_id = ?').get(reqId);
    if (!job || !canAccessJobRecord(session, job)) {
      sendJson(res, 404, { ok: false, message: 'Vacancy not found.' });
      return true;
    }
    if (action === 'open') {
      (await db.prepare(`UPDATE jobs SET status = 'Open', publish_at = COALESCE(publish_at, ?), updated_at = ? WHERE requisition_id = ?`).run(nowIso, nowIso, reqId));
    } else if (action === 'pause') {
      (await db.prepare(`UPDATE jobs SET status = 'Paused', updated_at = ? WHERE requisition_id = ?`).run(nowIso, reqId));
    } else if (action === 'close') {
      (await db.prepare(`UPDATE jobs SET status = 'Closed', close_at = ?, updated_at = ? WHERE requisition_id = ?`).run(nowIso, nowIso, reqId));
    } else if (action === 'reopen') {
      // PRD 17.05: Reopening creates a NEW opening_cycle_id so stale forms from a closed cycle cannot silently enter!
      const newCycle = `CYCLE-${generateUuid().slice(0, 8)}`;
      await db.prepare(`UPDATE jobs SET status = 'Open', opening_cycle_id = ?, publish_at = ?, close_at = NULL, updated_at = ? WHERE requisition_id = ?`).run(
        newCycle,
        nowIso,
        nowIso,
        reqId
      );
    }
    await bumpPublicCache(db);
    await recordAudit(db, session, 'hiring', `vacancy_${action}`, 'job', reqId);
    sendJson(res, 200, { ok: true });
    return true;
  }

  const jobEditMatch = pathname.match(/^\/admin\/api\/jobs\/([a-zA-Z0-9-]+)$/);
  if (jobEditMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_VACANCIES)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const reqId = jobEditMatch[1];
    const job = await db.prepare('SELECT * FROM jobs WHERE requisition_id = ?').get(reqId);
    if (!job || !canAccessJobRecord(session, job)) {
      sendJson(res, 404, { ok: false, message: 'Vacancy not found.' });
      return true;
    }
    const publishIso =
      fields.publish_phoenix !== undefined
        ? fields.publish_phoenix
          ? phoenixLocalToUtcIso(fields.publish_phoenix)
          : null
        : job.publish_at;
    const closeIso =
      fields.close_phoenix !== undefined
        ? fields.close_phoenix
          ? phoenixLocalToUtcIso(fields.close_phoenix)
          : null
        : job.close_at;
    if (fields.publish_phoenix && !publishIso) {
      sendJson(res, 422, { ok: false, message: 'Invalid America/Phoenix publish date/time.' });
      return true;
    }
    if (fields.close_phoenix && !closeIso) {
      sendJson(res, 422, { ok: false, message: 'Invalid America/Phoenix closing date/time.' });
      return true;
    }
    if (publishIso && closeIso && new Date(closeIso) <= new Date(publishIso)) {
      sendJson(res, 422, { ok: false, message: 'Closing time must be after publish time.' });
      return true;
    }
    const reviewersJson =
      fields.assigned_reviewers !== undefined
        ? JSON.stringify(
            Array.isArray(fields.assigned_reviewers)
              ? fields.assigned_reviewers
              : String(fields.assigned_reviewers)
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean)
          )
        : job.assigned_reviewers_json;
    const nextFormRev = Number(job.form_revision || 1) + 1;

    await db.prepare(
      `UPDATE jobs SET
        title = ?, role_family = ?, employment_type = ?, work_area = ?, schedule_text = ?,
        travel_requirements = ?, responsibilities_html = ?, qualifications_html = ?,
        pay_info = ?, benefits_info = ?, resume_policy = ?, publish_at = ?, close_at = ?,
        backup_owner_id = ?, assigned_reviewers_json = ?, form_revision = ?, updated_at = ?
       WHERE requisition_id = ?`
    ).run(
      String(fields.title ?? job.title).trim(),
      String(fields.role_family ?? job.role_family).trim(),
      String(fields.employment_type ?? job.employment_type).trim(),
      String(fields.work_area ?? job.work_area).trim(),
      String(fields.schedule_text ?? job.schedule_text).trim(),
      String(fields.travel_requirements ?? job.travel_requirements).trim(),
      fields.responsibilities_html !== undefined ? sanitizeRichHtml(fields.responsibilities_html) : job.responsibilities_html,
      fields.qualifications_html !== undefined ? sanitizeRichHtml(fields.qualifications_html) : job.qualifications_html,
      String(fields.pay_info ?? job.pay_info).trim(),
      String(fields.benefits_info ?? job.benefits_info).trim(),
      fields.resume_policy === 'required' ? 'required' : fields.resume_policy === 'optional' ? 'optional' : job.resume_policy,
      publishIso,
      closeIso,
      fields.backup_owner_id !== undefined ? (fields.backup_owner_id || null) : job.backup_owner_id,
      reviewersJson,
      nextFormRev,
      nowIso,
      reqId
    );
    await bumpPublicCache(db);
    await recordAudit(db, session, 'hiring', 'edit_vacancy', 'job', reqId, { form_revision: nextFormRev });
    sendJson(res, 200, { ok: true, form_revision: nextFormRev });
    return true;
  }

  const resumeReplaceMatch = pathname.match(/^\/admin\/api\/applications\/([a-zA-Z0-9-]+)\/attachments\/([a-zA-Z0-9-]+)\/replace$/);
  if (resumeReplaceMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_VACANCIES)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Hiring Owner permission required to replace resumes.' });
      return true;
    }
    const [, appId, attId] = resumeReplaceMatch;
    const app = await db.prepare('SELECT * FROM applications WHERE application_id = ?').get(appId);
    if (!app || !await canAccessApplicationRecord(db, session, app)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: outside assigned recruiting scope.' });
      return true;
    }
    const oldAtt = await db
      .prepare('SELECT * FROM application_attachments WHERE attachment_id = ? AND application_id = ? AND deleted_at IS NULL')
      .get(attId, appId);
    if (!oldAtt) {
      sendJson(res, 404, { ok: false, message: 'Attachment not found.' });
      return true;
    }
    const fileItem = files.find((f) => f.buffer && f.buffer.length > 0);
    if (!fileItem) {
      sendJson(res, 422, { ok: false, message: 'Select a valid PDF or DOCX resume file.' });
      return true;
    }
    const resProc = await processPrivateDocumentUploadAsync({
      buffer: fileItem.buffer,
      originalName: fileItem.originalName,
      allowedTypes: UPLOAD_LIMITS.resume.allowedTypes,
      maxBytes: UPLOAD_LIMITS.resume.maxFileBytes,
      destDir: storagePaths.resumes,
      storagePaths,
      area: 'resumes',
    });
    if (!resProc.ok) {
      sendJson(res, 422, { ok: false, message: resProc.message || 'Invalid resume file.' });
      return true;
    }
    const newAttId = generateUuid();
    await db.prepare(
      `INSERT INTO application_attachments (
        attachment_id, application_id, object_id, storage_key, original_display_name,
        mime_type, byte_size, scan_state, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      newAttId,
      appId,
      resProc.file.object_id,
      resProc.file.storage_key,
      resProc.file.original_name,
      resProc.file.mime_type,
      resProc.file.byte_size,
      resProc.file.scan_state,
      nowIso
    );
    await db.prepare(`UPDATE application_attachments SET replaced_by = ?, deleted_at = ? WHERE attachment_id = ?`).run(
      newAttId,
      nowIso,
      oldAtt.attachment_id
    );
    const store = createObjectStore(storagePaths);
    await store.deleteObject({ area: 'resumes', key: path.basename(oldAtt.storage_key) });
    await recordAudit(db, session, 'hiring', 'replace_resume', 'application_attachment', newAttId, {
      application_id: appId,
      replaced_attachment_id: oldAtt.attachment_id,
    });
    sendJson(res, 200, { ok: true, attachment_id: newAttId });
    return true;
  }

  const resumeDeleteMatch = pathname.match(/^\/admin\/api\/applications\/([a-zA-Z0-9-]+)\/attachments\/([a-zA-Z0-9-]+)\/delete$/);
  if (resumeDeleteMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_VACANCIES)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Hiring Owner permission required to delete resumes.' });
      return true;
    }
    const [, appId, attId] = resumeDeleteMatch;
    const app = await db.prepare('SELECT * FROM applications WHERE application_id = ?').get(appId);
    if (!app || !await canAccessApplicationRecord(db, session, app)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: outside assigned recruiting scope.' });
      return true;
    }
    const oldAtt = await db
      .prepare('SELECT * FROM application_attachments WHERE attachment_id = ? AND application_id = ? AND deleted_at IS NULL')
      .get(attId, appId);
    if (!oldAtt) {
      sendJson(res, 404, { ok: false, message: 'Attachment not found.' });
      return true;
    }
    (await db.prepare(`UPDATE application_attachments SET deleted_at = ? WHERE attachment_id = ?`).run(nowIso, oldAtt.attachment_id));
    const store = createObjectStore(storagePaths);
    await store.deleteObject({ area: 'resumes', key: path.basename(oldAtt.storage_key) });
    await recordAudit(db, session, 'hiring', 'delete_resume', 'application_attachment', oldAtt.attachment_id, {
      application_id: appId,
    });
    sendJson(res, 200, { ok: true });
    return true;
  }

  const appReviewMatch = pathname.match(/^\/admin\/api\/applications\/([a-zA-Z0-9-]+)\/review$/);
  if (appReviewMatch) {
    if (!hasPermission(session, PERMISSIONS.REVIEW_APPLICATIONS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const app = await db.prepare('SELECT * FROM applications WHERE application_id = ?').get(appReviewMatch[1]);
    if (!app || !await canAccessApplicationRecord(db, session, app)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: outside assigned recruiting scope.' });
      return true;
    }
    const nextStage = String(fields.stage || app.stage);
    const assignedRev = hasPermission(session, PERMISSIONS.MANAGE_VACANCIES) && fields.assigned_reviewer_id !== undefined
      ? (fields.assigned_reviewer_id || null)
      : app.assigned_reviewer_id;

    await db.prepare(`UPDATE applications SET stage = ?, assigned_reviewer_id = ?, updated_at = ? WHERE application_id = ?`).run(
      nextStage,
      assignedRev,
      nowIso,
      app.application_id
    );
    if (fields.note_text && String(fields.note_text).trim()) {
      (await db.prepare(
        `INSERT INTO application_notes (note_id, application_id, author_id, author_name, note_text, stage_change_from, stage_change_to, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(generateUuid(), app.application_id, session.user_id, session.full_name, String(fields.note_text).trim(), app.stage, nextStage, nowIso));
    }
    await recordAudit(db, session, 'hiring', 'review_application', 'application', app.application_id, { stage: nextStage });
    sendJson(res, 200, { ok: true });
    return true;
  }

  // ============================================================
  // 8. LEADS, CRM REPLAY & SETTINGS
  // ============================================================
  if (pathname === '/admin/api/crm/fault-mode') {
    if (ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production') {
      sendJson(res, 403, { ok: false, message: 'CRM fault simulation is disabled in production.' });
      return true;
    }
    if (!hasPermission(session, PERMISSIONS.MANAGE_LEADS_CRM)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const mode = urlObj.searchParams.get('mode') || 'none';
    setCrmFaultMode(mode);
    sendJson(res, 200, { ok: true, mode });
    return true;
  }

  const crmReplayMatch = pathname.match(/^\/admin\/api\/crm\/replay\/([a-zA-Z0-9-]+)$/);
  if (crmReplayMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_LEADS_CRM)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    (await db.prepare(`UPDATE crm_delivery_queue SET status = 'pending', attempts = 0, next_attempt_at = ?, updated_at = ? WHERE delivery_id = ?`).run(
      nowIso,
      nowIso,
      crmReplayMatch[1]
    ));
    const workerRes = await processDeliveryQueues(db);
    await recordAudit(db, session, 'crm', 'manual_replay', 'crm_delivery_queue', crmReplayMatch[1]);
    sendJson(res, 200, { ok: true, ...workerRes });
    return true;
  }

  const notifReplayMatch = pathname.match(/^\/admin\/api\/notifications\/replay\/([a-zA-Z0-9-]+)$/);
  if (notifReplayMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_LEADS_CRM)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const existingNotif = await db.prepare(`SELECT * FROM notification_queue WHERE notification_id = ?`).get(notifReplayMatch[1]);
    if (!existingNotif) {
      sendJson(res, 404, { ok: false, message: 'Notification record not found.' });
      return true;
    }
    (await db.prepare(
      `UPDATE notification_queue SET status = 'pending', attempts = 0, next_attempt_at = ?, last_error = NULL, updated_at = ? WHERE notification_id = ?`
    ).run(nowIso, nowIso, notifReplayMatch[1]));
    const workerRes = await processDeliveryQueues(db);
    await recordAudit(db, session, 'notifications', 'manual_replay', 'notification_queue', notifReplayMatch[1]);
    sendJson(res, 200, { ok: true, ...workerRes });
    return true;
  }

  const inqStatusMatch = pathname.match(/^\/admin\/api\/inquiries\/([a-zA-Z0-9-]+)\/status$/);
  if (inqStatusMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_LEADS_CRM)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const existingInquiry = await db.prepare(`SELECT * FROM inquiries WHERE inquiry_id = ?`).get(inqStatusMatch[1]);
    if (!existingInquiry) {
      sendJson(res, 404, { ok: false, message: 'Inquiry not found.' });
      return true;
    }

    const allowedClassifications = ['valid', 'existing_service', 'spam', 'job', 'vendor', 'out_of_area', 'test'];
    const allowedStatuses = ['received', 'qualified', 'proposal_sent', 'closed_won', 'disqualified'];
    const nextClassification = String(fields.classification || existingInquiry.classification);
    const nextStatus = String(fields.status || existingInquiry.status);

    if (!allowedClassifications.includes(nextClassification) || !allowedStatuses.includes(nextStatus)) {
      sendJson(res, 400, { ok: false, message: 'Invalid classification or pipeline status.' });
      return true;
    }

    let nextDealValue = existingInquiry.deal_value ?? null;
    if (fields.deal_value !== undefined && fields.deal_value !== null && String(fields.deal_value).trim() !== '') {
      const parsedVal = Number(fields.deal_value);
      if (!Number.isFinite(parsedVal) || parsedVal < 0) {
        sendJson(res, 400, { ok: false, message: 'Deal value must be a non-negative number.' });
        return true;
      }
      nextDealValue = parsedVal;
    }

    (await db.prepare(`UPDATE inquiries SET classification = ?, status = ?, deal_value = ?, updated_at = ? WHERE inquiry_id = ?`).run(
      nextClassification,
      nextStatus,
      nextDealValue,
      nowIso,
      inqStatusMatch[1]
    ));

    let milestoneRecorded = null;
    let crmSync = null;
    const milestoneMap = {
      qualified: { eventName: 'qualified_lead', column: 'milestone_qualified_at' },
      proposal_sent: { eventName: 'proposal_sent', column: 'milestone_proposal_at' },
      closed_won: { eventName: 'closed_won', column: 'milestone_won_at' },
    };

    const milestoneInfo = milestoneMap[nextStatus];
    if (nextClassification === 'valid' && existingInquiry.inquiry_kind === 'new_business' && milestoneInfo) {
      if (!existingInquiry[milestoneInfo.column]) {
        let attr = {};
        try {
          attr = existingInquiry.attribution_json ? JSON.parse(existingInquiry.attribution_json) : {};
        } catch {
          attr = {};
        }
        const acq = attr.acquisition_utms && typeof attr.acquisition_utms === 'object' ? attr.acquisition_utms : attr;
        await recordAnalyticsEvent(db, {
          event_name: milestoneInfo.eventName,
          page_type: 'crm_pipeline',
          service_id: existingInquiry.service_family,
          acquisition_utm_source: acq.utm_source || null,
          acquisition_utm_medium: acq.utm_medium || null,
          acquisition_utm_campaign: acq.utm_campaign || null,
          acquisition_utm_content: acq.utm_content || null,
          consent_mode: 'first_party_crm',
        });
        await db.prepare(`UPDATE inquiries SET ${milestoneInfo.column} = ?, updated_at = ? WHERE inquiry_id = ?`).run(
          nowIso,
          nowIso,
          inqStatusMatch[1]
        );
        milestoneRecorded = milestoneInfo.eventName;
      }

      const updatedInquiry = await db.prepare(`SELECT * FROM inquiries WHERE inquiry_id = ?`).get(inqStatusMatch[1]);
      const account = await db.prepare(`SELECT * FROM accounts WHERE account_id = ?`).get(updatedInquiry.account_id);
      const contact = await db.prepare(`SELECT * FROM contacts WHERE contact_id = ?`).get(updatedInquiry.contact_id);
      const property = updatedInquiry.property_id
        ? (await db.prepare(`SELECT * FROM properties WHERE property_id = ?`).get(updatedInquiry.property_id))
        : null;

      crmSync = await syncDealMilestoneToFreshsales({
        inquiry: updatedInquiry,
        account,
        contact,
        property,
        milestone: nextStatus,
        dealValue: nextDealValue,
      });

      if (crmSync.ok) {
        if (crmSync.crmDealId) {
          (await db.prepare(`UPDATE inquiries SET crm_deal_id = ?, updated_at = ? WHERE inquiry_id = ?`).run(
            crmSync.crmDealId,
            nowIso,
            inqStatusMatch[1]
          ));
        }
        if (account && crmSync.crmAccountId) {
          (await db.prepare(`UPDATE accounts SET crm_account_id = ? WHERE account_id = ?`).run(crmSync.crmAccountId, account.account_id));
        }
        if (contact && crmSync.crmContactId) {
          (await db.prepare(`UPDATE contacts SET crm_contact_id = ? WHERE contact_id = ?`).run(crmSync.crmContactId, contact.contact_id));
        }
        if (crmSync.crmNoteId) {
          (await db.prepare(`UPDATE inquiries SET crm_note_id = ? WHERE inquiry_id = ?`).run(crmSync.crmNoteId, inqStatusMatch[1]));
        }
        if (property && crmSync.crmPropertyNoteId) {
          (await db.prepare(`UPDATE properties SET crm_property_note_id = ? WHERE property_id = ?`).run(
            crmSync.crmPropertyNoteId,
            property.property_id
          ));
        }
      } else {
        await recordAudit(db, session, 'crm', 'deal_sync_failed', 'inquiry', inqStatusMatch[1], {
          milestone: nextStatus,
          error: crmSync.error,
        });
      }
    }

    await recordAudit(db, session, 'crm', 'update_inquiry_disposition', 'inquiry', inqStatusMatch[1], {
      classification: nextClassification,
      status: nextStatus,
      deal_value: nextDealValue,
      milestoneRecorded,
    });
    sendJson(res, 200, { ok: true, milestoneRecorded, crmSync });
    return true;
  }

  if (pathname === '/admin/api/settings') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_SETTINGS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    (await db.prepare(
      `UPDATE business_settings SET
        trading_name = ?, legal_entity = ?, phone_display = ?, hours_display = ?,
        address_display = ?, roc_numbers = ?, insurance_statement = ?, updated_at = ?, updated_by = ?
       WHERE id = 1`
    ).run(
      fields.trading_name,
      fields.legal_entity,
      fields.phone_display,
      fields.hours_display,
      fields.address_display,
      fields.roc_numbers,
      fields.insurance_statement,
      nowIso,
      session.full_name
    ));
    await bumpPublicCache(db);
    await recordAudit(db, session, 'settings', 'update_business_settings', 'business_settings', '1');
    sendJson(res, 200, { ok: true });
    return true;
  }

  // ============================================================
  // 9. STAFF USER & ROLE MANAGEMENT (Platform Administrator)
  // ============================================================
  if (pathname === '/admin/api/users') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_USERS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Platform Administrator required.' });
      return true;
    }
    const validRoles = Object.values(ROLES);
    const email = String(fields.email || '').trim().toLowerCase();
    const fullName = String(fields.full_name || '').trim();
    const role = String(fields.role || '').trim();
    const password = String(fields.password || '');
    const extraRolesRaw = Array.isArray(fields.extra_roles)
      ? fields.extra_roles.map((s) => String(s || '').trim()).filter(Boolean)
      : String(fields.extra_roles || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
    const invalidExtra = extraRolesRaw.filter((r) => !validRoles.includes(r));
    if (invalidExtra.length > 0) {
      sendJson(res, 422, { ok: false, message: `Unrecognized role(s): ${invalidExtra.join(', ')}` });
      return true;
    }
    const extraRoles = Array.from(new Set(extraRolesRaw.filter((r) => r !== role)));

    if (!isValidEmail(email) || !fullName || !validRoles.includes(role) || password.length < 10) {
      sendJson(res, 422, { ok: false, message: 'Provide a valid email, full name, allowed role, and password (minimum 10 characters).' });
      return true;
    }
    const existingUser = await db.prepare('SELECT 1 FROM users WHERE email = ?').get(email);
    if (existingUser) {
      sendJson(res, 409, { ok: false, message: 'A staff account with this email already exists.' });
      return true;
    }
    const userId = `usr-${generateUuid().slice(0, 12)}`;
    const totpSecret = generateTotpSecret();
    const encryptedTotpSecret = encryptMfaSecret(totpSecret);
    const mfaEnabled = fields.mfa_enabled === false || fields.mfa_enabled === 'false' || fields.mfa_enabled === '0' ? 0 : 1;

    await db.prepare(
      `INSERT INTO users (
        user_id, email, full_name, password_hash, role, extra_roles_json,
        totp_secret, mfa_enabled, mfa_enrolled, active, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 1, ?, ?)`
    ).run(userId, email, fullName, hashPassword(password), role, JSON.stringify(extraRoles), encryptedTotpSecret, mfaEnabled, nowIso, nowIso);

    const assignedRoles = Array.from(new Set([role, ...extraRoles]));
    const hiringPrivilegeGranted = assignedRoles.some((r) => r === ROLES.HIRING_OWNER || r === ROLES.HIRING_REVIEWER);
    const adminPrivilegeGranted = assignedRoles.includes(ROLES.PLATFORM_ADMIN);

    await recordAudit(db, session, 'users', 'create_user', 'user', userId, {
      role,
      extraRoles,
      assigned_roles: assignedRoles,
      hiring_privilege_granted: hiringPrivilegeGranted,
      admin_privilege_granted: adminPrivilegeGranted,
      mfa_enabled: Boolean(mfaEnabled),
    });
    sendJson(res, 201, {
      ok: true,
      user_id: userId,
      mfa_enabled: Boolean(mfaEnabled),
      mfa_enrolled: false,
      message: mfaEnabled
        ? `Staff account created for ${email}. Issue a single-use MFA Setup Link from Staff Accounts to authorize Google Authenticator enrollment.`
        : `Staff account created cleanly for ${email}.`,
    });
    return true;
  }

  const mfaRecoveryMatch = pathname.match(/^\/admin\/api\/users\/([a-zA-Z0-9-]+)\/mfa-recovery-token$/);
  if (mfaRecoveryMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_USERS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: Platform Administrator required.' });
      return true;
    }
    const targetId = mfaRecoveryMatch[1];
    const targetUser = await db.prepare('SELECT user_id, email, mfa_enrolled, active FROM users WHERE user_id = ?').get(targetId);
    if (!targetUser || !targetUser.active) {
      sendJson(res, 404, { ok: false, message: 'Active staff account not found.' });
      return true;
    }
    const purpose = targetUser.mfa_enrolled ? 'recovery' : 'first_time_enroll';
    const tokenRes = await issueMfaSetupToken(db, {
      userId: targetUser.user_id,
      purpose,
      issuedBy: session.user_id,
      ttlMinutes: 15,
    });
    if (!tokenRes.ok) {
      sendJson(res, tokenRes.status || 422, { ok: false, message: tokenRes.error });
      return true;
    }
    sendJson(res, 200, {
      ok: true,
      purpose: tokenRes.purpose,
      expires_at: tokenRes.expiresAt,
      setup_url: `/admin/mfa-setup?token=${tokenRes.rawToken}`,
      message: `Single-use 15-minute MFA ${purpose === 'recovery' ? 'recovery' : 'setup'} link issued for ${targetUser.email}.`,
    });
    return true;
  }

  const userLifecycleMatch = pathname.match(/^\/admin\/api\/users\/([a-zA-Z0-9-]+)\/(deactivate|activate|revoke-sessions)$/);
  if (userLifecycleMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_USERS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const [, targetId, action] = userLifecycleMatch;
    const targetUser = await db.prepare('SELECT * FROM users WHERE user_id = ?').get(targetId);
    if (!targetUser) {
      sendJson(res, 404, { ok: false, message: 'Staff user not found.' });
      return true;
    }
    if (action === 'revoke-sessions') {
      await revokeUserSessions(db, targetId);
      await recordAudit(db, session, 'users', 'revoke_user_sessions', 'user', targetId);
      sendJson(res, 200, { ok: true, message: 'Active staff sessions revoked.' });
      return true;
    }
    if (action === 'deactivate') {
      if (targetId === session.user_id) {
        sendJson(res, 422, { ok: false, message: 'Cannot deactivate your own active administrator session.' });
        return true;
      }
      if (targetUser.role === ROLES.PLATFORM_ADMIN) {
        const otherAdmins = (await db
          .prepare(`SELECT COUNT(*) as c FROM users WHERE active = 1 AND role = ? AND user_id != ?`)
          .get(ROLES.PLATFORM_ADMIN, targetId)).c;
        if (otherAdmins < 1) {
          sendJson(res, 422, { ok: false, message: 'Cannot deactivate the last active Platform Administrator.' });
          return true;
        }
      }
      (await db.prepare(`UPDATE users SET active = 0, updated_at = ? WHERE user_id = ?`).run(nowIso, targetId));
      await revokeUserSessions(db, targetId);
      await recordAudit(db, session, 'users', 'deactivate_user', 'user', targetId, { sessions_revoked: true });
      sendJson(res, 200, { ok: true, active: 0 });
      return true;
    }
    (await db.prepare(`UPDATE users SET active = 1, updated_at = ? WHERE user_id = ?`).run(nowIso, targetId));
    await recordAudit(db, session, 'users', 'activate_user', 'user', targetId);
    sendJson(res, 200, { ok: true, active: 1 });
    return true;
  }

  const userEditMatch = pathname.match(/^\/admin\/api\/users\/([a-zA-Z0-9-]+)$/);
  if (userEditMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_USERS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const targetId = userEditMatch[1];
    const targetUser = await db.prepare('SELECT * FROM users WHERE user_id = ?').get(targetId);
    if (!targetUser) {
      sendJson(res, 404, { ok: false, message: 'Staff user not found.' });
      return true;
    }
    const validRoles = Object.values(ROLES);
    const nextRole = fields.role ? String(fields.role).trim() : targetUser.role;
    if (!validRoles.includes(nextRole)) {
      sendJson(res, 422, { ok: false, message: 'Invalid role selected.' });
      return true;
    }
    const extraRolesRaw =
      fields.extra_roles !== undefined
        ? Array.isArray(fields.extra_roles)
          ? fields.extra_roles.map((s) => String(s || '').trim()).filter(Boolean)
          : String(fields.extra_roles || '')
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
        : JSON.parse(targetUser.extra_roles_json || '[]');
    const invalidExtra = extraRolesRaw.filter((r) => !validRoles.includes(r));
    if (invalidExtra.length > 0) {
      sendJson(res, 422, { ok: false, message: `Unrecognized role(s): ${invalidExtra.join(', ')}` });
      return true;
    }
    const filteredExtra = Array.from(new Set(extraRolesRaw.filter((r) => r !== nextRole)));
    const nextExtraRolesJson = JSON.stringify(filteredExtra);
    const nextActive =
      fields.active !== undefined ? (fields.active === true || fields.active === 'true' || fields.active === '1' || fields.active === 1 || fields.active === 'on' ? 1 : 0) : targetUser.active;

    if (targetId === session.user_id && nextActive === 0) {
      sendJson(res, 422, { ok: false, message: 'Cannot deactivate your own active administrator session.' });
      return true;
    }

    if (targetUser.role === ROLES.PLATFORM_ADMIN && (nextActive === 0 || nextRole !== ROLES.PLATFORM_ADMIN)) {
      const otherAdmins = (await db
        .prepare(`SELECT COUNT(*) as c FROM users WHERE active = 1 AND role = ? AND user_id != ?`)
        .get(ROLES.PLATFORM_ADMIN, targetId)).c;
      if (otherAdmins < 1) {
        sendJson(res, 422, { ok: false, message: 'Cannot remove or deactivate the last active Platform Administrator.' });
        return true;
      }
    }

    const nextFullName = String(fields.full_name ?? targetUser.full_name).trim();
    const hasNewPass = Boolean(fields.new_password && String(fields.new_password).length >= 10);
    if (fields.new_password && String(fields.new_password).length > 0 && String(fields.new_password).length < 10) {
      sendJson(res, 422, { ok: false, message: 'New password must be at least 10 characters.' });
      return true;
    }

    const prevRoles = getUserRoles(targetUser);
    const nextRoles = Array.from(new Set([nextRole, ...filteredExtra]));
    const addedRoles = nextRoles.filter((r) => !prevRoles.includes(r));
    const removedRoles = prevRoles.filter((r) => !nextRoles.includes(r));
    const hiringPrivilegeGranted = addedRoles.some((r) => r === ROLES.HIRING_OWNER || r === ROLES.HIRING_REVIEWER);
    const adminPrivilegeGranted = addedRoles.includes(ROLES.PLATFORM_ADMIN);

    const nextPasswordHash = hasNewPass ? hashPassword(String(fields.new_password)) : targetUser.password_hash;
    await db.prepare(
      `UPDATE users SET full_name = ?, role = ?, extra_roles_json = ?, active = ?, password_hash = ?, updated_at = ? WHERE user_id = ?`
    ).run(nextFullName || targetUser.full_name, nextRole, nextExtraRolesJson, nextActive, nextPasswordHash, nowIso, targetId);

    const roleOrAccessChanged =
      nextRole !== targetUser.role ||
      nextExtraRolesJson !== targetUser.extra_roles_json ||
      nextActive === 0 ||
      hasNewPass;
    if (roleOrAccessChanged) {
      await revokeUserSessions(db, targetId);
    }

    await recordAudit(db, session, 'users', 'update_user', 'user', targetId, {
      previous_role: targetUser.role,
      new_role: nextRole,
      previous_roles: prevRoles,
      new_roles: nextRoles,
      added_roles: addedRoles,
      removed_roles: removedRoles,
      hiring_privilege_granted: hiringPrivilegeGranted,
      admin_privilege_granted: adminPrivilegeGranted,
      self_modified: targetId === session.user_id,
      active: Boolean(nextActive),
      sessions_revoked: roleOrAccessChanged,
    });
    sendJson(res, 200, { ok: true, sessions_revoked: roleOrAccessChanged, roles: nextRoles });
    return true;
  }

  // ============================================================
  // 10. AUTOMATED BACKUPS, INTEGRITY CHECK, RESTORE & RETENTION (OPS-01 / OPS-03)
  // ============================================================
  if (pathname === '/admin/api/backups/create') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_BACKUPS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: backup permission required.' });
      return true;
    }
    const resBak = await createFullBackup(db, { storagePaths, actor: session, reason: 'manual' });
    sendJson(res, 201, resBak);
    return true;
  }

  const backupVerifyMatch = pathname.match(/^\/admin\/api\/backups\/([a-zA-Z0-9-]+)\/verify$/);
  if (backupVerifyMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_BACKUPS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const row = await db.prepare('SELECT * FROM backup_runs WHERE backup_id = ?').get(backupVerifyMatch[1]);
    if (!row) {
      sendJson(res, 404, { ok: false, message: 'Backup record not found.' });
      return true;
    }
    const check = await verifyBackupIntegrity(row.backup_dir, storagePaths);
    await db.prepare(`UPDATE backup_runs SET status = ? WHERE backup_id = ?`).run(check.ok ? 'verified' : 'corrupted', row.backup_id);
    await recordAudit(db, session, 'ops', 'verify_backup', 'backup', row.backup_id, { ok: check.ok, error: check.error || null });
    sendJson(res, check.ok ? 200 : 422, { ok: check.ok, error: check.error || null, manifest: check.manifest || null });
    return true;
  }

  const backupRestoreMatch = pathname.match(/^\/admin\/api\/backups\/([a-zA-Z0-9-]+)\/restore$/);
  if (backupRestoreMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_BACKUPS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: backup restore privilege required.' });
      return true;
    }
    const resRestore = await restoreFromBackup(db, {
      backupId: backupRestoreMatch[1],
      storagePaths,
      actor: session,
      nowDate: new Date(),
    });
    sendJson(res, resRestore.ok ? 200 : resRestore.statusCode || 422, resRestore);
    return true;
  }

  const retentionApproveMatch = pathname.match(/^\/admin\/api\/retention\/policies\/([a-zA-Z0-9_]+)$/);
  if (retentionApproveMatch) {
    if (!hasPermission(session, PERMISSIONS.MANAGE_BACKUPS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden: platform administrator permission required.' });
      return true;
    }
    const approved = fields.approved === undefined ? true : fields.approved === true || fields.approved === 'true' || fields.approved === '1' || fields.approved === 'on';
    const resApprove = await approveRetentionPolicy(db, {
      policyKey: retentionApproveMatch[1],
      retentionDays: fields.retention_days,
      approved,
      actor: session,
      notes: fields.notes || null,
    });
    sendJson(res, resApprove.ok ? 200 : resApprove.statusCode || 422, resApprove);
    return true;
  }

  if (pathname === '/admin/api/retention/run') {
    if (!hasPermission(session, PERMISSIONS.MANAGE_BACKUPS)) {
      sendJson(res, 403, { ok: false, message: 'Forbidden' });
      return true;
    }
    const dryRun = fields.dry_run === true || fields.dry_run === 'true';
    const sweepRes = await runRetentionSweep(db, { storagePaths, actor: session, nowDate: new Date(), dryRun });
    sendJson(res, 200, sweepRes);
    return true;
  }

  return false;
}
