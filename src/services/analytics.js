import { generateUuid } from '../lib/crypto.js';
import { canAccessApplicationRecord, canAccessJobRecord, hasPermission, PERMISSIONS } from './auth.js';

const ALLOWED_EVENTS = new Set([
  'view_service',
  'form_start',
  'form_error',
  'generate_lead',
  'service_request_received',
  'phone_click',
  'email_click',
  'download_capabilities',
  'qualified_lead',
  'proposal_sent',
  'closed_won',
  'campaign_view',
  'campaign_click',
  'view_project',
  'view_job',
  'application_start',
  'application_received',
]);

// Strictly scrub any accidental PII patterns (DATA-01)
function scrubNonPiiString(val, maxLen = 64) {
  if (!val) return null;
  const s = String(val).trim().slice(0, maxLen);
  if (/@/.test(s) || /\d{3}[-.\s)]*\d{3}[-.\s]*\d{4}/.test(s)) {
    return null;
  }
  return s;
}

export async function recordAnalyticsEvent(db, evt) {
  if (!evt || !ALLOWED_EVENTS.has(evt.event_name)) {
    return { ok: false, error: 'unsupported_event' };
  }
  // Never store applicant PII or commercial conversion overlap on hiring pages
  const id = generateUuid();
  await db.prepare(
    `INSERT INTO analytics_events
     (event_id, event_name, page_type, service_id, project_id, job_id,
      on_site_campaign_id, placement_id, content_revision,
      acquisition_utm_source, acquisition_utm_medium, acquisition_utm_campaign, acquisition_utm_content,
      error_code, consent_mode, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    evt.event_name,
    scrubNonPiiString(evt.page_type, 40),
    scrubNonPiiString(evt.service_id, 60),
    scrubNonPiiString(evt.project_id, 60),
    scrubNonPiiString(evt.job_id, 60),
    scrubNonPiiString(evt.on_site_campaign_id, 60),
    scrubNonPiiString(evt.placement_id, 40),
    Number.isFinite(Number(evt.content_revision)) ? Number(evt.content_revision) : null,
    scrubNonPiiString(evt.acquisition_utm_source, 60),
    scrubNonPiiString(evt.acquisition_utm_medium, 60),
    scrubNonPiiString(evt.acquisition_utm_campaign, 80),
    scrubNonPiiString(evt.acquisition_utm_content, 80),
    scrubNonPiiString(evt.error_code, 40),
    scrubNonPiiString(evt.consent_mode || 'essential_only', 30),
    new Date().toISOString()
  );
  return { ok: true, event_id: id };
}

export async function getAnalyticsSummary(db, { range = 'all', user = null } = {}) {
  const daysMap = { '7d': 7, '30d': 30, '90d': 90 };
  const days = daysMap[range] || null;
  const sinceIso = days ? new Date(Date.now() - days * 86_400_000).toISOString() : '';

  const eventCounts = sinceIso
    ? await db
        .prepare(
          `SELECT event_name, COUNT(*) as total
           FROM analytics_events
           WHERE created_at >= ?
           GROUP BY event_name
           ORDER BY total DESC`
        )
        .all(sinceIso)
    : await db
        .prepare(
          `SELECT event_name, COUNT(*) as total
           FROM analytics_events
           GROUP BY event_name
           ORDER BY total DESC`
        )
        .all();

  const leadsByService = sinceIso
    ? await db
        .prepare(
          `SELECT service_family,
                  COUNT(*) as total_inquiries,
                  SUM(CASE WHEN classification = 'valid' AND inquiry_kind = 'new_business' THEN 1 ELSE 0 END) as accepted_new_business,
                  SUM(CASE WHEN status = 'qualified' THEN 1 ELSE 0 END) as qualified_opportunities,
                  SUM(CASE WHEN status = 'proposal_sent' THEN 1 ELSE 0 END) as proposals_sent,
                  SUM(CASE WHEN status = 'closed_won' THEN 1 ELSE 0 END) as closed_won,
                  SUM(CASE WHEN inquiry_kind = 'existing_service' THEN 1 ELSE 0 END) as existing_service_requests,
                  SUM(CASE WHEN classification IN ('spam', 'job', 'vendor', 'out_of_area', 'test') THEN 1 ELSE 0 END) as excluded_non_sales
           FROM inquiries
           WHERE received_at >= ?
           GROUP BY service_family`
        )
        .all(sinceIso)
    : await db
        .prepare(
          `SELECT service_family,
                  COUNT(*) as total_inquiries,
                  SUM(CASE WHEN classification = 'valid' AND inquiry_kind = 'new_business' THEN 1 ELSE 0 END) as accepted_new_business,
                  SUM(CASE WHEN status = 'qualified' THEN 1 ELSE 0 END) as qualified_opportunities,
                  SUM(CASE WHEN status = 'proposal_sent' THEN 1 ELSE 0 END) as proposals_sent,
                  SUM(CASE WHEN status = 'closed_won' THEN 1 ELSE 0 END) as closed_won,
                  SUM(CASE WHEN inquiry_kind = 'existing_service' THEN 1 ELSE 0 END) as existing_service_requests,
                  SUM(CASE WHEN classification IN ('spam', 'job', 'vendor', 'out_of_area', 'test') THEN 1 ELSE 0 END) as excluded_non_sales
           FROM inquiries
           GROUP BY service_family`
        )
        .all();

  const channelBreakdown = sinceIso
    ? await db
        .prepare(
          `SELECT COALESCE(NULLIF(TRIM(acquisition_utm_source), ''), 'direct / unattributed') as source,
                  COALESCE(NULLIF(TRIM(acquisition_utm_medium), ''), '—') as medium,
                  SUM(CASE WHEN event_name = 'generate_lead' THEN 1 ELSE 0 END) as accepted_leads,
                  COUNT(*) as events_total
           FROM analytics_events
           WHERE created_at >= ?
           GROUP BY source, medium
           ORDER BY accepted_leads DESC, events_total DESC`
        )
        .all(sinceIso)
    : await db
        .prepare(
          `SELECT COALESCE(NULLIF(TRIM(acquisition_utm_source), ''), 'direct / unattributed') as source,
                  COALESCE(NULLIF(TRIM(acquisition_utm_medium), ''), '—') as medium,
                  SUM(CASE WHEN event_name = 'generate_lead' THEN 1 ELSE 0 END) as accepted_leads,
                  COUNT(*) as events_total
           FROM analytics_events
           GROUP BY source, medium
           ORDER BY accepted_leads DESC, events_total DESC`
        )
        .all();

  const campaignPerformance = await db
    .prepare(
      `SELECT c.campaign_id, c.internal_title, c.placement_slot, c.activation_state,
              (SELECT COUNT(*) FROM analytics_events e WHERE e.on_site_campaign_id = c.campaign_id AND e.event_name = 'campaign_view') as views,
              (SELECT COUNT(*) FROM analytics_events e WHERE e.on_site_campaign_id = c.campaign_id AND e.event_name = 'campaign_click') as clicks
       FROM campaigns c
       ORDER BY c.updated_at DESC`
    )
    .all();

  const projectReadiness = await db
    .prepare(
      `SELECT activation_state, editorial_state, COUNT(*) as total,
              SUM(CASE WHEN is_private_test = 1 THEN 1 ELSE 0 END) as test_records
       FROM projects
       GROUP BY activation_state, editorial_state`
    )
    .all();

  let hiringActivity = null;
  if (user && (hasPermission(user, PERMISSIONS.MANAGE_VACANCIES) || hasPermission(user, PERMISSIONS.REVIEW_APPLICATIONS))) {
    const allJobs = await db.prepare('SELECT requisition_id, title, status, hiring_owner_id, backup_owner_id, assigned_reviewers_json, is_private_test FROM jobs').all();
    const scopedJobs = allJobs.filter((j) => canAccessJobRecord(user, j));
    const allApps = await db
      .prepare(
        `SELECT a.application_id, a.requisition_id, a.stage, a.received_at, a.assigned_reviewer_id,
                (SELECT MIN(n.created_at) FROM application_notes n WHERE n.application_id = a.application_id) as first_note_at
         FROM applications a`
      )
      .all();
    const scopedApps = [];
    for (const a of allApps) {
      if (sinceIso && a.received_at < sinceIso) continue;
      if (await canAccessApplicationRecord(db, user, a)) {
        scopedApps.push(a);
      }
    }

    const byJobMap = new Map();
    for (const j of scopedJobs) {
      byJobMap.set(j.requisition_id, {
        requisition_id: j.requisition_id,
        title: j.title,
        status: j.status,
        total: 0,
        pendingReview: 0,
        reviewHoursSum: 0,
        reviewedCount: 0,
      });
    }
    for (const a of scopedApps) {
      const entry = byJobMap.get(a.requisition_id);
      if (!entry) continue;
      entry.total += 1;
      if (a.stage === 'Received') entry.pendingReview += 1;
      if (a.first_note_at) {
        const hrs = Math.max(0, (new Date(a.first_note_at).getTime() - new Date(a.received_at).getTime()) / 3_600_000);
        entry.reviewHoursSum += hrs;
        entry.reviewedCount += 1;
      }
    }
    hiringActivity = Array.from(byJobMap.values()).map((r) => ({
      ...r,
      avgReviewHours: r.reviewedCount > 0 ? Math.round((r.reviewHoursSum / r.reviewedCount) * 10) / 10 : null,
    }));
  }

  return { range, eventCounts, leadsByService, channelBreakdown, campaignPerformance, projectReadiness, hiringActivity };
}
