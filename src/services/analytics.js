import { generateUuid } from '../lib/crypto.js';

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

export async function getAnalyticsSummary(db) {
  const eventCounts = await db
    .prepare(
      `SELECT event_name, COUNT(*) as total
       FROM analytics_events
       GROUP BY event_name
       ORDER BY total DESC`
    )
    .all();

  const leadsByService = await db
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

  return { eventCounts, leadsByService, campaignPerformance, projectReadiness };
}
