import { recordAudit } from './auth.js';

/**
 * Evaluates campaign eligibility at a specific timestamp (defaults to current time).
 * Supports "As of" future Phoenix date/time preview without mutating live records.
 * Rules (PRD Section 18):
 * - Start inclusive: start_at <= now
 * - End exclusive: now < end_at (or omitted when is_evergreen = 1)
 * - Must be Approved + Live (or Scheduled/Live in preview mode when checking upcoming)
 * - If asset_id is set, that asset must have rights_status === 'approved'
 * - Precedence: highest numeric priority, then latest start_at, then immutable campaign_id ASC
 */
export async function resolveActiveCampaigns(db, { asOfIso = null, includeDraftIds = [] } = {}) {
  const nowMs = asOfIso ? new Date(asOfIso).getTime() : Date.now();
  const rows = await db.prepare('SELECT * FROM campaigns').all();

  const eligible = [];
  for (const c of rows) {
    const isPreviewOverride = includeDraftIds.includes(c.campaign_id);
    if (!isPreviewOverride) {
      if (c.editorial_state !== 'Approved') continue;
      if (c.activation_state !== 'Live' && !(asOfIso && c.activation_state === 'Scheduled')) continue;
    }

    const startMs = new Date(c.start_at).getTime();
    if (Number.isNaN(startMs) || startMs > nowMs) continue;

    if (!c.is_evergreen) {
      const endMs = c.end_at ? new Date(c.end_at).getTime() : NaN;
      if (Number.isNaN(endMs) || nowMs >= endMs) continue;
    }

    // Verify CTA destination exists & asset rights are valid
    if (!c.cta_destination || !c.cta_destination.startsWith('/')) continue;

    let asset = null;
    if (c.asset_id) {
      asset = await db.prepare('SELECT * FROM media_assets WHERE asset_id = ?').get(c.asset_id);
      if (!asset || asset.rights_status !== 'approved') {
        // Withdrawn or invalid asset rights: ineligible for display
        continue;
      }
      if (asset.expiry_date && new Date(asset.expiry_date).getTime() <= nowMs) {
        continue;
      }
    }

    eligible.push({ ...c, asset });
  }

  // Defensive runtime ordering: priority DESC, start_at DESC, campaign_id ASC
  eligible.sort((a, b) => {
    if (b.priority !== a.priority) return b.priority - a.priority;
    const sa = new Date(a.start_at).getTime();
    const sb = new Date(b.start_at).getTime();
    if (sb !== sa) return sb - sa;
    return a.campaign_id.localeCompare(b.campaign_id);
  });

  // Resolve per slot
  const noticeStrip = eligible.find((c) => c.placement_slot === 'notice_strip') || null;
  const homepageFeature = eligible.find((c) => c.placement_slot === 'homepage_feature') || null;

  const serviceModules = new Map();
  for (const c of eligible) {
    if (c.placement_slot !== 'service_contextual') continue;
    let targets = [];
    try {
      targets = JSON.parse(c.target_service_slugs_json || '[]');
    } catch {
      targets = [];
    }
    for (const slug of targets) {
      if (!serviceModules.has(slug)) {
        serviceModules.set(slug, c);
      }
    }
  }

  return { noticeStrip, homepageFeature, serviceModules, allEligible: eligible };
}

/**
 * Checks if a candidate campaign overlaps with existing approved/scheduled/live campaigns
 * on the same placement_slot with equal priority (which PRD 18.03 requires blocking before approval).
 */
export async function detectCampaignSlotConflicts(db, candidate) {
  const rows = await db
    .prepare(
      `SELECT * FROM campaigns
       WHERE campaign_id != ?
         AND placement_slot = ?
         AND activation_state IN ('Scheduled', 'Live')`
    )
    .all(candidate.campaign_id || '', candidate.placement_slot);

  const cStart = new Date(candidate.start_at).getTime();
  const cEnd = candidate.is_evergreen ? Number.POSITIVE_INFINITY : new Date(candidate.end_at || 0).getTime();
  let cTargets = [];
  try {
    cTargets = JSON.parse(candidate.target_service_slugs_json || '[]');
  } catch {
    cTargets = [];
  }

  const overlaps = [];
  const equalPriorityConflicts = [];

  for (const other of rows) {
    const oStart = new Date(other.start_at).getTime();
    const oEnd = other.is_evergreen ? Number.POSITIVE_INFINITY : new Date(other.end_at || 0).getTime();

    // Half-open interval overlap [start, end)
    const timeOverlaps = cStart < oEnd && oStart < cEnd;
    if (!timeOverlaps) continue;

    if (candidate.placement_slot === 'service_contextual') {
      let oTargets = [];
      try {
        oTargets = JSON.parse(other.target_service_slugs_json || '[]');
      } catch {
        oTargets = [];
      }
      const sharedTarget = cTargets.some((t) => oTargets.includes(t));
      if (!sharedTarget) continue;
    }

    overlaps.push(other);
    if (Number(other.priority) === Number(candidate.priority)) {
      equalPriorityConflicts.push(other);
    }
  }

  return { overlaps, equalPriorityConflicts };
}

/**
 * Background scheduler sweep:
 * - Activates Approved + Scheduled campaigns whose start_at <= now < end_at
 * - Expires Live campaigns whose end_at <= now (never leaving expired offers active)
 * - Also checks Scheduled/Open jobs close_at timestamps
 * - Bumps cache_version whenever any public state transitions
 */
export async function runScheduleEvaluation(db, nowDate = new Date()) {
  const nowIso = nowDate.toISOString();
  const nowMs = nowDate.getTime();
  let transitions = 0;

  try {
    const campaigns = await db.prepare(`SELECT * FROM campaigns WHERE activation_state IN ('Scheduled', 'Live')`).all();
    for (const c of campaigns) {
      const startMs = new Date(c.start_at).getTime();
      const endMs = c.is_evergreen ? Number.POSITIVE_INFINITY : new Date(c.end_at || 0).getTime();

      if (c.activation_state === 'Scheduled') {
        if (!c.is_evergreen && nowMs >= endMs) {
          // After downtime, reconcile directly to Ended; never briefly publish elapsed windows!
          await db.prepare(`UPDATE campaigns SET activation_state = 'Ended', updated_at = ? WHERE campaign_id = ?`).run(nowIso, c.campaign_id);
          await recordAudit(db, null, 'campaigns', 'auto_expired_before_activation', 'campaign', c.campaign_id, { nowIso });
          transitions++;
        } else if (c.editorial_state === 'Approved' && nowMs >= startMs && nowMs < endMs) {
          await db.prepare(`UPDATE campaigns SET activation_state = 'Live', updated_at = ? WHERE campaign_id = ?`).run(nowIso, c.campaign_id);
          await recordAudit(db, null, 'campaigns', 'auto_activated', 'campaign', c.campaign_id, { nowIso });
          transitions++;
        }
      } else if (c.activation_state === 'Live') {
        if (!c.is_evergreen && nowMs >= endMs) {
          await db.prepare(`UPDATE campaigns SET activation_state = 'Ended', updated_at = ? WHERE campaign_id = ?`).run(nowIso, c.campaign_id);
          await recordAudit(db, null, 'campaigns', 'auto_ended', 'campaign', c.campaign_id, { nowIso });
          transitions++;
        }
      }
    }

    // Reconcile Scheduled / Open jobs
    const jobs = await db.prepare(`SELECT * FROM jobs WHERE status IN ('Scheduled', 'Open')`).all();
    for (const j of jobs) {
      if (j.status === 'Scheduled' && j.publish_at && new Date(j.publish_at).getTime() <= nowMs) {
        if (j.close_at && new Date(j.close_at).getTime() <= nowMs) {
          await db.prepare(`UPDATE jobs SET status = 'Closed', updated_at = ? WHERE requisition_id = ?`).run(nowIso, j.requisition_id);
        } else {
          await db.prepare(`UPDATE jobs SET status = 'Open', updated_at = ? WHERE requisition_id = ?`).run(nowIso, j.requisition_id);
        }
        transitions++;
      } else if (j.status === 'Open' && j.close_at && new Date(j.close_at).getTime() <= nowMs) {
        await db.prepare(`UPDATE jobs SET status = 'Closed', updated_at = ? WHERE requisition_id = ?`).run(nowIso, j.requisition_id);
        transitions++;
      }
    }

    if (transitions > 0) {
      await db.prepare(`UPDATE scheduler_health SET cache_version = cache_version + 1 WHERE id = 1`).run();
    }
    await db.prepare(
      `UPDATE scheduler_health SET last_run_at = ?, last_success_at = ?, status = 'healthy', last_error = NULL WHERE id = 1`
    ).run(nowIso, nowIso);

    return { ok: true, transitions };
  } catch (err) {
    await db.prepare(`UPDATE scheduler_health SET last_run_at = ?, status = 'error', last_error = ? WHERE id = 1`).run(
      nowIso,
      err.message
    );
    return { ok: false, error: err.message };
  }
}

export async function bumpPublicCache(db) {
  await db.prepare(`UPDATE scheduler_health SET cache_version = cache_version + 1 WHERE id = 1`).run();
}
