import path from 'node:path';
import { generateUuid } from '../lib/crypto.js';
import { recordAudit } from './auth.js';
import { createObjectStore } from './object-store.js';

/**
 * Automated Retention & Deletion Service (PRD 17.09 & 21.03).
 * Strict Rule: Unapproved policies (approved_by_client = 0) or unspecified durations (retention_days IS NULL)
 * MUST NOT auto-delete production or recruiting records — they are flagged for client/legal approval.
 */

export async function listRetentionPolicies(db) {
  return db.prepare('SELECT * FROM retention_policies ORDER BY policy_key ASC').all();
}

export async function approveRetentionPolicy(db, { policyKey, retentionDays, approved = true, actor = null, notes = null }) {
  const existing = await db.prepare('SELECT * FROM retention_policies WHERE policy_key = ?').get(policyKey);
  if (!existing) {
    return { ok: false, statusCode: 404, error: 'Retention policy not found.' };
  }
  const daysNum = Number(retentionDays);
  if (!Number.isInteger(daysNum) || daysNum < 1 || daysNum > 3650) {
    return { ok: false, statusCode: 422, error: 'Retention period must be a positive integer between 1 and 3650 days.' };
  }
  const nowIso = new Date().toISOString();
  const isApproved = approved ? 1 : 0;

  await db.prepare(
    `UPDATE retention_policies
     SET retention_days = ?, approved_by_client = ?, approved_by_user = ?, approved_at = ?,
         notes = COALESCE(?, notes), updated_at = ?
     WHERE policy_key = ?`
  ).run(
    daysNum,
    isApproved,
    isApproved ? actor?.full_name || 'Administrator' : null,
    isApproved ? nowIso : null,
    notes,
    nowIso,
    policyKey
  );

  await recordAudit(db, actor, 'ops', isApproved ? 'approve_retention_policy' : 'revoke_retention_approval', 'retention_policy', policyKey, {
    retention_days: daysNum,
  });

  return { ok: true, policy: await db.prepare('SELECT * FROM retention_policies WHERE policy_key = ?').get(policyKey) };
}

async function logDeletion(db, { objectType, objectId, storageKey = null, reason, actorName, nowIso }) {
  await db.prepare(
    `INSERT INTO deletion_ledger (ledger_id, object_type, object_id, storage_key, reason, deleted_at, deleted_by)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(generateUuid(), objectType, objectId, storageKey, reason, nowIso, actorName);
}

export async function runRetentionSweep(db, { storagePaths, actor = null, nowDate = new Date(), dryRun = false } = {}) {
  const nowIso = nowDate.toISOString();
  const actorName = actor?.full_name || 'Retention Scheduler';
  const policies = await listRetentionPolicies(db);
  const store = createObjectStore(storagePaths);

  const purged = {
    quarantined_spam_uploads: 0,
    resolved_delivery_payloads: 0,
    transient_technical_logs: 0,
    unqualified_prospects: 0,
    recruiting_applicants_and_resumes: 0,
  };
  const skippedPendingApproval = [];

  for (const pol of policies) {
    if (!pol.approved_by_client || pol.retention_days === null || pol.retention_days <= 0) {
      skippedPendingApproval.push({
        policy_key: pol.policy_key,
        label: pol.label,
        reason: pol.retention_days === null ? 'retention_period_unspecified_requires_client_approval' : 'pending_client_approval',
      });
      continue;
    }

    const cutoffIso = new Date(nowDate.getTime() - pol.retention_days * 86_400_000).toISOString();

    if (pol.policy_key === 'quarantined_spam_uploads') {
      const targets = await db
        .prepare(
          `SELECT ia.* FROM inquiry_attachments ia
           JOIN inquiries i ON i.inquiry_id = ia.inquiry_id
           WHERE ia.created_at < ? AND COALESCE(i.legal_hold, 0) = 0
             AND (ia.scan_state = 'quarantined' OR i.classification IN ('spam', 'test'))`
        )
        .all(cutoffIso);
      if (!dryRun) {
        for (const att of targets) {
          await store.deleteObject({ area: 'quarantine', key: path.basename(att.storage_key) });
          await db.prepare('DELETE FROM inquiry_attachments WHERE attachment_id = ?').run(att.attachment_id);
          await logDeletion(db, {
            objectType: 'inquiry_attachment',
            objectId: att.attachment_id,
            storageKey: att.storage_key,
            reason: `retention:${pol.policy_key}:${pol.retention_days}d`,
            actorName,
            nowIso,
          });
        }
      }
      purged.quarantined_spam_uploads = targets.length;
    } else if (pol.policy_key === 'resolved_delivery_payloads') {
      const notifTargets = await db
        .prepare(`SELECT notification_id FROM notification_queue WHERE status = 'sent' AND updated_at < ?`)
        .all(cutoffIso);
      const crmTargets = await db
        .prepare(`SELECT delivery_id FROM crm_delivery_queue WHERE status IN ('delivered', 'replayed') AND updated_at < ?`)
        .all(cutoffIso);
      if (!dryRun) {
        for (const n of notifTargets) {
          await db.prepare('DELETE FROM notification_queue WHERE notification_id = ?').run(n.notification_id);
        }
        for (const c of crmTargets) {
          await db.prepare('DELETE FROM crm_delivery_queue WHERE delivery_id = ?').run(c.delivery_id);
        }
      }
      purged.resolved_delivery_payloads = notifTargets.length + crmTargets.length;
    } else if (pol.policy_key === 'transient_technical_logs') {
      const countRow = await db.prepare(`SELECT COUNT(*) as c FROM analytics_events WHERE created_at < ?`).get(cutoffIso);
      const totalOld = Number(countRow?.c || 0);
      if (!dryRun && totalOld > 0) {
        await db.prepare(`DELETE FROM analytics_events WHERE created_at < ?`).run(cutoffIso);
      }
      purged.transient_technical_logs = totalOld;
    } else if (pol.policy_key === 'unqualified_prospects') {
      const oldInquiries = await db
        .prepare(
          `SELECT inquiry_id FROM inquiries
           WHERE updated_at < ? AND COALESCE(legal_hold, 0) = 0
             AND classification IN ('spam', 'disqualified', 'out_of_area', 'test')`
        )
        .all(cutoffIso);
      if (!dryRun) {
        for (const inq of oldInquiries) {
          const atts = await db.prepare('SELECT attachment_id, storage_key FROM inquiry_attachments WHERE inquiry_id = ?').all(inq.inquiry_id);
          for (const a of atts) {
            await store.deleteObject({ area: 'quarantine', key: path.basename(a.storage_key) });
            await logDeletion(db, {
              objectType: 'inquiry_attachment',
              objectId: a.attachment_id,
              storageKey: a.storage_key,
              reason: `retention:${pol.policy_key}:${pol.retention_days}d`,
              actorName,
              nowIso,
            });
          }
          await db.prepare('DELETE FROM inquiries WHERE inquiry_id = ?').run(inq.inquiry_id);
          await logDeletion(db, {
            objectType: 'inquiry',
            objectId: inq.inquiry_id,
            reason: `retention:${pol.policy_key}:${pol.retention_days}d`,
            actorName,
            nowIso,
          });
        }
      }
      purged.unqualified_prospects = oldInquiries.length;
    } else if (pol.policy_key === 'recruiting_applicants_and_resumes') {
      // Only runs if explicitly approved & positive retention_days configured; deletes closed/old apps not on legal hold
      const oldApps = await db
        .prepare(
          `SELECT a.application_id FROM applications a
           JOIN jobs j ON j.requisition_id = a.requisition_id
           WHERE a.updated_at < ? AND COALESCE(a.legal_hold, 0) = 0 AND j.status IN ('Closed', 'Archived')`
        )
        .all(cutoffIso);
      if (!dryRun) {
        for (const app of oldApps) {
          const resAtts = await db.prepare('SELECT attachment_id, storage_key FROM application_attachments WHERE application_id = ?').all(app.application_id);
          for (const ra of resAtts) {
            await store.deleteObject({ area: 'resumes', key: path.basename(ra.storage_key) });
            await logDeletion(db, {
              objectType: 'application_attachment',
              objectId: ra.attachment_id,
              storageKey: ra.storage_key,
              reason: `retention:${pol.policy_key}:${pol.retention_days}d`,
              actorName,
              nowIso,
            });
          }
          await db.prepare('DELETE FROM applications WHERE application_id = ?').run(app.application_id);
          await logDeletion(db, {
            objectType: 'application',
            objectId: app.application_id,
            reason: `retention:${pol.policy_key}:${pol.retention_days}d`,
            actorName,
            nowIso,
          });
        }
      }
      purged.recruiting_applicants_and_resumes = oldApps.length;
    }

    if (!dryRun) {
      await db.prepare(`UPDATE retention_policies SET last_run_at = ?, updated_at = ? WHERE policy_key = ?`).run(nowIso, nowIso, pol.policy_key);
    }
  }

  if (!dryRun) {
    await recordAudit(db, actor, 'ops', 'run_retention_sweep', 'retention', nowIso, {
      purged,
      skippedPendingApproval: skippedPendingApproval.map((s) => s.policy_key),
    });
  }

  return { ok: true, dryRun, nowIso, purged, skippedPendingApproval };
}
