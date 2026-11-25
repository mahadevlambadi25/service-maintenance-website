import { ENV, STORAGE_PATHS } from '../config.js';
import { generateUuid } from '../lib/crypto.js';
import { deliverInquiryToFreshsales } from './crm-adapter.js';
import { runScheduleEvaluation } from './campaign-engine.js';
import { recordAudit } from './auth.js';
import { sendEmailViaMicrosoftGraph } from './mailer.js';
import { createFullBackup } from './backup-service.js';
import { runRetentionSweep } from './retention-service.js';

let notificationFaultMode = false;
export function setNotificationFaultMode(enabled) {
  if (ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production') {
    notificationFaultMode = false;
    return false;
  }
  notificationFaultMode = Boolean(enabled);
  return true;
}
export function getNotificationFaultMode() {
  if (ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production') {
    return false;
  }
  return notificationFaultMode;
}

export async function processDeliveryQueues(db, nowDate = new Date()) {
  const nowIso = nowDate.toISOString();
  const isProd = ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production';
  let crmProcessed = 0;
  let notificationsProcessed = 0;

  // 1. Process CRM delivery queue
  const crmJobs = await db
    .prepare(
      `SELECT * FROM crm_delivery_queue
       WHERE status = 'pending' AND next_attempt_at <= ?
       ORDER BY created_at ASC LIMIT 20`
    )
    .all(nowIso);

  for (const job of crmJobs) {
    const inquiry = await db.prepare('SELECT * FROM inquiries WHERE inquiry_id = ?').get(job.inquiry_id);
    if (!inquiry) continue;
    const account = await db.prepare('SELECT * FROM accounts WHERE account_id = ?').get(inquiry.account_id);
    const contact = await db.prepare('SELECT * FROM contacts WHERE contact_id = ?').get(inquiry.contact_id);
    const property = inquiry.property_id
      ? await db.prepare('SELECT * FROM properties WHERE property_id = ?').get(inquiry.property_id)
      : null;

    const result = await deliverInquiryToFreshsales({ inquiry, account, contact, property });
    const nextAttempts = job.attempts + 1;

    if (result.ok) {
      await db.prepare(
        `UPDATE crm_delivery_queue
         SET status = 'delivered', attempts = ?, external_record_id = ?, last_error = NULL, updated_at = ?
         WHERE delivery_id = ?`
      ).run(nextAttempts, result.externalId, nowIso, job.delivery_id);

      if (account && result.crmAccountId) {
        await db.prepare(`UPDATE accounts SET crm_account_id = ? WHERE account_id = ?`).run(result.crmAccountId, account.account_id);
      }
      if (contact && (result.crmContactId || result.externalId)) {
        await db.prepare(`UPDATE contacts SET crm_contact_id = ? WHERE contact_id = ?`).run(
          result.crmContactId || result.externalId,
          contact.contact_id
        );
      }
      if (result.crmNoteId) {
        await db.prepare(`UPDATE inquiries SET crm_note_id = ?, updated_at = ? WHERE inquiry_id = ?`).run(
          result.crmNoteId,
          nowIso,
          inquiry.inquiry_id
        );
      }
      if (property && result.crmPropertyNoteId) {
        await db.prepare(`UPDATE properties SET crm_property_note_id = ? WHERE property_id = ?`).run(
          result.crmPropertyNoteId,
          property.property_id
        );
      }
      crmProcessed++;
    } else if (result.transient && nextAttempts < job.max_attempts) {
      // Bounded exponential backoff: 5s, 20s, 45s
      const backoffMs = Math.min(60_000, 5_000 * nextAttempts * nextAttempts);
      const nextAt = new Date(nowDate.getTime() + backoffMs).toISOString();
      await db.prepare(
        `UPDATE crm_delivery_queue
         SET attempts = ?, next_attempt_at = ?, last_error = ?, updated_at = ?
         WHERE delivery_id = ?`
      ).run(nextAttempts, nextAt, result.error, nowIso, job.delivery_id);
    } else {
      // Move exhausted or permanent failures to review queue and alert named owner
      await db.prepare(
        `UPDATE crm_delivery_queue
         SET status = 'failed_review', attempts = ?, last_error = ?, updated_at = ?
         WHERE delivery_id = ?`
      ).run(nextAttempts, result.error, nowIso, job.delivery_id);

      await db.prepare(
        `INSERT INTO notification_queue
         (notification_id, domain, reference_id, recipient_role, recipient_target, subject, body_summary, status, attempts, next_attempt_at, created_at, updated_at)
         VALUES (?, 'system_alert', ?, 'Platform Administrator', 'ops-alerts@smiaz.com', ?, ?, 'pending', 0, ?, ?, ?)`
      ).run(
        generateUuid(),
        inquiry.inquiry_id,
        `CRM Delivery Failure Review Required (${inquiry.inquiry_id.slice(0, 8)})`,
        `Inquiry ${inquiry.inquiry_id} failed CRM delivery after ${nextAttempts} attempts: ${result.error}`,
        nowIso,
        nowIso,
        nowIso
      );
      await recordAudit(db, null, 'crm', 'delivery_moved_to_review', 'crm_delivery_queue', job.delivery_id, {
        inquiry_id: inquiry.inquiry_id,
        error: result.error,
      });
    }
  }

  // 2. Process Notification Queue via Microsoft Graph sendMail API
  // Notifications are NEVER marked 'sent' unless Microsoft Graph confirms acceptance (2xx).
  const notifJobs = await db
    .prepare(
      `SELECT * FROM notification_queue
       WHERE status = 'pending' AND next_attempt_at <= ?
       ORDER BY created_at ASC LIMIT 30`
    )
    .all(nowIso);

  for (const n of notifJobs) {
    const nextAttempts = n.attempts + 1;
    let mailResult;

    if (!isProd && notificationFaultMode) {
      mailResult = { ok: false, transient: true, error: 'Simulated SMTP/M365 delivery error' };
    } else {
      mailResult = await sendEmailViaMicrosoftGraph({
        to: n.recipient_target,
        subject: n.subject,
        bodyText: n.body_summary,
        replyTo: n.reply_to || null,
      });
    }

    if (mailResult.ok) {
      await db.prepare(
        `UPDATE notification_queue
         SET status = 'sent', attempts = ?, provider_message_id = ?, last_error = NULL, updated_at = ?
         WHERE notification_id = ?`
      ).run(nextAttempts, mailResult.providerMessageId || null, nowIso, n.notification_id);
      notificationsProcessed++;
    } else if (mailResult.transient && nextAttempts < 3) {
      const backoffMs = Math.min(60_000, 5_000 * nextAttempts * nextAttempts);
      const nextAt = new Date(nowDate.getTime() + backoffMs).toISOString();
      await db.prepare(
        `UPDATE notification_queue
         SET attempts = ?, next_attempt_at = ?, last_error = ?, updated_at = ?
         WHERE notification_id = ?`
      ).run(nextAttempts, nextAt, mailResult.error, nowIso, n.notification_id);
    } else {
      await db.prepare(
        `UPDATE notification_queue
         SET status = 'failed_review', attempts = ?, last_error = ?, updated_at = ?
         WHERE notification_id = ?`
      ).run(nextAttempts, mailResult.error, nowIso, n.notification_id);
      await recordAudit(db, null, 'notifications', 'email_moved_to_review', 'notification_queue', n.notification_id, {
        domain: n.domain,
        recipient: n.recipient_target,
        attempts: nextAttempts,
        error: mailResult.error,
      });
    }
  }

  return { crmProcessed, notificationsProcessed };
}

let workerTimer = null;

export async function runMaintenanceTasksIfDue(db, storagePaths = STORAGE_PATHS, nowDate = new Date()) {
  const intervalMs = Math.max(1, Number(ENV.BACKUP_INTERVAL_HOURS || 24)) * 3600 * 1000;
  const latestBackup = await db
    .prepare(`SELECT created_at FROM backup_runs WHERE reason = 'scheduled' ORDER BY created_at DESC LIMIT 1`)
    .get();
  const backupDue =
    !latestBackup || nowDate.getTime() - new Date(latestBackup.created_at).getTime() >= intervalMs;
  let backupResult = null;
  if (backupDue) {
    backupResult = await createFullBackup(db, { storagePaths, actor: null, reason: 'scheduled', nowDate });
  }

  const anyRetentionDue = await db
    .prepare(
      `SELECT 1 FROM retention_policies
       WHERE approved_by_client = 1 AND retention_days IS NOT NULL AND retention_days > 0
         AND (last_run_at IS NULL OR last_run_at < ?) LIMIT 1`
    )
    .get(new Date(nowDate.getTime() - 24 * 3600 * 1000).toISOString());
  let retentionResult = null;
  if (anyRetentionDue) {
    retentionResult = await runRetentionSweep(db, { storagePaths, actor: null, nowDate });
  }
  return { backupResult, retentionResult };
}

export function startBackgroundWorker(db, intervalMs = 10_000, storagePaths = STORAGE_PATHS) {
  if (workerTimer) return;
  const tick = async () => {
    try {
      await runScheduleEvaluation(db, new Date());
      await processDeliveryQueues(db, new Date());
      await runMaintenanceTasksIfDue(db, storagePaths, new Date());
    } catch (err) {
      console.error('[worker] tick error:', err.message);
    }
  };
  tick();
  workerTimer = setInterval(tick, intervalMs);
  workerTimer.unref?.();
}

export function stopBackgroundWorker() {
  if (workerTimer) {
    clearInterval(workerTimer);
    workerTimer = null;
  }
}
