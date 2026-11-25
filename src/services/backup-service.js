import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { ENV } from '../config.js';
import { generateUuid, sha256Hex } from '../lib/crypto.js';
import { recordAudit } from './auth.js';
import { bumpPublicCache, runScheduleEvaluation } from './campaign-engine.js';

const SNAPSHOT_TABLES = [
  'business_settings',
  'pages',
  'page_revisions',
  'articles',
  'testimonials_claims',
  'redirects',
  'campaigns',
  'media_assets',
  'projects',
  'project_gallery_items',
  'project_before_after_pairs',
  'jobs',
  'accounts',
  'contacts',
  'properties',
  'inquiries',
  'inquiry_attachments',
  'applicants',
  'applications',
  'application_attachments',
  'application_notes',
  'crm_delivery_queue',
  'notification_queue',
];

function sha256File(filePath) {
  return sha256Hex(fs.readFileSync(filePath));
}

function collectStorageAreas(storagePaths) {
  return [
    { area: 'originals', dir: storagePaths.originals },
    { area: 'resumes', dir: storagePaths.resumes },
    { area: 'quarantine', dir: storagePaths.quarantine },
    { area: 'publicMedia', dir: storagePaths.publicMedia },
  ];
}

export async function reconcileStorageReferences(db, storagePaths) {
  const missing = [];
  const media = await db.prepare('SELECT asset_id, private_original_key, public_derivative_key, rights_status FROM media_assets').all();
  for (const m of media) {
    if (m.private_original_key && !fs.existsSync(path.join(storagePaths.originals, path.basename(m.private_original_key)))) {
      missing.push({ type: 'media_original', id: m.asset_id, key: m.private_original_key });
    }
    if (m.public_derivative_key && m.rights_status !== 'withdrawn' && !fs.existsSync(path.join(storagePaths.publicMedia, path.basename(m.public_derivative_key)))) {
      missing.push({ type: 'media_derivative', id: m.asset_id, key: m.public_derivative_key });
    }
  }
  const appAtts = await db.prepare('SELECT attachment_id, storage_key FROM application_attachments WHERE deleted_at IS NULL').all();
  for (const a of appAtts) {
    if (!fs.existsSync(path.join(storagePaths.resumes, path.basename(a.storage_key)))) {
      missing.push({ type: 'application_attachment', id: a.attachment_id, key: a.storage_key });
    }
  }
  const inqAtts = await db.prepare('SELECT attachment_id, storage_key FROM inquiry_attachments').all();
  for (const ia of inqAtts) {
    if (!fs.existsSync(path.join(storagePaths.quarantine, path.basename(ia.storage_key)))) {
      missing.push({ type: 'inquiry_attachment', id: ia.attachment_id, key: ia.storage_key });
    }
  }
  return missing;
}

export async function createFullBackup(db, { storagePaths, actor = null, reason = 'scheduled', nowDate = new Date() }) {
  const nowIso = nowDate.toISOString();
  const backupId = generateUuid();
  const stamp = nowIso.replace(/[:.]/g, '-');
  const backupDir = path.join(storagePaths.backups, `backup-${stamp}-${backupId.slice(0, 8)}`);
  fs.mkdirSync(backupDir, { recursive: true });

  let dbFilename = 'database.sqlite';
  if (db.dialect === 'sqlite') {
    const backupDbPath = path.join(backupDir, dbFilename);
    const escapedDbDest = backupDbPath.replace(/'/g, "''");
    await db.exec(`VACUUM INTO '${escapedDbDest}';`);
  } else {
    dbFilename = 'database.snapshot.json';
    const tables = {};
    for (const table of SNAPSHOT_TABLES) {
      tables[table] = await db.prepare(`SELECT * FROM ${table}`).all();
    }
    fs.writeFileSync(
      path.join(backupDir, dbFilename),
      JSON.stringify({ dialect: 'postgres', created_at: nowIso, tables }, null, 2),
      'utf8'
    );
  }
  const dbSha256 = sha256File(path.join(backupDir, dbFilename));

  const manifestFiles = [];
  for (const { area, dir } of collectStorageAreas(storagePaths)) {
    const destAreaDir = path.join(backupDir, 'files', area);
    fs.mkdirSync(destAreaDir, { recursive: true });
    if (!fs.existsSync(dir)) continue;
    for (const entry of fs.readdirSync(dir)) {
      const srcPath = path.join(dir, entry);
      if (!fs.statSync(srcPath).isFile()) continue;
      const dstPath = path.join(destAreaDir, entry);
      fs.copyFileSync(srcPath, dstPath);
      manifestFiles.push({
        area,
        filename: entry,
        bytes: fs.statSync(dstPath).size,
        sha256: sha256File(dstPath),
      });
    }
  }

  const missingReferences = await reconcileStorageReferences(db, storagePaths);
  const counts = {
    pages: (await db.prepare('SELECT COUNT(*) as c FROM pages').get()).c,
    campaigns: (await db.prepare('SELECT COUNT(*) as c FROM campaigns').get()).c,
    projects: (await db.prepare('SELECT COUNT(*) as c FROM projects').get()).c,
    media_assets: (await db.prepare('SELECT COUNT(*) as c FROM media_assets').get()).c,
    inquiries: (await db.prepare('SELECT COUNT(*) as c FROM inquiries').get()).c,
    applications: (await db.prepare('SELECT COUNT(*) as c FROM applications').get()).c,
  };

  const manifestBody = {
    backup_id: backupId,
    created_at: nowIso,
    created_by: actor?.full_name || 'System Scheduler',
    reason,
    db_filename: dbFilename,
    db_sha256: dbSha256,
    files: manifestFiles,
    counts,
    reconciliation_ok: missingReferences.length === 0,
    missing_references: missingReferences,
  };
  const manifestJsonStr = JSON.stringify(manifestBody, null, 2);
  const manifestSha256 = sha256Hex(manifestJsonStr);
  fs.writeFileSync(path.join(backupDir, 'manifest.json'), manifestJsonStr, 'utf8');
  fs.writeFileSync(path.join(backupDir, 'manifest.sha256'), manifestSha256, 'utf8');

  await db.prepare(
    `INSERT INTO backup_runs (backup_id, backup_dir, created_at, created_by, reason, db_sha256, manifest_sha256, file_count, status, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    backupId,
    backupDir,
    nowIso,
    actor?.full_name || 'System Scheduler',
    reason,
    dbSha256,
    manifestSha256,
    manifestFiles.length,
    missingReferences.length === 0 ? 'verified' : 'verified_with_warnings',
    missingReferences.length ? `${missingReferences.length} missing file reference(s) flagged` : 'Clean full snapshot'
  );

  await recordAudit(db, actor, 'ops', 'create_full_backup', 'backup', backupId, {
    reason,
    file_count: manifestFiles.length,
    reconciliation_ok: manifestBody.reconciliation_ok,
  });

  // Retention cleanup of old scheduled snapshots beyond BACKUP_KEEP_COUNT
  if (reason === 'scheduled') {
    const keep = Math.max(3, Number(ENV.BACKUP_KEEP_COUNT || 14));
    const oldScheduled = await db
      .prepare(`SELECT * FROM backup_runs WHERE reason = 'scheduled' ORDER BY created_at DESC LIMIT 10000 OFFSET ?`)
      .all(keep);
    for (const old of oldScheduled) {
      if (old.backup_dir && fs.existsSync(old.backup_dir)) {
        try {
          fs.rmSync(old.backup_dir, { recursive: true, force: true });
        } catch {}
      }
      await db.prepare('DELETE FROM backup_runs WHERE backup_id = ?').run(old.backup_id);
    }
  }

  return { ok: true, backup_id: backupId, backup_dir: backupDir, manifest: manifestBody, manifest_sha256: manifestSha256 };
}

export function verifyBackupIntegrity(backupDir) {
  if (!backupDir || !fs.existsSync(backupDir)) {
    return { ok: false, error: 'Backup directory does not exist.' };
  }
  const manifestPath = path.join(backupDir, 'manifest.json');
  const sigPath = path.join(backupDir, 'manifest.sha256');
  if (!fs.existsSync(manifestPath) || !fs.existsSync(sigPath)) {
    return { ok: false, error: 'Backup missing required manifest or checksum signature.' };
  }

  const manifestRaw = fs.readFileSync(manifestPath, 'utf8');
  const expectedManifestSha = fs.readFileSync(sigPath, 'utf8').trim();
  const actualManifestSha = sha256Hex(manifestRaw);
  if (actualManifestSha !== expectedManifestSha) {
    return { ok: false, error: 'Manifest checksum mismatch (backup may be corrupted or tampered).' };
  }

  let manifest;
  try {
    manifest = JSON.parse(manifestRaw);
  } catch {
    return { ok: false, error: 'Corrupt backup manifest JSON.' };
  }

  const dbFilename = path.basename(manifest.db_filename || 'database.sqlite');
  const dbPath = path.join(backupDir, dbFilename);
  if (!fs.existsSync(dbPath)) {
    return { ok: false, error: 'Backup missing database snapshot.' };
  }

  const actualDbSha = sha256File(dbPath);
  if (actualDbSha !== manifest.db_sha256) {
    return { ok: false, error: 'Database snapshot SHA-256 mismatch.' };
  }

  for (const f of manifest.files || []) {
    const fPath = path.join(backupDir, 'files', path.basename(f.area), path.basename(f.filename));
    if (!fs.existsSync(fPath)) {
      return { ok: false, error: `Missing backed-up file: ${f.area}/${f.filename}` };
    }
    if (sha256File(fPath) !== f.sha256) {
      return { ok: false, error: `File checksum mismatch: ${f.area}/${f.filename}` };
    }
  }

  return { ok: true, manifest, dbPath, dbFilename };
}

export async function restoreFromBackup(db, { backupId, storagePaths, actor = null, nowDate = new Date() }) {
  const row = await db.prepare('SELECT * FROM backup_runs WHERE backup_id = ?').get(backupId);
  if (!row) {
    return { ok: false, statusCode: 404, error: 'Backup record not found.' };
  }

  const verify = verifyBackupIntegrity(row.backup_dir);
  if (!verify.ok) {
    await recordAudit(db, actor, 'ops', 'restore_backup_rejected', 'backup', backupId, { error: verify.error });
    return { ok: false, statusCode: 422, error: `Backup integrity verification failed: ${verify.error}` };
  }

  // Always create a pre-restore safety snapshot before altering state
  await createFullBackup(db, { storagePaths, actor, reason: 'pre_restore', nowDate });

  const nowIso = nowDate.toISOString();
  const backupCreatedAt = verify.manifest.created_at;

  let readBakTable;
  let closeBak = () => {};
  if (verify.dbFilename.endsWith('.json')) {
    const snapshotData = JSON.parse(fs.readFileSync(verify.dbPath, 'utf8'));
    readBakTable = (table) => snapshotData.tables?.[table] || [];
  } else {
    const bakDb = new DatabaseSync(verify.dbPath, { readOnly: true });
    readBakTable = (table) => bakDb.prepare(`SELECT * FROM ${table}`).all();
    closeBak = () => bakDb.close();
  }

  // Authoritative deletion & withdrawal guardrails captured BEFORE mutating
  const purgedKeys = new Set(
    (await db.prepare('SELECT storage_key FROM deletion_ledger WHERE storage_key IS NOT NULL').all()).map((r) => path.basename(r.storage_key))
  );
  const purgedIds = new Set((await db.prepare('SELECT object_id FROM deletion_ledger').all()).map((r) => r.object_id));
  const withdrawnAssets = new Set((await db.prepare(`SELECT asset_id FROM media_assets WHERE rights_status = 'withdrawn'`).all()).map((r) => r.asset_id));
  const closedJobIds = new Set((await db.prepare(`SELECT requisition_id FROM jobs WHERE status = 'Closed'`).all()).map((r) => r.requisition_id));
  const deletedAttachments = new Set((await db.prepare(`SELECT attachment_id FROM application_attachments WHERE deleted_at IS NOT NULL`).all()).map((r) => r.attachment_id));
  const alreadySentNotifs = new Set((await db.prepare(`SELECT notification_id FROM notification_queue WHERE status = 'sent'`).all()).map((r) => r.notification_id));
  const alreadyDeliveredCrm = new Set((await db.prepare(`SELECT delivery_id FROM crm_delivery_queue WHERE status = 'delivered'`).all()).map((r) => r.delivery_id));

  let restoredRows = 0;
  try {
    await db.transaction(async (tx) => {
      const copyUpsert = async (table, pkCol, filterFn = () => true, transformFn = (r) => r) => {
        const bakRows = readBakTable(table);
        if (bakRows.length === 0) return;
        const cols = Object.keys(bakRows[0]);
        const placeholders = cols.map(() => '?').join(', ');
        const updateSet = cols
          .filter((c) => c !== pkCol)
          .map((c) => `${c} = excluded.${c}`)
          .join(', ');
        const sql = `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders}) ON CONFLICT(${pkCol}) DO UPDATE SET ${updateSet}`;
        const stmt = tx.prepare(sql);
        for (const raw of bakRows) {
          if (!filterFn(raw)) continue;
          const rowObj = transformFn({ ...raw });
          await stmt.run(...cols.map((c) => rowObj[c]));
          restoredRows++;
        }
      };

      await copyUpsert('business_settings', 'id');
      await copyUpsert('pages', 'page_id');
      await copyUpsert('page_revisions', 'revision_id');
      await copyUpsert('articles', 'article_id');
      await copyUpsert('testimonials_claims', 'claim_id');
      await copyUpsert('redirects', 'redirect_id');

      await copyUpsert(
        'campaigns',
        'campaign_id',
        () => true,
        (c) => {
          if (!c.is_evergreen && c.end_at && new Date(c.end_at).getTime() <= nowDate.getTime()) {
            c.activation_state = 'Ended';
          }
          return c;
        }
      );

      await copyUpsert(
        'media_assets',
        'asset_id',
        () => true,
        (m) => {
          if (withdrawnAssets.has(m.asset_id)) {
            m.rights_status = 'withdrawn';
            m.is_public_published = 0;
          }
          return m;
        }
      );
      await copyUpsert('projects', 'project_id', (p) => !withdrawnAssets.has(p.cover_asset_id));
      await copyUpsert('project_gallery_items', 'item_id', (g) => !withdrawnAssets.has(g.asset_id));
      await copyUpsert(
        'project_before_after_pairs',
        'pair_id',
        (b) => !withdrawnAssets.has(b.before_asset_id) && !withdrawnAssets.has(b.after_asset_id)
      );

      await copyUpsert(
        'jobs',
        'requisition_id',
        () => true,
        (j) => {
          if (closedJobIds.has(j.requisition_id) || (j.close_at && new Date(j.close_at).getTime() <= nowDate.getTime())) {
            j.status = 'Closed';
          }
          return j;
        }
      );

      await copyUpsert('accounts', 'account_id');
      await copyUpsert('contacts', 'contact_id');
      await copyUpsert('properties', 'property_id');
      await copyUpsert('inquiries', 'inquiry_id', (i) => !purgedIds.has(i.inquiry_id));
      await copyUpsert('inquiry_attachments', 'attachment_id', (a) => !purgedIds.has(a.attachment_id) && !purgedKeys.has(path.basename(a.storage_key)));

      await copyUpsert('applicants', 'applicant_id', (a) => !purgedIds.has(a.applicant_id));
      await copyUpsert('applications', 'application_id', (a) => !purgedIds.has(a.application_id));
      await copyUpsert(
        'application_attachments',
        'attachment_id',
        (a) => !purgedIds.has(a.attachment_id) && !purgedKeys.has(path.basename(a.storage_key)),
        (a) => {
          if (deletedAttachments.has(a.attachment_id)) {
            a.deleted_at = a.deleted_at || nowIso;
          }
          return a;
        }
      );
      await copyUpsert('application_notes', 'note_id', (n) => !purgedIds.has(n.application_id));

      await copyUpsert(
        'crm_delivery_queue',
        'delivery_id',
        (d) => !purgedIds.has(d.inquiry_id),
        (d) => {
          if (alreadyDeliveredCrm.has(d.delivery_id)) d.status = 'delivered';
          return d;
        }
      );
      await copyUpsert(
        'notification_queue',
        'notification_id',
        () => true,
        (n) => {
          if (alreadySentNotifs.has(n.notification_id)) n.status = 'sent';
          return n;
        }
      );
    });
  } catch (err) {
    closeBak();
    return { ok: false, statusCode: 500, error: `Restore transaction failed: ${err.message}` };
  }
  closeBak();

  // Restore files from verified backup (excluding retention-purged or withdrawn public files)
  const areaDirs = Object.fromEntries(collectStorageAreas(storagePaths).map((a) => [a.area, a.dir]));
  let filesRestored = 0;
  for (const f of verify.manifest.files || []) {
    const fname = path.basename(f.filename);
    if (purgedKeys.has(fname)) continue;
    const destDir = areaDirs[f.area];
    if (!destDir) continue;
    fs.mkdirSync(destDir, { recursive: true });
    const srcPath = path.join(row.backup_dir, 'files', f.area, fname);
    const dstPath = path.join(destDir, fname);
    if (fs.existsSync(srcPath)) {
      fs.copyFileSync(srcPath, dstPath);
      filesRestored++;
    }
  }

  // Re-run scheduler against nowDate & invalidate cache so no expired offer or closed job shows live
  await runScheduleEvaluation(db, nowDate);
  await bumpPublicCache(db);

  await recordAudit(db, actor, 'ops', 'restore_backup', 'backup', backupId, {
    backup_created_at: backupCreatedAt,
    restored_rows: restoredRows,
    files_restored: filesRestored,
  });

  return {
    ok: true,
    backup_id: backupId,
    backup_created_at: backupCreatedAt,
    restored_rows: restoredRows,
    files_restored: filesRestored,
  };
}
