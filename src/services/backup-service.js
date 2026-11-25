import fs from 'node:fs';
import path from 'node:path';
import { ENV } from '../config.js';
import { generateUuid, sha256Hex } from '../lib/crypto.js';
import { recordAudit } from './auth.js';
import { bumpPublicCache, runScheduleEvaluation } from './campaign-engine.js';
import { createObjectStore, isS3StorageConfigured } from './object-store.js';

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

const STORAGE_AREAS = ['originals', 'resumes', 'quarantine', 'publicMedia'];

export async function reconcileStorageReferences(db, storagePaths) {
  const store = createObjectStore(storagePaths);
  const missing = [];
  const media = await db.prepare('SELECT asset_id, private_original_key, public_derivative_key, rights_status FROM media_assets').all();
  for (const m of media) {
    if (m.private_original_key && !(await store.existsObject({ area: 'originals', key: path.basename(m.private_original_key) }))) {
      missing.push({ type: 'media_original', id: m.asset_id, key: m.private_original_key });
    }
    if (m.public_derivative_key && m.rights_status !== 'withdrawn' && !(await store.existsObject({ area: 'publicMedia', key: path.basename(m.public_derivative_key) }))) {
      missing.push({ type: 'media_derivative', id: m.asset_id, key: m.public_derivative_key });
    }
  }
  const appAtts = await db.prepare('SELECT attachment_id, storage_key FROM application_attachments WHERE deleted_at IS NULL').all();
  for (const a of appAtts) {
    if (!(await store.existsObject({ area: 'resumes', key: path.basename(a.storage_key) }))) {
      missing.push({ type: 'application_attachment', id: a.attachment_id, key: a.storage_key });
    }
  }
  const inqAtts = await db.prepare('SELECT attachment_id, storage_key FROM inquiry_attachments').all();
  for (const ia of inqAtts) {
    if (!(await store.existsObject({ area: 'quarantine', key: path.basename(ia.storage_key) }))) {
      missing.push({ type: 'inquiry_attachment', id: ia.attachment_id, key: ia.storage_key });
    }
  }
  return missing;
}

export async function createFullBackup(db, { storagePaths, actor = null, reason = 'scheduled', nowDate = new Date() }) {
  const store = createObjectStore(storagePaths);
  const s3Mode = isS3StorageConfigured();
  const nowIso = nowDate.toISOString();
  const backupId = generateUuid();
  const stamp = nowIso.replace(/[:.]/g, '-');
  const backupName = `backup-${stamp}-${backupId.slice(0, 8)}`;
  const backupDir = s3Mode ? `s3:${backupName}` : path.join(storagePaths.backups, backupName);

  let dbFilename = 'database.sqlite';
  let dbBuf;
  if (db.dialect === 'sqlite' && !s3Mode) {
    fs.mkdirSync(backupDir, { recursive: true });
    const backupDbPath = path.join(backupDir, dbFilename);
    const escapedDbDest = backupDbPath.replace(/'/g, "''");
    await db.exec(`VACUUM INTO '${escapedDbDest}';`);
    dbBuf = fs.readFileSync(backupDbPath);
  } else {
    dbFilename = 'database.snapshot.json';
    const tables = {};
    for (const table of SNAPSHOT_TABLES) {
      tables[table] = await db.prepare(`SELECT * FROM ${table}`).all();
    }
    dbBuf = Buffer.from(JSON.stringify({ dialect: db.dialect, created_at: nowIso, tables }, null, 2), 'utf8');
    await store.putObject({ area: 'backups', key: `${backupName}/${dbFilename}`, buffer: dbBuf, contentType: 'application/json' });
  }
  const dbSha256 = sha256Hex(dbBuf);

  const manifestFiles = [];
  for (const area of STORAGE_AREAS) {
    const objs = await store.listAreaObjects({ area });
    for (const obj of objs) {
      const filename = path.basename(obj.key);
      const buf = await store.getObjectBuffer({ area, key: filename });
      if (!buf) continue;
      await store.putObject({
        area: 'backups',
        key: `${backupName}/files/${area}/${filename}`,
        buffer: buf,
      });
      manifestFiles.push({
        area,
        filename,
        bytes: buf.length,
        sha256: sha256Hex(buf),
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
    backup_name: backupName,
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

  await store.putObject({
    area: 'backups',
    key: `${backupName}/manifest.json`,
    buffer: Buffer.from(manifestJsonStr, 'utf8'),
    contentType: 'application/json',
  });
  await store.putObject({
    area: 'backups',
    key: `${backupName}/manifest.sha256`,
    buffer: Buffer.from(manifestSha256, 'utf8'),
    contentType: 'text/plain',
  });

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

  if (reason === 'scheduled') {
    const keep = Math.max(3, Number(ENV.BACKUP_KEEP_COUNT || 14));
    const oldScheduled = await db
      .prepare(`SELECT * FROM backup_runs WHERE reason = 'scheduled' ORDER BY created_at DESC LIMIT 10000 OFFSET ?`)
      .all(keep);
    for (const old of oldScheduled) {
      if (old.backup_dir?.startsWith('s3:')) {
        const oldName = old.backup_dir.slice(3);
        const oldObjs = await store.listAreaObjects({ area: 'backups', prefix: `${oldName}/` });
        for (const o of oldObjs) {
          await store.deleteObject({ area: 'backups', key: o.key });
        }
      } else if (old.backup_dir && fs.existsSync(old.backup_dir)) {
        try {
          fs.rmSync(old.backup_dir, { recursive: true, force: true });
        } catch {}
      }
      await db.prepare('DELETE FROM backup_runs WHERE backup_id = ?').run(old.backup_id);
    }
  }

  return { ok: true, backup_id: backupId, backup_dir: backupDir, manifest: manifestBody, manifest_sha256: manifestSha256 };
}

export async function verifyBackupIntegrity(backupDir, storagePaths = null) {
  if (!backupDir) {
    return { ok: false, error: 'Backup directory does not exist.' };
  }

  if (backupDir.startsWith('s3:')) {
    const backupName = backupDir.slice(3);
    const store = createObjectStore(storagePaths);
    const manifestBuf = await store.getObjectBuffer({ area: 'backups', key: `${backupName}/manifest.json` });
    const sigBuf = await store.getObjectBuffer({ area: 'backups', key: `${backupName}/manifest.sha256` });
    if (!manifestBuf || !sigBuf) {
      return { ok: false, error: 'Backup missing required manifest or checksum signature.' };
    }
    const manifestRaw = manifestBuf.toString('utf8');
    const expectedManifestSha = sigBuf.toString('utf8').trim();
    if (sha256Hex(manifestRaw) !== expectedManifestSha) {
      return { ok: false, error: 'Manifest checksum mismatch (backup may be corrupted or tampered).' };
    }
    let manifest;
    try {
      manifest = JSON.parse(manifestRaw);
    } catch {
      return { ok: false, error: 'Corrupt backup manifest JSON.' };
    }
    const dbFilename = path.basename(manifest.db_filename || 'database.snapshot.json');
    const dbBuf = await store.getObjectBuffer({ area: 'backups', key: `${backupName}/${dbFilename}` });
    if (!dbBuf) return { ok: false, error: 'Backup missing database snapshot.' };
    if (sha256Hex(dbBuf) !== manifest.db_sha256) {
      return { ok: false, error: 'Database snapshot SHA-256 mismatch.' };
    }
    for (const f of manifest.files || []) {
      const fBuf = await store.getObjectBuffer({
        area: 'backups',
        key: `${backupName}/files/${path.basename(f.area)}/${path.basename(f.filename)}`,
      });
      if (!fBuf) return { ok: false, error: `Missing backed-up file: ${f.area}/${f.filename}` };
      if (sha256Hex(fBuf) !== f.sha256) return { ok: false, error: `File checksum mismatch: ${f.area}/${f.filename}` };
    }
    return { ok: true, manifest, dbBuffer: dbBuf, dbFilename, s3BackupName: backupName };
  }

  if (!fs.existsSync(backupDir)) {
    return { ok: false, error: 'Backup directory does not exist.' };
  }
  const manifestPath = path.join(backupDir, 'manifest.json');
  const sigPath = path.join(backupDir, 'manifest.sha256');
  if (!fs.existsSync(manifestPath) || !fs.existsSync(sigPath)) {
    return { ok: false, error: 'Backup missing required manifest or checksum signature.' };
  }

  const manifestRaw = fs.readFileSync(manifestPath, 'utf8');
  const expectedManifestSha = fs.readFileSync(sigPath, 'utf8').trim();
  if (sha256Hex(manifestRaw) !== expectedManifestSha) {
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
  if (sha256Hex(fs.readFileSync(dbPath)) !== manifest.db_sha256) {
    return { ok: false, error: 'Database snapshot SHA-256 mismatch.' };
  }

  for (const f of manifest.files || []) {
    const fPath = path.join(backupDir, 'files', path.basename(f.area), path.basename(f.filename));
    if (!fs.existsSync(fPath)) {
      return { ok: false, error: `Missing backed-up file: ${f.area}/${f.filename}` };
    }
    if (sha256Hex(fs.readFileSync(fPath)) !== f.sha256) {
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

  const verify = await verifyBackupIntegrity(row.backup_dir, storagePaths);
  if (!verify.ok) {
    await recordAudit(db, actor, 'ops', 'restore_backup_rejected', 'backup', backupId, { error: verify.error });
    return { ok: false, statusCode: 422, error: `Backup integrity verification failed: ${verify.error}` };
  }

  await createFullBackup(db, { storagePaths, actor, reason: 'pre_restore', nowDate });

  const nowIso = nowDate.toISOString();
  const backupCreatedAt = verify.manifest.created_at;

  let readBakTable;
  let closeBak = () => {};
  if (verify.dbFilename.endsWith('.json')) {
    const snapshotRaw = verify.dbBuffer ? verify.dbBuffer.toString('utf8') : fs.readFileSync(verify.dbPath, 'utf8');
    const snapshotData = JSON.parse(snapshotRaw);
    readBakTable = (table) => snapshotData.tables?.[table] || [];
  } else {
    const { DatabaseSync } = await import('node:sqlite');
    const bakDb = new DatabaseSync(verify.dbPath, { readOnly: true });
    readBakTable = (table) => bakDb.prepare(`SELECT * FROM ${table}`).all();
    closeBak = () => bakDb.close();
  }

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

      await copyUpsert('campaigns', 'campaign_id', () => true, (c) => {
        if (!c.is_evergreen && c.end_at && new Date(c.end_at).getTime() <= nowDate.getTime()) {
          c.activation_state = 'Ended';
        }
        return c;
      });

      await copyUpsert('media_assets', 'asset_id', () => true, (m) => {
        if (withdrawnAssets.has(m.asset_id)) {
          m.rights_status = 'withdrawn';
          m.is_public_published = 0;
        }
        return m;
      });
      await copyUpsert('projects', 'project_id', (p) => !withdrawnAssets.has(p.cover_asset_id));
      await copyUpsert('project_gallery_items', 'item_id', (g) => !withdrawnAssets.has(g.asset_id));
      await copyUpsert('project_before_after_pairs', 'pair_id', (b) => !withdrawnAssets.has(b.before_asset_id) && !withdrawnAssets.has(b.after_asset_id));

      await copyUpsert('jobs', 'requisition_id', () => true, (j) => {
        if (closedJobIds.has(j.requisition_id) || (j.close_at && new Date(j.close_at).getTime() <= nowDate.getTime())) {
          j.status = 'Closed';
        }
        return j;
      });

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
          if (deletedAttachments.has(a.attachment_id)) a.deleted_at = a.deleted_at || nowIso;
          return a;
        }
      );
      await copyUpsert('application_notes', 'note_id', (n) => !purgedIds.has(n.application_id));

      await copyUpsert('crm_delivery_queue', 'delivery_id', (d) => !purgedIds.has(d.inquiry_id), (d) => {
        if (alreadyDeliveredCrm.has(d.delivery_id)) d.status = 'delivered';
        return d;
      });
      await copyUpsert('notification_queue', 'notification_id', () => true, (n) => {
        if (alreadySentNotifs.has(n.notification_id)) n.status = 'sent';
        return n;
      });
    });
  } catch (err) {
    closeBak();
    return { ok: false, statusCode: 500, error: `Restore transaction failed: ${err.message}` };
  }
  closeBak();

  const store = createObjectStore(storagePaths);
  let filesRestored = 0;
  for (const f of verify.manifest.files || []) {
    const fname = path.basename(f.filename);
    if (purgedKeys.has(fname)) continue;
    let buf = null;
    if (verify.s3BackupName) {
      buf = await store.getObjectBuffer({ area: 'backups', key: `${verify.s3BackupName}/files/${f.area}/${fname}` });
    } else {
      const srcPath = path.join(row.backup_dir, 'files', f.area, fname);
      if (fs.existsSync(srcPath)) buf = fs.readFileSync(srcPath);
    }
    if (buf) {
      await store.putObject({ area: f.area, key: fname, buffer: buf });
      filesRestored++;
    }
  }

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
