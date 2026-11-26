import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  buildTotpOtpAuthUri,
  decryptSecret,
  encryptSecret,
  generateRecoveryCodes,
  generateTotpCode,
  generateTotpSecret,
  hashPassword,
  hashRecoveryCodeList,
  verifyPassword,
  verifyRecoveryCodeInList,
  verifyTotpCode,
} from '../src/lib/crypto.js';
import {
  detectFileSignature,
  inspectImageDimensions,
  processPrivateDocumentUpload,
  processProjectImageUpload,
  stripImageMetadata,
} from '../src/lib/media-processor.js';
import { generateCapabilitiesPdf } from '../src/lib/pdf-generator.js';
import { buildSafeCsv, csvSafeCell, sanitizeRichHtml } from '../src/lib/sanitize.js';
import { formatPhoenixDateTime, phoenixLocalToUtcIso, utcIsoToPhoenixInput } from '../src/lib/time.js';
import { validateInquiryPayload } from '../src/lib/validation.js';

function makeMinimalPng(width = 120, height = 90, withTextChunk = true) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 2; // RGB
  const ihdr = makePngChunk('IHDR', ihdrData);
  const idat = makePngChunk('IDAT', Buffer.from([0x78, 0x9c, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01]));
  const iend = makePngChunk('IEND', Buffer.alloc(0));
  if (withTextChunk) {
    const txt = makePngChunk('tEXt', Buffer.from('GPSLatitude\0SecretSite123', 'ascii'));
    return Buffer.concat([sig, ihdr, txt, idat, iend]);
  }
  return Buffer.concat([sig, ihdr, idat, iend]);
}

function makePngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function makeMinimalJpegWithExif(width = 800, height = 600) {
  const soi = Buffer.from([0xff, 0xd8]);
  // APP1 EXIF segment containing "Exif\0\0" and secret GPS text
  const exifPayload = Buffer.from('Exif\0\0MM\x00\x2a\x00\x00\x00\x08\x00\x00GPS_SECRET_COORD', 'latin1');
  const app1Len = Buffer.alloc(2);
  app1Len.writeUInt16BE(exifPayload.length + 2, 0);
  const app1 = Buffer.concat([Buffer.from([0xff, 0xe1]), app1Len, exifPayload]);

  // SOF0 segment
  const sofData = Buffer.alloc(11);
  sofData[0] = 8;
  sofData.writeUInt16BE(height, 1);
  sofData.writeUInt16BE(width, 3);
  sofData[5] = 3;
  const sofLen = Buffer.alloc(2);
  sofLen.writeUInt16BE(sofData.length + 2, 0);
  const sof0 = Buffer.concat([Buffer.from([0xff, 0xc0]), sofLen, sofData]);

  const sos = Buffer.from([0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0xaa, 0xff, 0xd9]);
  return Buffer.concat([soi, app1, sof0, sos]);
}

test('Scrypt password hashing & verification', () => {
  const h = hashPassword('SM-Staff-2026!');
  assert.equal(verifyPassword('SM-Staff-2026!', h), true);
  assert.equal(verifyPassword('wrong-password', h), false);
});

test('RFC 6238 TOTP MFA generation & verification', () => {
  const secret = generateTotpSecret();
  const now = Date.now();
  const code = generateTotpCode(secret, now);
  assert.match(code, /^\d{6}$/);
  assert.equal(verifyTotpCode(secret, code, now), true);
  assert.equal(verifyTotpCode(secret, '000000', now), false);
});

test('America/Phoenix UTC conversions are deterministic without DST drift', () => {
  const utc = phoenixLocalToUtcIso('2026-07-15T09:30');
  assert.equal(utc, '2026-07-15T16:30:00.000Z'); // Always UTC-7 in Phoenix
  assert.equal(utcIsoToPhoenixInput(utc), '2026-07-15T09:30');
  assert.match(formatPhoenixDateTime(utc), /America\/Phoenix/);
});

test('Sanitizer strips XSS vectors and CWE-1236 neutralizes CSV formulas', () => {
  const dirty = '<p>Safe</p><script>alert(1)</script><a href="javascript:evil()">bad</a><img src=x onerror=alert(1)>';
  const clean = sanitizeRichHtml(dirty);
  assert.equal(clean.includes('<script>'), false);
  assert.equal(clean.includes('javascript:'), false);
  assert.equal(clean.includes('onerror'), false);
  assert.equal(clean.includes('<p>Safe</p>'), true);

  assert.equal(csvSafeCell('=CMD("calc")'), '"\'=CMD(""calc"")"');
  assert.equal(csvSafeCell('+1+2'), '"\'+1+2"');
  assert.equal(csvSafeCell(' -SUM(A1)'), '"\' -SUM(A1)"');
  assert.equal(csvSafeCell('@IMPORT'), '"\'@IMPORT"');
  const csv = buildSafeCsv(['Name'], [['=1+1']]);
  assert.ok(csv.includes('"\'=1+1"'));
});

test('Validation allows personal email domains, single names, and international phone numbers', () => {
  const resEmail = validateInquiryPayload({
    name: 'Cher',
    company: 'Solo Facility Owner',
    preferred_contact_method: 'email',
    email: 'owner@gmail.com',
    service_needed: 'day-porter',
    property_city_or_zip: 'Phoenix, AZ 85004',
    description: 'Need daytime porter review.',
  });
  assert.equal(resEmail.valid, true);

  const resIntlPhone = validateInquiryPayload({
    name: 'Kenji Sato',
    company: 'Pacific Properties',
    preferred_contact_method: 'telephone',
    telephone: '+81 3 5555 0199',
    service_needed: 'warehouse-repairs',
    property_city_or_zip: 'Tempe 85281',
    description: 'Dock concrete spall.',
  });
  assert.equal(resIntlPhone.valid, true);
});

test('Media processor strips EXIF/GPS metadata, enforces 64MP limit, and blocks active PDF/macro DOCM', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-media-'));
  const storagePaths = {
    originals: path.join(tmpDir, 'originals'),
    publicMedia: path.join(tmpDir, 'public'),
    resumes: path.join(tmpDir, 'resumes'),
  };

  // 1. JPEG EXIF stripping
  const jpg = makeMinimalJpegWithExif(1200, 900);
  const jpgDims = inspectImageDimensions(jpg, 'image/jpeg');
  assert.equal(jpgDims.width, 1200);
  const strippedJpg = stripImageMetadata(jpg, 'image/jpeg');
  assert.equal(strippedJpg.toString('latin1').includes('GPS_SECRET_COORD'), false);

  // 2. PNG tEXt stripping & upload pipeline
  const png = makeMinimalPng(800, 600, true);
  const proc = processProjectImageUpload({ buffer: png, originalName: 'site.png', storagePaths });
  assert.equal(proc.ok, true);
  const derivBuf = fs.readFileSync(path.join(storagePaths.publicMedia, proc.asset.public_derivative_key));
  assert.equal(derivBuf.toString('ascii').includes('SecretSite123'), false);

  // 3. 64MP pixel limit rejection
  const hugePng = makeMinimalPng(10000, 8000, false); // 80 MP
  const hugeProc = processProjectImageUpload({ buffer: hugePng, originalName: 'huge.png', storagePaths });
  assert.equal(hugeProc.ok, false);
  assert.equal(hugeProc.errorCode, 'pixel_limit_exceeded');

  // 4. Active PDF JavaScript quarantine & macro DOCM rejection
  const activePdf = Buffer.from('%PDF-1.4\n1 0 obj << /JavaScript (app.alert(1)) >> endobj', 'ascii');
  const pdfRes = processPrivateDocumentUpload({
    buffer: activePdf,
    originalName: 'resume.pdf',
    allowedTypes: ['application/pdf'],
    maxBytes: 1024 * 1024,
    destDir: storagePaths.resumes,
  });
  assert.equal(pdfRes.ok, true);
  assert.equal(pdfRes.file.scan_state, 'quarantined');

  const fakeDocm = Buffer.from('PK\x03\x04[Content_Types].xml word/document.xml vbaProject.bin', 'latin1');
  const docmSig = detectFileSignature(fakeDocm);
  assert.equal(docmSig.unsafeMacro, true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('PDF generator produces valid %PDF-1.4 Capabilities Statement', () => {
  const pdf = generateCapabilitiesPdf({
    trading_name: 'Service Maintenance',
    legal_entity: 'Promptitude Inc.',
    phone_display: '(480) 423-9196',
    hours_display: 'Mon-Fri 7AM-5PM (America/Phoenix)',
    timezone: 'America/Phoenix',
    address_display: '2105 S Hardy Dr., Suite 17, Tempe, AZ',
    roc_numbers: 'ROC 334827, ROC 328349, ROC 328350',
    insurance_statement: 'Insurance documentation available on request',
    website_url: 'https://smiaz.com',
  });
  assert.equal(pdf.subarray(0, 8).toString('ascii'), '%PDF-1.4');
  assert.ok(pdf.toString('ascii').includes('Promptitude Inc.'));
});

test('Production config fails startup when SESSION_SECRET is missing, short, or uses dev fallback', async () => {
  const { DEV_FALLBACK_SESSION_SECRET, validateSecurityConfig } = await import('../src/config.js');
  assert.throws(() => validateSecurityConfig({ NODE_ENV: 'production', SESSION_SECRET: '' }), /FATAL SECURITY ERROR/);
  assert.throws(
    () => validateSecurityConfig({ NODE_ENV: 'production', SESSION_SECRET: DEV_FALLBACK_SESSION_SECRET }),
    /FATAL SECURITY ERROR/
  );
  assert.throws(() => validateSecurityConfig({ NODE_ENV: 'production', SESSION_SECRET: 'too-short' }), /FATAL SECURITY ERROR/);
  assert.doesNotThrow(() =>
    validateSecurityConfig({ NODE_ENV: 'production', SESSION_SECRET: 'strong-production-secret-key-with-more-than-32-chars' })
  );
  assert.doesNotThrow(() => validateSecurityConfig({ NODE_ENV: 'development', SESSION_SECRET: '' }));
});

test('canAccessJobRecord and canAccessApplicationRecord enforce strict assigned recruiting scope', async () => {
  const { ROLES } = await import('../src/config.js');
  const { canAccessApplicationRecord, canAccessJobRecord } = await import('../src/services/auth.js');

  const owner1 = { user_id: 'u-ho-1', role: ROLES.HIRING_OWNER, active: 1, extra_roles_json: '[]' };
  const owner2 = { user_id: 'u-ho-2', role: ROLES.HIRING_OWNER, active: 1, extra_roles_json: '[]' };
  const reviewerAssigned = { user_id: 'u-rev-1', role: ROLES.HIRING_REVIEWER, active: 1, extra_roles_json: '[]' };
  const reviewerUnassigned = { user_id: 'u-rev-2', role: ROLES.HIRING_REVIEWER, active: 1, extra_roles_json: '[]' };

  const job = {
    requisition_id: 'REQ-1',
    hiring_owner_id: 'u-ho-1',
    backup_owner_id: 'u-ho-backup',
    assigned_reviewers_json: '["u-rev-1"]',
  };
  const app = { application_id: 'APP-1', requisition_id: 'REQ-1', assigned_reviewer_id: null };
  const fakeDb = { prepare: () => ({ get: () => job }) };

  assert.equal(canAccessJobRecord(owner1, job), true);
  assert.equal(canAccessJobRecord(owner2, job), false);
  assert.equal(canAccessJobRecord(reviewerAssigned, job), true);
  assert.equal(canAccessJobRecord(reviewerUnassigned, job), false);

  assert.equal(await canAccessApplicationRecord(fakeDb, owner1, app), true);
  assert.equal(await canAccessApplicationRecord(fakeDb, owner2, app), false);
  assert.equal(await canAccessApplicationRecord(fakeDb, reviewerAssigned, app), true);
  assert.equal(await canAccessApplicationRecord(fakeDb, reviewerUnassigned, app), false);
});

test('AES-256-GCM MFA encryption, otpauth URI, and single-use recovery code hashing', () => {
  const key = 'test-mfa-encryption-key-material-32bytes';
  const secret = generateTotpSecret();
  const encrypted = encryptSecret(secret, key);
  assert.ok(encrypted.startsWith('enc:v1:'));
  assert.equal(encrypted.includes(secret), false);
  assert.equal(decryptSecret(encrypted, key), secret);
  assert.equal(decryptSecret(secret, key), secret); // Legacy Base32 backward compatibility
  assert.throws(() => decryptSecret(`${encrypted.slice(0, -2)}ff`, key));

  const uri = buildTotpOtpAuthUri({ issuer: 'ServiceMaintenance', email: 'admin@smiaz.local', secret });
  assert.ok(uri.startsWith('otpauth://totp/ServiceMaintenance%3Aadmin%40smiaz.local?'));

  const codes = generateRecoveryCodes(8);
  assert.equal(codes.length, 8);
  const hashedJson = JSON.stringify(hashRecoveryCodeList(codes));
  assert.equal(hashedJson.includes(codes[0].replace(/-/g, '')), false);
  assert.equal(verifyRecoveryCodeInList(codes[0], hashedJson).matched, true);
  assert.equal(verifyRecoveryCodeInList('WRONG-CODE-00', hashedJson).matched, false);
});

test('isAdminMfaRequired feature flag parses true/false cleanly', async () => {
  const { isAdminMfaRequired } = await import('../src/config.js');
  assert.equal(isAdminMfaRequired({}), false);
  assert.equal(isAdminMfaRequired({ ADMIN_MFA_REQUIRED: 'false' }), false);
  assert.equal(isAdminMfaRequired({ ADMIN_MFA_REQUIRED: '0' }), false);
  assert.equal(isAdminMfaRequired({ ADMIN_MFA_REQUIRED: 'true' }), true);
  assert.equal(isAdminMfaRequired({ ADMIN_MFA_REQUIRED: '1' }), true);
});

test('PRD v2.0 7-role permission matrix enforces least privilege, hiring isolation, and multi-role union', async () => {
  const { ROLES } = await import('../src/config.js');
  const { getUserRoles, hasPermission, PERMISSIONS } = await import('../src/services/auth.js');

  const mkUser = (role, extra = [], active = 1) => ({
    user_id: 'u-test',
    role,
    extra_roles_json: JSON.stringify(extra),
    active,
  });

  const admin = mkUser(ROLES.PLATFORM_ADMIN);
  assert.equal(hasPermission(admin, PERMISSIONS.MANAGE_USERS), true);
  assert.equal(hasPermission(admin, PERMISSIONS.VIEW_CONTENT), true);
  assert.equal(hasPermission(admin, PERMISSIONS.EDIT_CONTENT), false);
  assert.equal(hasPermission(admin, PERMISSIONS.PUBLISH_CONTENT), false);
  assert.equal(hasPermission(admin, PERMISSIONS.MANAGE_VACANCIES), false);
  assert.equal(hasPermission(admin, PERMISSIONS.REVIEW_APPLICATIONS), false);
  assert.equal(hasPermission(admin, PERMISSIONS.EXPORT_APPLICATIONS), false);

  const editor = mkUser(ROLES.CONTENT_EDITOR);
  assert.equal(hasPermission(editor, PERMISSIONS.EDIT_CONTENT), true);
  assert.equal(hasPermission(editor, PERMISSIONS.UPLOAD_PROJECT_MEDIA), true);
  assert.equal(hasPermission(editor, PERMISSIONS.APPROVE_CONTENT), false);
  assert.equal(hasPermission(editor, PERMISSIONS.PUBLISH_CONTENT), false);
  assert.equal(hasPermission(editor, PERMISSIONS.REVIEW_APPLICATIONS), false);

  const publisher = mkUser(ROLES.APPROVER_PUBLISHER);
  assert.equal(hasPermission(publisher, PERMISSIONS.APPROVE_CONTENT), true);
  assert.equal(hasPermission(publisher, PERMISSIONS.PUBLISH_CONTENT), true);
  assert.equal(hasPermission(publisher, PERMISSIONS.PUBLISH_PROJECTS), true);
  assert.equal(hasPermission(publisher, PERMISSIONS.MANAGE_USERS), false);
  assert.equal(hasPermission(publisher, PERMISSIONS.REVIEW_APPLICATIONS), false);

  const hiringOwner = mkUser(ROLES.HIRING_OWNER);
  assert.equal(hasPermission(hiringOwner, PERMISSIONS.MANAGE_VACANCIES), true);
  assert.equal(hasPermission(hiringOwner, PERMISSIONS.EXPORT_APPLICATIONS), true);
  assert.equal(hasPermission(hiringOwner, PERMISSIONS.PUBLISH_CONTENT), false);

  const reviewer = mkUser(ROLES.HIRING_REVIEWER);
  assert.equal(hasPermission(reviewer, PERMISSIONS.REVIEW_APPLICATIONS), true);
  assert.equal(hasPermission(reviewer, PERMISSIONS.MANAGE_VACANCIES), false);
  assert.equal(hasPermission(reviewer, PERMISSIONS.EXPORT_APPLICATIONS), false);

  const contributor = mkUser(ROLES.PROJECT_CONTRIBUTOR);
  assert.equal(hasPermission(contributor, PERMISSIONS.EDIT_PROJECTS), true);
  assert.equal(hasPermission(contributor, PERMISSIONS.UPLOAD_PROJECT_MEDIA), true);
  assert.equal(hasPermission(contributor, PERMISSIONS.PUBLISH_PROJECTS), false);
  assert.equal(hasPermission(contributor, PERMISSIONS.VIEW_CONTENT), false);

  const analyst = mkUser(ROLES.ANALYST);
  assert.equal(hasPermission(analyst, PERMISSIONS.VIEW_ANALYTICS), true);
  assert.equal(hasPermission(analyst, PERMISSIONS.EDIT_CONTENT), false);
  assert.equal(hasPermission(analyst, PERMISSIONS.MANAGE_LEADS_CRM), false);

  // Inactive users denied by default
  assert.equal(hasPermission(mkUser(ROLES.PLATFORM_ADMIN, [], 0), PERMISSIONS.MANAGE_USERS), false);

  // Multi-role combination inherits union without implicit hiring leak unless assigned
  const combo = mkUser(ROLES.CONTENT_EDITOR, [ROLES.HIRING_REVIEWER, ROLES.ANALYST]);
  assert.deepEqual(getUserRoles(combo), [ROLES.CONTENT_EDITOR, ROLES.HIRING_REVIEWER, ROLES.ANALYST]);
  assert.equal(hasPermission(combo, PERMISSIONS.EDIT_CONTENT), true);
  assert.equal(hasPermission(combo, PERMISSIONS.REVIEW_APPLICATIONS), true);
  assert.equal(hasPermission(combo, PERMISSIONS.VIEW_ANALYTICS), true);
  assert.equal(hasPermission(combo, PERMISSIONS.PUBLISH_CONTENT), false);
});

test('detectPgNeedsMigration detects missing users.last_login_at and additive migration preserves legacy data', async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const { DatabaseSync } = await import('node:sqlite');
  const { detectPgNeedsMigration, getDb, migrateSchema } = await import('../src/db/database.js');

  // 1. Postgres detection probe: missing last_login_at throws on probe query -> must return true
  const missingColPool = {
    async query(sql) {
      if (sql.includes('business_settings')) return { rows: [{ id: 1 }] };
      if (sql.includes('last_login_at')) {
        throw new Error('column "last_login_at" does not exist');
      }
      return { rows: [{ ok: 1 }] };
    },
  };
  assert.equal(await detectPgNeedsMigration(missingColPool), true);

  // 2. Postgres detection probe: once last_login_at and required tables/rows exist -> returns false
  const upToDatePool = {
    async query(sql) {
      if (sql.includes('business_settings')) return { rows: [{ id: 1 }] };
      return { rows: [{ ok: 1 }] };
    },
  };
  assert.equal(await detectPgNeedsMigration(upToDatePool), false);

  // 3. Legacy SQLite database missing last_login_at preserves existing user rows when migrated
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-mig-legacy-'));
  const legacyPath = path.join(tmpDir, 'legacy.db');
  try {
    const rawDb = new DatabaseSync(legacyPath);
    rawDb.exec(`
      CREATE TABLE users (
        user_id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        full_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        extra_roles_json TEXT NOT NULL DEFAULT '[]',
        totp_secret TEXT NOT NULL,
        mfa_enabled INTEGER NOT NULL DEFAULT 1,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      INSERT INTO users (user_id, email, full_name, password_hash, role, totp_secret, created_at, updated_at)
      VALUES ('usr-legacy-1', 'legacy@smiaz.local', 'Legacy User', 'hash', 'Analyst', 'enc:v1:abc', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
    `);
    rawDb.close();

    const db = await getDb(legacyPath);
    const cols = (await db.prepare('PRAGMA table_info(users)').all()).map((c) => c.name);
    assert.ok(cols.includes('last_login_at'), 'Expected additive migration to add last_login_at');

    const preserved = await db.prepare('SELECT user_id, email, last_login_at FROM users WHERE user_id = ?').get('usr-legacy-1');
    assert.equal(preserved.email, 'legacy@smiaz.local');
    assert.equal(preserved.last_login_at, null);

    // 4. Verify Postgres DDL statements generated for migrateSchema include idempotent ADD COLUMN IF NOT EXISTS
    const pgStatements = [];
    await migrateSchema({
      dialect: 'postgres',
      prepare() {
        return { async get() {}, async all() { return []; }, async run() { return { changes: 0 }; } };
      },
      async exec(sql) {
        pgStatements.push(sql);
      },
    });
    assert.ok(pgStatements.some((s) => s.includes('ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TEXT;')));

    await db.close();
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
