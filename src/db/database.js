import fs from 'node:fs';
import path from 'node:path';
import { attachDatabasePool } from '@vercel/functions';
import pg from 'pg';
import { ENV, getValidatedNeonPostgresEnv, STORAGE_PATHS } from '../config.js';

// Ensure COUNT(*) and bigint aggregates return JS numbers instead of strings in node-postgres
pg.types.setTypeParser(20, (val) => (val === null ? null : Number(val)));

let dbInstance = null;

export function ensureStorageDirs(storagePaths = STORAGE_PATHS) {
  for (const dir of Object.values(storagePaths)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export function translateSqlForPg(sql) {
  let out = '';
  let paramIdx = 1;
  let i = 0;
  let inSingleQuote = false;
  let inLineComment = false;
  let inBlockComment = false;

  while (i < sql.length) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (inLineComment) {
      out += ch;
      if (ch === '\n') inLineComment = false;
      i++;
      continue;
    }
    if (inBlockComment) {
      out += ch;
      if (ch === '*' && next === '/') {
        out += '/';
        inBlockComment = false;
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    if (inSingleQuote) {
      out += ch;
      if (ch === "'" && next === "'") {
        out += "'";
        i += 2;
        continue;
      }
      if (ch === "'") inSingleQuote = false;
      i++;
      continue;
    }

    if (ch === '-' && next === '-') {
      inLineComment = true;
      out += '--';
      i += 2;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlockComment = true;
      out += '/*';
      i += 2;
      continue;
    }
    if (ch === "'") {
      inSingleQuote = true;
      out += ch;
      i++;
      continue;
    }
    if (ch === '?') {
      out += `$${paramIdx++}`;
      i++;
      continue;
    }
    out += ch;
    i++;
  }

  let pgSql = out.replace(/\bLIMIT\s+-1\b/gi, 'LIMIT ALL');

  if (/\bINSERT\s+OR\s+IGNORE\s+INTO\b/i.test(pgSql)) {
    pgSql = pgSql.replace(/\bINSERT\s+OR\s+IGNORE\s+INTO\b/gi, 'INSERT INTO');
    if (!/\bON\s+CONFLICT\b/i.test(pgSql)) {
      if (pgSql.trimEnd().endsWith(';')) {
        pgSql = pgSql.replace(/;\s*$/, ' ON CONFLICT DO NOTHING;');
      } else {
        pgSql = `${pgSql.trimEnd()} ON CONFLICT DO NOTHING`;
      }
    }
  }

  return pgSql;
}

function createPgQueryInterface(executor) {
  return {
    dialect: 'postgres',
    prepare(sql) {
      const pgSql = translateSqlForPg(sql);
      return {
        async get(...params) {
          const res = await executor.query(pgSql, params);
          return res.rows[0];
        },
        async all(...params) {
          const res = await executor.query(pgSql, params);
          return res.rows;
        },
        async run(...params) {
          const res = await executor.query(pgSql, params);
          return { changes: res.rowCount ?? 0 };
        },
      };
    },
    async exec(sql) {
      const cleaned = sql
        .split(';')
        .map((s) => s.trim())
        .filter((s) => s && !/^PRAGMA\b/i.test(s))
        .join(';\n');
      if (!cleaned.trim()) return;
      await executor.query(translateSqlForPg(cleaned));
    },
  };
}

function createSqliteQueryInterface(sqliteDb) {
  return {
    dialect: 'sqlite',
    rawSqliteDb: sqliteDb,
    prepare(sql) {
      const stmt = sqliteDb.prepare(sql);
      return {
        async get(...params) {
          return stmt.get(...params);
        },
        async all(...params) {
          return stmt.all(...params);
        },
        async run(...params) {
          return stmt.run(...params);
        },
      };
    },
    async exec(sql) {
      sqliteDb.exec(sql);
    },
  };
}

export async function detectPgNeedsMigration(runtimePool) {
  try {
    const check = await runtimePool.query('SELECT id FROM business_settings WHERE id = 1 LIMIT 1');
    await runtimePool.query(
      'SELECT mfa_enrolled, mfa_pending_secret, recovery_codes_json, last_login_at FROM users LIMIT 1'
    );
    await runtimePool.query('SELECT token_id FROM mfa_recovery_tokens LIMIT 1');
    await runtimePool.query('SELECT mfa_required FROM auth_policy_state LIMIT 1');
    return !check.rows?.length;
  } catch {
    return true;
  }
}

export async function getDb(customPath = null, storagePaths = STORAGE_PATHS, { forceMigrate = false } = {}) {
  if (dbInstance && !customPath && !forceMigrate) return dbInstance;
  ensureStorageDirs(storagePaths);

  const useSqlite = Boolean(customPath) || !ENV.DATABASE_URL;
  if (useSqlite) {
    const { DatabaseSync } = await import('node:sqlite');
    const dbPath = customPath || ENV.DB_PATH;
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    const sqliteDb = new DatabaseSync(dbPath);
    sqliteDb.exec('PRAGMA journal_mode = WAL;');
    sqliteDb.exec('PRAGMA foreign_keys = ON;');
    sqliteDb.exec('PRAGMA busy_timeout = 5000;');

    const base = createSqliteQueryInterface(sqliteDb);
    const adapter = {
      ...base,
      async transaction(fn) {
        sqliteDb.exec('BEGIN IMMEDIATE;');
        try {
          const result = await fn(base);
          sqliteDb.exec('COMMIT;');
          return result;
        } catch (err) {
          try {
            sqliteDb.exec('ROLLBACK;');
          } catch {}
          throw err;
        }
      },
      async close() {
        sqliteDb.close();
        if (dbInstance === adapter) dbInstance = null;
      },
    };

    await migrateSchema(adapter);
    if (!customPath) dbInstance = adapter;
    return adapter;
  }

  // Neon Lakebase Postgres mode:
  // - Pooled DATABASE_URL for runtime Pool queries (attached to Vercel Fluid Compute when active)
  // - Direct DATABASE_URL_UNPOOLED for schema migrations (per neon-postgres skill)
  const neonPg = getValidatedNeonPostgresEnv();
  const pooledUrl = neonPg?.databaseUrl || ENV.DATABASE_URL;
  const directUrl = neonPg?.databaseUrlUnpooled || ENV.DATABASE_URL_UNPOOLED || pooledUrl;

  const runtimePool =
    dbInstance?.pool ||
    new pg.Pool({
      connectionString: pooledUrl,
      max: ENV.IS_VERCEL ? 5 : 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 15_000,
    });

  if (!dbInstance?.pool) {
    try {
      attachDatabasePool(runtimePool);
    } catch {}
  }

  const needsMigration = Boolean(forceMigrate) || (await detectPgNeedsMigration(runtimePool));

  if (needsMigration) {
    const migrationPool = new pg.Pool({
      connectionString: directUrl,
      max: 2,
      connectionTimeoutMillis: 15_000,
    });
    const migClient = await migrationPool.connect();
    try {
      const migAdapter = { ...createPgQueryInterface(migClient), dialect: 'postgres' };
      await migrateSchema(migAdapter);
    } finally {
      migClient.release();
      await migrationPool.end();
    }
  }

  if (dbInstance && !customPath) return dbInstance;

  const base = createPgQueryInterface(runtimePool);
  const adapter = {
    ...base,
    pool: runtimePool,
    unpooledUrl: directUrl,
    async transaction(fn) {
      const client = await runtimePool.connect();
      const txBase = createPgQueryInterface(client);
      await client.query('BEGIN');
      try {
        const result = await fn(txBase);
        await client.query('COMMIT');
        return result;
      } catch (err) {
        try {
          await client.query('ROLLBACK');
        } catch {}
        throw err;
      } finally {
        client.release();
      }
    },
    async close() {
      await runtimePool.end();
      if (dbInstance === adapter) dbInstance = null;
    },
  };

  dbInstance = adapter;
  return adapter;
}

export async function closeDb() {
  if (dbInstance) {
    await dbInstance.close();
    dbInstance = null;
  }
}

const CORE_SCHEMA_DDL = `
  CREATE TABLE IF NOT EXISTS users (
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

  CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    mfa_verified INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    ip_hash TEXT
  );

  CREATE TABLE IF NOT EXISTS mfa_recovery_tokens (
    token_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    issued_by TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS auth_policy_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    mfa_required INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    audit_id TEXT PRIMARY KEY,
    actor_id TEXT,
    actor_name TEXT,
    actor_role TEXT,
    domain TEXT NOT NULL,
    action TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS business_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    trading_name TEXT NOT NULL,
    legal_entity TEXT NOT NULL,
    phone_display TEXT NOT NULL,
    phone_e164 TEXT NOT NULL,
    address_display TEXT NOT NULL,
    address_verified INTEGER NOT NULL DEFAULT 0,
    hours_display TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT 'America/Phoenix',
    monitored_inbox TEXT NOT NULL,
    recruiting_contact TEXT NOT NULL,
    privacy_contact TEXT NOT NULL,
    roc_numbers TEXT NOT NULL,
    roc_verification_notes TEXT NOT NULL,
    insurance_statement TEXT NOT NULL,
    service_area_cities_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT
  );

  CREATE TABLE IF NOT EXISTS pages (
    page_id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    template TEXT NOT NULL,
    title TEXT NOT NULL,
    service_family TEXT,
    owner_name TEXT NOT NULL,
    editorial_state TEXT NOT NULL DEFAULT 'Approved',
    activation_state TEXT NOT NULL DEFAULT 'Live',
    is_conditional INTEGER NOT NULL DEFAULT 0,
    indexable INTEGER NOT NULL DEFAULT 1,
    current_revision INTEGER NOT NULL DEFAULT 1,
    published_revision INTEGER,
    review_date TEXT,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS page_revisions (
    revision_id TEXT PRIMARY KEY,
    page_id TEXT NOT NULL REFERENCES pages(page_id) ON DELETE CASCADE,
    revision_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    meta_title TEXT NOT NULL,
    meta_description TEXT NOT NULL,
    hero_headline TEXT NOT NULL,
    hero_summary TEXT NOT NULL,
    cta_label TEXT NOT NULL,
    cta_route TEXT NOT NULL,
    body_html TEXT NOT NULL,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    faqs_json TEXT NOT NULL DEFAULT '[]',
    claim_status TEXT NOT NULL DEFAULT 'approved for publication',
    author_id TEXT,
    approver_id TEXT,
    review_comment TEXT,
    editorial_state TEXT NOT NULL DEFAULT 'Draft',
    created_at TEXT NOT NULL,
    UNIQUE(page_id, revision_number)
  );

  CREATE TABLE IF NOT EXISTS testimonials_claims (
    claim_id TEXT PRIMARY KEY,
    claim_type TEXT NOT NULL,
    title TEXT NOT NULL,
    exact_text TEXT NOT NULL,
    attribution TEXT NOT NULL,
    evidence_source TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'evidence needed',
    allowed_placements_json TEXT NOT NULL DEFAULT '[]',
    review_date TEXT,
    expiry_date TEXT,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS articles (
    article_id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    buyer_target TEXT NOT NULL,
    related_service TEXT,
    summary TEXT NOT NULL,
    body_html TEXT NOT NULL,
    sources_note TEXT NOT NULL,
    author_name TEXT NOT NULL,
    reviewer_name TEXT,
    editorial_state TEXT NOT NULL DEFAULT 'Draft',
    activation_state TEXT NOT NULL DEFAULT 'Unpublished',
    published_at TEXT,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS redirects (
    redirect_id TEXT PRIMARY KEY,
    old_path TEXT NOT NULL UNIQUE,
    destination_path TEXT NOT NULL,
    status_code INTEGER NOT NULL DEFAULT 301,
    reason TEXT NOT NULL,
    author_name TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    internal_title TEXT NOT NULL,
    service_family TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    placement_slot TEXT NOT NULL,
    target_service_slugs_json TEXT NOT NULL DEFAULT '[]',
    heading TEXT NOT NULL,
    summary TEXT NOT NULL,
    cta_label TEXT NOT NULL,
    cta_destination TEXT NOT NULL,
    asset_id TEXT,
    priority INTEGER NOT NULL DEFAULT 10,
    start_at TEXT NOT NULL,
    end_at TEXT,
    is_evergreen INTEGER NOT NULL DEFAULT 0,
    editorial_state TEXT NOT NULL DEFAULT 'Draft',
    activation_state TEXT NOT NULL DEFAULT 'Unpublished',
    landing_page_enabled INTEGER NOT NULL DEFAULT 0,
    landing_page_noindex INTEGER NOT NULL DEFAULT 1,
    landing_expiry_policy TEXT NOT NULL DEFAULT 'ended_notice',
    landing_expiry_redirect TEXT,
    content_revision INTEGER NOT NULL DEFAULT 1,
    approver_id TEXT,
    review_date TEXT,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS scheduler_health (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_run_at TEXT,
    last_success_at TEXT,
    status TEXT NOT NULL DEFAULT 'idle',
    last_error TEXT,
    cache_version INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS media_assets (
    asset_id TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    derivative_mime TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    orientation INTEGER NOT NULL DEFAULT 1,
    focal_x INTEGER NOT NULL DEFAULT 50,
    focal_y INTEGER NOT NULL DEFAULT 50,
    alt_text TEXT NOT NULL DEFAULT '',
    caption TEXT NOT NULL DEFAULT '',
    credit TEXT NOT NULL DEFAULT '',
    rights_owner TEXT NOT NULL DEFAULT '',
    permitted_uses TEXT NOT NULL DEFAULT 'website_only',
    client_approved INTEGER NOT NULL DEFAULT 0,
    rights_status TEXT NOT NULL DEFAULT 'pending',
    review_date TEXT,
    expiry_date TEXT,
    private_original_key TEXT NOT NULL,
    public_derivative_key TEXT NOT NULL,
    is_public_published INTEGER NOT NULL DEFAULT 0,
    uploaded_by TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    is_private_test INTEGER NOT NULL DEFAULT 0,
    naming_decision TEXT NOT NULL DEFAULT 'anonymized',
    client_name_internal TEXT,
    property_type TEXT NOT NULL,
    city_region TEXT NOT NULL,
    completion_date TEXT,
    completion_documented INTEGER NOT NULL DEFAULT 0,
    client_permission_verified INTEGER NOT NULL DEFAULT 0,
    challenge TEXT NOT NULL,
    agreed_scope TEXT NOT NULL,
    delivery_role TEXT NOT NULL,
    self_performed_notes TEXT NOT NULL,
    coordinated_notes TEXT NOT NULL,
    operating_constraints TEXT NOT NULL,
    completed_work TEXT NOT NULL,
    verified_result TEXT NOT NULL,
    related_services_json TEXT NOT NULL DEFAULT '[]',
    cover_asset_id TEXT REFERENCES media_assets(asset_id),
    featured_on_home INTEGER NOT NULL DEFAULT 0,
    featured_order INTEGER NOT NULL DEFAULT 100,
    editorial_state TEXT NOT NULL DEFAULT 'Draft',
    activation_state TEXT NOT NULL DEFAULT 'Unpublished',
    owner_id TEXT,
    approver_id TEXT,
    meta_title TEXT NOT NULL DEFAULT '',
    meta_description TEXT NOT NULL DEFAULT '',
    current_revision INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS project_gallery_items (
    item_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES media_assets(asset_id),
    caption TEXT NOT NULL DEFAULT '',
    alt_text TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS project_before_after_pairs (
    pair_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    pair_title TEXT NOT NULL,
    before_asset_id TEXT NOT NULL REFERENCES media_assets(asset_id),
    after_asset_id TEXT NOT NULL REFERENCES media_assets(asset_id),
    before_capture_date TEXT,
    after_capture_date TEXT,
    before_caption TEXT NOT NULL DEFAULT '',
    after_caption TEXT NOT NULL DEFAULT '',
    before_alt TEXT NOT NULL DEFAULT '',
    after_alt TEXT NOT NULL DEFAULT '',
    viewpoint_note TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    organization_name TEXT NOT NULL,
    verified_ownership INTEGER NOT NULL DEFAULT 0,
    crm_account_id TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS contacts (
    contact_id TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id),
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    preferred_method TEXT NOT NULL,
    consent_marketing INTEGER NOT NULL DEFAULT 0,
    consent_version TEXT,
    consent_recorded_at TEXT,
    crm_contact_id TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS properties (
    property_id TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(account_id),
    site_label TEXT NOT NULL,
    city_or_zip TEXT NOT NULL,
    property_type TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS inquiries (
    inquiry_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL,
    inquiry_kind TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'valid',
    account_id TEXT REFERENCES accounts(account_id),
    contact_id TEXT REFERENCES contacts(contact_id),
    property_id TEXT REFERENCES properties(property_id),
    service_family TEXT NOT NULL,
    routing_queue TEXT NOT NULL,
    assigned_owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'received',
    payload_json TEXT NOT NULL,
    attribution_json TEXT NOT NULL,
    sla_target_at TEXT,
    received_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS inquiry_attachments (
    attachment_id TEXT PRIMARY KEY,
    inquiry_id TEXT NOT NULL REFERENCES inquiries(inquiry_id) ON DELETE CASCADE,
    object_id TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    scan_state TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS crm_delivery_queue (
    delivery_id TEXT PRIMARY KEY,
    inquiry_id TEXT NOT NULL REFERENCES inquiries(inquiry_id) ON DELETE CASCADE,
    target_system TEXT NOT NULL DEFAULT 'freshsales',
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    external_record_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notification_queue (
    notification_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    reference_id TEXT NOT NULL,
    recipient_role TEXT NOT NULL,
    recipient_target TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_summary TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS jobs (
    requisition_id TEXT PRIMARY KEY,
    opening_cycle_id TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    role_family TEXT NOT NULL,
    employment_type TEXT NOT NULL,
    work_area TEXT NOT NULL,
    schedule_text TEXT NOT NULL,
    travel_requirements TEXT NOT NULL DEFAULT '',
    responsibilities_html TEXT NOT NULL,
    qualifications_html TEXT NOT NULL,
    pay_info TEXT NOT NULL,
    benefits_info TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Draft',
    publish_at TEXT,
    close_at TEXT,
    internal_review_date TEXT,
    form_revision INTEGER NOT NULL DEFAULT 1,
    require_city_zip INTEGER NOT NULL DEFAULT 0,
    resume_policy TEXT NOT NULL DEFAULT 'optional',
    questions_json TEXT NOT NULL DEFAULT '[]',
    hiring_owner_id TEXT NOT NULL REFERENCES users(user_id),
    backup_owner_id TEXT REFERENCES users(user_id),
    assigned_reviewers_json TEXT NOT NULL DEFAULT '[]',
    is_private_test INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS applicants (
    applicant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email_normalized TEXT,
    phone_normalized TEXT,
    preferred_method TEXT NOT NULL,
    city_or_zip TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS applications (
    application_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_hash TEXT NOT NULL,
    submission_token_hash TEXT NOT NULL,
    applicant_id TEXT NOT NULL REFERENCES applicants(applicant_id),
    requisition_id TEXT NOT NULL REFERENCES jobs(requisition_id),
    opening_cycle_id TEXT NOT NULL,
    form_revision INTEGER NOT NULL,
    stage TEXT NOT NULL DEFAULT 'Received',
    assigned_reviewer_id TEXT REFERENCES users(user_id),
    snapshot_json TEXT NOT NULL,
    answers_json TEXT NOT NULL,
    source_attribution_json TEXT NOT NULL,
    privacy_notice_version TEXT NOT NULL,
    privacy_ack_at TEXT NOT NULL,
    possible_duplicate_of TEXT,
    follow_up_due_at TEXT,
    received_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS application_attachments (
    attachment_id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(application_id) ON DELETE CASCADE,
    object_id TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    original_display_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    byte_size INTEGER NOT NULL,
    scan_state TEXT NOT NULL,
    replaced_by TEXT,
    deleted_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS application_notes (
    note_id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(application_id) ON DELETE CASCADE,
    author_id TEXT NOT NULL REFERENCES users(user_id),
    author_name TEXT NOT NULL,
    note_text TEXT NOT NULL,
    stage_change_from TEXT,
    stage_change_to TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS analytics_events (
    event_id TEXT PRIMARY KEY,
    event_name TEXT NOT NULL,
    page_type TEXT,
    service_id TEXT,
    project_id TEXT,
    job_id TEXT,
    on_site_campaign_id TEXT,
    placement_id TEXT,
    content_revision INTEGER,
    acquisition_utm_source TEXT,
    acquisition_utm_medium TEXT,
    acquisition_utm_campaign TEXT,
    acquisition_utm_content TEXT,
    error_code TEXT,
    consent_mode TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS backup_runs (
    backup_id TEXT PRIMARY KEY,
    backup_dir TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT 'scheduled',
    db_sha256 TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    file_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'verified',
    notes TEXT
  );

  CREATE TABLE IF NOT EXISTS retention_policies (
    policy_key TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    prd_reference TEXT NOT NULL,
    retention_days INTEGER,
    approved_by_client INTEGER NOT NULL DEFAULT 0,
    approved_by_user TEXT,
    approved_at TEXT,
    notes TEXT,
    last_run_at TEXT,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS deletion_ledger (
    ledger_id TEXT PRIMARY KEY,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    storage_key TEXT,
    reason TEXT NOT NULL,
    deleted_at TEXT NOT NULL,
    deleted_by TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_inquiries_received ON inquiries(received_at);
  CREATE INDEX IF NOT EXISTS idx_applications_req ON applications(requisition_id, opening_cycle_id);
  CREATE INDEX IF NOT EXISTS idx_campaigns_slot ON campaigns(placement_slot, activation_state);
  CREATE INDEX IF NOT EXISTS idx_analytics_name ON analytics_events(event_name, created_at);
`;

export async function migrateSchema(db) {
  await db.exec(CORE_SCHEMA_DDL);
  await db.prepare(`INSERT OR IGNORE INTO scheduler_health (id, status) VALUES (1, 'ready')`).run();

  const additiveColumns = [
    ['properties', 'crm_property_note_id', 'TEXT'],
    ['inquiries', 'crm_deal_id', 'TEXT'],
    ['inquiries', 'crm_note_id', 'TEXT'],
    ['inquiries', 'deal_value', 'DOUBLE PRECISION'],
    ['inquiries', 'milestone_qualified_at', 'TEXT'],
    ['inquiries', 'milestone_proposal_at', 'TEXT'],
    ['inquiries', 'milestone_won_at', 'TEXT'],
    ['notification_queue', 'provider_message_id', 'TEXT'],
    ['notification_queue', 'reply_to', 'TEXT'],
    ['media_assets', 'variants_json', 'TEXT'],
    ['media_assets', 'sha256', 'TEXT'],
    ['media_assets', 'scan_state', "TEXT DEFAULT 'clean'"],
    ['inquiries', 'legal_hold', 'INTEGER DEFAULT 0'],
    ['applications', 'legal_hold', 'INTEGER DEFAULT 0'],
    ['users', 'mfa_enrolled', 'INTEGER NOT NULL DEFAULT 0'],
    ['users', 'mfa_enrolled_at', 'TEXT'],
    ['users', 'mfa_pending_secret', 'TEXT'],
    ['users', 'recovery_codes_json', "TEXT NOT NULL DEFAULT '[]'"],
    ['users', 'last_login_at', 'TEXT'],
  ];

  for (const [table, column, definition] of additiveColumns) {
    await ensureColumn(db, table, column, definition);
  }

  await seedRetentionDefaults(db);
}

async function seedRetentionDefaults(db) {
  const nowIso = new Date().toISOString();
  const defaults = [
    {
      key: 'quarantined_spam_uploads',
      label: 'Quarantined & Spam Inquiry Uploads',
      ref: 'PRD 21.03 (Suggested default: 30 days pending client confirmation)',
      days: 30,
      notes: 'Suggested operational default; requires client sign-off before automated purge runs.',
    },
    {
      key: 'resolved_delivery_payloads',
      label: 'Resolved CRM / Notification Queue Records',
      ref: 'PRD 21.03 (Suggested default: 90 days after resolution)',
      days: 90,
      notes: 'Prunes old completed delivery logs; pending/failed_review records preserved.',
    },
    {
      key: 'transient_technical_logs',
      label: 'Transient Technical & Non-Compliance Diagnostics',
      ref: 'PRD 21.03 (Suggested default: 90 days)',
      days: 90,
      notes: 'Preserves security, permission, deletion, and rights audit entries.',
    },
    {
      key: 'unqualified_prospects',
      label: 'Disqualified / Spam / Out-of-Area Prospect Inquiries',
      ref: 'PRD 21.03 (Suggested default: 365 days / 12 months before review)',
      days: 365,
      notes: 'Excludes valid customers, active inquiries, and records under legal hold.',
    },
    {
      key: 'recruiting_applicants_and_resumes',
      label: 'Applicant Records, Notes & Resumes (Recruiting Policy)',
      ref: 'PRD 17.09 & 21.03 (Unspecified — MUST be explicitly approved by Client & Legal)',
      days: null,
      notes: 'BLOCKED until client/HR/legal establishes exact applicant retention days and approves.',
    },
  ];
  const stmt = db.prepare(
    `INSERT OR IGNORE INTO retention_policies (policy_key, label, prd_reference, retention_days, approved_by_client, notes, updated_at)
     VALUES (?, ?, ?, ?, 0, ?, ?)`
  );
  for (const d of defaults) {
    await stmt.run(d.key, d.label, d.ref, d.days, d.notes, nowIso);
  }
}

async function ensureColumn(db, table, column, definition) {
  if (db.dialect === 'postgres') {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${definition};`);
    return;
  }
  const cols = await db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
  }
}
