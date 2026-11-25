import path from 'node:path';
import { CONSENT_VERSION, ENV, PRIVACY_NOTICE_VERSION, SERVICE_FAMILIES, STORAGE_PATHS, UPLOAD_LIMITS } from '../config.js';
import { generateUuid, sha256Hex, signHmac, verifyHmac } from '../lib/crypto.js';
import { processPrivateDocumentUploadAsync } from '../lib/media-processor.js';
import { parseRequestBody } from '../lib/multipart.js';
import { normalizePhone, validateApplicationPayload, validateInquiryPayload, validateServiceRequestPayload } from '../lib/validation.js';
import { addBusinessDaysPhoenix } from '../lib/time.js';
import { checkRateLimit } from '../services/auth.js';
import { recordAnalyticsEvent } from '../services/analytics.js';
import { processDeliveryQueues, scheduleBackgroundWork } from '../services/delivery-worker.js';
import { createObjectStore } from '../services/object-store.js';

function createSignedUploadToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = signHmac(encoded, ENV.SESSION_SECRET);
  return `${encoded}.${sig}`;
}

function verifySignedUploadToken(token, expectedPurpose) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [encoded, sig] = token.split('.');
  if (!verifyHmac(encoded, sig, ENV.SESSION_SECRET)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!parsed || parsed.purpose !== expectedPurpose) return null;
    if (!parsed.expiresAt || Number(parsed.expiresAt) < Date.now()) return null;
    if (!parsed.stagingKey || !String(parsed.stagingKey).startsWith(`public/${expectedPurpose}/`)) return null;
    return parsed;
  } catch {
    return null;
  }
}

// Simulated durable storage failure hook for staging acceptance testing (FORM-05 / HIRE-05)
let simulateStorageFailure = false;
export function setSimulateStorageFailure(enabled) {
  simulateStorageFailure = Boolean(enabled);
}
export function getSimulateStorageFailure() {
  return simulateStorageFailure;
}

function sendJson(res, status, data, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(JSON.stringify(data));
}

function prefersHtmlRedirect(req) {
  const accept = String(req.headers.accept || '');
  const ct = String(req.headers['content-type'] || '');
  return accept.includes('text/html') && !accept.includes('application/json') && !ct.includes('application/json');
}

function sendFormOutcome(req, res, status, data, headers = {}) {
  if (!prefersHtmlRedirect(req)) {
    sendJson(res, status, data, headers);
    return;
  }
  if (data.ok && data.redirect_url) {
    res.writeHead(303, { Location: data.redirect_url, 'Cache-Control': 'no-store', ...headers });
    res.end();
    return;
  }
  const errList = data.errors
    ? `<ul>${Object.values(data.errors).map((m) => `<li>${String(m).replace(/</g, '&lt;')}</li>`).join('')}</ul>`
    : '';
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Submission Notice | Service Maintenance</title><link rel="stylesheet" href="/css/tokens.css"><link rel="stylesheet" href="/css/main.css"></head><body><main class="section"><div class="container"><h1>Submission Notice</h1><p>${String(data.message || 'Please check your entries.').replace(/</g, '&lt;')}</p>${errList}<p>Use your browser Back button to keep your entries, or call <a href="tel:+14804239196">(480) 423-9196</a>.</p><p><a href="/contact/" class="btn btn--secondary">Contact options</a></p></div></main></body></html>`
  );
}

function resolveRouting(serviceFamily) {
  const found = SERVICE_FAMILIES.find((s) => s.id === serviceFamily);
  if (!found) return { queue: 'general_monitored', owner: 'Operations Administrator' };
  if (found.queue === 'day_porter_sales') return { queue: 'day_porter_sales', owner: 'Day Porter Manager / Sales' };
  if (found.queue === 'operations_admin') return { queue: 'operations_admin', owner: 'Operations Administrator' };
  if (found.queue === 'sales_estimating') return { queue: 'sales_estimating', owner: 'Sales / Estimating Queue' };
  return { queue: 'general_monitored', owner: 'Operations Administrator' };
}

export async function handlePublicApi(req, res, db, urlObj, storagePaths = STORAGE_PATHS) {
  const pathname = urlObj.pathname;
  const ip = req.socket?.remoteAddress || 'unknown';

  // 1. Consent Preferences
  if (pathname === '/api/consent' && req.method === 'POST') {
    const { fields } = await parseRequestBody(req, 64 * 1024);
    const choice = fields.consent === 'analytics_accepted' ? 'analytics_accepted' : 'essential_only';
    const isHttps = ENV.BASE_URL.startsWith('https://');
    const cookie = `sm_consent=${choice}; Path=/; SameSite=Lax; Max-Age=${180 * 86400}${isHttps ? '; Secure' : ''}`;
    sendJson(res, 200, { ok: true, consent: choice, version: CONSENT_VERSION }, { 'Set-Cookie': cookie });
    return true;
  }

  // 2. First-Party PII-Scrubbed Analytics Event Collector
  if (pathname === '/api/analytics/event' && req.method === 'POST') {
    const { fields } = await parseRequestBody(req, 64 * 1024);
    const result = await recordAnalyticsEvent(db, fields);
    sendJson(res, result.ok ? 202 : 400, result);
    return true;
  }

  // 2b. Direct Presigned Upload Request (Supports > 4.5 MB attachments/resumes on Vercel via S3/Neon Object Storage)
  if (pathname === '/api/uploads/presign' && req.method === 'POST') {
    const rl = checkRateLimit(`presign:${ip}`, 30, 60_000);
    if (!rl.allowed) {
      sendJson(res, 429, { ok: false, message: 'Too many upload requests. Please wait a moment.' }, { 'Retry-After': String(rl.retryAfterSec) });
      return true;
    }
    const { fields } = await parseRequestBody(req, 64 * 1024);
    const purpose = fields.purpose === 'resume' ? 'resume' : 'inquiry';
    const items = Array.isArray(fields.files) ? fields.files : [];
    const limits = purpose === 'resume' ? UPLOAD_LIMITS.resume : UPLOAD_LIMITS.inquiry;

    if (items.length === 0 || items.length > limits.maxFiles) {
      sendJson(res, 422, { ok: false, message: `Select between 1 and ${limits.maxFiles} file(s).` });
      return true;
    }
    const totalBytes = items.reduce((s, f) => s + Number(f.size || 0), 0);
    if (limits.maxTotalBytes && totalBytes > limits.maxTotalBytes) {
      sendJson(res, 413, { ok: false, message: 'Total attachments exceed the 25 MB limit.' });
      return true;
    }

    const store = createObjectStore(storagePaths);
    if (store.mode !== 's3') {
      sendJson(res, 200, { ok: true, mode: 'direct_multipart', uploads: [] });
      return true;
    }

    const uploads = [];
    for (const f of items) {
      const byteSize = Number(f.size || 0);
      const mime = String(f.type || 'application/octet-stream').toLowerCase();
      const origName = path.basename(String(f.name || 'document')).slice(0, 140);
      if (byteSize <= 0 || byteSize > limits.maxFileBytes) {
        sendJson(res, 413, { ok: false, message: `${origName}: exceeds ${(limits.maxFileBytes / (1024 * 1024)).toFixed(0)} MB per-file limit.` });
        return true;
      }
      if (!limits.allowedTypes.includes(mime)) {
        sendJson(res, 422, { ok: false, message: `${origName}: unsupported file type.` });
        return true;
      }
      const stagingKey = `public/${purpose}/${generateUuid()}-${origName.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      const presigned = await store.createPresignedUpload({ key: stagingKey, contentType: mime, expiresIn: 600 });
      const upload_token = createSignedUploadToken({
        purpose,
        stagingKey: presigned.stagingKey,
        originalName: origName,
        maxBytes: limits.maxFileBytes,
        expiresAt: Date.now() + 600_000,
      });
      uploads.push({ ...presigned, originalName: origName, upload_token });
    }

    sendJson(res, 200, { ok: true, mode: 's3_presigned_put', uploads });
    return true;
  }

  // 3. New Commercial Inquiry Submission (POST /api/inquiries)
  if (pathname === '/api/inquiries' && req.method === 'POST') {
    const rl = checkRateLimit(`inq:${ip}`, 30, 60_000);
    if (!rl.allowed) {
      sendJson(res, 429, { ok: false, message: 'Too many requests. Please wait a moment or call our office.' }, { 'Retry-After': String(rl.retryAfterSec) });
      return true;
    }

    let parsed;
    try {
      parsed = await parseRequestBody(req, UPLOAD_LIMITS.inquiry.maxTotalBytes + 1024 * 1024);
    } catch (err) {
      if (err.statusCode === 413) {
        sendJson(res, 413, { ok: false, message: 'Uploaded files exceed the 25 MB total limit. Submit without files and we will provide a secure link.' });
        return true;
      }
      sendJson(res, 400, { ok: false, message: 'Malformed request body.' });
      return true;
    }

    const { fields, files } = parsed;
    const idempotencyKey = String(req.headers['idempotency-key'] || fields.idempotency_key || generateUuid()).trim().slice(0, 100);
    const validation = validateInquiryPayload(fields);

    if (!validation.valid) {
      sendFormOutcome(req, res, 422, { ok: false, errors: validation.errors, message: 'Please correct the highlighted fields.' });
      return true;
    }

    // Validate attachments limits (max 5 files, 10MB each, 25MB total)
    const uploadFiles = files.filter((f) => f.buffer && f.buffer.length > 0);
    if (uploadFiles.length > UPLOAD_LIMITS.inquiry.maxFiles) {
      sendJson(res, 413, { ok: false, message: 'Up to 5 attachments are permitted per inquiry.' });
      return true;
    }
    const totalAttachBytes = uploadFiles.reduce((s, f) => s + f.buffer.length, 0);
    if (totalAttachBytes > UPLOAD_LIMITS.inquiry.maxTotalBytes) {
      sendJson(res, 413, { ok: false, message: 'Total attachments exceed the 25 MB limit.' });
      return true;
    }

    const payloadHash = sha256Hex(JSON.stringify({ kind: 'new_business', data: validation.data }));

    // Check idempotency key BEFORE mutating
    const existing = await db.prepare('SELECT * FROM inquiries WHERE idempotency_key = ?').get(idempotencyKey);
    if (existing) {
      if (existing.payload_hash === payloadHash) {
        sendJson(res, 200, {
          ok: true,
          status: 'accepted_idempotent_replay',
          inquiry_id: existing.inquiry_id,
          redirect_url: `/thank-you/?ref=${encodeURIComponent(existing.inquiry_id)}&kind=new_business`,
        });
        return true;
      }
      sendJson(res, 409, {
        ok: false,
        code: 'idempotency_conflict',
        message: 'This submission token was already used for a different request. Refresh or submit with a new request.',
      });
      return true;
    }

    // Simulated durable storage outage check (FORM-05)
    if (simulateStorageFailure) {
      sendJson(res, 503, {
        ok: false,
        code: 'storage_unavailable',
        message: 'Temporary storage interruption prevented saving your request. Your form entries remain intact; please retry or call (480) 423-9196.',
      });
      return true;
    }

    // Process optional attachments securely (direct multipart OR verified staged S3 uploads)
    let stagedTokens = [];
    if (fields.staged_uploads) {
      try {
        stagedTokens = typeof fields.staged_uploads === 'string' ? JSON.parse(fields.staged_uploads) : fields.staged_uploads;
      } catch {
        stagedTokens = [];
      }
      if (!Array.isArray(stagedTokens)) stagedTokens = [];
    }
    if (uploadFiles.length + stagedTokens.length > UPLOAD_LIMITS.inquiry.maxFiles) {
      sendJson(res, 413, { ok: false, message: 'Up to 5 attachments are permitted per inquiry.' });
      return true;
    }

    const processedFiles = [];
    for (const f of uploadFiles) {
      const resFile = await processPrivateDocumentUploadAsync({
        buffer: f.buffer,
        originalName: f.originalName,
        allowedTypes: UPLOAD_LIMITS.inquiry.allowedTypes,
        maxBytes: UPLOAD_LIMITS.inquiry.maxFileBytes,
        destDir: storagePaths.quarantine,
        storagePaths,
        area: 'quarantine',
      });
      if (!resFile.ok) {
        sendJson(res, 422, {
          ok: false,
          errors: { attachments: `${f.originalName}: ${resFile.message}` },
          message: `Attachment rejected (${f.originalName}): ${resFile.message} You may remove the file and submit without it.`,
        });
        return true;
      }
      processedFiles.push(resFile.file);
    }

    if (stagedTokens.length > 0) {
      const store = createObjectStore(storagePaths);
      let stagedTotalBytes = totalAttachBytes;
      for (const tok of stagedTokens) {
        const verified = verifySignedUploadToken(tok, 'inquiry');
        if (!verified) {
          sendJson(res, 422, { ok: false, message: 'Invalid or expired attachment upload token. Please re-attach and submit.' });
          return true;
        }
        try {
          const buf = await store.getObjectBuffer({ area: 'staging', key: verified.stagingKey });
          if (!buf) {
            sendJson(res, 422, { ok: false, message: `Uploaded attachment (${verified.originalName}) missing from staging.` });
            return true;
          }
          stagedTotalBytes += buf.length;
          if (stagedTotalBytes > UPLOAD_LIMITS.inquiry.maxTotalBytes) {
            sendJson(res, 413, { ok: false, message: 'Total attachments exceed the 25 MB limit.' });
            return true;
          }
          const resFile = await processPrivateDocumentUploadAsync({
            buffer: buf,
            originalName: verified.originalName,
            allowedTypes: UPLOAD_LIMITS.inquiry.allowedTypes,
            maxBytes: UPLOAD_LIMITS.inquiry.maxFileBytes,
            destDir: storagePaths.quarantine,
            storagePaths,
            area: 'quarantine',
          });
          if (!resFile.ok) {
            sendJson(res, 422, {
              ok: false,
              errors: { attachments: `${verified.originalName}: ${resFile.message}` },
              message: `Attachment rejected (${verified.originalName}): ${resFile.message}`,
            });
            return true;
          }
          processedFiles.push(resFile.file);
        } finally {
          await store.deleteObject({ area: 'staging', key: verified.stagingKey });
        }
      }
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const inquiryId = generateUuid();
    const routing = resolveRouting(validation.data.service_needed);
    const isHoneypotSpam = Boolean(String(fields.website_url_hp || '').trim());
    const classification = isHoneypotSpam ? 'spam' : 'valid';

    // Attribution separation: acquisition UTMs vs on-site campaign
    let acqUtms = {};
    let onSiteCamp = null;
    try { acqUtms = JSON.parse(fields.acquisition_utms_json || '{}'); } catch { acqUtms = {}; }
    try { onSiteCamp = fields.on_site_campaign_json ? JSON.parse(fields.on_site_campaign_json) : null; } catch { onSiteCamp = null; }

    const attribution = {
      landing_page: String(fields.landing_page || '/').slice(0, 160),
      submitting_page: String(fields.submitting_page || '/request-proposal/').slice(0, 160),
      acquisition_utms: acqUtms,
      on_site_campaign: onSiteCamp,
      privacy_notice_version: PRIVACY_NOTICE_VERSION,
      consent_recorded_at: nowIso,
    };

    try {
      await db.transaction(async (tx) => {
        // Account lookup/create by exact organization name (never merge contacts by domain alone!)
        let account = await tx.prepare('SELECT * FROM accounts WHERE LOWER(organization_name) = LOWER(?)').get(validation.data.company);
        if (!account) {
          account = { account_id: generateUuid(), organization_name: validation.data.company };
          await tx.prepare('INSERT INTO accounts (account_id, organization_name, verified_ownership, created_at) VALUES (?, ?, 0, ?)').run(
            account.account_id,
            account.organization_name,
            nowIso
          );
        }

        // Contact lookup by exact validated email or normalized phone
        const normPhone = normalizePhone(validation.data.telephone);
        let contact = null;
        if (validation.data.email) {
          contact = await tx.prepare('SELECT * FROM contacts WHERE account_id = ? AND email = ?').get(account.account_id, validation.data.email);
        } else if (normPhone) {
          contact = await tx.prepare('SELECT * FROM contacts WHERE account_id = ? AND phone = ?').get(account.account_id, normPhone);
        }

        if (!contact) {
          contact = { contact_id: generateUuid() };
          await tx.prepare(
            `INSERT INTO contacts (contact_id, account_id, name, email, phone, preferred_method, consent_marketing, consent_version, consent_recorded_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            contact.contact_id,
            account.account_id,
            validation.data.name,
            validation.data.email || null,
            normPhone || null,
            validation.data.preferred_contact_method,
            validation.data.marketing_opt_in ? 1 : 0,
            validation.data.marketing_opt_in ? CONSENT_VERSION : null,
            validation.data.marketing_opt_in ? nowIso : null,
            nowIso
          );
        }

        // Property record: DO NOT overwrite an existing property when a contact requests work at a new location!
        let property = await tx
          .prepare('SELECT * FROM properties WHERE account_id = ? AND LOWER(city_or_zip) = LOWER(?) AND property_type = ?')
          .get(account.account_id, validation.data.property_city_or_zip, validation.data.property_type);
        if (!property) {
          property = { property_id: generateUuid() };
          await tx.prepare(
            `INSERT INTO properties (property_id, account_id, site_label, city_or_zip, property_type, created_at)
             VALUES (?, ?, ?, ?, ?, ?)`
          ).run(
            property.property_id,
            account.account_id,
            validation.data.ti_property_address || validation.data.property_city_or_zip,
            validation.data.property_city_or_zip,
            validation.data.property_type,
            nowIso
          );
        }

        const slaTarget = addBusinessDaysPhoenix(now, 1);

        await tx.prepare(
          `INSERT INTO inquiries (
            inquiry_id, idempotency_key, payload_hash, inquiry_kind, classification,
            account_id, contact_id, property_id, service_family, routing_queue,
            assigned_owner, status, payload_json, attribution_json, sla_target_at, received_at, updated_at
          ) VALUES (?, ?, ?, 'new_business', ?, ?, ?, ?, ?, ?, ?, 'received', ?, ?, ?, ?, ?)`
        ).run(
          inquiryId,
          idempotencyKey,
          payloadHash,
          classification,
          account.account_id,
          contact.contact_id,
          property.property_id,
          validation.data.service_needed,
          routing.queue,
          routing.owner,
          JSON.stringify(validation.data),
          JSON.stringify(attribution),
          slaTarget,
          nowIso,
          nowIso
        );

        for (const pf of processedFiles) {
          await tx.prepare(
            `INSERT INTO inquiry_attachments (attachment_id, inquiry_id, object_id, storage_key, original_name, mime_type, byte_size, scan_state, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(generateUuid(), inquiryId, pf.object_id, pf.storage_key, pf.original_name, pf.mime_type, pf.byte_size, pf.scan_state, nowIso);
        }

        if (classification === 'valid') {
          await tx.prepare(
            `INSERT INTO crm_delivery_queue (delivery_id, inquiry_id, target_system, status, attempts, max_attempts, next_attempt_at, created_at, updated_at)
             VALUES (?, ?, 'freshsales', 'pending', 0, 3, ?, ?, ?)`
          ).run(generateUuid(), inquiryId, nowIso, nowIso, nowIso);

          await tx.prepare(
            `INSERT INTO notification_queue (notification_id, domain, reference_id, recipient_role, recipient_target, reply_to, subject, body_summary, status, attempts, next_attempt_at, created_at, updated_at)
             VALUES (?, 'commercial', ?, ?, 'sales@smiaz.com', ?, ?, ?, 'pending', 0, ?, ?, ?)`
          ).run(
            generateUuid(),
            inquiryId,
            routing.owner,
            validation.data.email || null,
            `New commercial inquiry (${validation.data.service_needed}) — ${inquiryId.slice(0, 8)}`,
            `Inquiry ${inquiryId} for ${validation.data.property_city_or_zip} routed to ${routing.queue}. Review in Freshsales/Dashboard.`,
            nowIso,
            nowIso,
            nowIso
          );

          // Backend-confirmed generate_lead event (once per inquiry_id!)
          await recordAnalyticsEvent(tx, {
            event_name: 'generate_lead',
            page_type: 'request_proposal',
            service_id: validation.data.service_needed,
            on_site_campaign_id: onSiteCamp?.on_site_campaign_id || null,
            placement_id: onSiteCamp?.placement_id || null,
            content_revision: onSiteCamp?.content_revision || null,
            acquisition_utm_source: acqUtms.utm_source || null,
            acquisition_utm_medium: acqUtms.utm_medium || null,
            acquisition_utm_campaign: acqUtms.utm_campaign || null,
            acquisition_utm_content: acqUtms.utm_content || null,
            consent_mode: 'server_confirmed',
          });
        }
      });
    } catch (err) {
      sendJson(res, 503, { ok: false, code: 'storage_unavailable', message: 'Unable to store request right now. Please call (480) 423-9196.' });
      return true;
    }

    // Trigger immediate async worker pass (uses @vercel/functions waitUntil when on Vercel)
    scheduleBackgroundWork(processDeliveryQueues(db));

    sendFormOutcome(req, res, 201, {
      ok: true,
      status: 'accepted',
      inquiry_id: inquiryId,
      redirect_url: `/thank-you/?ref=${encodeURIComponent(inquiryId)}&kind=new_business`,
    });
    return true;
  }

  // 4. Existing Client Service Request (POST /api/service-requests)
  if (pathname === '/api/service-requests' && req.method === 'POST') {
    const rl = checkRateLimit(`sr:${ip}`, 30, 60_000);
    if (!rl.allowed) {
      sendJson(res, 429, { ok: false, message: 'Too many requests.' }, { 'Retry-After': String(rl.retryAfterSec) });
      return true;
    }

    const { fields } = await parseRequestBody(req, 512 * 1024);
    const idempotencyKey = String(req.headers['idempotency-key'] || fields.idempotency_key || generateUuid()).trim().slice(0, 100);
    const validation = validateServiceRequestPayload(fields);
    if (!validation.valid) {
      sendJson(res, 422, { ok: false, errors: validation.errors, message: 'Please review the highlighted fields.' });
      return true;
    }

    const payloadHash = sha256Hex(JSON.stringify({ kind: 'existing_service', data: validation.data }));
    const existing = await db.prepare('SELECT * FROM inquiries WHERE idempotency_key = ?').get(idempotencyKey);
    if (existing) {
      if (existing.payload_hash === payloadHash) {
        sendJson(res, 200, {
          ok: true,
          status: 'accepted_idempotent_replay',
          inquiry_id: existing.inquiry_id,
          redirect_url: `/thank-you/?ref=${encodeURIComponent(existing.inquiry_id)}&kind=existing_service`,
        });
        return true;
      }
      sendJson(res, 409, { ok: false, code: 'idempotency_conflict', message: 'Duplicate token used with modified payload.' });
      return true;
    }

    if (simulateStorageFailure) {
      sendJson(res, 503, { ok: false, code: 'storage_unavailable', message: 'Temporary storage error. Call (480) 423-9196.' });
      return true;
    }

    const nowIso = new Date().toISOString();
    const inquiryId = generateUuid();

    try {
      await db.transaction(async (tx) => {
        let account = await tx.prepare('SELECT * FROM accounts WHERE LOWER(organization_name) = LOWER(?)').get(validation.data.company);
        if (!account) {
          account = { account_id: generateUuid() };
          await tx.prepare('INSERT INTO accounts (account_id, organization_name, verified_ownership, created_at) VALUES (?, ?, 1, ?)').run(
            account.account_id,
            validation.data.company,
            nowIso
          );
        }

        const normPhone = normalizePhone(validation.data.telephone);
        const contactId = generateUuid();
        await tx.prepare(
          `INSERT INTO contacts (contact_id, account_id, name, email, phone, preferred_method, consent_marketing, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 0, ?)`
        ).run(contactId, account.account_id, validation.data.name, validation.data.email || null, normPhone || null, validation.data.preferred_contact_method, nowIso);

        const propId = generateUuid();
        await tx.prepare(`INSERT INTO properties (property_id, account_id, site_label, city_or_zip, property_type, created_at) VALUES (?, ?, ?, ?, 'commercial', ?)`).run(
          propId,
          account.account_id,
          validation.data.property,
          validation.data.property,
          nowIso
        );

        await tx.prepare(
          `INSERT INTO inquiries (
            inquiry_id, idempotency_key, payload_hash, inquiry_kind, classification,
            account_id, contact_id, property_id, service_family, routing_queue,
            assigned_owner, status, payload_json, attribution_json, received_at, updated_at
          ) VALUES (?, ?, ?, 'existing_service', 'existing_service', ?, ?, ?, 'existing-service', 'service_operations', 'Operations Queue', 'received', ?, '{}', ?, ?)`
        ).run(inquiryId, idempotencyKey, payloadHash, account.account_id, contactId, propId, JSON.stringify(validation.data), nowIso, nowIso);

        await tx.prepare(
          `INSERT INTO crm_delivery_queue (delivery_id, inquiry_id, target_system, status, attempts, max_attempts, next_attempt_at, created_at, updated_at)
           VALUES (?, ?, 'freshsales', 'pending', 0, 3, ?, ?, ?)`
        ).run(generateUuid(), inquiryId, nowIso, nowIso, nowIso);

        await tx.prepare(
          `INSERT INTO notification_queue (notification_id, domain, reference_id, recipient_role, recipient_target, reply_to, subject, body_summary, status, attempts, next_attempt_at, created_at, updated_at)
           VALUES (?, 'commercial', ?, 'Operations Queue', 'operations@smiaz.com', ?, ?, ?, 'pending', 0, ?, ?, ?)`
        ).run(
          generateUuid(),
          inquiryId,
          validation.data.email || null,
          `Existing Client Service Request (${validation.data.urgency}) — ${inquiryId.slice(0, 8)}`,
          `Property: ${validation.data.property}. Ref: ${validation.data.reference_number || 'None'}.`,
          nowIso,
          nowIso,
          nowIso
        );

        await recordAnalyticsEvent(tx, {
          event_name: 'service_request_received',
          page_type: 'request_service',
          service_id: 'existing-service',
          consent_mode: 'server_confirmed',
        });
      });
    } catch {
      sendJson(res, 503, { ok: false, code: 'storage_unavailable', message: 'Storage unavailable. Please call (480) 423-9196.' });
      return true;
    }

    scheduleBackgroundWork(processDeliveryQueues(db));
    sendFormOutcome(req, res, 201, {
      ok: true,
      inquiry_id: inquiryId,
      redirect_url: `/thank-you/?ref=${encodeURIComponent(inquiryId)}&kind=existing_service`,
    });
    return true;
  }

  // 5. Protected Job Application Submission (POST /api/jobs/:slug/apply)
  const applyMatch = pathname.match(/^\/api\/jobs\/([a-z0-9-]+)\/apply$/);
  if (applyMatch && req.method === 'POST') {
    const rl = checkRateLimit(`apply:${ip}`, 20, 60_000);
    if (!rl.allowed) {
      sendJson(res, 429, { ok: false, message: 'Too many requests.' }, { 'Retry-After': String(rl.retryAfterSec) });
      return true;
    }

    let parsed;
    try {
      parsed = await parseRequestBody(req, UPLOAD_LIMITS.resume.maxFileBytes + 512 * 1024);
    } catch (err) {
      if (err.statusCode === 413) {
        sendJson(res, 413, { ok: false, message: 'Resume file exceeds the 10 MB maximum size.' });
        return true;
      }
      sendJson(res, 400, { ok: false, message: 'Invalid form submission.' });
      return true;
    }

    const { fields, files } = parsed;
    const slug = applyMatch[1];
    const idempotencyKey = String(req.headers['idempotency-key'] || fields.idempotency_key || generateUuid()).trim().slice(0, 100);
    const resumeFile = files.find((f) => f.buffer && f.buffer.length > 0) || null;

    const stagedResumeToken = String(fields.staged_resume_token || '').trim();

    // Look up job by slug
    const job = await db.prepare('SELECT * FROM jobs WHERE slug = ?').get(slug);
    if (!job) {
      sendJson(res, 404, { ok: false, code: 'invalid_role', message: 'Position not found.' });
      return true;
    }

    // Validate fields against presented job schema
    const validation = validateApplicationPayload({ ...fields, has_resume: Boolean(resumeFile || stagedResumeToken) }, job);
    if (!validation.valid) {
      sendJson(res, 422, { ok: false, errors: validation.errors, message: 'Please review the highlighted fields.' });
      return true;
    }

    const payloadHash = sha256Hex(JSON.stringify({ slug, reqId: fields.requisition_id, cycleId: fields.opening_cycle_id, data: validation.data }));

    // Idempotency check BEFORE closure check (PRD 17.05: identical retry returns original receipt even if position subsequently closed!)
    const existingApp = await db.prepare('SELECT * FROM applications WHERE idempotency_key = ?').get(idempotencyKey);
    if (existingApp) {
      if (existingApp.payload_hash === payloadHash) {
        const att = await db.prepare('SELECT scan_state FROM application_attachments WHERE application_id = ?').get(existingApp.application_id);
        sendJson(res, 200, {
          ok: true,
          status: 'accepted_idempotent_replay',
          application_id: existingApp.application_id,
          redirect_url: `/application-received/?ref=${encodeURIComponent(existingApp.application_id)}&role=${encodeURIComponent(job.title)}&att=${encodeURIComponent(att?.scan_state || '')}`,
        });
        return true;
      }
      sendJson(res, 409, { ok: false, code: 'idempotency_conflict', message: 'Submission token conflict with modified payload.' });
      return true;
    }

    if (simulateStorageFailure) {
      sendJson(res, 503, { ok: false, code: 'storage_unavailable', message: 'Unable to save application right now. Please try again or contact recruiting.' });
      return true;
    }

    // Resume file validation & private quarantine storage (never in public media!)
    let processedResume = null;
    if (resumeFile) {
      const resCheck = await processPrivateDocumentUploadAsync({
        buffer: resumeFile.buffer,
        originalName: resumeFile.originalName,
        allowedTypes: UPLOAD_LIMITS.resume.allowedTypes,
        maxBytes: UPLOAD_LIMITS.resume.maxFileBytes,
        destDir: storagePaths.resumes,
        storagePaths,
        area: 'resumes',
      });
      if (!resCheck.ok) {
        sendJson(res, 422, {
          ok: false,
          errors: { resume: `${resCheck.message} You may submit using the relevant-experience field without attaching a resume.` },
          message: resCheck.message,
        });
        return true;
      }
      processedResume = resCheck.file;
    } else if (stagedResumeToken) {
      const verified = verifySignedUploadToken(stagedResumeToken, 'resume');
      if (!verified) {
        sendJson(res, 422, { ok: false, message: 'Invalid or expired resume upload token. Please re-attach your resume.' });
        return true;
      }
      const store = createObjectStore(storagePaths);
      try {
        const buf = await store.getObjectBuffer({ area: 'staging', key: verified.stagingKey });
        if (!buf) {
          sendJson(res, 422, { ok: false, message: 'Staged resume missing. Please retry uploading.' });
          return true;
        }
        const resCheck = await processPrivateDocumentUploadAsync({
          buffer: buf,
          originalName: verified.originalName,
          allowedTypes: UPLOAD_LIMITS.resume.allowedTypes,
          maxBytes: UPLOAD_LIMITS.resume.maxFileBytes,
          destDir: storagePaths.resumes,
          storagePaths,
          area: 'resumes',
        });
        if (!resCheck.ok) {
          sendJson(res, 422, {
            ok: false,
            errors: { resume: `${resCheck.message} You may submit using the relevant-experience field without attaching a resume.` },
            message: resCheck.message,
          });
          return true;
        }
        processedResume = resCheck.file;
      } finally {
        await store.deleteObject({ area: 'staging', key: verified.stagingKey });
      }
    }

    const nowIso = new Date().toISOString();
    const applicationId = generateUuid();
    const submittedReqId = String(fields.requisition_id || '');
    const submittedCycleId = String(fields.opening_cycle_id || '');

    // Atomic transaction checking exact requisition_id + opening_cycle_id + Open state (HIRE-03 / HIRE-04)
    try {
      await db.transaction(async (tx) => {
        const liveJob = await tx.prepare('SELECT * FROM jobs WHERE slug = ?').get(slug);
        const nowMs = Date.now();
        const withinWindow =
          liveJob &&
          (!liveJob.publish_at || new Date(liveJob.publish_at).getTime() <= nowMs) &&
          (!liveJob.close_at || new Date(liveJob.close_at).getTime() > nowMs);

        if (
          !liveJob ||
          liveJob.status !== 'Open' ||
          !withinWindow ||
          (submittedReqId && submittedReqId !== liveJob.requisition_id) ||
          (submittedCycleId && submittedCycleId !== liveJob.opening_cycle_id)
        ) {
          const closedErr = new Error('job_closed');
          closedErr.isJobClosed = true;
          throw closedErr;
        }

        const normEmail = validation.data.email || null;
        const normPhone = normalizePhone(validation.data.telephone) || null;

        // Flag possible duplicates for authorized staff review (never disclose to unauthenticated applicant!)
        let duplicateOf = null;
        if (normEmail || normPhone) {
          const dupConds = [];
          const dupParams = [liveJob.requisition_id];
          if (normEmail) {
            dupConds.push('p.email_normalized = ?');
            dupParams.push(normEmail);
          }
          if (normPhone) {
            dupConds.push('p.phone_normalized = ?');
            dupParams.push(normPhone);
          }
          const dup = await tx
            .prepare(
              `SELECT a.application_id
               FROM applications a
               JOIN applicants p ON p.applicant_id = a.applicant_id
               WHERE a.requisition_id = ? AND (${dupConds.join(' OR ')})
               LIMIT 1`
            )
            .get(...dupParams);
          if (dup) duplicateOf = dup.application_id;
        }

        const applicantId = generateUuid();
        await tx.prepare(
          `INSERT INTO applicants (applicant_id, name, email_normalized, phone_normalized, preferred_method, city_or_zip, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(applicantId, validation.data.name, normEmail, normPhone, validation.data.preferred_contact_method, validation.data.city_or_zip, nowIso);

        // Immutable submission snapshot (preserving exact presented job title, pay, questions, notice)
        const snapshot = {
          requisition_id: liveJob.requisition_id,
          opening_cycle_id: liveJob.opening_cycle_id,
          form_revision: Number(fields.form_revision || liveJob.form_revision),
          job_title: liveJob.title,
          work_area: liveJob.work_area,
          pay_info: liveJob.pay_info,
          benefits_info: liveJob.benefits_info,
          questions_presented: JSON.parse(liveJob.questions_json || '[]'),
          privacy_notice_version: PRIVACY_NOTICE_VERSION,
        };

        const answersPayload = {
          relevant_experience: validation.data.relevant_experience,
          availability: validation.data.availability,
          role_questions: validation.data.answers,
        };

        const followUpDue = addBusinessDaysPhoenix(new Date(), 1);

        await tx.prepare(
          `INSERT INTO applications (
            application_id, idempotency_key, payload_hash, submission_token_hash,
            applicant_id, requisition_id, opening_cycle_id, form_revision, stage,
            snapshot_json, answers_json, source_attribution_json,
            privacy_notice_version, privacy_ack_at, possible_duplicate_of, follow_up_due_at,
            received_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Received', ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(
          applicationId,
          idempotencyKey,
          payloadHash,
          sha256Hex(idempotencyKey),
          applicantId,
          liveJob.requisition_id,
          liveJob.opening_cycle_id,
          snapshot.form_revision,
          JSON.stringify(snapshot),
          JSON.stringify(answersPayload),
          JSON.stringify({ landing_page: String(fields.landing_page || '').slice(0, 160) }),
          PRIVACY_NOTICE_VERSION,
          nowIso,
          duplicateOf,
          followUpDue,
          nowIso,
          nowIso
        );

        if (processedResume) {
          await tx.prepare(
            `INSERT INTO application_attachments (
              attachment_id, application_id, object_id, storage_key, original_display_name,
              mime_type, byte_size, scan_state, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).run(
            generateUuid(),
            applicationId,
            processedResume.object_id,
            processedResume.storage_key,
            processedResume.original_name,
            processedResume.mime_type,
            processedResume.byte_size,
            processedResume.scan_state,
            nowIso
          );
        }

        // Notify assigned Hiring Owner (never include applicant resume or answers in email notification!)
        const owner = await tx.prepare('SELECT email FROM users WHERE user_id = ?').get(liveJob.hiring_owner_id);
        await tx.prepare(
          `INSERT INTO notification_queue (notification_id, domain, reference_id, recipient_role, recipient_target, subject, body_summary, status, attempts, next_attempt_at, created_at, updated_at)
           VALUES (?, 'hiring', ?, 'Hiring Owner', ?, ?, ?, 'pending', 0, ?, ?, ?)`
        ).run(
          generateUuid(),
          applicationId,
          owner?.email || 'hiring@smiaz.com',
          `New application received for ${liveJob.title} (${applicationId.slice(0, 8)})`,
          `Role: ${liveJob.title} (${liveJob.requisition_id}). Review in protected staff hiring workspace.`,
          nowIso,
          nowIso,
          nowIso
        );

        // Non-identifying operational recruitment count (never generate_lead!)
        await recordAnalyticsEvent(tx, {
          event_name: 'application_received',
          page_type: 'job_application',
          job_id: liveJob.requisition_id,
          consent_mode: 'server_confirmed',
        });
      });
    } catch (err) {
      if (err?.isJobClosed) {
        sendJson(res, 409, {
          ok: false,
          code: 'job_closed',
          message: 'This position has closed or its opening cycle changed while the form was open. Your entries have been preserved.',
        });
        return true;
      }
      sendJson(res, 503, { ok: false, code: 'storage_unavailable', message: 'Unable to record application right now.' });
      return true;
    }

    scheduleBackgroundWork(processDeliveryQueues(db));

    sendFormOutcome(req, res, 201, {
      ok: true,
      application_id: applicationId,
      attachment_state: processedResume?.scan_state || 'none',
      redirect_url: `/application-received/?ref=${encodeURIComponent(applicationId)}&role=${encodeURIComponent(job.title)}&att=${encodeURIComponent(processedResume?.scan_state || '')}`,
    });
    return true;
  }

  return false;
}
