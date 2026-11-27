import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import sharp from 'sharp';
import { generateTotpCode } from '../src/lib/crypto.js';
import { DEMO_USERS } from '../src/db/seed.js';
import { createAppServer } from '../src/server.js';
import { setSimulateStorageFailure } from '../src/routes/api-public.js';
import { setHeicConverter } from '../src/lib/media-processor.js';
import { setCrmFaultMode, setCrmFetch } from '../src/services/crm-adapter.js';
import { clearMailerTokenCache, setMailerFetch } from '../src/services/mailer.js';
import { runScheduleEvaluation } from '../src/services/campaign-engine.js';
import { processDeliveryQueues } from '../src/services/delivery-worker.js';
import { setCustomMalwareScanner } from '../src/services/malware-scanner.js';
import { setCustomS3Client } from '../src/services/object-store.js';
import { S3Client } from '@aws-sdk/client-s3';

function makePngBytes(width = 800, height = 600, secretText = 'GPS_HIDDEN_EXIF') {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const chunk = (type, data) => {
    const typeBuf = Buffer.from(type, 'ascii');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(zlib.crc32(Buffer.concat([typeBuf, data])) >>> 0, 0);
    return Buffer.concat([len, typeBuf, data, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const rowSize = 1 + width * 3;
  const raw = Buffer.alloc(rowSize * height);
  const idat = zlib.deflateSync(raw);
  return Buffer.concat([
    sig,
    chunk('IHDR', ihdr),
    chunk('tEXt', Buffer.from(`Comment\0${secretText}`, 'ascii')),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const loginCache = new Map();
async function loginAs(baseUrl, email, secretOverride = null) {
  const cacheKey = `${baseUrl}|${email}`;
  if (!secretOverride && loginCache.has(cacheKey)) {
    return loginCache.get(cacheKey);
  }
  const user = DEMO_USERS.find((u) => u.email === email);
  const totp = generateTotpCode(secretOverride || user.totp_secret);
  const body = new URLSearchParams({
    email,
    password: 'SM-Staff-2026!',
    totp_code: totp,
  });
  const res = await fetch(`${baseUrl}/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    redirect: 'manual',
  });
  assert.equal(res.status, 302, `Login failed for ${email}`);
  const cookie = res.headers.get('set-cookie').split(';')[0];
  const dashRes = await fetch(`${baseUrl}/admin/`, { headers: { Cookie: cookie } });
  const html = await dashRes.text();
  const csrfMatch = html.match(/data-csrf="([^"]+)"/);
  const result = { cookie, csrf: csrfMatch ? csrfMatch[1] : '' };
  if (!secretOverride) loginCache.set(cacheKey, result);
  return result;
}

test('Full PRD P0 Acceptance Register Integration Suite', async (t) => {
  const prevDisableS3 = process.env.DISABLE_S3_STORAGE;
  process.env.DISABLE_S3_STORAGE = '1';
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-int-'));
  const dbPath = path.join(tmpDir, 'test.db');
  const storageRoot = path.join(tmpDir, 'storage');
  const { server, db } = await createAppServer({ dbPath, storageRoot, startWorker: false });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  t.after(async () => {
    if (prevDisableS3 === undefined) delete process.env.DISABLE_S3_STORAGE;
    else process.env.DISABLE_S3_STORAGE = prevDisableS3;
    server.close();
    await db.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  await t.test('BRAND/CONTENT/SEO-01..04: Public pages, legacy redirects, sitemap, truthful empty states', async () => {
    const home = await fetch(`${baseUrl}/`);
    assert.equal(home.status, 200);
    const homeHtml = await home.text();
    assert.ok(homeHtml.includes('Commercial maintenance. Carefully managed.'));
    assert.ok(homeHtml.includes('Promptitude Inc.'));
    assert.ok(homeHtml.includes('Our roots date to 1989'));
    assert.ok(homeHtml.includes('(480) 423-9196'));
    assert.equal(homeHtml.includes('lowest turnover'), false);

    // Conditional Building Engineer & Insights are hidden until approved live
    const beRes = await fetch(`${baseUrl}/services/building-engineer/`);
    assert.equal(beRes.status, 404);
    const insRes = await fetch(`${baseUrl}/insights/`);
    assert.equal(insRes.status, 404);

    // Projects and Careers truthful empty states
    const projRes = await fetch(`${baseUrl}/projects/`);
    assert.equal(projRes.status, 200);
    assert.ok((await projRes.text()).includes('Approved project case studies are being prepared'));

    const carRes = await fetch(`${baseUrl}/careers/`);
    assert.equal(carRes.status, 200);
    assert.ok((await carRes.text()).includes('No current open positions'));

    // Capabilities PDF
    const pdfRes = await fetch(`${baseUrl}/credentials/capabilities.pdf`);
    assert.equal(pdfRes.status, 200);
    assert.equal(pdfRes.headers.get('content-type'), 'application/pdf');

    // Legacy 301 Redirects
    for (const [oldPath, expectedDest] of [
      ['/services', '/services/'],
      ['/building-engineering', '/services/commercial-maintenance/'],
      ['/day-porter-services', '/services/day-porter/'],
      ['/special-projects', '/services/tenant-move-outs/'],
      ['/tenant-improvements-1', '/services/tenant-improvements/'],
      ['/contact-us', '/contact/'],
    ]) {
      const r = await fetch(`${baseUrl}${oldPath}`, { redirect: 'manual' });
      assert.equal(r.status, 301);
      assert.equal(r.headers.get('location'), expectedDest);
    }

    // Sitemap excludes admin, thank-you, and drafts
    const smRes = await fetch(`${baseUrl}/sitemap.xml`);
    assert.equal(smRes.status, 200);
    const smXml = await smRes.text();
    assert.ok(smXml.includes('/services/day-porter/'));
    assert.equal(smXml.includes('/admin/'), false);
    assert.equal(smXml.includes('/thank-you/'), false);
    assert.equal(smXml.includes('/services/building-engineer/'), false);
  });

  await t.test('FORM-01..05 & CRM-01..03: Inquiry durability, idempotency, CRM outage replay & PII-free analytics', async () => {
    const idempKey = 'test-idemp-key-001';
    const payload = {
      idempotency_key: idempKey,
      name: 'Alex Rivera',
      company: 'Desert Logistics LLC',
      preferred_contact_method: 'email',
      email: 'alex@gmail.com',
      service_needed: 'warehouse-repairs',
      property_city_or_zip: 'Phoenix, AZ 85043',
      description: 'Torn scrim near dock 4.',
    };

    // Simulate CRM outage during submission -> Inquiry MUST still persist (201)!
    setCrmFaultMode('outage_503');
    const res1 = await fetch(`${baseUrl}/api/inquiries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    assert.equal(res1.status, 201);
    const j1 = await res1.json();
    assert.ok(j1.inquiry_id);

    // Exhaust retries to verify failed_review queue
    for (let i = 0; i < 4; i++) {
      await processDeliveryQueues(db, new Date(Date.now() + (i + 1) * 120_000));
    }
    const queueRow = await db.prepare('SELECT * FROM crm_delivery_queue WHERE inquiry_id = ?').get(j1.inquiry_id);
    assert.equal(queueRow.status, 'failed_review');

    // Recover CRM & replay via Platform Admin
    setCrmFaultMode('none');
    const adminAuth = await loginAs(baseUrl, 'admin@smiaz.local');
    const replayRes = await fetch(`${baseUrl}/admin/api/crm/replay/${queueRow.delivery_id}`, {
      method: 'POST',
      headers: { Cookie: adminAuth.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': adminAuth.csrf },
      body: JSON.stringify({ csrf_token: adminAuth.csrf }),
    });
    assert.equal(replayRes.status, 200);
    const replayedRow = await db.prepare('SELECT * FROM crm_delivery_queue WHERE inquiry_id = ?').get(j1.inquiry_id);
    assert.equal(replayedRow.status, 'delivered');

    // Idempotency identical retry -> 200 with same inquiry_id
    const resRetry = await fetch(`${baseUrl}/api/inquiries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    assert.equal(resRetry.status, 200);
    assert.equal((await resRetry.json()).inquiry_id, j1.inquiry_id);

    // Idempotency reused with different payload -> 409 conflict
    const resConflict = await fetch(`${baseUrl}/api/inquiries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, description: 'Changed scope' }),
    });
    assert.equal(resConflict.status, 409);

    // Storage outage simulation -> 503 no false success
    setSimulateStorageFailure(true);
    const resFail = await fetch(`${baseUrl}/api/inquiries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...payload, idempotency_key: 'new-key-fail' }),
    });
    assert.equal(resFail.status, 503);
    setSimulateStorageFailure(false);

    // DATA-01 / DATA-02: Analytics contains no PII and only 1 generate_lead for idempotent replay
    const leadEvents = (await db.prepare(`SELECT COUNT(*) as c FROM analytics_events WHERE event_name = 'generate_lead'`).get()).c;
    assert.equal(leadEvents, 1);

    await fetch(`${baseUrl}/api/analytics/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_name: 'phone_click', service_id: 'alex@gmail.com' }),
    });
    const scrubbed = await db.prepare(`SELECT * FROM analytics_events WHERE event_name = 'phone_click'`).get();
    assert.equal(scrubbed.service_id, null);
  });

  await t.test('ADMIN-02 & SEC-01: Server-side RBAC denies unauthorized cross-role access', async () => {
    const editor = await loginAs(baseUrl, 'editor@smiaz.local');
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');
    const contributor = await loginAs(baseUrl, 'projects@smiaz.local');

    // Content Editor cannot access Hiring or Publish Pages
    const edJobs = await fetch(`${baseUrl}/admin/jobs`, { headers: { Cookie: editor.cookie } });
    assert.equal(edJobs.status, 403);
    const edPub = await fetch(`${baseUrl}/admin/api/pages/pg-home/publish`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf }),
    });
    assert.equal(edPub.status, 403);

    // Platform Admin has NO hiring data access by default (PRD 16.03)
    const admJobs = await fetch(`${baseUrl}/admin/jobs`, { headers: { Cookie: admin.cookie } });
    assert.equal(admJobs.status, 403);
    const admExport = await fetch(`${baseUrl}/admin/api/applications/export.csv`, { headers: { Cookie: admin.cookie } });
    assert.equal(admExport.status, 403);

    // Project Contributor cannot publish projects or access applicants
    const conPub = await fetch(`${baseUrl}/admin/api/projects/proj-private-test-01/publish`, {
      method: 'POST',
      headers: { Cookie: contributor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': contributor.csrf },
      body: JSON.stringify({ csrf_token: contributor.csrf }),
    });
    assert.equal(conPub.status, 403);

    // Concurrent edit version check -> 409
    const draft1 = await fetch(`${baseUrl}/admin/api/pages/pg-about/draft`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf, expected_revision: 1, hero_headline: 'Updated v2' }),
    });
    assert.equal(draft1.status, 200);
    const staleDraft = await fetch(`${baseUrl}/admin/api/pages/pg-about/draft`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf, expected_revision: 1, hero_headline: 'Stale overwrite' }),
    });
    assert.equal(staleDraft.status, 409);
  });

  await t.test('HIRE-01..08: Vacancy lifecycle, immutable snapshot, closure race, private resume & CWE-1236 export', async () => {
    const hiringOwner = await loginAs(baseUrl, 'hiring@smiaz.local');

    // Create & Open a genuine vacancy
    const createJob = await fetch(`${baseUrl}/admin/api/jobs`, {
      method: 'POST',
      headers: { Cookie: hiringOwner.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': hiringOwner.csrf },
      body: JSON.stringify({
        csrf_token: hiringOwner.csrf,
        title: 'Commercial Maintenance Technician',
        slug: 'maintenance-tech-phoenix',
        role_family: 'Maintenance',
        employment_type: 'Full-time',
        work_area: 'Phoenix / Tempe',
        schedule_text: 'Mon-Fri 7:00 AM - 3:30 PM (America/Phoenix)',
        pay_info: '$26-$32/hr DOE',
        responsibilities_html: '<p>Perform commercial repairs.</p>',
        qualifications_html: '<p>2+ years commercial experience.</p>',
      }),
    });
    assert.equal(createJob.status, 201);
    const jobCreated = await createJob.json();

    const openRes = await fetch(`${baseUrl}/admin/api/jobs/${jobCreated.requisition_id}/open`, {
      method: 'POST',
      headers: { Cookie: hiringOwner.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': hiringOwner.csrf },
      body: JSON.stringify({ csrf_token: hiringOwner.csrf }),
    });
    assert.equal(openRes.status, 200);

    // Public Job Detail has JobPosting JSON-LD while Open
    const jobPage = await fetch(`${baseUrl}/careers/maintenance-tech-phoenix/`);
    assert.equal(jobPage.status, 200);
    assert.ok((await jobPage.text()).includes('"@type":"JobPosting"'));

    // Submit application with PDF resume & formula-injection name test
    const fd = new FormData();
    fd.append('idempotency_key', 'app-idemp-001');
    fd.append('requisition_id', jobCreated.requisition_id);
    fd.append('opening_cycle_id', jobCreated.opening_cycle_id);
    fd.append('form_revision', '1');
    fd.append('name', '=CMD("bad") Jordan');
    fd.append('preferred_contact_method', 'email');
    fd.append('email', 'jordan@yahoo.com');
    fd.append('city_or_zip', '85281');
    fd.append('relevant_experience', '5 years commercial doors and drywall.');
    fd.append('privacy_ack', 'on');
    fd.append('resume', new Blob([Buffer.from('%PDF-1.4\nResume Content', 'ascii')], { type: 'application/pdf' }), 'jordan_resume.pdf');

    const applyRes = await fetch(`${baseUrl}/api/jobs/maintenance-tech-phoenix/apply`, { method: 'POST', body: fd });
    assert.equal(applyRes.status, 201);
    const applyJson = await applyRes.json();
    assert.ok(applyJson.application_id);

    // Close the role
    await fetch(`${baseUrl}/admin/api/jobs/${jobCreated.requisition_id}/close`, {
      method: 'POST',
      headers: { Cookie: hiringOwner.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': hiringOwner.csrf },
      body: JSON.stringify({ csrf_token: hiringOwner.csrf }),
    });

    // Closed job page removes JobPosting markup
    const closedPage = await fetch(`${baseUrl}/careers/maintenance-tech-phoenix/`);
    assert.equal((await closedPage.text()).includes('"@type":"JobPosting"'), false);

    // Retry of already accepted application still returns 200 receipt even after closure (HIRE-03)
    const retryRes = await fetch(`${baseUrl}/api/jobs/maintenance-tech-phoenix/apply`, { method: 'POST', body: fd });
    assert.equal(retryRes.status, 200);

    // New application while closed returns 409 job_closed (HIRE-04)
    const fdNew = new FormData();
    fdNew.append('idempotency_key', 'app-idemp-002');
    fdNew.append('requisition_id', jobCreated.requisition_id);
    fdNew.append('opening_cycle_id', jobCreated.opening_cycle_id);
    fdNew.append('name', 'Sam');
    fdNew.append('preferred_contact_method', 'telephone');
    fdNew.append('telephone', '480-555-0144');
    fdNew.append('relevant_experience', 'Porter experience');
    fdNew.append('privacy_ack', 'on');
    const closedSubmit = await fetch(`${baseUrl}/api/jobs/maintenance-tech-phoenix/apply`, { method: 'POST', body: fdNew });
    assert.equal(closedSubmit.status, 409);
    assert.equal((await closedSubmit.json()).code, 'job_closed');

    // Reopen creates a NEW opening_cycle_id; stale cycle form still gets 409 job_closed!
    await fetch(`${baseUrl}/admin/api/jobs/${jobCreated.requisition_id}/reopen`, {
      method: 'POST',
      headers: { Cookie: hiringOwner.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': hiringOwner.csrf },
      body: JSON.stringify({ csrf_token: hiringOwner.csrf }),
    });
    const staleCycleSubmit = await fetch(`${baseUrl}/api/jobs/maintenance-tech-phoenix/apply`, { method: 'POST', body: fdNew });
    assert.equal(staleCycleSubmit.status, 409);

    // Verify resume attachment NOT accessible via public /media/ and CWE-1236 protected in CSV export
    const attRow = await db.prepare('SELECT * FROM application_attachments WHERE application_id = ?').get(applyJson.application_id);
    const pubLeakCheck = await fetch(`${baseUrl}/media/${attRow.storage_key}`);
    assert.equal(pubLeakCheck.status, 404);

    const csvRes = await fetch(`${baseUrl}/admin/api/applications/export.csv`, { headers: { Cookie: hiringOwner.cookie } });
    assert.equal(csvRes.status, 200);
    const csvText = await csvRes.text();
    assert.ok(csvText.includes("'=CMD"));
  });

  await t.test('CAMP-01..05: Seasonal campaigns, conflict blocking, Phoenix schedule activation & expiry', async () => {
    const editor = await loginAs(baseUrl, 'editor@smiaz.local');
    const publisher = await loginAs(baseUrl, 'publisher@smiaz.local');

    // Create two overlapping campaigns in notice_strip with equal priority
    const c1 = await fetch(`${baseUrl}/admin/api/campaigns`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        internal_title: 'Monsoon Prep Strip A',
        slug: 'monsoon-prep-a',
        placement_slot: 'notice_strip',
        priority: 30,
        start_phoenix: '2026-01-01T00:00',
        end_phoenix: '2027-12-31T23:59',
        heading: 'Monsoon Drainage Checks',
        summary: 'Prepare scuppers and downspouts before storms.',
        cta_label: 'Book review',
        cta_destination: '/request-proposal/',
      }),
    });
    const j1 = await c1.json();

    const c2 = await fetch(`${baseUrl}/admin/api/campaigns`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        internal_title: 'Monsoon Prep Strip B (Conflict)',
        slug: 'monsoon-prep-b',
        placement_slot: 'notice_strip',
        priority: 30,
        start_phoenix: '2026-01-01T00:00',
        end_phoenix: '2027-12-31T23:59',
        heading: 'Conflicting Strip',
        summary: 'Should fail approval conflict check.',
        cta_label: 'Go',
        cta_destination: '/services/',
      }),
    });
    const j2 = await c2.json();

    const pub1 = await fetch(`${baseUrl}/admin/api/campaigns/${j1.campaign_id}/approve-schedule`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    assert.equal(pub1.status, 200);

    // Equal-priority conflict must be blocked (409)
    const pub2 = await fetch(`${baseUrl}/admin/api/campaigns/${j2.campaign_id}/approve-schedule`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    assert.equal(pub2.status, 409);

    // Active notice strip appears on Home
    const homeLive = await (await fetch(`${baseUrl}/`)).text();
    assert.ok(homeLive.includes('Monsoon Drainage Checks'));

    // Scheduler expiry evaluation past end_at immediately removes notice strip
    await runScheduleEvaluation(db, new Date('2028-06-01T00:00:00Z'));
    const homeAfterExpiry = await (await fetch(`${baseUrl}/`)).text();
    assert.equal(homeAfterExpiry.includes('Monsoon Drainage Checks'), false);
  });

  await t.test('PROJ-01..05 & OPS-01: Photo upload EXIF strip, Before/After pairing, publish, rights withdrawal & backup', async () => {
    const contributor = await loginAs(baseUrl, 'projects@smiaz.local');
    const publisher = await loginAs(baseUrl, 'publisher@smiaz.local');
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');

    // Upload before & after PNGs containing hidden metadata text
    const fd = new FormData();
    fd.append('rights_owner', 'Client Approved');
    fd.append('alt_text', 'Warehouse concrete spall repair');
    fd.append('photos', new Blob([makePngBytes(800, 600, 'SECRET_GPS_1')], { type: 'image/png' }), 'before.png');
    fd.append('photos', new Blob([makePngBytes(800, 600, 'SECRET_GPS_2')], { type: 'image/png' }), 'after.png');

    const upRes = await fetch(`${baseUrl}/admin/api/media/upload`, {
      method: 'POST',
      headers: { Cookie: contributor.cookie, 'X-CSRF-Token': contributor.csrf },
      body: fd,
    });
    assert.equal(upRes.status, 201);
    const upJson = await upRes.json();
    assert.equal(upJson.accepted.length, 2);
    const [beforeAsset, afterAsset] = upJson.accepted;

    // Create project, pair images, mark documented & permitted
    const prRes = await fetch(`${baseUrl}/admin/api/projects`, {
      method: 'POST',
      headers: { Cookie: contributor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': contributor.csrf },
      body: JSON.stringify({
        csrf_token: contributor.csrf,
        title: 'West Valley Distribution Dock Concrete Repair',
        slug: 'west-valley-dock-concrete',
        property_type: 'Industrial / Warehouse',
        city_region: 'Phoenix / West Valley',
        completion_date: '2026-10-28',
        challenge: 'Spalled expansion joint at dock 7.',
        agreed_scope: 'Saw-cut, dowel, and epoxy mortar pour.',
        completed_work: 'Completed agreed concrete repair around shift hours.',
      }),
    });
    const prId = (await prRes.json()).project_id;

    await fetch(`${baseUrl}/admin/api/projects/${prId}/pairs`, {
      method: 'POST',
      headers: { Cookie: contributor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': contributor.csrf },
      body: JSON.stringify({
        csrf_token: contributor.csrf,
        pair_title: 'Dock 7 Apron',
        before_asset_id: beforeAsset.asset_id,
        after_asset_id: afterAsset.asset_id,
        before_caption: 'Damaged concrete apron before saw-cutting.',
        after_caption: 'Repaired level apron ready for forklifts.',
      }),
    });

    await fetch(`${baseUrl}/admin/api/projects/${prId}`, {
      method: 'POST',
      headers: { Cookie: contributor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': contributor.csrf },
      body: JSON.stringify({
        csrf_token: contributor.csrf,
        naming_decision: 'anonymized',
        cover_asset_id: afterAsset.asset_id,
        completion_documented: true,
        client_permission_verified: true,
        featured_on_home: true,
        is_private_test: false,
      }),
    });

    // Cannot publish before rights approved on assets
    const pubFail = await fetch(`${baseUrl}/admin/api/projects/${prId}/publish`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    assert.equal(pubFail.status, 422);

    // Approve rights & publish
    for (const a of [beforeAsset, afterAsset]) {
      await fetch(`${baseUrl}/admin/api/media/${a.asset_id}/approve-rights`, {
        method: 'POST',
        headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
        body: JSON.stringify({ csrf_token: publisher.csrf }),
      });
    }
    const pubOk = await fetch(`${baseUrl}/admin/api/projects/${prId}/publish`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    assert.equal(pubOk.status, 200);

    // Public project page & derivative image (stripped of SECRET_GPS_2!)
    const projHtml = await (await fetch(`${baseUrl}/projects/west-valley-dock-concrete/`)).text();
    assert.ok(projHtml.includes('Dock 7 Apron'));
    const imgRes = await fetch(`${baseUrl}/media/${afterAsset.public_derivative_key}`);
    assert.equal(imgRes.status, 200);
    const imgBuf = Buffer.from(await imgRes.arrayBuffer());
    assert.equal(imgBuf.toString('ascii').includes('SECRET_GPS_2'), false);

    // Withdraw rights -> public derivative immediately returns 404!
    await fetch(`${baseUrl}/admin/api/media/${afterAsset.asset_id}/withdraw`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    const imgAfterWithdraw = await fetch(`${baseUrl}/media/${afterAsset.public_derivative_key}`);
    assert.equal(imgAfterWithdraw.status, 404);

    // OPS-01: Portable backup export
    const bkRes = await fetch(`${baseUrl}/admin/api/backup/export.json`, { headers: { Cookie: admin.cookie } });
    assert.equal(bkRes.status, 200);
    const bkJson = await bkRes.json();
    assert.equal(bkJson.business_settings.legal_entity, 'Promptitude Inc.');
  });

  await t.test('PHASE-1-SEC: Hiring Owner assigned-scope isolation & production fault-mode guard', async () => {
    const { hashPassword } = await import('../src/lib/crypto.js');
    const { ROLES } = await import('../src/config.js');
    const nowIso = new Date().toISOString();

    // Seed a second Hiring Owner and second Hiring Reviewer who are NOT assigned to the earlier job
    const ho2Secret = 'JBSWY3DPEHPK3PXQ';
    const hr2Secret = 'KRSXG5CTMVRXEZLV';
    await db.prepare(
      `INSERT INTO users (user_id, email, full_name, password_hash, role, extra_roles_json, totp_secret, mfa_enabled, active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, '[]', ?, 1, 1, ?, ?)`
    ).run('usr-hiring-owner-02', 'hiring2@smiaz.local', 'Other Hiring Owner', hashPassword('SM-Staff-2026!'), ROLES.HIRING_OWNER, ho2Secret, nowIso, nowIso);
    await db.prepare(
      `INSERT INTO users (user_id, email, full_name, password_hash, role, extra_roles_json, totp_secret, mfa_enabled, active, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, '[]', ?, 1, 1, ?, ?)`
    ).run('usr-hiring-reviewer-02', 'reviewer2@smiaz.local', 'Unassigned Reviewer', hashPassword('SM-Staff-2026!'), ROLES.HIRING_REVIEWER, hr2Secret, nowIso, nowIso);

    const existingJob = await db.prepare(`SELECT * FROM jobs WHERE slug = 'maintenance-tech-phoenix'`).get();
    const existingApp = await db.prepare(`SELECT * FROM applications WHERE requisition_id = ?`).get(existingJob.requisition_id);
    const existingAtt = await db.prepare(`SELECT * FROM application_attachments WHERE application_id = ?`).get(existingApp.application_id);

    const ho2 = await loginAs(baseUrl, 'hiring2@smiaz.local', ho2Secret);
    const hr2 = await loginAs(baseUrl, 'reviewer2@smiaz.local', hr2Secret);

    // 1. Unassigned Hiring Owner CANNOT see other owner's job/application in /admin/jobs or direct URL ?app=...
    const ho2List = await (await fetch(`${baseUrl}/admin/jobs`, { headers: { Cookie: ho2.cookie } })).text();
    assert.equal(ho2List.includes(existingJob.requisition_id), false);
    assert.equal(ho2List.includes(existingApp.application_id), false);

    const ho2DirectUrl = await fetch(`${baseUrl}/admin/jobs?app=${encodeURIComponent(existingApp.application_id)}`, {
      headers: { Cookie: ho2.cookie },
    });
    assert.equal(ho2DirectUrl.status, 403);

    // 2. Unassigned Hiring Owner CANNOT review, download resume, close job, or export other owner's applications
    const ho2Review = await fetch(`${baseUrl}/admin/api/applications/${existingApp.application_id}/review`, {
      method: 'POST',
      headers: { Cookie: ho2.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': ho2.csrf },
      body: JSON.stringify({ csrf_token: ho2.csrf, stage: 'Interview' }),
    });
    assert.equal(ho2Review.status, 403);

    const ho2Resume = await fetch(`${baseUrl}/admin/api/applications/${existingApp.application_id}/attachments/${existingAtt.attachment_id}`, {
      headers: { Cookie: ho2.cookie },
    });
    assert.equal(ho2Resume.status, 403);

    const ho2Close = await fetch(`${baseUrl}/admin/api/jobs/${existingJob.requisition_id}/close`, {
      method: 'POST',
      headers: { Cookie: ho2.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': ho2.csrf },
      body: JSON.stringify({ csrf_token: ho2.csrf }),
    });
    assert.equal(ho2Close.status, 404);

    const ho2Csv = await (await fetch(`${baseUrl}/admin/api/applications/export.csv`, { headers: { Cookie: ho2.cookie } })).text();
    assert.equal(ho2Csv.includes(existingApp.application_id), false);

    // 3. Unassigned Hiring Reviewer also denied direct access
    const hr2Direct = await fetch(`${baseUrl}/admin/jobs?app=${encodeURIComponent(existingApp.application_id)}`, {
      headers: { Cookie: hr2.cookie },
    });
    assert.equal(hr2Direct.status, 403);

    const hr2Resume = await fetch(`${baseUrl}/admin/api/applications/${existingApp.application_id}/attachments/${existingAtt.attachment_id}`, {
      headers: { Cookie: hr2.cookie },
    });
    assert.equal(hr2Resume.status, 403);

    // 4. /admin/api/crm/fault-mode is disabled when NODE_ENV === 'production'
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');
    const prevNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      const faultProdRes = await fetch(`${baseUrl}/admin/api/crm/fault-mode?mode=outage_503`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf }),
      });
      assert.equal(faultProdRes.status, 403);
    } finally {
      process.env.NODE_ENV = prevNodeEnv;
    }

    // 5. Storage isolation check: uploaded assets live inside tmpDir/storage, NOT workspace storage
    assert.ok(fs.existsSync(path.join(storageRoot, 'private', 'resumes', existingAtt.storage_key)));
  });

  await t.test('M365-01: Real Microsoft Graph email delivery fails safely when unconfigured, retries on 500, and succeeds via manual replay', async () => {
    const savedEnv = {
      MS_GRAPH_TENANT_ID: process.env.MS_GRAPH_TENANT_ID,
      MS_GRAPH_CLIENT_ID: process.env.MS_GRAPH_CLIENT_ID,
      MS_GRAPH_CLIENT_SECRET: process.env.MS_GRAPH_CLIENT_SECRET,
      M365_SENDER: process.env.M365_SENDER,
    };
    delete process.env.MS_GRAPH_TENANT_ID;
    delete process.env.MS_GRAPH_CLIENT_ID;
    delete process.env.MS_GRAPH_CLIENT_SECRET;
    delete process.env.M365_SENDER;
    clearMailerTokenCache();

    try {
      // Create a fresh inquiry that queues an email notification
      const inqRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: 'm365-test-001',
          name: 'Mail Test User',
          company: 'Mail Test Properties',
          preferred_contact_method: 'email',
          email: 'mailtest@example.org',
          property_city_or_zip: 'Phoenix, AZ 85004',
          service_needed: 'warehouse-repairs',
          description: 'Routine facility maintenance quote.',
        }),
      });
      assert.equal(inqRes.status, 201);
      const { inquiry_id: inquiryId } = await inqRes.json();

      // Without Graph credentials, notification MUST NOT falsely be marked 'sent'
      await processDeliveryQueues(db);
      const unconfiguredNotif = await db
        .prepare(`SELECT * FROM notification_queue WHERE reference_id = ? AND domain = 'commercial'`)
        .get(inquiryId);
      assert.equal(unconfiguredNotif.status, 'failed_review');
      assert.match(unconfiguredNotif.last_error, /not configured/i);
      assert.equal(unconfiguredNotif.provider_message_id, null);

      // Configure Graph env vars + mock Entra ID & Graph sendMail endpoints (first transient 500, then 202 Accepted)
      process.env.MS_GRAPH_TENANT_ID = 'tenant-123';
      process.env.MS_GRAPH_CLIENT_ID = 'client-456';
      process.env.MS_GRAPH_CLIENT_SECRET = 'secret-789';
      process.env.M365_SENDER = 'notifications@smiaz.com';
      clearMailerTokenCache();

      let graphMode = 'fail_500';
      const capturedGraphCalls = [];
      setMailerFetch(async (url, opts) => {
        capturedGraphCalls.push({ url, method: opts.method, body: opts.body });
        if (url.includes('login.microsoftonline.com/tenant-123/oauth2/v2.0/token')) {
          return new Response(JSON.stringify({ access_token: 'mock-graph-token', expires_in: 3600 }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        if (url.includes('graph.microsoft.com/v1.0/users/notifications%40smiaz.com/sendMail')) {
          if (graphMode === 'fail_500') {
            return new Response('Upstream error', { status: 500 });
          }
          return new Response(null, {
            status: 202,
            headers: { 'request-id': 'graph-msg-accepted-001' },
          });
        }
        throw new Error(`Unexpected mailer URL: ${url}`);
      });

      // Reset to pending -> hits 500 transient backoff, stays pending (attempts = 1)
      const admin = await loginAs(baseUrl, 'admin@smiaz.local');
      const replayRetryRes = await fetch(`${baseUrl}/admin/api/notifications/replay/${unconfiguredNotif.notification_id}`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf }),
      });
      assert.equal(replayRetryRes.status, 200);
      const after500 = await db.prepare(`SELECT * FROM notification_queue WHERE notification_id = ?`).get(unconfiguredNotif.notification_id);
      assert.equal(after500.status, 'pending');
      assert.equal(after500.attempts, 1);
      assert.match(after500.last_error, /500/);

      // Switch mock to 202 Accepted -> manual replay delivers & stores provider_message_id + replyTo
      graphMode = 'ok_202';
      const replayOkRes = await fetch(`${baseUrl}/admin/api/notifications/replay/${unconfiguredNotif.notification_id}`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf }),
      });
      assert.equal(replayOkRes.status, 200);
      const after202 = await db.prepare(`SELECT * FROM notification_queue WHERE notification_id = ?`).get(unconfiguredNotif.notification_id);
      assert.equal(after202.status, 'sent');
      assert.equal(after202.provider_message_id, 'graph-msg-accepted-001');
      assert.equal(after202.last_error, null);

      const sendCall = capturedGraphCalls.filter((c) => c.url.includes('/sendMail')).pop();
      const sendPayload = JSON.parse(sendCall.body);
      assert.equal(sendPayload.message.toRecipients[0].emailAddress.address, 'sales@smiaz.com');
      assert.equal(sendPayload.message.replyTo[0].emailAddress.address, 'mailtest@example.org');
    } finally {
      setMailerFetch(null);
      clearMailerTokenCache();
      for (const [k, v] of Object.entries(savedEnv)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  await t.test('CRM-03: Freshsales multi-entity upsert, duplicate prevention, Deal milestones, and analytics events', async () => {
    const savedEnv = {
      FRESHSALES_DOMAIN: process.env.FRESHSALES_DOMAIN,
      FRESHSALES_API_KEY: process.env.FRESHSALES_API_KEY,
      FRESHSALES_DEAL_STAGE_QUALIFIED: process.env.FRESHSALES_DEAL_STAGE_QUALIFIED,
      FRESHSALES_DEAL_STAGE_PROPOSAL: process.env.FRESHSALES_DEAL_STAGE_PROPOSAL,
      FRESHSALES_DEAL_STAGE_WON: process.env.FRESHSALES_DEAL_STAGE_WON,
    };
    process.env.FRESHSALES_DOMAIN = 'acme-test.myfreshworks.com';
    process.env.FRESHSALES_API_KEY = 'fs-test-key';
    process.env.FRESHSALES_DEAL_STAGE_QUALIFIED = '101';
    process.env.FRESHSALES_DEAL_STAGE_PROPOSAL = '102';
    process.env.FRESHSALES_DEAL_STAGE_WON = '103';

    const crmCalls = [];
    setCrmFetch(async (url, opts) => {
      assert.equal(opts.headers.Authorization, 'Token token=fs-test-key');
      const body = JSON.parse(opts.body);
      crmCalls.push({ url, body });

      if (url.endsWith('/crm/sales/api/sales_accounts/upsert')) {
        return new Response(JSON.stringify({ sales_account: { id: 9001, name: body.sales_account.name } }), { status: 200 });
      }
      if (url.endsWith('/crm/sales/api/contacts/upsert') || url.endsWith('/crm/sales/api/contacts')) {
        return new Response(JSON.stringify({ contact: { id: 8001, last_name: body.contact.last_name } }), { status: 200 });
      }
      if (url.endsWith('/crm/sales/api/notes')) {
        const noteId = body.note.targetable_type === 'SalesAccount' ? 7001 : 7002;
        return new Response(JSON.stringify({ note: { id: noteId } }), { status: 201 });
      }
      if (url.endsWith('/crm/sales/api/deals')) {
        return new Response(JSON.stringify({ deal: { id: 6001, name: body.deal.name } }), { status: 201 });
      }
      if (url.endsWith('/crm/sales/api/deals/upsert')) {
        return new Response(JSON.stringify({ deal: { id: body.unique_identifier.id, name: body.deal.name } }), { status: 200 });
      }
      throw new Error(`Unexpected Freshsales URL: ${url}`);
    });

    try {
      const inqRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: 'crm03-test-001',
          name: 'Elena Martinez',
          company: 'Copper Creek Plaza LLC',
          preferred_contact_method: 'email',
          email: 'elena@coppercreek.example',
          telephone: '(602) 555-0192',
          property_city_or_zip: 'Phoenix 85016',
          property_type: 'retail',
          service_needed: 'day-porter',
          description: 'Sealcoat and restriping across 3 buildings.',
          acquisition_utms_json: JSON.stringify({
            utm_source: 'google',
            utm_medium: 'cpc',
            utm_campaign: 'az-sealcoat',
          }),
        }),
      });
      assert.equal(inqRes.status, 201);
      const { inquiry_id: inquiryId } = await inqRes.json();

      // Prevent notification queue calls from hitting unconfigured Graph during CRM test
      (await db.prepare(`UPDATE notification_queue SET status = 'sent' WHERE reference_id = ?`).run(inquiryId));

      await processDeliveryQueues(db);

      const inqRow = await db.prepare(`SELECT * FROM inquiries WHERE inquiry_id = ?`).get(inquiryId);
      const acctRow = await db.prepare(`SELECT * FROM accounts WHERE account_id = ?`).get(inqRow.account_id);
      const contactRow = await db.prepare(`SELECT * FROM contacts WHERE contact_id = ?`).get(inqRow.contact_id);
      const propRow = await db.prepare(`SELECT * FROM properties WHERE property_id = ?`).get(inqRow.property_id);
      const queueRow = await db.prepare(`SELECT * FROM crm_delivery_queue WHERE inquiry_id = ?`).get(inquiryId);

      assert.equal(queueRow.status, 'delivered');
      assert.equal(acctRow.crm_account_id, '9001');
      assert.equal(contactRow.crm_contact_id, '8001');
      assert.equal(propRow.crm_property_note_id, '7001');
      assert.equal(inqRow.crm_note_id, '7002');

      const notesCountAfterSync = crmCalls.filter((c) => c.url.endsWith('/notes')).length;
      assert.equal(notesCountAfterSync, 2);

      // Replaying delivery uses stored CRM IDs and must NOT duplicate Notes
      const admin = await loginAs(baseUrl, 'admin@smiaz.local');
      await fetch(`${baseUrl}/admin/api/crm/replay/${queueRow.delivery_id}`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf }),
      });
      const notesCountAfterReplay = crmCalls.filter((c) => c.url.endsWith('/notes')).length;
      assert.equal(notesCountAfterReplay, 2);

      // Advance inquiry milestones: qualified -> qualified (dup guard) -> proposal_sent -> closed_won
      const stageUpdate = async (status, dealValue) => {
        const res = await fetch(`${baseUrl}/admin/api/inquiries/${inquiryId}/status`, {
          method: 'POST',
          headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
          body: JSON.stringify({ csrf_token: admin.csrf, classification: 'valid', status, deal_value: dealValue }),
        });
        assert.equal(res.status, 200);
        return res.json();
      };

      const r1 = await stageUpdate('qualified', 18500);
      assert.equal(r1.milestoneRecorded, 'qualified_lead');
      assert.equal(r1.crmSync.crmDealId, '6001');

      const r1Dup = await stageUpdate('qualified', 18500);
      assert.equal(r1Dup.milestoneRecorded, null);

      const r2 = await stageUpdate('proposal_sent', 19200);
      assert.equal(r2.milestoneRecorded, 'proposal_sent');

      const r3 = await stageUpdate('closed_won', 19200);
      assert.equal(r3.milestoneRecorded, 'closed_won');

      // Verify exactly 1 Deal create (/deals) and 3 updates (/deals/upsert) using crm_deal_id = 6001
      const dealCreateCalls = crmCalls.filter((c) => c.url.endsWith('/crm/sales/api/deals'));
      const dealUpsertCalls = crmCalls.filter((c) => c.url.endsWith('/crm/sales/api/deals/upsert'));
      assert.equal(dealCreateCalls.length, 1);
      assert.equal(dealCreateCalls[0].body.deal.deal_stage_id, 101);
      assert.equal(dealCreateCalls[0].body.deal.amount, 18500);
      assert.equal(dealUpsertCalls.length, 3);
      assert.equal(dealUpsertCalls[2].body.unique_identifier.id, 6001);
      assert.equal(dealUpsertCalls[2].body.deal.deal_stage_id, 103);

      // Verify milestone analytics events recorded with attribution & without duplicating on repeat status save
      const milestoneEvents = await db
        .prepare(
          `SELECT event_name, service_id, acquisition_utm_source, acquisition_utm_campaign
           FROM analytics_events
           WHERE event_name IN ('qualified_lead', 'proposal_sent', 'closed_won') AND service_id = 'day-porter'
           ORDER BY created_at ASC`
        )
        .all();
      assert.deepEqual(
        milestoneEvents.map((e) => e.event_name),
        ['qualified_lead', 'proposal_sent', 'closed_won']
      );
      assert.equal(milestoneEvents[0].acquisition_utm_source, 'google');
      assert.equal(milestoneEvents[2].acquisition_utm_campaign, 'az-sealcoat');

      // Non-valid classification (existing_service) must NOT record Deal milestone analytics events
      const svcRes = await fetch(`${baseUrl}/api/service-requests`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idempotency_key: 'crm03-existing-001',
          name: 'Existing Client',
          company: 'Mesa Office Park',
          preferred_contact_method: 'email',
          email: 'client@mesaoffice.example',
          property: 'Mesa Suite 100',
          urgency: 'routine',
          description: 'Replace lobby door closer.',
        }),
      });
      assert.equal(svcRes.status, 201);
      const { inquiry_id: existingSvcId } = await svcRes.json();
      const nonMilestoneRes = await fetch(`${baseUrl}/admin/api/inquiries/${existingSvcId}/status`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf, classification: 'existing_service', status: 'closed_won' }),
      });
      assert.equal(nonMilestoneRes.status, 200);
      const nonMilestoneJson = await nonMilestoneRes.json();
      assert.equal(nonMilestoneJson.milestoneRecorded, null);
      assert.equal(nonMilestoneJson.crmSync, null);
    } finally {
      setCrmFetch(null);
      for (const [k, v] of Object.entries(savedEnv)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  });

  await t.test('PHASE-3-USERS & UX: Staff user CRUD, role change/deactivation revokes sessions, and no window.alert', async () => {
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');
    const editor = await loginAs(baseUrl, 'editor@smiaz.local');

    // Non-admin denied user creation
    const denyCreate = await fetch(`${baseUrl}/admin/api/users`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        email: 'unauth@smiaz.local',
        full_name: 'Unauth User',
        role: 'Content Editor',
        password: 'StrongPassword#2026',
      }),
    });
    assert.equal(denyCreate.status, 403);

    // Admin creates new staff user with extra role
    const createRes = await fetch(`${baseUrl}/admin/api/users`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({
        csrf_token: admin.csrf,
        email: 'ops.staff@smiaz.local',
        full_name: 'Maya Patel',
        role: 'Content Editor',
        extra_roles: ['Analyst'],
        password: 'StrongPassword#2026',
      }),
    });
    assert.equal(createRes.status, 201);
    const created = await createRes.json();
    assert.ok(created.user_id);
    assert.equal(created.totp_secret, undefined);
    assert.equal('totp_secret' in created, false);
    assert.equal(created.mfa_enrolled, false);

    // Issue authorized single-use first-time MFA setup link & enroll via /admin/mfa-setup
    const tokenIssueRes = await fetch(`${baseUrl}/admin/api/users/${created.user_id}/mfa-recovery-token`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf }),
    });
    assert.equal(tokenIssueRes.status, 200);
    const tokenIssueData = await tokenIssueRes.json();
    assert.equal(tokenIssueData.purpose, 'first_time_enroll');
    assert.ok(tokenIssueData.setup_url.startsWith('/admin/mfa-setup?token='));
    const setupToken = new URL(tokenIssueData.setup_url, baseUrl).searchParams.get('token');

    const mfaGetRes = await fetch(`${baseUrl}${tokenIssueData.setup_url}`);
    assert.equal(mfaGetRes.status, 200);
    const mfaGetHtml = await mfaGetRes.text();
    const mfaCsrfCookie = (mfaGetRes.headers.getSetCookie?.() || [mfaGetRes.headers.get('set-cookie')])
      .find((c) => c?.startsWith('sm_mfa_csrf='))
      .split(';')[0];
    const mfaStep1Csrf = mfaGetHtml.match(/name="csrf_token" value="([^"]+)"/)[1];

    const mfaBeginRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: mfaCsrfCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: mfaStep1Csrf,
        step: 'begin',
        email: 'ops.staff@smiaz.local',
        password: 'StrongPassword#2026',
        setup_token: setupToken,
      }).toString(),
    });
    assert.equal(mfaBeginRes.status, 200);
    const mfaStep2Html = await mfaBeginRes.text();
    const enrolledManualSecret = mfaStep2Html.match(/<code[^>]*>([A-Z2-7 ]{16,})<\/code>/)[1].replace(/\s+/g, '');
    const mfaStep2Csrf = mfaStep2Html.match(/name="csrf_token" value="([^"]+)"/)[1];
    const mfaStep2Cookies = (mfaBeginRes.headers.getSetCookie?.() || [mfaBeginRes.headers.get('set-cookie')])
      .map((c) => c.split(';')[0])
      .join('; ');

    const mfaConfirmRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: mfaStep2Cookies, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: mfaStep2Csrf,
        step: 'confirm',
        totp_code: generateTotpCode(enrolledManualSecret),
      }).toString(),
    });
    assert.equal(mfaConfirmRes.status, 200);
    assert.ok((await mfaConfirmRes.text()).includes('Google Authenticator Enrolled'));

    // Log in as new user with newly enrolled MFA TOTP
    const loginResp = await fetch(`${baseUrl}/admin/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        email: 'ops.staff@smiaz.local',
        password: 'StrongPassword#2026',
        totp_code: generateTotpCode(enrolledManualSecret),
      }),
    });
    assert.equal(loginResp.status, 302);
    const staffCookie = loginResp.headers.get('set-cookie').split(';')[0];

    // New user can access /admin/analytics via extra role 'Analyst'
    const anaCheck = await fetch(`${baseUrl}/admin/analytics`, { headers: { Cookie: staffCookie } });
    assert.equal(anaCheck.status, 200);

    // Admin updates role & removes Analyst -> MUST revoke active session immediately!
    const editRes = await fetch(`${baseUrl}/admin/api/users/${created.user_id}`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({
        csrf_token: admin.csrf,
        role: 'Project Contributor',
        extra_roles: [],
        active: true,
      }),
    });
    assert.equal(editRes.status, 200);
    assert.equal((await editRes.json()).sessions_revoked, true);

    const postRevoke = await fetch(`${baseUrl}/admin/analytics`, { headers: { Cookie: staffCookie }, redirect: 'manual' });
    assert.equal(postRevoke.status, 302);

    // Prevent self-deactivation by admin
    const selfDeact = await fetch(`${baseUrl}/admin/api/users/usr-admin-01/deactivate`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf }),
    });
    assert.equal(selfDeact.status, 422);

    // Deactivate created staff user + confirm audit entries & inline UX elements (no alert())
    const deactRes = await fetch(`${baseUrl}/admin/api/users/${created.user_id}/deactivate`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf }),
    });
    assert.equal(deactRes.status, 200);
    const auditActions = (await db
      .prepare(`SELECT action FROM audit_log WHERE domain = 'users' AND object_id = ? ORDER BY created_at ASC`)
      .all(created.user_id))
      .map((r) => r.action);
    assert.deepEqual(auditActions, ['create_user', 'update_user', 'deactivate_user']);

    const adminJsText = fs.readFileSync(path.join(process.cwd(), 'public', 'js', 'admin.js'), 'utf8');
    assert.equal(/\balert\s*\(/.test(adminJsText), false);

    const settingsHtml = await (await fetch(`${baseUrl}/admin/settings`, { headers: { Cookie: admin.cookie } })).text();
    assert.ok(settingsHtml.includes('id="admin-inline-alert"'));
    assert.ok(settingsHtml.includes('id="admin-confirm-dialog"'));

    // Redesigned UI/UX: Overview VIEW_CONTENT KPIs + Role-Scoped Expiring Schedules + Progressive Disclosure tabs & Edit User
    const overviewHtml = await (await fetch(`${baseUrl}/admin/`, { headers: { Cookie: admin.cookie } })).text();
    assert.ok(overviewHtml.includes('Live Public Pages'));
    assert.ok(overviewHtml.includes('Pages In Review'));
    assert.equal(overviewHtml.includes('Expiring Schedules'), false);
    assert.ok(overviewHtml.includes('My Role Scope'));
    const pubForOverview = await loginAs(baseUrl, 'publisher@smiaz.local');
    const pubOverviewHtml = await (await fetch(`${baseUrl}/admin/`, { headers: { Cookie: pubForOverview.cookie } })).text();
    assert.ok(pubOverviewHtml.includes('Expiring Schedules'));

    const usersDefaultHtml = await (
      await fetch(`${baseUrl}/admin/users?user=${encodeURIComponent(created.user_id)}`, { headers: { Cookie: admin.cookie } })
    ).text();
    assert.ok(usersDefaultHtml.includes('+ Add User'));
    assert.ok(usersDefaultHtml.includes('id="edit-user-form"'));
    assert.ok(usersDefaultHtml.includes('Edit User:'));
    assert.equal(usersDefaultHtml.includes('id="create-user-form"'), false);
    assert.equal(usersDefaultHtml.includes('PRD Role Explorer &amp; Server-Side Permission Matrix'), false);
    assert.equal(usersDefaultHtml.includes('Staff Roles &amp; Access Boundaries'), false);

    const usersCreateHtml = await (await fetch(`${baseUrl}/admin/users?action=create`, { headers: { Cookie: admin.cookie } })).text();
    assert.ok(usersCreateHtml.includes('id="create-user-form"'));

    const usersRolesTabHtml = await (await fetch(`${baseUrl}/admin/users?tab=roles`, { headers: { Cookie: admin.cookie } })).text();
    assert.ok(usersRolesTabHtml.includes('Staff Roles &amp; Access Boundaries'));

    // Edit User form supports full_name + reactivation + new_password
    const renameRes = await fetch(`${baseUrl}/admin/api/users/${created.user_id}`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({
        csrf_token: admin.csrf,
        full_name: 'Updated Contributor Name',
        role: 'Project Contributor',
        extra_roles: [],
        active: true,
        new_password: 'UpdatedPass!2026',
      }),
    });
    assert.equal(renameRes.status, 200);
    const updatedUserHtml = await (
      await fetch(`${baseUrl}/admin/users?user=${encodeURIComponent(created.user_id)}`, { headers: { Cookie: admin.cookie } })
    ).text();
    assert.ok(updatedUserHtml.includes('Updated Contributor Name'));

    const reLoginResp = await fetch(`${baseUrl}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      redirect: 'manual',
      body: new URLSearchParams({
        email: 'ops.staff@smiaz.local',
        password: 'UpdatedPass!2026',
        totp_code: generateTotpCode(enrolledManualSecret),
      }),
    });
    assert.equal(reLoginResp.status, 302);

    // Module tabs & project filter work cleanly
    const pagesArticlesHtml = await (await fetch(`${baseUrl}/admin/pages?tab=articles`, { headers: { Cookie: admin.cookie } })).text();
    assert.ok(pagesArticlesHtml.includes('Insights Articles'));
    assert.equal(pagesArticlesHtml.includes('<h2>Website Pages</h2>'), false);

    const pagesClaimsHtml = await (await fetch(`${baseUrl}/admin/pages?tab=claims`, { headers: { Cookie: admin.cookie } })).text();
    assert.ok(pagesClaimsHtml.includes('Fact, Claim &amp; Testimonial Evidence Register'));

    const projectsFilteredResp = await fetch(`${baseUrl}/admin/projects?q=Tempe`, { headers: { Cookie: editor.cookie } });
    assert.equal(projectsFilteredResp.status, 200);
    const projectsFilteredHtml = await projectsFilteredResp.text();
    assert.ok(projectsFilteredHtml.includes('id="prj-q"'));

    const leadsQueuesHtml = await (await fetch(`${baseUrl}/admin/leads?tab=queues`, { headers: { Cookie: admin.cookie } })).text();
    assert.ok(leadsQueuesHtml.includes('Freshsales CRM Delivery Queue'));
    assert.ok(leadsQueuesHtml.includes('M365 Notification Dispatch Queue'));
  });

  await t.test('PHASE-3-JOBS: Vacancy edit, Phoenix schedule evaluation, applicant search/pagination & resume replace/delete', async () => {
    const ho = await loginAs(baseUrl, 'hiring@smiaz.local');
    const hr = await loginAs(baseUrl, 'reviewer@smiaz.local');

    // Create vacancy, then edit it and verify immutable requisition_id & opening_cycle_id + form_revision++
    const createJobRes = await fetch(`${baseUrl}/admin/api/jobs`, {
      method: 'POST',
      headers: { Cookie: ho.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': ho.csrf },
      body: JSON.stringify({
        csrf_token: ho.csrf,
        title: 'Lead Maintenance Tech Phase3',
        slug: 'lead-maint-phase3',
        role_family: 'Maintenance Technician',
        employment_type: 'Full-time',
        work_area: 'Tempe / Phoenix',
        schedule_text: 'M-F 7am-3:30pm',
        pay_info: '$28/hr',
        responsibilities_html: '<p>Preventive maintenance</p>',
        qualifications_html: '<p>3+ years experience</p>',
      }),
    });
    assert.equal(createJobRes.status, 201);
    const { requisition_id: reqId, opening_cycle_id: cycleId } = await createJobRes.json();

    const editJobRes = await fetch(`${baseUrl}/admin/api/jobs/${reqId}`, {
      method: 'POST',
      headers: { Cookie: ho.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': ho.csrf },
      body: JSON.stringify({
        csrf_token: ho.csrf,
        title: 'Lead Maintenance Tech Phase3 (Updated)',
        pay_info: '$30/hr DOE',
        resume_policy: 'optional',
      }),
    });
    assert.equal(editJobRes.status, 200);
    const editedJob = await db.prepare('SELECT * FROM jobs WHERE requisition_id = ?').get(reqId);
    assert.equal(editedJob.opening_cycle_id, cycleId);
    assert.equal(editedJob.form_revision, 2);
    assert.equal(editedJob.pay_info, '$30/hr DOE');

    // Schedule publish (already due in Phoenix) & auto-close (future Phoenix), verify runScheduleEvaluation opens & closes cleanly
    const schedRes = await fetch(`${baseUrl}/admin/api/jobs/${reqId}/schedule`, {
      method: 'POST',
      headers: { Cookie: ho.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': ho.csrf },
      body: JSON.stringify({
        csrf_token: ho.csrf,
        publish_phoenix: '2026-11-24T08:00',
        close_phoenix: '2026-12-05T17:00',
      }),
    });
    assert.equal(schedRes.status, 200);
    await runScheduleEvaluation(db, new Date());
    assert.equal((await db.prepare('SELECT status FROM jobs WHERE requisition_id = ?').get(reqId)).status, 'Open');

    // Submit application with PDF resume to new Open role
    const fd = new FormData();
    fd.append('idempotency_key', 'phase3-app-001');
    fd.append('requisition_id', reqId);
    fd.append('opening_cycle_id', cycleId);
    fd.append('form_revision', '2');
    fd.append('name', 'Carlos Vega');
    fd.append('preferred_contact_method', 'email');
    fd.append('email', 'carlos.vega@example.org');
    fd.append('relevant_experience', '5 years commercial maintenance');
    fd.append('privacy_ack', 'on');
    fd.append('resume', new Blob([Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF')], { type: 'application/pdf' }), 'vega-v1.pdf');

    const applyRes = await fetch(`${baseUrl}/api/jobs/lead-maint-phase3/apply`, { method: 'POST', body: fd });
    assert.equal(applyRes.status, 201);
    const { application_id: appId } = await applyRes.json();

    // Applicant inbox search & filter by applicant name
    const inboxHtml = await (await fetch(`${baseUrl}/admin/jobs?q=Carlos+Vega&req=${encodeURIComponent(reqId)}`, { headers: { Cookie: ho.cookie } })).text();
    assert.ok(inboxHtml.includes('Carlos Vega'));

    // Replace resume (Hiring Reviewer denied 403, Hiring Owner permitted 200)
    const oldAtt = await db.prepare('SELECT * FROM application_attachments WHERE application_id = ? AND deleted_at IS NULL').get(appId);
    const repFdDeny = new FormData();
    repFdDeny.append('csrf_token', hr.csrf);
    repFdDeny.append('resume', new Blob([Buffer.from('%PDF-1.4\n%%EOF')], { type: 'application/pdf' }), 'vega-v2.pdf');
    const denyRep = await fetch(`${baseUrl}/admin/api/applications/${appId}/attachments/${oldAtt.attachment_id}/replace`, {
      method: 'POST',
      headers: { Cookie: hr.cookie, 'X-CSRF-Token': hr.csrf },
      body: repFdDeny,
    });
    assert.equal(denyRep.status, 403);

    const repFdOk = new FormData();
    repFdOk.append('csrf_token', ho.csrf);
    repFdOk.append('resume', new Blob([Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF')], { type: 'application/pdf' }), 'vega-v2.pdf');
    const okRep = await fetch(`${baseUrl}/admin/api/applications/${appId}/attachments/${oldAtt.attachment_id}/replace`, {
      method: 'POST',
      headers: { Cookie: ho.cookie, 'X-CSRF-Token': ho.csrf },
      body: repFdOk,
    });
    assert.equal(okRep.status, 200);
    const { attachment_id: newAttId } = await okRep.json();
    assert.notEqual(newAttId, oldAtt.attachment_id);

    // Delete new resume
    const delAttRes = await fetch(`${baseUrl}/admin/api/applications/${appId}/attachments/${newAttId}/delete`, {
      method: 'POST',
      headers: { Cookie: ho.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': ho.csrf },
      body: JSON.stringify({ csrf_token: ho.csrf }),
    });
    assert.equal(delAttRes.status, 200);
    assert.equal((await db.prepare('SELECT COUNT(*) as c FROM application_attachments WHERE application_id = ? AND deleted_at IS NULL').get(appId)).c, 0);

    // Scheduled close transitions role to Closed
    await runScheduleEvaluation(db, new Date('2026-12-06T01:00:00Z')); // after Dec 5 17:00 Phoenix
    assert.equal((await db.prepare('SELECT status FROM jobs WHERE requisition_id = ?').get(reqId)).status, 'Closed');
  });

  await t.test('PHASE-3-CAMPAIGNS, PROJECTS, CMS, PREVIEW & LEADS: Full editorial, gallery/focal-point, calendar & inquiry attachments', async () => {
    const editor = await loginAs(baseUrl, 'editor@smiaz.local');
    const publisher = await loginAs(baseUrl, 'publisher@smiaz.local');
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');

    // 1. Campaigns: edit existing campaign & archive + calendar view
    const campCreate = await fetch(`${baseUrl}/admin/api/campaigns`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        internal_title: 'Spring Roof Prep',
        slug: 'spring-roof-prep',
        placement_slot: 'notice_strip',
        priority: 30,
        start_phoenix: '2026-11-01T08:00',
        end_phoenix: '2026-12-30T17:00',
        heading: 'Spring Roof Drain Check',
        summary: 'Schedule drainage clearance.',
        cta_label: 'Request Proposal',
        cta_destination: '/request-proposal/',
      }),
    });
    assert.equal(campCreate.status, 201);
    const { campaign_id: campId } = await campCreate.json();

    const campEdit = await fetch(`${baseUrl}/admin/api/campaigns/${campId}`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        heading: 'Spring Roof Drain Check v2',
        priority: 35,
      }),
    });
    assert.equal(campEdit.status, 200);
    assert.equal((await campEdit.json()).content_revision, 2);

    const calHtml = await (await fetch(`${baseUrl}/admin/campaigns?view=calendar&month=2026-11`, { headers: { Cookie: editor.cookie } })).text();
    assert.ok(calHtml.includes('Phoenix Schedule Calendar: 2026-11'));
    assert.ok(calHtml.includes('Accessible Calendar Schedule List'));

    const campArch = await fetch(`${baseUrl}/admin/api/campaigns/${campId}/archive`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    assert.equal(campArch.status, 200);
    assert.equal((await db.prepare('SELECT activation_state FROM campaigns WHERE campaign_id = ?').get(campId)).activation_state, 'Archived');

    // 2. Projects & Media: focal point, gallery order, edit project narrative, pre-withdraw usage check
    const mediaFd = new FormData();
    mediaFd.append('csrf_token', editor.csrf);
    mediaFd.append('rights_owner', 'Promptitude Photo');
    mediaFd.append('alt_text', 'Warehouse bay door repair');
    mediaFd.append('photos', new Blob([makePngBytes(800, 600)], { type: 'image/png' }), 'gal1.png');
    mediaFd.append('photos', new Blob([makePngBytes(800, 600)], { type: 'image/png' }), 'gal2.png');
    const upRes = await fetch(`${baseUrl}/admin/api/media/upload`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'X-CSRF-Token': editor.csrf },
      body: mediaFd,
    });
    assert.equal(upRes.status, 201);
    const { accepted: upAssets } = await upRes.json();

    const focalRes = await fetch(`${baseUrl}/admin/api/media/${upAssets[0].asset_id}/focal-point`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf, focal_x: 25, focal_y: 75 }),
    });
    assert.equal(focalRes.status, 200);
    const assetUpdated = await db.prepare('SELECT focal_x, focal_y FROM media_assets WHERE asset_id = ?').get(upAssets[0].asset_id);
    assert.equal(assetUpdated.focal_x, 25);
    assert.equal(assetUpdated.focal_y, 75);

    const existingProj = await db.prepare('SELECT * FROM projects LIMIT 1').get();
    const editProjRes = await fetch(`${baseUrl}/admin/api/projects/${existingProj.project_id}`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        agreed_scope: 'Updated Warehouse Concrete & Bollard Scope',
      }),
    });
    assert.equal(editProjRes.status, 200);

    const g1 = await (await fetch(`${baseUrl}/admin/api/projects/${existingProj.project_id}/gallery`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf, asset_id: upAssets[0].asset_id, caption: 'First shot' }),
    })).json();
    const g2 = await (await fetch(`${baseUrl}/admin/api/projects/${existingProj.project_id}/gallery`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf, asset_id: upAssets[1].asset_id, caption: 'Second shot' }),
    })).json();
    await fetch(`${baseUrl}/admin/api/projects/${existingProj.project_id}/gallery/${g2.item_id}/move?dir=up`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf }),
    });
    const galOrder = await db.prepare('SELECT item_id FROM project_gallery_items WHERE project_id = ? ORDER BY sort_order ASC').all(existingProj.project_id);
    assert.equal(galOrder[0].item_id, g2.item_id);

    const usageJson = await (await fetch(`${baseUrl}/admin/api/media/${upAssets[0].asset_id}/usage`, { headers: { Cookie: publisher.cookie } })).json();
    assert.ok(usageJson.totalAffected >= 1);

    // 3. CMS Articles, Claims, Revision Diff & Mobile Preview
    const artRes = await (await fetch(`${baseUrl}/admin/api/articles`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        slug: 'day-porter-checklist',
        title: 'Commercial Day Porter Checklist',
        buyer_target: 'Property managers',
        summary: 'Key daily site tasks for retail centers.',
        body_html: '<p>Inspect walkways and receptacles.</p>',
        sources_note: 'Operations SOP',
      }),
    })).json();
    assert.ok(artRes.article_id);
    await fetch(`${baseUrl}/admin/api/articles/${artRes.article_id}/publish`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    const pubInsight = await fetch(`${baseUrl}/insights/day-porter-checklist/`);
    assert.equal(pubInsight.status, 200);

    const clRes = await (await fetch(`${baseUrl}/admin/api/claims`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        claim_type: 'testimonial',
        title: 'Phoenix Retail Manager Quote',
        exact_text: 'Consistent day porter coverage across our retail suite.',
        attribution: 'Regional Property Director',
        evidence_source: 'Signed Client Email 2026-10',
      }),
    })).json();
    await fetch(`${baseUrl}/admin/api/claims/${clRes.claim_id}/approve`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    assert.equal(
      (await db.prepare('SELECT status FROM testimonials_claims WHERE claim_id = ?').get(clRes.claim_id)).status,
      'approved for publication'
    );

    const homePage = await db.prepare(`SELECT page_id, current_revision FROM pages WHERE slug = '/'`).get();
    if (homePage.current_revision >= 2) {
      const cmp = await (await fetch(`${baseUrl}/admin/api/pages/${homePage.page_id}/compare?revA=1&revB=${homePage.current_revision}`, {
        headers: { Cookie: editor.cookie },
      })).json();
      assert.equal(cmp.ok, true);
      assert.ok(Array.isArray(cmp.diffs));
    }
    const mobilePrevHtml = await (await fetch(`${baseUrl}/admin/preview?path=/&viewport=mobile`, { headers: { Cookie: editor.cookie } })).text();
    assert.ok(mobilePrevHtml.includes('Mobile 390px'));
    assert.ok(mobilePrevHtml.includes('preview-viewport-frame'));

    // 4. Leads: Inquiry attachment secure view/download + permission + audit
    const inqFd = new FormData();
    inqFd.append('idempotency_key', 'phase3-inq-att-001');
    inqFd.append('name', 'RFP Sender');
    inqFd.append('company', 'Sonoran Holdings');
    inqFd.append('preferred_contact_method', 'email');
    inqFd.append('email', 'rfp@sonoran.example');
    inqFd.append('service_needed', 'tenant-improvements');
    inqFd.append('property_city_or_zip', 'Scottsdale 85251');
    inqFd.append('description', 'Suite 200 build-out scope.');
    inqFd.append('attachments', new Blob([Buffer.from('%PDF-1.4\n%RFP Scope\n%%EOF')], { type: 'application/pdf' }), 'suite200-rfp.pdf');

    const inqResp = await fetch(`${baseUrl}/api/inquiries`, { method: 'POST', body: inqFd });
    assert.equal(inqResp.status, 201);
    const { inquiry_id: attInqId } = await inqResp.json();
    const inqAtt = await db.prepare('SELECT * FROM inquiry_attachments WHERE inquiry_id = ?').get(attInqId);
    assert.ok(inqAtt);

    // Editor cannot access Lead inquiry attachment (403); Admin downloads & audits (200)
    const denyInqAtt = await fetch(`${baseUrl}/admin/api/inquiries/${attInqId}/attachments/${inqAtt.attachment_id}`, {
      headers: { Cookie: editor.cookie },
    });
    assert.equal(denyInqAtt.status, 403);

    const okInqAtt = await fetch(`${baseUrl}/admin/api/inquiries/${attInqId}/attachments/${inqAtt.attachment_id}`, {
      headers: { Cookie: admin.cookie },
    });
    assert.equal(okInqAtt.status, 200);
    assert.ok((await okInqAtt.text()).startsWith('%PDF-1.4'));
    const attAudit = await db
      .prepare(`SELECT action FROM audit_log WHERE domain = 'crm' AND object_id = ?`)
      .get(inqAtt.attachment_id);
    assert.equal(attAudit.action, 'download_inquiry_attachment');
  });

  await t.test('PHASE-4-MEDIA: EXIF orientation rotation, responsive WebP/JPEG generation & HEIC conversion', async () => {
    const editor = await loginAs(baseUrl, 'editor@smiaz.local');
    const publisher = await loginAs(baseUrl, 'publisher@smiaz.local');

    // 1. Create real JPEG 800x600 with EXIF orientation = 6 (90 deg CW -> must become upright 600x800!) + EXIF metadata
    const exifJpgBuf = await sharp({
      create: { width: 800, height: 600, channels: 3, background: { r: 107, g: 48, b: 38 } },
    })
      .jpeg({ quality: 85 })
      .withMetadata({ orientation: 6, exif: { IFD0: { ImageDescription: 'SENSITIVE_SITE_GPS_XYZ' } } })
      .toBuffer();

    const fd = new FormData();
    fd.append('csrf_token', editor.csrf);
    fd.append('rights_owner', 'Field Supervisor');
    fd.append('alt_text', 'Rotated jobsite photo');
    fd.append('photos', new Blob([exifJpgBuf], { type: 'image/jpeg' }), 'portrait-iphone.jpg');

    const upRes = await fetch(`${baseUrl}/admin/api/media/upload`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'X-CSRF-Token': editor.csrf },
      body: fd,
    });
    assert.equal(upRes.status, 201);
    const { accepted } = await upRes.json();
    assert.equal(accepted.length, 1);
    const asset = accepted[0];

    // Normalized upright dimensions after EXIF orientation 6 rotation: width=600, height=800
    assert.equal(asset.width, 600);
    assert.equal(asset.height, 800);
    assert.equal(asset.orientation, 6);
    assert.equal(asset.normalized_orientation, 1);

    // Responsive desktop, tablet & mobile WebP/JPEG variants exist on disk and metadata is stripped
    for (const sz of ['desktop', 'tablet', 'mobile']) {
      const wKey = asset.variants.webp[sz];
      const jKey = asset.variants.jpeg[sz];
      assert.ok(fs.existsSync(path.join(storageRoot, 'public', 'media', wKey)));
      assert.ok(fs.existsSync(path.join(storageRoot, 'public', 'media', jKey)));
    }
    const cleanDesktopJpg = fs.readFileSync(path.join(storageRoot, 'public', 'media', asset.variants.jpeg.desktop));
    assert.equal(cleanDesktopJpg.toString('latin1').includes('SENSITIVE_SITE_GPS_XYZ'), false);
    const cleanMeta = await sharp(cleanDesktopJpg).metadata();
    assert.equal(cleanMeta.exif, undefined);

    // 2. HEIC conversion pipeline -> produces clean WebP/JPEG responsive derivatives
    const heicFakeContainer = Buffer.concat([Buffer.from('\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heic'), Buffer.alloc(32)]);
    const cleanTargetJpg = await sharp({
      create: { width: 1200, height: 900, channels: 3, background: { r: 244, g: 240, b: 232 } },
    })
      .jpeg()
      .toBuffer();

    setHeicConverter(async () => cleanTargetJpg);
    try {
      const hFd = new FormData();
      hFd.append('csrf_token', editor.csrf);
      hFd.append('rights_owner', 'Field Lead');
      hFd.append('alt_text', 'HEIC facility photo');
      hFd.append('photos', new Blob([heicFakeContainer], { type: 'image/heic' }), 'iphone-capture.heic');

      const hRes = await fetch(`${baseUrl}/admin/api/media/upload`, {
        method: 'POST',
        headers: { Cookie: editor.cookie, 'X-CSRF-Token': editor.csrf },
        body: hFd,
      });
      assert.equal(hRes.status, 201);
      const hJson = await hRes.json();
      assert.equal(hJson.accepted[0].derivative_mime, 'image/jpeg');
      assert.equal(hJson.accepted[0].width, 1200);
      assert.ok(hJson.accepted[0].variants.webp.mobile);
    } finally {
      setHeicConverter(null);
    }

    // 3. Corrupt PNG rejected strictly (never falsely accepted)
    const badFd = new FormData();
    badFd.append('csrf_token', editor.csrf);
    badFd.append('rights_owner', 'Test');
    badFd.append('alt_text', 'Corrupt');
    badFd.append('photos', new Blob([Buffer.from('\x89PNG\r\n\x1a\nCORRUPT_BODY_BYTES')], { type: 'image/png' }), 'broken.png');
    const badRes = await fetch(`${baseUrl}/admin/api/media/upload`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'X-CSRF-Token': editor.csrf },
      body: badFd,
    });
    assert.equal(badRes.status, 422);

    // 4. Approve asset, publish on project & verify public <picture> WebP variant delivery + 404 after withdrawal
    await fetch(`${baseUrl}/admin/api/media/${asset.asset_id}/approve-rights`, {
      method: 'POST',
      headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
      body: JSON.stringify({ csrf_token: publisher.csrf }),
    });
    const proj = await db.prepare(`SELECT * FROM projects WHERE editorial_state = 'Approved' LIMIT 1`).get();
    await db.prepare(`UPDATE projects SET cover_asset_id = ? WHERE project_id = ?`).run(asset.asset_id, proj.project_id);
    await db.prepare(`UPDATE media_assets SET is_public_published = 1 WHERE asset_id = ?`).run(asset.asset_id);

    const archiveHtml = await (await fetch(`${baseUrl}/projects/`)).text();
    assert.ok(archiveHtml.includes(`<source type="image/webp"`));
    assert.ok(archiveHtml.includes(asset.variants.webp.mobile));

    const webpFetch = await fetch(`${baseUrl}/media/${asset.variants.webp.mobile}`);
    assert.equal(webpFetch.status, 200);
    assert.equal(webpFetch.headers.get('content-type'), 'image/webp');
  });

  await t.test('PHASE-4-SCAN: Fail-closed malware scanning blocks EICAR and scanner outages', async () => {
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');

    // 1. EICAR test string inside uploaded PDF -> quarantined, download denied (403)
    const eicarPdf = Buffer.from(
      '%PDF-1.4\n% X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n%%EOF',
      'ascii'
    );
    const inqFd = new FormData();
    inqFd.append('idempotency_key', 'phase4-eicar-001');
    inqFd.append('name', 'Test Sender');
    inqFd.append('company', 'Security QA');
    inqFd.append('preferred_contact_method', 'email');
    inqFd.append('email', 'qa@example.org');
    inqFd.append('service_needed', 'warehouse-repairs');
    inqFd.append('property_city_or_zip', 'Phoenix 85004');
    inqFd.append('description', 'Check scan quarantine');
    inqFd.append('attachments', new Blob([eicarPdf], { type: 'application/pdf' }), 'eicar.pdf');

    const eicarResp = await fetch(`${baseUrl}/api/inquiries`, { method: 'POST', body: inqFd });
    assert.equal(eicarResp.status, 201);
    const { inquiry_id: eInqId } = await eicarResp.json();
    const eAtt = await db.prepare('SELECT * FROM inquiry_attachments WHERE inquiry_id = ?').get(eInqId);
    assert.equal(eAtt.scan_state, 'quarantined');

    const dlBlocked = await fetch(`${baseUrl}/admin/api/inquiries/${eInqId}/attachments/${eAtt.attachment_id}`, {
      headers: { Cookie: admin.cookie },
    });
    assert.equal(dlBlocked.status, 403);

    // 2. External scanner outage -> fails CLOSED (NEVER marks clean)
    setCustomMalwareScanner(async () => {
      throw new Error('clamd connection refused');
    });
    try {
      const cleanLookingPdf = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF', 'ascii');
      const failFd = new FormData();
      failFd.append('idempotency_key', 'phase4-failclosed-001');
      failFd.append('name', 'FailClosed Sender');
      failFd.append('company', 'Security QA');
      failFd.append('preferred_contact_method', 'email');
      failFd.append('email', 'qa2@example.org');
      failFd.append('service_needed', 'day-porter');
      failFd.append('property_city_or_zip', 'Tempe 85281');
      failFd.append('description', 'Check scanner failure isolation');
      failFd.append('attachments', new Blob([cleanLookingPdf], { type: 'application/pdf' }), 'doc.pdf');

      const failResp = await fetch(`${baseUrl}/api/inquiries`, { method: 'POST', body: failFd });
      assert.equal(failResp.status, 201);
      const { inquiry_id: fInqId } = await failResp.json();
      const fAtt = await db.prepare('SELECT * FROM inquiry_attachments WHERE inquiry_id = ?').get(fInqId);
      assert.equal(fAtt.scan_state, 'quarantined');
    } finally {
      setCustomMalwareScanner(null);
    }
  });

  await t.test('PHASE-4-BACKUP & RETENTION: Verified full backup/restore, tamper rejection & client-gated retention', async () => {
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');
    const editor = await loginAs(baseUrl, 'editor@smiaz.local');
    const publisher = await loginAs(baseUrl, 'publisher@smiaz.local');
    const ho = await loginAs(baseUrl, 'hiring@smiaz.local');

    // Content editor denied backup endpoints (403)
    const denyBak = await fetch(`${baseUrl}/admin/api/backups/create`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf }),
    });
    assert.equal(denyBak.status, 403);

    // Prepare state before backup: approved campaign expiring in past when restored + open job + sent notification + approved asset
    const expCampId = 'cmp-restore-exp-01';
    await db.prepare(
      `INSERT INTO campaigns (
        campaign_id, slug, internal_title, service_family, owner_name, placement_slot,
        heading, summary, cta_label, cta_destination, priority, start_at, end_at,
        editorial_state, activation_state, updated_at
      ) VALUES (?, 'restore-exp-camp', 'Expiring Campaign', 'general', 'Editor', 'notice_strip',
        'Temp Offer', 'Summary', 'Contact', '/contact/', 5, '2026-01-01T00:00:00Z', '2026-01-05T00:00:00Z',
        'Approved', 'Live', ?)`
    ).run(expCampId, new Date().toISOString());

    // Admin creates full verified backup
    const bakCreateRes = await fetch(`${baseUrl}/admin/api/backups/create`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf }),
    });
    assert.equal(bakCreateRes.status, 201);
    const bakJson = await bakCreateRes.json();
    assert.equal(bakJson.ok, true);
    assert.ok(fs.existsSync(path.join(bakJson.backup_dir, 'database.sqlite')));
    assert.ok(fs.existsSync(path.join(bakJson.backup_dir, 'manifest.json')));

    // Verify backup SHA-256 passes
    const verOk = await fetch(`${baseUrl}/admin/api/backups/${bakJson.backup_id}/verify`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf }),
    });
    assert.equal(verOk.status, 200);

    // Post-backup events: close a job, withdraw a media asset, mark a notification sent, and receive a new inquiry!
    const existingJob = await db.prepare(`SELECT * FROM jobs WHERE status = 'Open' LIMIT 1`).get();
    if (existingJob) {
      await fetch(`${baseUrl}/admin/api/jobs/${existingJob.requisition_id}/close`, {
        method: 'POST',
        headers: { Cookie: ho.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': ho.csrf },
        body: JSON.stringify({ csrf_token: ho.csrf }),
      });
    }
    const approvedMedia = await db.prepare(`SELECT * FROM media_assets WHERE rights_status = 'approved' LIMIT 1`).get();
    if (approvedMedia) {
      await fetch(`${baseUrl}/admin/api/media/${approvedMedia.asset_id}/withdraw`, {
        method: 'POST',
        headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
        body: JSON.stringify({ csrf_token: publisher.csrf }),
      });
    }
    const postInq = await fetch(`${baseUrl}/api/inquiries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        idempotency_key: 'post-backup-inq-001',
        name: 'Post Backup Client',
        company: 'Saguaro Plaza',
        preferred_contact_method: 'email',
        email: 'postbak@example.org',
        service_needed: 'day-porter',
        property_city_or_zip: 'Phoenix 85012',
        description: 'Must survive restore!',
      }),
    });
    assert.equal(postInq.status, 201);
    const { inquiry_id: postInqId } = await postInq.json();
    await db.prepare(`UPDATE notification_queue SET status = 'sent' WHERE reference_id = ?`).run(postInqId);

    // Restore from backup -> preserves postInq, preserves sent notification, keeps expired campaign Ended, keeps closed job Closed, keeps withdrawn rights!
    const restoreRes = await fetch(`${baseUrl}/admin/api/backups/${bakJson.backup_id}/restore`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf }),
    });
    assert.equal(restoreRes.status, 200);

    assert.equal((await db.prepare('SELECT activation_state FROM campaigns WHERE campaign_id = ?').get(expCampId)).activation_state, 'Ended');
    if (existingJob) {
      assert.equal((await db.prepare('SELECT status FROM jobs WHERE requisition_id = ?').get(existingJob.requisition_id)).status, 'Closed');
    }
    if (approvedMedia) {
      assert.equal((await db.prepare('SELECT rights_status FROM media_assets WHERE asset_id = ?').get(approvedMedia.asset_id)).rights_status, 'withdrawn');
    }
    assert.ok(await db.prepare('SELECT inquiry_id FROM inquiries WHERE inquiry_id = ?').get(postInqId));
    assert.equal((await db.prepare(`SELECT status FROM notification_queue WHERE reference_id = ?`).get(postInqId)).status, 'sent');

    // Tamper backup DB file -> verify & restore MUST reject fail-closed!
    const tamperedDir = bakJson.backup_dir;
    fs.appendFileSync(path.join(tamperedDir, 'database.sqlite'), Buffer.from('TAMPERED'));
    const verFail = await fetch(`${baseUrl}/admin/api/backups/${bakJson.backup_id}/verify`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf }),
    });
    assert.equal(verFail.status, 422);

    // Retention sweep BEFORE client approval skips ALL categories cleanly (does not delete!)
    const preSweep = await (
      await fetch(`${baseUrl}/admin/api/retention/run`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf }),
      })
    ).json();
    assert.equal(preSweep.skippedPendingApproval.length, 5);

    // Seed an old unheld spam inquiry + attachment (60 days old) and a legal_hold spam inquiry (60 days old)
    const oldDate = new Date(Date.now() - 400 * 86_400_000).toISOString();
    const spamInqId = 'inq-old-spam-01';
    const heldInqId = 'inq-held-spam-02';
    await db.prepare(
      `INSERT INTO inquiries (inquiry_id, idempotency_key, payload_hash, inquiry_kind, classification, service_family, routing_queue, assigned_owner, status, payload_json, attribution_json, received_at, updated_at, legal_hold)
       VALUES (?, 'old-spam-1', 'h1', 'new_business', 'spam', 'day-porter', 'q', 'o', 'disqualified', '{}', '{}', ?, ?, 0)`
    ).run(spamInqId, oldDate, oldDate);
    await db.prepare(
      `INSERT INTO inquiries (inquiry_id, idempotency_key, payload_hash, inquiry_kind, classification, service_family, routing_queue, assigned_owner, status, payload_json, attribution_json, received_at, updated_at, legal_hold)
       VALUES (?, 'held-spam-2', 'h2', 'new_business', 'spam', 'day-porter', 'q', 'o', 'disqualified', '{}', '{}', ?, ?, 1)`
    ).run(heldInqId, oldDate, oldDate);

    // Approve 365-day unqualified_prospects rule (leave recruiting_applicants_and_resumes unapproved!)
    const approveRetRes = await fetch(`${baseUrl}/admin/api/retention/policies/unqualified_prospects`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf, retention_days: 365, approved: true }),
    });
    assert.equal(approveRetRes.status, 200);

    const sweepRes = await (
      await fetch(`${baseUrl}/admin/api/retention/run`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf }),
      })
    ).json();
    assert.equal(sweepRes.purged.unqualified_prospects, 1);
    assert.equal(await db.prepare('SELECT * FROM inquiries WHERE inquiry_id = ?').get(spamInqId), undefined);
    assert.ok(await db.prepare('SELECT * FROM inquiries WHERE inquiry_id = ?').get(heldInqId));
    assert.ok(sweepRes.skippedPendingApproval.some((s) => s.policy_key === 'recruiting_applicants_and_resumes'));
  });

  await t.test('VERCEL-S3-01: Neon Object Storage S3 persistence, large >4.5MB presigned inquiry/media, and S3 backups', async () => {
    const s3Objects = new Map();
    const mockS3 = new S3Client({
      region: 'ap-southeast-1',
      endpoint: 'https://mock-neon-storage.local',
      forcePathStyle: true,
      credentials: { accessKeyId: 'testkey', secretAccessKey: 'testsecret' },
    });
    mockS3.send = async (cmd) => {
      const name = cmd.constructor?.name || '';
      const key = `${cmd.input.Bucket}/${cmd.input.Key}`;
      if (name === 'PutObjectCommand') {
        s3Objects.set(key, { Body: Buffer.from(cmd.input.Body), ContentType: cmd.input.ContentType });
        return {};
      }
      if (name === 'GetObjectCommand') {
        const obj = s3Objects.get(key);
        if (!obj) {
          const err = new Error('NoSuchKey');
          err.name = 'NoSuchKey';
          throw err;
        }
        return { Body: { transformToByteArray: async () => new Uint8Array(obj.Body) }, ContentType: obj.ContentType };
      }
      if (name === 'HeadObjectCommand') {
        if (!s3Objects.has(key)) {
          const err = new Error('NotFound');
          err.name = 'NotFound';
          throw err;
        }
        return { ContentLength: s3Objects.get(key).Body.length };
      }
      if (name === 'DeleteObjectCommand') {
        s3Objects.delete(key);
        return {};
      }
      if (name === 'ListObjectsV2Command') {
        const prefix = `${cmd.input.Bucket}/${cmd.input.Prefix || ''}`;
        const Contents = [];
        for (const [fullK, val] of s3Objects.entries()) {
          if (fullK.startsWith(prefix)) {
            Contents.push({ Key: fullK.slice(cmd.input.Bucket.length + 1), Size: val.Body.length });
          }
        }
        return { Contents, IsTruncated: false };
      }
      throw new Error(`Unsupported S3 cmd in test: ${name}`);
    };

    setCustomS3Client(mockS3);
    try {
      // 1. Forged upload token is rejected
      const forgedRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 's3-forged-1' },
        body: JSON.stringify({
          name: 'Taylor Brooks',
          company: 'Pacific Facilities LLC',
          preferred_contact_method: 'email',
          email: 'taylor@pacificfacilities.com',
          service_needed: 'day-porter',
          property_city_or_zip: 'Phoenix, AZ 85004',
          description: 'Testing forged upload token rejection.',
          staged_uploads: ['forged.invalid_sig'],
        }),
      });
      assert.equal(forgedRes.status, 422);

      // 2. Presigned large >4.5 MB PDF inquiry upload (5.1 MB)
      const largePdf = Buffer.concat([Buffer.from('%PDF-1.4\n%large\n'), Buffer.alloc(5.1 * 1024 * 1024, 0x20)]);
      const presignRes = await fetch(`${baseUrl}/api/uploads/presign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          purpose: 'inquiry',
          files: [{ name: 'site-plans.pdf', size: largePdf.length, type: 'application/pdf' }],
        }),
      });
      assert.equal(presignRes.status, 200);
      const presignJson = await presignRes.json();
      assert.equal(presignJson.mode, 's3_presigned_put');
      assert.ok(presignJson.uploads[0].url.includes('X-Amz-Signature'));

      // Simulate browser PUT directly into mock Neon Object Storage staging key
      const stagedKey = presignJson.uploads[0].stagingKey;
      s3Objects.set(`${presignJson.uploads[0].bucket}/staging/${stagedKey}`, { Body: largePdf, ContentType: 'application/pdf' });

      const inqRes = await fetch(`${baseUrl}/api/inquiries`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 's3-large-pdf-1' },
        body: JSON.stringify({
          name: 'Taylor Brooks',
          company: 'Pacific Facilities LLC',
          preferred_contact_method: 'email',
          email: 'taylor@pacificfacilities.com',
          service_needed: 'day-porter',
          property_city_or_zip: 'Phoenix, AZ 85004',
          description: 'Large 5.1 MB drawing upload via S3 presigned URL.',
          staged_uploads: [presignJson.uploads[0].upload_token],
        }),
      });
      assert.equal(inqRes.status, 201);
      const inqJson = await inqRes.json();
      // Staging object deleted after move to quarantine
      assert.equal(s3Objects.has(`${presignJson.uploads[0].bucket}/staging/${stagedKey}`), false);

      const admin = await loginAs(baseUrl, 'admin@smiaz.local');
      const attRow = await db.prepare('SELECT * FROM inquiry_attachments WHERE inquiry_id = ?').get(inqJson.inquiry_id);
      assert.equal(attRow.byte_size, largePdf.length);
      const dlRes = await fetch(`${baseUrl}/admin/api/inquiries/${inqJson.inquiry_id}/attachments/${attRow.attachment_id}`, {
        headers: { Cookie: admin.cookie },
      });
      assert.equal(dlRes.status, 200);
      const dlBuf = Buffer.from(await dlRes.arrayBuffer());
      assert.equal(dlBuf.length, largePdf.length);

      // 3. Admin Media presign + finalize + public /media/<key> serving from S3
      const pub = await loginAs(baseUrl, 'publisher@smiaz.local');
      const pngBytes = await sharp({
        create: { width: 320, height: 240, channels: 3, background: { r: 70, g: 90, b: 110 } },
      })
        .png()
        .toBuffer();

      const mPre = await fetch(`${baseUrl}/admin/api/media/presign`, {
        method: 'POST',
        headers: { Cookie: pub.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': pub.csrf },
        body: JSON.stringify({ csrf_token: pub.csrf, files: [{ name: 'exterior.png', size: pngBytes.length, type: 'image/png' }] }),
      });
      assert.equal(mPre.status, 200);
      const mPreJson = await mPre.json();
      assert.equal(mPreJson.mode, 's3_presigned_put');
      s3Objects.set(`${mPreJson.uploads[0].bucket}/staging/${mPreJson.uploads[0].stagingKey}`, {
        Body: pngBytes,
        ContentType: 'image/png',
      });

      const mFin = await fetch(`${baseUrl}/admin/api/media/finalize`, {
        method: 'POST',
        headers: { Cookie: pub.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': pub.csrf },
        body: JSON.stringify({
          csrf_token: pub.csrf,
          alt_text: 'S3 Finalized Photo',
          rights_owner: 'Service Maintenance',
          staged_files: [{ stagingKey: mPreJson.uploads[0].stagingKey, originalName: 'exterior.png' }],
        }),
      });
      assert.equal(mFin.status, 201);
      const mFinJson = await mFin.json();
      const assetId = mFinJson.accepted[0].asset_id;
      const derKey = mFinJson.accepted[0].public_derivative_key;

      await fetch(`${baseUrl}/admin/api/media/${assetId}/approve-rights`, {
        method: 'POST',
        headers: { Cookie: pub.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': pub.csrf },
        body: JSON.stringify({ csrf_token: pub.csrf }),
      });
      await db.prepare('UPDATE media_assets SET is_public_published = 1 WHERE asset_id = ?').run(assetId);
      const mediaServe = await fetch(`${baseUrl}/media/${derKey}`);
      assert.equal(mediaServe.status, 200);
      assert.equal(mediaServe.headers.get('content-type'), 'image/jpeg');

      // 4. S3 Backup & Integrity Verify
      const bakRes = await (
        await fetch(`${baseUrl}/admin/api/backups/create`, {
          method: 'POST',
          headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
          body: JSON.stringify({ csrf_token: admin.csrf }),
        })
      ).json();
      assert.equal(bakRes.ok, true);
      assert.ok(bakRes.backup_dir.startsWith('s3:backup-'));
      const verRes = await (
        await fetch(`${baseUrl}/admin/api/backups/${bakRes.backup_id}/verify`, {
          method: 'POST',
          headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
          body: JSON.stringify({ csrf_token: admin.csrf }),
        })
      ).json();
      assert.equal(verRes.ok, true);
    } finally {
      setCustomS3Client(null);
    }
  });

  await t.test('VERCEL-CRON-02: /api/health and /api/cron/worker require valid CRON_SECRET', async () => {
    const prevCron = process.env.CRON_SECRET;
    process.env.CRON_SECRET = 'cron-test-secret-xyz-123456';
    try {
      const health = await (await fetch(`${baseUrl}/api/health`)).json();
      assert.equal(health.ok, true);
      assert.equal(health.dialect, 'sqlite');

      const unauth = await fetch(`${baseUrl}/api/cron/worker`);
      assert.equal(unauth.status, 401);

      const authRes = await fetch(`${baseUrl}/api/cron/worker`, {
        headers: { Authorization: 'Bearer cron-test-secret-xyz-123456' },
      });
      assert.equal(authRes.status, 200);
      const authJson = await authRes.json();
      assert.equal(authJson.ok, true);
      assert.equal(authJson.schedule.ok, true);
    } finally {
      if (prevCron === undefined) delete process.env.CRON_SECRET;
      else process.env.CRON_SECRET = prevCron;
    }
  });

  await t.test('PHASE-4-RBAC: Granular 7-role matrix, multi-role reviewer fix, last_login_at, Return to Draft & escalation audit', async () => {
    const { resetRateLimitBuckets, syncAuthPolicyState } = await import('../src/services/auth.js');
    const prevMfaFlag = process.env.ADMIN_MFA_REQUIRED;
    process.env.ADMIN_MFA_REQUIRED = 'true';
    resetRateLimitBuckets();
    loginCache.clear();
    await syncAuthPolicyState(db);

    try {
      const admin = await loginAs(baseUrl, 'admin@smiaz.local');
      const editor = await loginAs(baseUrl, 'editor@smiaz.local');
      const publisher = await loginAs(baseUrl, 'publisher@smiaz.local');
      const hiringOwner = await loginAs(baseUrl, 'hiring@smiaz.local');
      const reviewer = await loginAs(baseUrl, 'reviewer@smiaz.local');
      const contributor = await loginAs(baseUrl, 'projects@smiaz.local');
      const analyst = await loginAs(baseUrl, 'analyst@smiaz.local');

      // 1. last_login_at persisted cleanly on login + readable via GET /admin/api/users/:id without leaking secrets
      const usersApiRes = await fetch(`${baseUrl}/admin/api/users`, { headers: { Cookie: admin.cookie } });
      assert.equal(usersApiRes.status, 200);
      const usersApiJson = await usersApiRes.json();
      assert.ok(Array.isArray(usersApiJson.users) && usersApiJson.users.length >= 7);
      const editorRow = usersApiJson.users.find((u) => u.email === 'editor@smiaz.local');
      assert.ok(editorRow && editorRow.last_login_at);
      assert.equal(editorRow.password_hash, undefined);
      assert.equal(editorRow.totp_secret, undefined);

      // Non-admins strictly denied GET /admin/api/users & GET /admin/api/users/:id & /admin/users
      for (const nonAdmin of [editor, publisher, hiringOwner, reviewer, contributor, analyst]) {
        assert.equal((await fetch(`${baseUrl}/admin/users`, { headers: { Cookie: nonAdmin.cookie } })).status, 403);
        assert.equal((await fetch(`${baseUrl}/admin/api/users`, { headers: { Cookie: nonAdmin.cookie } })).status, 403);
        assert.equal((await fetch(`${baseUrl}/admin/api/users/usr-editor-01`, { headers: { Cookie: nonAdmin.cookie } })).status, 403);
      }

      // 2. All 7 roles enforced server-side on pages + granular APIs
      // Platform Admin: can view /admin/pages & compare read-only, denied draft/publish/return-draft & denied hiring & denied analytics mutation
      assert.equal((await fetch(`${baseUrl}/admin/pages`, { headers: { Cookie: admin.cookie } })).status, 200);
      assert.equal((await fetch(`${baseUrl}/admin/api/pages/pg-home/compare?revA=1&revB=1`, { headers: { Cookie: admin.cookie } })).status, 200);
      assert.equal(
        (await fetch(`${baseUrl}/admin/api/pages/pg-home/draft`, {
          method: 'POST',
          headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
          body: JSON.stringify({ csrf_token: admin.csrf, expected_revision: 1, title: 'Blocked Admin Edit' }),
        })).status,
        403
      );
      assert.equal((await fetch(`${baseUrl}/admin/jobs`, { headers: { Cookie: admin.cookie } })).status, 403);
      assert.equal((await fetch(`${baseUrl}/admin/api/applications/export.csv`, { headers: { Cookie: admin.cookie } })).status, 403);

      // Analyst: ONLY /admin/ & /admin/analytics allowed; denied pages, projects, campaigns, leads, jobs, reviews, settings, users
      assert.equal((await fetch(`${baseUrl}/admin/analytics`, { headers: { Cookie: analyst.cookie } })).status, 200);
      for (const blockedPath of ['/admin/pages', '/admin/projects', '/admin/campaigns', '/admin/leads', '/admin/jobs', '/admin/reviews', '/admin/settings', '/admin/users']) {
        assert.equal((await fetch(`${baseUrl}${blockedPath}`, { headers: { Cookie: analyst.cookie } })).status, 403, `Analyst must get 403 on ${blockedPath}`);
      }

      // Project Contributor: denied pages/preview & hiring, allowed projects upload/draft, denied project publish
      assert.equal((await fetch(`${baseUrl}/admin/pages`, { headers: { Cookie: contributor.cookie } })).status, 403);
      assert.equal((await fetch(`${baseUrl}/admin/preview?path=/`, { headers: { Cookie: contributor.cookie } })).status, 403);
      assert.equal((await fetch(`${baseUrl}/admin/jobs`, { headers: { Cookie: contributor.cookie } })).status, 403);

      // Hiring Reviewer: allowed /admin/jobs (scoped), strictly denied CSV export, vacancy creation, and CMS/CRM/Settings
      assert.equal((await fetch(`${baseUrl}/admin/jobs`, { headers: { Cookie: reviewer.cookie } })).status, 200);
      assert.equal((await fetch(`${baseUrl}/admin/api/applications/export.csv`, { headers: { Cookie: reviewer.cookie } })).status, 403);
      assert.equal(
        (await fetch(`${baseUrl}/admin/api/jobs`, {
          method: 'POST',
          headers: { Cookie: reviewer.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': reviewer.csrf },
          body: JSON.stringify({ csrf_token: reviewer.csrf, title: 'Blocked', slug: 'blocked' }),
        })).status,
        403
      );
      assert.equal((await fetch(`${baseUrl}/admin/pages`, { headers: { Cookie: reviewer.cookie } })).status, 403);

      // Hiring Owner: allowed /admin/jobs & export CSV, denied CMS/CRM/Settings
      assert.equal((await fetch(`${baseUrl}/admin/jobs`, { headers: { Cookie: hiringOwner.cookie } })).status, 200);
      assert.equal((await fetch(`${baseUrl}/admin/api/applications/export.csv`, { headers: { Cookie: hiringOwner.cookie } })).status, 200);
      assert.equal((await fetch(`${baseUrl}/admin/leads`, { headers: { Cookie: hiringOwner.cookie } })).status, 403);

      // 3. Return to Draft workflow with review comments + audit logging
      const pageBefore = await db.prepare('SELECT current_revision, published_revision FROM pages WHERE page_id = ?').get('pg-about');
      const submitRes = await fetch(`${baseUrl}/admin/api/pages/pg-about/submit-review`, {
        method: 'POST',
        headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
        body: JSON.stringify({ csrf_token: editor.csrf }),
      });
      assert.equal(submitRes.status, 200);

      // Content Editor cannot invoke return-draft (403)
      const edReturn = await fetch(`${baseUrl}/admin/api/pages/pg-about/return-draft`, {
        method: 'POST',
        headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
        body: JSON.stringify({ csrf_token: editor.csrf, review_comment: 'Unauthorized' }),
      });
      assert.equal(edReturn.status, 403);

      // Publisher missing review_comment rejected (422)
      const emptyReturn = await fetch(`${baseUrl}/admin/api/pages/pg-about/return-draft`, {
        method: 'POST',
        headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
        body: JSON.stringify({ csrf_token: publisher.csrf, review_comment: '   ' }),
      });
      assert.equal(emptyReturn.status, 422);

      // Publisher valid return-draft succeeds, preserves published_revision, persists review_comment & audit entry
      const okReturn = await fetch(`${baseUrl}/admin/api/pages/pg-about/return-draft`, {
        method: 'POST',
        headers: { Cookie: publisher.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': publisher.csrf },
        body: JSON.stringify({ csrf_token: publisher.csrf, review_comment: 'Please clarify 1989 vs 2020 transition wording.' }),
      });
      assert.equal(okReturn.status, 200);
      const pgAfter = await db.prepare('SELECT editorial_state, published_revision FROM pages WHERE page_id = ?').get('pg-about');
      assert.equal(pgAfter.editorial_state, 'Draft');
      assert.equal(pgAfter.published_revision, pageBefore.published_revision);
      const revRow = await db.prepare('SELECT editorial_state, review_comment FROM page_revisions WHERE page_id = ? AND revision_number = ?').get('pg-about', pageBefore.current_revision);
      assert.equal(revRow.editorial_state, 'Draft');
      assert.ok(revRow.review_comment.includes('1989 vs 2020'));
      const retAudit = await db.prepare(`SELECT * FROM audit_log WHERE domain = 'content' AND action = 'return_page_draft' AND object_id = 'pg-about' ORDER BY created_at DESC LIMIT 1`).get();
      assert.ok(retAudit);

      // 4. Role validation + multi-role Hiring Reviewer bug fix + hiring_privilege_granted audit
      const badRoleRes = await fetch(`${baseUrl}/admin/api/users/usr-analyst-01`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf, role: 'Analyst', extra_roles: ['SuperUser999'] }),
      });
      assert.equal(badRoleRes.status, 422);

      // Grant Hiring Reviewer as extra role to Priya Nair (Analyst) -> MUST appear in /admin/jobs reviewer dropdown & log hiring_privilege_granted!
      const grantHrRes = await fetch(`${baseUrl}/admin/api/users/usr-analyst-01`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf, role: 'Analyst', extra_roles: ['Hiring Reviewer'] }),
      });
      assert.equal(grantHrRes.status, 200);

      const jobsPageHtml = await (await fetch(`${baseUrl}/admin/jobs?job=REQ-TEST-01&app=${(await db.prepare('SELECT application_id FROM applications LIMIT 1').get())?.application_id || ''}`, {
        headers: { Cookie: hiringOwner.cookie },
      })).text();
      if (jobsPageHtml.includes('id="app-rev"')) {
        assert.ok(jobsPageHtml.includes('Priya Nair'));
      }

      const privAudit = await db.prepare(`SELECT details_json FROM audit_log WHERE domain = 'users' AND action = 'update_user' AND object_id = 'usr-analyst-01' ORDER BY created_at DESC LIMIT 1`).get();
      assert.ok(privAudit && privAudit.details_json.includes('"hiring_privilege_granted":true'));

      // Non-admin escalation attempt blocked
      const escAttempt = await fetch(`${baseUrl}/admin/api/users/usr-editor-01`, {
        method: 'POST',
        headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
        body: JSON.stringify({ csrf_token: editor.csrf, role: 'Platform Administrator', extra_roles: ['Hiring Owner'] }),
      });
      assert.equal(escAttempt.status, 403);

      // Restore Analyst role cleanly for downstream tests
      await fetch(`${baseUrl}/admin/api/users/usr-analyst-01`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf, role: 'Analyst', extra_roles: [] }),
      });
    } finally {
      if (prevMfaFlag === undefined) delete process.env.ADMIN_MFA_REQUIRED;
      else process.env.ADMIN_MFA_REQUIRED = prevMfaFlag;
      loginCache.clear();
    }
  });

  await t.test('MFA-ENROLL-01: First-time Google Authenticator enrollment denies unauthorized callers and enforces password + TOTP', async () => {
    const prevMfaFlag = process.env.ADMIN_MFA_REQUIRED;
    process.env.ADMIN_MFA_REQUIRED = 'true';
    loginCache.clear();
    try {
      const { issueMfaSetupToken, syncAuthPolicyState } = await import('../src/services/auth.js');
      await syncAuthPolicyState(db);
      const editor = await loginAs(baseUrl, 'editor@smiaz.local');

    // Prepare an un-enrolled staff/admin state on usr-admin-01 for first-time enrollment verification
    await db
      .prepare(`UPDATE users SET mfa_enrolled = 0, mfa_enrolled_at = NULL, mfa_pending_secret = NULL WHERE user_id = 'usr-admin-01'`)
      .run();

    // 1. Visiting GET /admin/mfa-setup unauthenticated NEVER reveals QR code or secret
    const getUnauth = await fetch(`${baseUrl}/admin/mfa-setup`);
    assert.equal(getUnauth.status, 200);
    const getUnauthHtml = await getUnauth.text();
    assert.equal(getUnauthHtml.includes('data:image/svg+xml;base64,'), false);
    assert.equal(getUnauthHtml.includes('JBSWY3DPEHPK3PXP'), false);
    const setupCsrfCookie = (getUnauth.headers.getSetCookie?.() || [getUnauth.headers.get('set-cookie')]).find((c) => c?.startsWith('sm_mfa_csrf=')).split(';')[0];
    const formCsrf = getUnauthHtml.match(/name="csrf_token" value="([^"]+)"/)[1];

    // 2. Unauthorized attempt WITHOUT token/session (even with valid password!) MUST BE DENIED (403)
    const unauthBegin = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: setupCsrfCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: formCsrf,
        step: 'begin',
        email: 'admin@smiaz.local',
        password: 'SM-Staff-2026!',
      }).toString(),
    });
    assert.equal(unauthBegin.status, 403);
    const unauthRow = await db.prepare(`SELECT mfa_enrolled, mfa_pending_secret FROM users WHERE user_id = 'usr-admin-01'`).get();
    assert.equal(unauthRow.mfa_enrolled, 0);
    assert.equal(unauthRow.mfa_pending_secret, null);

    // 3. Non-admin staff CANNOT issue recovery/setup links (403 Forbidden)
    const nonAdminIssue = await fetch(`${baseUrl}/admin/api/users/usr-admin-01/mfa-recovery-token`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({ csrf_token: editor.csrf }),
    });
    assert.equal(nonAdminIssue.status, 403);

    // 4. Forged/invalid setup token is rejected (403)
    const forgedGet = await fetch(`${baseUrl}/admin/mfa-setup?token=forged-invalid-token-1234567890`);
    assert.equal(forgedGet.status, 403);

    // 5. Issue single-use authorized first-time enrollment token & verify raw token is hashed in DB
    const issued = await issueMfaSetupToken(db, {
      userId: 'usr-admin-01',
      purpose: 'first_time_enroll',
      issuedBy: 'operator-cli',
      ttlMinutes: 15,
    });
    assert.equal(issued.ok, true);
    const tokenDbRow = await db.prepare('SELECT token_hash, used_at FROM mfa_recovery_tokens WHERE token_id = ?').get(issued.tokenId);
    assert.notEqual(tokenDbRow.token_hash, issued.rawToken);
    assert.equal(tokenDbRow.used_at, null);

    const tokenGet = await fetch(`${baseUrl}/admin/mfa-setup?token=${encodeURIComponent(issued.rawToken)}`);
    assert.equal(tokenGet.status, 200);
    const tokenGetHtml = await tokenGet.text();
    assert.equal(tokenGetHtml.includes('data:image/svg+xml;base64,'), false);
    const step1CsrfCookie = (tokenGet.headers.getSetCookie?.() || [tokenGet.headers.get('set-cookie')]).find((c) => c?.startsWith('sm_mfa_csrf=')).split(';')[0];
    const step1Csrf = tokenGetHtml.match(/name="csrf_token" value="([^"]+)"/)[1];

    // 6. Wrong password fails identity verification (401) without revealing QR
    const wrongPassRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: step1CsrfCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: step1Csrf,
        step: 'begin',
        email: 'admin@smiaz.local',
        password: 'WrongPassword!123',
        setup_token: issued.rawToken,
      }).toString(),
    });
    assert.equal(wrongPassRes.status, 401);
    const step1RetryCsrfCookie = (wrongPassRes.headers.getSetCookie?.() || [wrongPassRes.headers.get('set-cookie')]).find((c) => c?.startsWith('sm_mfa_csrf=')).split(';')[0];
    const step1RetryHtml = await wrongPassRes.text();
    const step1RetryCsrf = step1RetryHtml.match(/name="csrf_token" value="([^"]+)"/)[1];

    // 7. Correct password reveals QR SVG data URI + formatted manual setup key & stores encrypted pending secret
    const beginOkRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: step1RetryCsrfCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: step1RetryCsrf,
        step: 'begin',
        email: 'admin@smiaz.local',
        password: 'SM-Staff-2026!',
        setup_token: issued.rawToken,
      }).toString(),
    });
    assert.equal(beginOkRes.status, 200);
    const step2Html = await beginOkRes.text();
    assert.ok(step2Html.includes('data:image/svg+xml;base64,'));
    const secretMatch = step2Html.match(/<code[^>]*>([A-Z2-7 ]{16,})<\/code>/);
    assert.ok(secretMatch);
    const enrolledManualSecret = secretMatch[1].replace(/\s+/g, '');
    const step2Csrf = step2Html.match(/name="csrf_token" value="([^"]+)"/)[1];
    const step2Cookies = (beginOkRes.headers.getSetCookie?.() || [beginOkRes.headers.get('set-cookie')])
      .map((c) => c.split(';')[0])
      .join('; ');

    const dbPendingRow = await db.prepare(`SELECT mfa_pending_secret FROM users WHERE user_id = 'usr-admin-01'`).get();
    assert.ok(dbPendingRow.mfa_pending_secret.startsWith('enc:v1:'));

    // 8. Wrong TOTP code fails confirmation (422) and leaves token unconsumed
    const badTotpRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: step2Cookies, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: step2Csrf,
        step: 'confirm',
        totp_code: '000000',
      }).toString(),
    });
    assert.equal(badTotpRes.status, 422);

    // 9. Valid 6-digit TOTP code activates encrypted secret, consumes token, issues session & recovery codes
    const validTotp = generateTotpCode(enrolledManualSecret);
    const confirmOkRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: step2Cookies, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: step2Csrf,
        step: 'confirm',
        totp_code: validTotp,
      }).toString(),
    });
    assert.equal(confirmOkRes.status, 200);
    const completeHtml = await confirmOkRes.text();
    assert.ok(completeHtml.includes('Google Authenticator Enrolled'));
    const recCodeMatch = completeHtml.match(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{2}/);
    assert.ok(recCodeMatch);
    const savedRecoveryCode = recCodeMatch[0];

    const enrolledSessionCookie = (confirmOkRes.headers.getSetCookie?.() || [confirmOkRes.headers.get('set-cookie')])
      .find((c) => c?.startsWith('sm_staff_session='))
      .split(';')[0];
    assert.ok(enrolledSessionCookie);

    // Replaying the same single-use token is now rejected (403)
    const replayTokenGet = await fetch(`${baseUrl}/admin/mfa-setup?token=${encodeURIComponent(issued.rawToken)}`);
    assert.equal(replayTokenGet.status, 403);

    // Verify encrypted DB state + dashboard session persistence
    const updatedUserRow = await db.prepare(`SELECT totp_secret, mfa_enrolled, mfa_pending_secret, recovery_codes_json FROM users WHERE user_id = 'usr-admin-01'`).get();
    assert.equal(updatedUserRow.mfa_enrolled, 1);
    assert.equal(updatedUserRow.mfa_pending_secret, null);
    assert.ok(updatedUserRow.totp_secret.startsWith('enc:v1:'));
    assert.equal(updatedUserRow.recovery_codes_json.includes(savedRecoveryCode.replace(/-/g, '')), false);

    const dashAfterEnroll = await fetch(`${baseUrl}/admin/`, { headers: { Cookie: enrolledSessionCookie }, redirect: 'manual' });
    assert.equal(dashAfterEnroll.status, 200);
    const dashHtml = await dashAfterEnroll.text();
    const dashCsrf = dashHtml.match(/data-csrf="([^"]+)"/)[1];

    // Logout & verify login succeeds ONLY with new Google Authenticator TOTP, rejecting old secret
    await fetch(`${baseUrl}/admin/logout`, {
      method: 'POST',
      headers: { Cookie: enrolledSessionCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ csrf_token: dashCsrf }).toString(),
    });
    const freshLoginOk = await fetch(`${baseUrl}/admin/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        email: 'admin@smiaz.local',
        password: 'SM-Staff-2026!',
        totp_code: generateTotpCode(enrolledManualSecret),
      }).toString(),
    });
    assert.equal(freshLoginOk.status, 302);
    const freshCookie = freshLoginOk.headers.get('set-cookie').split(';')[0];

    // Store recovery code & session cookie on db context via local variable check in MFA-RECOVER-02:
    const recoverPageGet = await fetch(`${baseUrl}/admin/mfa-setup`);
    const recCsrfCookie = (recoverPageGet.headers.getSetCookie?.() || [recoverPageGet.headers.get('set-cookie')]).find((c) => c?.startsWith('sm_mfa_csrf=')).split(';')[0];
    const recFormCsrf = (await recoverPageGet.text()).match(/name="csrf_token" value="([^"]+)"/)[1];

    // MFA-RECOVER-02: Recover using password + single-use recovery code -> rotates secret, invalidates old sessions, blocks code reuse
    const recBeginRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: recCsrfCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: recFormCsrf,
        step: 'begin',
        email: 'admin@smiaz.local',
        password: 'SM-Staff-2026!',
        recovery_code: savedRecoveryCode,
      }).toString(),
    });
    assert.equal(recBeginRes.status, 200);
    const recStep2Html = await recBeginRes.text();
    const recSecret = recStep2Html.match(/<code[^>]*>([A-Z2-7 ]{16,})<\/code>/)[1].replace(/\s+/g, '');
    assert.notEqual(recSecret, enrolledManualSecret);
    const recStep2Csrf = recStep2Html.match(/name="csrf_token" value="([^"]+)"/)[1];
    const recStep2Cookies = (recBeginRes.headers.getSetCookie?.() || [recBeginRes.headers.get('set-cookie')])
      .map((c) => c.split(';')[0])
      .join('; ');

    const recConfirmRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: recStep2Cookies, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: recStep2Csrf,
        step: 'confirm',
        totp_code: generateTotpCode(recSecret),
      }).toString(),
    });
    assert.equal(recConfirmRes.status, 200);

    // Prior session MUST be revoked after MFA recovery!
    const oldSessAfterRec = await fetch(`${baseUrl}/admin/`, { headers: { Cookie: freshCookie }, redirect: 'manual' });
    assert.equal(oldSessAfterRec.status, 302);

    // Reusing the same recovery code MUST be rejected!
    const recReuseGet = await fetch(`${baseUrl}/admin/mfa-setup`);
    const reuseCsrfCookie = (recReuseGet.headers.getSetCookie?.() || [recReuseGet.headers.get('set-cookie')]).find((c) => c?.startsWith('sm_mfa_csrf=')).split(';')[0];
    const reuseCsrf = (await recReuseGet.text()).match(/name="csrf_token" value="([^"]+)"/)[1];
    const reuseRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: reuseCsrfCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: reuseCsrf,
        step: 'begin',
        email: 'admin@smiaz.local',
        password: 'SM-Staff-2026!',
        recovery_code: savedRecoveryCode,
      }).toString(),
    });
    assert.equal(reuseRes.status, 403);

    // Platform Admin can issue a recovery link for another enrolled user via dashboard API
    const newSessionCookie = (recConfirmRes.headers.getSetCookie?.() || [recConfirmRes.headers.get('set-cookie')])
      .find((c) => c?.startsWith('sm_staff_session='))
      .split(';')[0];
    const newDashHtml = await (await fetch(`${baseUrl}/admin/`, { headers: { Cookie: newSessionCookie } })).text();
    const newAdminCsrf = newDashHtml.match(/data-csrf="([^"]+)"/)[1];
    const adminIssueLinkRes = await fetch(`${baseUrl}/admin/api/users/usr-editor-01/mfa-recovery-token`, {
      method: 'POST',
      headers: { Cookie: newSessionCookie, 'Content-Type': 'application/json', 'X-CSRF-Token': newAdminCsrf },
      body: JSON.stringify({ csrf_token: newAdminCsrf }),
    });
    assert.equal(adminIssueLinkRes.status, 200);
    const adminIssueLinkJson = await adminIssueLinkRes.json();
    assert.ok(adminIssueLinkJson.setup_url.startsWith('/admin/mfa-setup?token='));
    } finally {
      if (prevMfaFlag === undefined) delete process.env.ADMIN_MFA_REQUIRED;
      else process.env.ADMIN_MFA_REQUIRED = prevMfaFlag;
      loginCache.clear();
    }
  });

  await t.test('AUTH-MFA-FLAG-01: Configurable ADMIN_MFA_REQUIRED supports password-only login, UI toggle, RBAC, expiry & session invalidation', async () => {
    const prevMfaFlag = process.env.ADMIN_MFA_REQUIRED;
    const { resetRateLimitBuckets, syncAuthPolicyState } = await import('../src/services/auth.js');
    const { generateUuid } = await import('../src/lib/crypto.js');
    resetRateLimitBuckets();
    loginCache.clear();

    try {
      // Phase A: ADMIN_MFA_REQUIRED=false -> Email + Password only
      process.env.ADMIN_MFA_REQUIRED = 'false';
      await syncAuthPolicyState(db);

      const loginPageRes = await fetch(`${baseUrl}/admin/login`);
      assert.equal(loginPageRes.status, 200);
      const loginHtml = await loginPageRes.text();
      assert.equal(loginHtml.includes('id="login-totp"'), false);
      assert.equal(loginHtml.includes('name="totp_code"'), false);
      assert.equal(loginHtml.includes('SM-Staff-2026'), false);
      assert.equal(loginHtml.includes('JBSWY3DPEHPK3PXP'), false);
      assert.ok(loginHtml.includes('Email & Password'));

      // Wrong password rejected (401)
      const badPassRes = await fetch(`${baseUrl}/admin/login`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: 'editor@smiaz.local', password: 'WrongPassword#999' }).toString(),
      });
      assert.equal(badPassRes.status, 401);

      // Valid Email + Password login WITHOUT totp_code succeeds + preserves MFA DB fields
      const beforeEditorRow = await db.prepare('SELECT totp_secret, mfa_enabled, mfa_enrolled FROM users WHERE user_id = ?').get('usr-editor-01');
      const pwLoginRes = await fetch(`${baseUrl}/admin/login`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: 'editor@smiaz.local', password: 'SM-Staff-2026!' }).toString(),
      });
      assert.equal(pwLoginRes.status, 302);
      const setCookieRaw = pwLoginRes.headers.get('set-cookie');
      assert.ok(setCookieRaw.includes('HttpOnly'));
      const pwSessionCookie = setCookieRaw.split(';')[0];
      const pwSid = decodeURIComponent(pwSessionCookie.split('=')[1]);
      const sessRow = await db.prepare('SELECT mfa_verified FROM sessions WHERE session_id = ?').get(pwSid);
      assert.equal(sessRow.mfa_verified, 0);

      // Dashboard access, RBAC, and CSRF still strictly enforced
      const editorDashRes = await fetch(`${baseUrl}/admin/`, { headers: { Cookie: pwSessionCookie } });
      assert.equal(editorDashRes.status, 200);
      const editorDashHtml = await editorDashRes.text();
      assert.ok(editorDashHtml.includes('ADMIN_MFA_REQUIRED=false'));
      const editorCsrf = editorDashHtml.match(/data-csrf="([^"]+)"/)[1];

      const rbacDenyRes = await fetch(`${baseUrl}/admin/settings`, { headers: { Cookie: pwSessionCookie } });
      assert.equal(rbacDenyRes.status, 403);

      const csrfDenyRes = await fetch(`${baseUrl}/admin/api/users/usr-editor-01/revoke-sessions`, {
        method: 'POST',
        headers: { Cookie: pwSessionCookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      assert.equal(csrfDenyRes.status, 403);

      const afterEditorRow = await db.prepare('SELECT totp_secret, mfa_enabled, mfa_enrolled FROM users WHERE user_id = ?').get('usr-editor-01');
      assert.deepEqual(afterEditorRow, beforeEditorRow);

      // Expired session check
      const expSid = `exp-${generateUuid()}`;
      await db
        .prepare(
          `INSERT INTO sessions (session_id, user_id, csrf_token, mfa_verified, expires_at, created_at, ip_hash)
           VALUES (?, 'usr-editor-01', 'c1', 0, ?, ?, 'h')`
        )
        .run(expSid, new Date(Date.now() - 60_000).toISOString(), new Date().toISOString());
      const expRes = await fetch(`${baseUrl}/admin/`, {
        headers: { Cookie: `sm_staff_session=${expSid}` },
        redirect: 'manual',
      });
      assert.equal(expRes.status, 302);

      // Logout clears session cleanly
      const logoutRes = await fetch(`${baseUrl}/admin/logout`, {
        method: 'POST',
        redirect: 'manual',
        headers: { Cookie: pwSessionCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf_token: editorCsrf }).toString(),
      });
      assert.equal(logoutRes.status, 302);
      const afterLogoutDash = await fetch(`${baseUrl}/admin/`, { headers: { Cookie: pwSessionCookie }, redirect: 'manual' });
      assert.equal(afterLogoutDash.status, 302);

      // Create another password-only session BEFORE flipping policy to true
      const preToggleLogin = await fetch(`${baseUrl}/admin/login`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: 'editor@smiaz.local', password: 'SM-Staff-2026!' }).toString(),
      });
      const preToggleCookie = preToggleLogin.headers.get('set-cookie').split(';')[0];

      // Phase B: Re-enable ADMIN_MFA_REQUIRED=true -> MUST invalidate old password-only session and require TOTP!
      process.env.ADMIN_MFA_REQUIRED = 'true';
      const policyUp = await syncAuthPolicyState(db);
      assert.equal(policyUp.changed, true);

      const oldPwSessBlocked = await fetch(`${baseUrl}/admin/`, { headers: { Cookie: preToggleCookie }, redirect: 'manual' });
      assert.equal(oldPwSessBlocked.status, 302);

      const mfaLoginHtml = await (await fetch(`${baseUrl}/admin/login`)).text();
      assert.ok(mfaLoginHtml.includes('id="login-totp"'));
      assert.ok(mfaLoginHtml.includes('name="totp_code"'));

      const pwOnlyBlocked = await fetch(`${baseUrl}/admin/login`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: 'editor@smiaz.local', password: 'SM-Staff-2026!' }).toString(),
      });
      assert.equal(pwOnlyBlocked.status, 401);

      // Re-enabled MFA accepts existing preserved TOTP secret without re-provisioning
      const mfaLoginOk = await fetch(`${baseUrl}/admin/login`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'editor@smiaz.local',
          password: 'SM-Staff-2026!',
          totp_code: generateTotpCode('KRSXG5CTMVRXEZLU'),
        }).toString(),
      });
      assert.equal(mfaLoginOk.status, 302);
      const mfaSessCookie = mfaLoginOk.headers.get('set-cookie').split(';')[0];
      const mfaDashOk = await fetch(`${baseUrl}/admin/`, { headers: { Cookie: mfaSessCookie } });
      assert.equal(mfaDashOk.status, 200);

      // Phase C: Policy flip true -> false ALSO invalidates old MFA sessions cleanly and records audit log
      process.env.ADMIN_MFA_REQUIRED = 'false';
      const policyDown = await syncAuthPolicyState(db);
      assert.equal(policyDown.changed, true);

      const oldMfaSessBlocked = await fetch(`${baseUrl}/admin/`, { headers: { Cookie: mfaSessCookie }, redirect: 'manual' });
      assert.equal(oldMfaSessBlocked.status, 302);

      const policyAudit = await db
        .prepare(`SELECT action, details_json FROM audit_log WHERE domain = 'auth' AND action = 'auth_policy_changed' ORDER BY created_at DESC LIMIT 1`)
        .get();
      assert.ok(policyAudit);
      assert.ok(policyAudit.details_json.includes('"sessions_invalidated":true'));
    } finally {
      if (prevMfaFlag === undefined) delete process.env.ADMIN_MFA_REQUIRED;
      else process.env.ADMIN_MFA_REQUIRED = prevMfaFlag;
      loginCache.clear();
    }
  });

  await t.test('STAGE-5-7-UX-REGRESSION: PDF URL, scoped overview/analytics, jobs tabs, plain headings & public copy', async () => {
    // 1. Capabilities PDF never prints undefined/credentials/
    const pdfRes = await fetch(`${baseUrl}/credentials/capabilities.pdf`);
    assert.equal(pdfRes.status, 200);
    const pdfBuf = Buffer.from(await pdfRes.arrayBuffer());
    assert.equal(pdfBuf.toString('latin1').includes('undefined/credentials/'), false);

    // 2. Public homepage & about page have no internal PRD scaffolding leaks
    const homeHtml = await (await fetch(`${baseUrl}/`)).text();
    assert.equal(homeHtml.includes('7. Operating Practices'), false);
    assert.equal(homeHtml.includes('9. Procurement Proof'), false);

    const aboutHtml = await (await fetch(`${baseUrl}/about/`)).text();
    assert.equal(aboutHtml.includes('Draft Mission'), false);
    assert.equal(aboutHtml.includes('Draft Vision'), false);

    // 3. Hiring Reviewer overview KPIs & /admin/jobs default tab are scoped and plain-language
    const reviewer = await loginAs(baseUrl, 'reviewer@smiaz.local');
    const revOverviewHtml = await (await fetch(`${baseUrl}/admin/`, { headers: { Cookie: reviewer.cookie } })).text();
    assert.ok(revOverviewHtml.includes('Your daily priorities, work awaiting review, and quick shortcuts for your role.'));

    const revJobsRes = await fetch(`${baseUrl}/admin/jobs`, { headers: { Cookie: reviewer.cookie } });
    assert.equal(revJobsRes.status, 200);
    const revJobsHtml = await revJobsRes.text();
    assert.ok(revJobsHtml.includes('Applicant Inbox'));
    assert.equal(revJobsHtml.includes('Vacancies (Isolated Recruiting Domain)'), false);

    // 4. Analytics: Hiring Owner sees Role-Scoped Hiring Activity; Analyst does NOT
    const hiringOwner = await loginAs(baseUrl, 'hiring@smiaz.local');
    const hiringAnaRes = await fetch(`${baseUrl}/admin/analytics?range=30d`, { headers: { Cookie: hiringOwner.cookie } });
    assert.equal(hiringAnaRes.status, 200);
    const hiringAnaHtml = await hiringAnaRes.text();
    assert.ok(hiringAnaHtml.includes('Role-Scoped Hiring Activity'));
    assert.ok(hiringAnaHtml.includes('Avg Review Hours'));

    const analyst = await loginAs(baseUrl, 'analyst@smiaz.local');
    const analystAnaHtml = await (await fetch(`${baseUrl}/admin/analytics?range=30d`, { headers: { Cookie: analyst.cookie } })).text();
    assert.equal(analystAnaHtml.includes('Role-Scoped Hiring Activity'), false);
    assert.ok(analystAnaHtml.includes('Inquiry Funnel by Service'));

    // 5. Settings page uses plain-language business headings
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');
    const settingsHtml = await (await fetch(`${baseUrl}/admin/settings`, { headers: { Cookie: admin.cookie } })).text();
    assert.ok(settingsHtml.includes('Company Contact &amp; Credential Profile'));
    assert.equal(settingsHtml.includes('Canonical Business Settings'), false);
  });

  await t.test('PHASE-5-INTEGRATIONS: Campaign automation, S3 resume security, Freshsales & M365 hardening', async () => {
    // 1. /api/health reports non-secret integration readiness
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    const health = await healthRes.json();
    assert.equal(health.ok, true);
    assert.ok(health.integrations);
    assert.equal(typeof health.integrations.freshsales, 'string');
    assert.equal(typeof health.integrations.m365_mail, 'string');

    // 2. Campaign & job scheduler records audit logs on job auto-open and auto-close
    const schedJobId = 'job-sched-audit-01';
    const pastIso = new Date(Date.now() - 120_000).toISOString();
    const futureIso = new Date(Date.now() + 3_600_000).toISOString();
    await db.prepare(
      `INSERT INTO jobs (
        requisition_id, opening_cycle_id, slug, title, role_family, employment_type, work_area,
        schedule_text, pay_info, benefits_info, responsibilities_html, qualifications_html,
        status, publish_at, close_at, hiring_owner_id, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Scheduled', ?, ?, 'usr-hiring-owner-01', ?)`
    ).run(
      schedJobId, 'CYC-AUDIT-01', 'scheduled-audit-tech', 'Scheduled Audit Tech',
      'Maintenance Technician', 'Full-time', 'Greater Phoenix',
      'Mon-Fri 7am-3:30pm', '$24/hr', 'Standard', '<p>Maintain</p>', '<p>2 yrs</p>',
      pastIso, futureIso, pastIso
    );
    await runScheduleEvaluation(db, new Date());
    const openedJob = await db.prepare('SELECT status FROM jobs WHERE requisition_id = ?').get(schedJobId);
    assert.equal(openedJob.status, 'Open');
    const openAudit = await db.prepare(`SELECT action FROM audit_log WHERE object_id = ? AND action = 'job_auto_opened'`).get(schedJobId);
    assert.ok(openAudit);

    // 3. S3 / private resume security: quarantined file is isolated in quarantine area and blocked from download
    const { buildStoragePaths } = await import('../src/config.js');
    const { createObjectStore } = await import('../src/services/object-store.js');
    const { sendEmailViaMicrosoftGraph, clearMailerTokenCache } = await import('../src/services/mailer.js');
    const testStoragePaths = buildStoragePaths(storageRoot);
    const store = createObjectStore(testStoragePaths);

    // Seed a stale staging object and verify cleanupStaleStagingObjects removes it while keeping fresh objects
    const staleKey = 'public/resume/stale-abandoned.pdf';
    const freshKey = 'public/resume/fresh-pending.pdf';
    await store.putObject({ area: 'staging', key: staleKey, buffer: Buffer.from('%PDF-1.4 stale') });
    await store.putObject({ area: 'staging', key: freshKey, buffer: Buffer.from('%PDF-1.4 fresh') });
    const staleFp = path.join(testStoragePaths.privateRoot, 'staging', staleKey);
    const oldTime = new Date(Date.now() - 48 * 3600 * 1000);
    fs.utimesSync(staleFp, oldTime, oldTime);

    const cleanupRes = await store.cleanupStaleStagingObjects({ nowDate: new Date() });
    assert.ok(cleanupRes.deleted >= 1);
    assert.equal(await store.existsObject({ area: 'staging', key: staleKey }), false);
    assert.equal(await store.existsObject({ area: 'staging', key: freshKey }), true);
    await store.deleteObject({ area: 'staging', key: freshKey });

    // Clean resume download enforces strict security headers + sanitized Content-Disposition
    const hiringOwner = await loginAs(baseUrl, 'hiring@smiaz.local');
    const appWithResume = await db
      .prepare(`SELECT a.application_id, att.attachment_id, att.original_display_name FROM applications a JOIN application_attachments att ON att.application_id = a.application_id WHERE att.scan_state = 'clean' AND att.deleted_at IS NULL LIMIT 1`)
      .get();
    if (appWithResume) {
      const dlRes = await fetch(
        `${baseUrl}/admin/api/applications/${appWithResume.application_id}/attachments/${appWithResume.attachment_id}`,
        { headers: { Cookie: hiringOwner.cookie } }
      );
      assert.equal(dlRes.status, 200);
      assert.equal(dlRes.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(dlRes.headers.get('content-security-policy'), "default-src 'none'; sandbox");
      assert.equal(dlRes.headers.get('cache-control'), 'no-store');

      // Cross-role access (Admin / Content Editor) must still be denied 403
      const editor = await loginAs(baseUrl, 'editor@smiaz.local');
      const deniedDl = await fetch(
        `${baseUrl}/admin/api/applications/${appWithResume.application_id}/attachments/${appWithResume.attachment_id}`,
        { headers: { Cookie: editor.cookie } }
      );
      assert.equal(deniedDl.status, 403);
    }

    // 4. M365 Mailer header/recipient hardening with mocked Graph API
    const prevTenant = process.env.MS_GRAPH_TENANT_ID;
    const prevClient = process.env.MS_GRAPH_CLIENT_ID;
    const prevSecret = process.env.MS_GRAPH_CLIENT_SECRET;
    try {
      process.env.MS_GRAPH_TENANT_ID = 'mock-tenant';
      process.env.MS_GRAPH_CLIENT_ID = 'mock-client';
      process.env.MS_GRAPH_CLIENT_SECRET = 'mock-secret';
      clearMailerTokenCache();

      const badTo = await sendEmailViaMicrosoftGraph({ to: 'invalid-email', subject: 'Test', bodyText: 'Hi' });
      assert.equal(badTo.ok, false);
      assert.equal(badTo.transient, false);

      let capturedSubject = '';
      setMailerFetch(async (url, opts) => {
        if (String(url).includes('oauth2/v2.0/token')) {
          return new Response(JSON.stringify({ access_token: 'tok-123', expires_in: 3600 }), { status: 200 });
        }
        const payload = JSON.parse(opts.body);
        capturedSubject = payload.message.subject;
        return new Response('', { status: 202, headers: { 'request-id': 'req-m365-1' } });
      });
      const mailOk = await sendEmailViaMicrosoftGraph({
        to: 'ops@smiaz.com',
        subject: "Line1\r\nBcc: evil@attacker.com",
        bodyText: 'Safe body',
      });
      assert.equal(mailOk.ok, true);
      assert.equal(capturedSubject.includes('\r'), false);
      assert.equal(capturedSubject.includes('\n'), false);
    } finally {
      setMailerFetch(null);
      clearMailerTokenCache();
      if (prevTenant === undefined) delete process.env.MS_GRAPH_TENANT_ID;
      else process.env.MS_GRAPH_TENANT_ID = prevTenant;
      if (prevClient === undefined) delete process.env.MS_GRAPH_CLIENT_ID;
      else process.env.MS_GRAPH_CLIENT_ID = prevClient;
      if (prevSecret === undefined) delete process.env.MS_GRAPH_CLIENT_SECRET;
      else process.env.MS_GRAPH_CLIENT_SECRET = prevSecret;
    }
  });

  await t.test('PHASE-6-ONBOARDING: Manual + M365 Email Onboarding, Self-Set Password, Resend & Security', async () => {
    const { sendEmailViaMicrosoftGraph, clearMailerTokenCache } = await import('../src/services/mailer.js');
    const admin = await loginAs(baseUrl, 'admin@smiaz.local');
    const editor = await loginAs(baseUrl, 'editor@smiaz.local');

    // 1. Non-admin denied user creation
    const denyCreate = await fetch(`${baseUrl}/admin/api/users`, {
      method: 'POST',
      headers: { Cookie: editor.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': editor.csrf },
      body: JSON.stringify({
        csrf_token: editor.csrf,
        email: 'unauth.invite@smiaz.local',
        full_name: 'Unauth Invite',
        role: 'Content Editor',
        onboarding_mode: 'manual',
      }),
    });
    assert.equal(denyCreate.status, 403);

    // 2. When M365 is unconfigured, UI shows Email option disabled/unavailable and API rejects email mode (422)
    const usersCreateHtml = await (
      await fetch(`${baseUrl}/admin/users?tab=directory&action=create`, { headers: { Cookie: admin.cookie } })
    ).text();
    assert.ok(usersCreateHtml.includes('Manual Invitation (Copy Setup Link)'));
    assert.ok(usersCreateHtml.includes('Microsoft 365 email is not configured'));

    const denyEmailUnconf = await fetch(`${baseUrl}/admin/api/users`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({
        csrf_token: admin.csrf,
        email: 'email.unconf@smiaz.local',
        full_name: 'Email Unconf',
        role: 'Content Editor',
        onboarding_mode: 'email',
      }),
    });
    assert.equal(denyEmailUnconf.status, 422);

    // 3. Manual Invitation creates user with must_set_password=1 & returns copyable single-use link
    const manualRes = await fetch(`${baseUrl}/admin/api/users`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({
        csrf_token: admin.csrf,
        email: 'manual.onboard@smiaz.local',
        full_name: 'Manual Onboard',
        role: 'Content Editor',
        onboarding_mode: 'manual',
      }),
    });
    assert.equal(manualRes.status, 201);
    const manualData = await manualRes.json();
    assert.ok(manualData.setup_url.startsWith('/admin/mfa-setup?token='));
    const firstToken = new URL(manualData.setup_url, baseUrl).searchParams.get('token');

    // User cannot sign in before completing onboarding
    const preOnboardLogin = await fetch(`${baseUrl}/admin/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ email: 'manual.onboard@smiaz.local', password: 'anything-123' }).toString(),
    });
    assert.equal(preOnboardLogin.status, 401);

    // 4. Resend invalidates previous unused token
    const resendRes = await fetch(`${baseUrl}/admin/api/users/${manualData.user_id}/mfa-recovery-token`, {
      method: 'POST',
      headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
      body: JSON.stringify({ csrf_token: admin.csrf, delivery_method: 'manual' }),
    });
    assert.equal(resendRes.status, 200);
    const resendData = await resendRes.json();
    const secondToken = new URL(resendData.setup_url, baseUrl).searchParams.get('token');
    assert.notEqual(secondToken, firstToken);

    const oldTokenGet = await fetch(`${baseUrl}/admin/mfa-setup?token=${encodeURIComponent(firstToken)}`);
    assert.equal(oldTokenGet.status, 403);

    // 5. Invited user completes self-set password + QR/TOTP + 8 recovery codes using secondToken
    const getSetup = await fetch(`${baseUrl}/admin/mfa-setup?token=${encodeURIComponent(secondToken)}`);
    assert.equal(getSetup.status, 200);
    const setupHtml = await getSetup.text();
    assert.ok(setupHtml.includes('name="new_password"'));
    assert.ok(setupHtml.includes('name="confirm_password"'));
    const csrfCookie = (getSetup.headers.getSetCookie?.() || [getSetup.headers.get('set-cookie')])
      .find((c) => c?.startsWith('sm_mfa_csrf='))
      .split(';')[0];
    const step1Csrf = setupHtml.match(/name="csrf_token" value="([^"]+)"/)[1];

    // Mismatched password rejected (422)
    const mismatchRes = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: csrfCookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: step1Csrf,
        step: 'begin',
        email: 'manual.onboard@smiaz.local',
        new_password: 'NewStaffPassword#2026',
        confirm_password: 'DifferentPassword#2026',
        setup_token: secondToken,
        must_set_password: '1',
      }).toString(),
    });
    assert.equal(mismatchRes.status, 422);
    const mismatchHtml = await mismatchRes.text();
    const step1Csrf2 = mismatchHtml.match(/name="csrf_token" value="([^"]+)"/)[1];
    const csrfCookie2 = (mismatchRes.headers.getSetCookie?.() || [mismatchRes.headers.get('set-cookie')])
      .find((c) => c?.startsWith('sm_mfa_csrf='))
      .split(';')[0];

    // Valid password starts QR stage
    const beginOk = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: csrfCookie2, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: step1Csrf2,
        step: 'begin',
        email: 'manual.onboard@smiaz.local',
        new_password: 'NewStaffPassword#2026',
        confirm_password: 'NewStaffPassword#2026',
        setup_token: secondToken,
        must_set_password: '1',
      }).toString(),
    });
    assert.equal(beginOk.status, 200);
    const step2Html = await beginOk.text();
    const manualSecret = step2Html.match(/<code[^>]*>([A-Z2-7 ]{16,})<\/code>/)[1].replace(/\s+/g, '');
    const step2Csrf = step2Html.match(/name="csrf_token" value="([^"]+)"/)[1];
    const step2Cookies = (beginOk.headers.getSetCookie?.() || [beginOk.headers.get('set-cookie')])
      .map((c) => c.split(';')[0])
      .join('; ');

    const confirmOk = await fetch(`${baseUrl}/admin/mfa-setup`, {
      method: 'POST',
      headers: { Cookie: step2Cookies, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        csrf_token: step2Csrf,
        step: 'confirm',
        totp_code: generateTotpCode(manualSecret),
      }).toString(),
    });
    assert.equal(confirmOk.status, 200);
    const doneHtml = await confirmOk.text();
    assert.ok(doneHtml.includes('Recovery Codes'));

    // Reusing token after completion is denied (403)
    const reuseRes = await fetch(`${baseUrl}/admin/mfa-setup?token=${encodeURIComponent(secondToken)}`);
    assert.equal(reuseRes.status, 403);

    // Invited user can now sign in with their own password + TOTP
    const loginOk = await fetch(`${baseUrl}/admin/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        email: 'manual.onboard@smiaz.local',
        password: 'NewStaffPassword#2026',
        totp_code: generateTotpCode(manualSecret),
      }).toString(),
    });
    assert.equal(loginOk.status, 302);

    // 6. Microsoft 365 Email Invitation (success + failure fallback) & zero secrets in audit_log
    const prevTenant = process.env.MS_GRAPH_TENANT_ID;
    const prevClient = process.env.MS_GRAPH_CLIENT_ID;
    const prevSecret = process.env.MS_GRAPH_CLIENT_SECRET;
    try {
      process.env.MS_GRAPH_TENANT_ID = 'mock-tenant';
      process.env.MS_GRAPH_CLIENT_ID = 'mock-client';
      process.env.MS_GRAPH_CLIENT_SECRET = 'mock-secret';
      clearMailerTokenCache();

      let mailedLink = '';
      setMailerFetch(async (url, opts) => {
        if (String(url).includes('oauth2/v2.0/token')) {
          return new Response(JSON.stringify({ access_token: 'tok-onb', expires_in: 3600 }), { status: 200 });
        }
        const payload = JSON.parse(opts.body);
        const match = payload.message.body.content.match(/\/admin\/mfa-setup\?token=[A-Za-z0-9_-]+/);
        mailedLink = match ? match[0] : '';
        return new Response('', { status: 202, headers: { 'request-id': 'req-onb-1' } });
      });

      const emailCreate = await fetch(`${baseUrl}/admin/api/users`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({
          csrf_token: admin.csrf,
          email: 'email.onboard@smiaz.local',
          full_name: 'Email Onboard',
          role: 'Analyst',
          onboarding_mode: 'email',
        }),
      });
      assert.equal(emailCreate.status, 201);
      const emailData = await emailCreate.json();
      assert.equal(emailData.onboarding_mode, 'email');
      assert.equal('setup_url' in emailData, false);
      assert.ok(mailedLink.startsWith('/admin/mfa-setup?token='));

      // Verify M365 email delivery failure returns 502 with manual fallback link
      setMailerFetch(async (url) => {
        if (String(url).includes('oauth2/v2.0/token')) {
          return new Response(JSON.stringify({ access_token: 'tok-onb', expires_in: 3600 }), { status: 200 });
        }
        return new Response('Graph unavailable', { status: 500 });
      });
      const failEmailRes = await fetch(`${baseUrl}/admin/api/users/${emailData.user_id}/mfa-recovery-token`, {
        method: 'POST',
        headers: { Cookie: admin.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': admin.csrf },
        body: JSON.stringify({ csrf_token: admin.csrf, delivery_method: 'email' }),
      });
      assert.equal(failEmailRes.status, 502);
      const failData = await failEmailRes.json();
      assert.equal(failData.email_failed, true);
      assert.ok(failData.setup_url.startsWith('/admin/mfa-setup?token='));

      // Verify audit_log never contains raw onboarding tokens or passwords
      const mailedTok = new URL(mailedLink, baseUrl).searchParams.get('token');
      const fallbackTok = new URL(failData.setup_url, baseUrl).searchParams.get('token');
      const leakCheck = await db
        .prepare(`SELECT COUNT(*) as cnt FROM audit_log WHERE details_json LIKE ? OR details_json LIKE ? OR details_json LIKE '%NewStaffPassword%'`)
        .get(`%${mailedTok}%`, `%${fallbackTok}%`);
      assert.equal(leakCheck.cnt, 0);
    } finally {
      setMailerFetch(null);
      clearMailerTokenCache();
      if (prevTenant === undefined) delete process.env.MS_GRAPH_TENANT_ID;
      else process.env.MS_GRAPH_TENANT_ID = prevTenant;
      if (prevClient === undefined) delete process.env.MS_GRAPH_CLIENT_ID;
      else process.env.MS_GRAPH_CLIENT_ID = prevClient;
      if (prevSecret === undefined) delete process.env.MS_GRAPH_CLIENT_SECRET;
      else process.env.MS_GRAPH_CLIENT_SECRET = prevSecret;
    }
  });
});
