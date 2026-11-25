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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sm-int-'));
  const dbPath = path.join(tmpDir, 'test.db');
  const storageRoot = path.join(tmpDir, 'storage');
  const { server, db } = await createAppServer({ dbPath, storageRoot, startWorker: false });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  t.after(async () => {
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
    assert.ok(created.user_id && created.totp_secret);

    // Log in as new user with MFA TOTP
    const loginResp = await fetch(`${baseUrl}/admin/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        email: 'ops.staff@smiaz.local',
        password: 'StrongPassword#2026',
        totp_code: generateTotpCode(created.totp_secret),
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
});
