import { ENV } from '../config.js';
import { generateUuid } from '../lib/crypto.js';

/**
 * Freshsales CRM adapter.
 * Uses Freshworks CRM REST API v2 when FRESHSALES_DOMAIN and FRESHSALES_API_KEY are configured:
 *   - Sales Accounts: POST /crm/sales/api/sales_accounts/upsert
 *   - Contacts:       POST /crm/sales/api/contacts/upsert (email/id) or POST /crm/sales/api/contacts (phone-only)
 *   - Notes (Prop):   POST /crm/sales/api/notes
 *   - Deals:          POST /crm/sales/api/deals (create) & POST /crm/sales/api/deals/upsert (update by crm_deal_id)
 *
 * In non-production without credentials, runs a deterministic sandbox adapter with configurable
 * fault injection for staging acceptance testing (CRM-02). Disabled in production.
 */
let simulatedFaultMode = 'none'; // none | outage_503 | rate_limit_429 | permanent_400
let customFetchImpl = null;

export function setCrmFetch(fetchFn) {
  customFetchImpl = fetchFn || null;
}

export function setCrmFaultMode(mode) {
  if (ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production') {
    simulatedFaultMode = 'none';
    return false;
  }
  simulatedFaultMode = mode;
  return true;
}

export function getCrmFaultMode() {
  if (ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production') {
    return 'none';
  }
  return simulatedFaultMode;
}

function getFreshsalesConfig() {
  return {
    domain: String(process.env.FRESHSALES_DOMAIN ?? ENV.FRESHSALES_DOMAIN ?? '').trim(),
    apiKey: String(process.env.FRESHSALES_API_KEY ?? ENV.FRESHSALES_API_KEY ?? '').trim(),
    stageQualified: String(process.env.FRESHSALES_DEAL_STAGE_QUALIFIED ?? ENV.FRESHSALES_DEAL_STAGE_QUALIFIED ?? '').trim(),
    stageProposal: String(process.env.FRESHSALES_DEAL_STAGE_PROPOSAL ?? ENV.FRESHSALES_DEAL_STAGE_PROPOSAL ?? '').trim(),
    stageWon: String(process.env.FRESHSALES_DEAL_STAGE_WON ?? ENV.FRESHSALES_DEAL_STAGE_WON ?? '').trim(),
  };
}

function checkFaultMode() {
  const isProd = ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production';
  if (isProd) return null;
  if (simulatedFaultMode === 'outage_503') {
    return { ok: false, transient: true, statusCode: 503, error: 'Simulated Freshsales CRM service outage (503)' };
  }
  if (simulatedFaultMode === 'rate_limit_429') {
    return { ok: false, transient: true, statusCode: 429, error: 'Simulated Freshsales API rate limit (429)' };
  }
  if (simulatedFaultMode === 'permanent_400') {
    return { ok: false, transient: false, statusCode: 400, error: 'Simulated Freshsales permanent schema rejection (400)' };
  }
  return null;
}

function safeJsonParse(raw, fallback = {}) {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function toCrmNumericOrStringId(val) {
  if (val === null || val === undefined || val === '') return undefined;
  const num = Number(val);
  return Number.isSafeInteger(num) && String(num) === String(val).trim() ? num : String(val);
}

async function freshsalesRequest({ domain, apiKey, path, method = 'POST', body }) {
  const fetchFn = customFetchImpl || globalThis.fetch;
  const endpoint = `https://${domain}/crm/sales/api/${path.replace(/^\/+/, '')}`;

  let res;
  try {
    res = await fetchFn(endpoint, {
      method,
      headers: {
        Authorization: `Token token=${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    return { ok: false, transient: true, statusCode: 0, error: `Freshsales network error: ${err.message}` };
  }

  if (res.status === 429 || res.status >= 500) {
    return { ok: false, transient: true, statusCode: res.status, error: `Freshsales HTTP ${res.status}` };
  }
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    return {
      ok: false,
      transient: false,
      statusCode: res.status,
      error: `Freshsales rejected ${path} (${res.status}): ${errText.slice(0, 160)}`,
    };
  }

  const data = await res.json().catch(() => ({}));
  return { ok: true, statusCode: res.status, data };
}

async function upsertAccountAndContact({ cfg, inquiry, account, contact, property }) {
  // 1. Upsert Sales Account (prevent duplicates via existing crm_account_id or exact org name)
  const accountName = account?.organization_name || 'Commercial Property Account';
  const accountUnique = account?.crm_account_id
    ? { id: toCrmNumericOrStringId(account.crm_account_id) }
    : { name: accountName };

  const acctRes = await freshsalesRequest({
    domain: cfg.domain,
    apiKey: cfg.apiKey,
    path: 'sales_accounts/upsert',
    body: {
      unique_identifier: accountUnique,
      sales_account: {
        name: accountName,
        city: property?.city_or_zip || undefined,
      },
    },
  });
  if (!acctRes.ok) return acctRes;
  const crmAccountId = String(acctRes.data?.sales_account?.id || account?.crm_account_id || '');

  // 2. Upsert Contact (by crm_contact_id or emails) or create phone-only contact without guessing
  const contactPayload = {
    last_name: contact?.name || 'Commercial Inquiry',
    email: contact?.email || undefined,
    work_number: contact?.phone || undefined,
    sales_account_id: toCrmNumericOrStringId(crmAccountId),
    custom_field: {
      cf_sm_inquiry_id: inquiry.inquiry_id,
      cf_sm_service_family: inquiry.service_family,
      cf_sm_property_location: property?.city_or_zip || '',
      cf_sm_routing_queue: inquiry.routing_queue,
    },
  };

  let contactRes;
  if (contact?.crm_contact_id) {
    contactRes = await freshsalesRequest({
      domain: cfg.domain,
      apiKey: cfg.apiKey,
      path: 'contacts/upsert',
      body: {
        unique_identifier: { id: toCrmNumericOrStringId(contact.crm_contact_id) },
        contact: contactPayload,
      },
    });
  } else if (contact?.email) {
    contactRes = await freshsalesRequest({
      domain: cfg.domain,
      apiKey: cfg.apiKey,
      path: 'contacts/upsert',
      body: {
        unique_identifier: { emails: contact.email },
        contact: contactPayload,
      },
    });
  } else {
    contactRes = await freshsalesRequest({
      domain: cfg.domain,
      apiKey: cfg.apiKey,
      path: 'contacts',
      body: { contact: contactPayload },
    });
  }
  if (!contactRes.ok) return contactRes;
  const crmContactId = String(contactRes.data?.contact?.id || contact?.crm_contact_id || '');

  // 3. Attach Property context note once per property
  let crmPropertyNoteId = property?.crm_property_note_id || null;
  if (property && !crmPropertyNoteId && crmAccountId) {
    const propDesc = [
      `Property Record (${property.property_id})`,
      `Location: ${property.city_or_zip || 'N/A'}`,
      `Property Type: ${property.property_type || 'N/A'}`,
      `Primary Service Family: ${property.service_family || inquiry.service_family}`,
    ].join('\n');
    const propNoteRes = await freshsalesRequest({
      domain: cfg.domain,
      apiKey: cfg.apiKey,
      path: 'notes',
      body: {
        note: {
          description: propDesc,
          targetable_type: 'SalesAccount',
          targetable_id: toCrmNumericOrStringId(crmAccountId),
        },
      },
    });
    if (!propNoteRes.ok) return propNoteRes;
    crmPropertyNoteId = String(propNoteRes.data?.note?.id || '');
  }

  // 4. Attach Inquiry & Attribution note once per inquiry
  let crmNoteId = inquiry.crm_note_id || null;
  if (!crmNoteId && crmContactId) {
    const inqPayload = safeJsonParse(inquiry.payload_json, {});
    const inqAttr = safeJsonParse(inquiry.attribution_json, {});
    const acq = inqAttr.acquisition_utms && typeof inqAttr.acquisition_utms === 'object' ? inqAttr.acquisition_utms : inqAttr;
    const inqDesc = [
      `Service Maintenance Inquiry (${inquiry.inquiry_id})`,
      `Kind: ${inquiry.inquiry_kind} | Service: ${inquiry.service_family} | Queue: ${inquiry.routing_queue}`,
      `Property: ${property?.city_or_zip || 'N/A'} (${property?.property_type || 'N/A'})`,
      `Urgency: ${inqPayload.urgency || inqPayload.desired_timing || 'normal'} | Classification: ${inquiry.classification}`,
      `Scope: ${inqPayload.description || 'N/A'}`,
      `Attribution: source=${acq.utm_source || 'direct'}, medium=${acq.utm_medium || 'none'}, campaign=${acq.utm_campaign || 'none'}, gclid=${acq.gclid || 'none'}`,
    ].join('\n');
    const noteRes = await freshsalesRequest({
      domain: cfg.domain,
      apiKey: cfg.apiKey,
      path: 'notes',
      body: {
        note: {
          description: inqDesc,
          targetable_type: 'Contact',
          targetable_id: toCrmNumericOrStringId(crmContactId),
        },
      },
    });
    if (!noteRes.ok) return noteRes;
    crmNoteId = String(noteRes.data?.note?.id || '');
  }

  return {
    ok: true,
    externalId: crmContactId,
    crmAccountId,
    crmContactId,
    crmNoteId,
    crmPropertyNoteId,
  };
}

export async function deliverInquiryToFreshsales({ inquiry, account, contact, property }) {
  const fault = checkFaultMode();
  if (fault) return fault;

  const cfg = getFreshsalesConfig();
  const isProd = ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production';

  if (cfg.domain && cfg.apiKey) {
    return upsertAccountAndContact({ cfg, inquiry, account, contact, property });
  }

  if (isProd) {
    return {
      ok: false,
      transient: false,
      statusCode: 503,
      error: 'Freshsales CRM credentials not configured (set FRESHSALES_DOMAIN and FRESHSALES_API_KEY).',
    };
  }

  // Sandbox / local development durable CRM delivery record
  const shortInq = inquiry.inquiry_id.slice(0, 8);
  const crmAccountId = account?.crm_account_id || `fs_sandbox_acct_${account.account_id.slice(0, 8)}`;
  const crmContactId = contact?.crm_contact_id || `fs_sandbox_${shortInq}`;
  const crmNoteId = inquiry.crm_note_id || `fs_sandbox_note_${shortInq}`;
  const crmPropertyNoteId = property ? property.crm_property_note_id || `fs_sandbox_prop_${property.property_id.slice(0, 8)}` : null;

  return {
    ok: true,
    externalId: crmContactId,
    crmAccountId,
    crmContactId,
    crmNoteId,
    crmPropertyNoteId,
    sandbox: true,
    mapped: {
      account_id: account.account_id,
      contact_id: contact.contact_id,
      property_id: property?.property_id || null,
      routing_queue: inquiry.routing_queue,
    },
  };
}

function getStageIdForMilestone(cfg, milestone) {
  if (milestone === 'qualified') return cfg.stageQualified || undefined;
  if (milestone === 'proposal_sent') return cfg.stageProposal || undefined;
  if (milestone === 'closed_won') return cfg.stageWon || undefined;
  return undefined;
}

export async function syncDealMilestoneToFreshsales({ inquiry, account, contact, property, milestone, dealValue = null }) {
  const fault = checkFaultMode();
  if (fault) return fault;

  const cfg = getFreshsalesConfig();
  const isProd = ENV.NODE_ENV === 'production' || process.env.NODE_ENV === 'production';

  if (!cfg.domain || !cfg.apiKey) {
    if (isProd) {
      return {
        ok: false,
        transient: false,
        statusCode: 503,
        error: 'Freshsales CRM credentials not configured for Deal sync.',
      };
    }
    return {
      ok: true,
      sandbox: true,
      crmDealId: inquiry.crm_deal_id || `fs_sandbox_deal_${inquiry.inquiry_id.slice(0, 8)}`,
    };
  }

  let crmAccountId = account?.crm_account_id || null;
  let crmContactId = contact?.crm_contact_id || null;
  let crmNoteId = inquiry.crm_note_id || null;
  let crmPropertyNoteId = property?.crm_property_note_id || null;

  if (!crmAccountId || !crmContactId) {
    const syncBase = await upsertAccountAndContact({ cfg, inquiry, account, contact, property });
    if (!syncBase.ok) return syncBase;
    crmAccountId = syncBase.crmAccountId;
    crmContactId = syncBase.crmContactId;
    crmNoteId = syncBase.crmNoteId;
    crmPropertyNoteId = syncBase.crmPropertyNoteId;
  }

  const stageId = getStageIdForMilestone(cfg, milestone);
  const resolvedAmount = dealValue !== null && dealValue !== undefined ? Number(dealValue) : inquiry.deal_value !== null && inquiry.deal_value !== undefined ? Number(inquiry.deal_value) : undefined;

  const dealPayload = {
    name: `${account?.organization_name || 'Commercial Property'} - ${inquiry.service_family} (${inquiry.inquiry_id.slice(0, 8)})`,
    amount: Number.isFinite(resolvedAmount) ? resolvedAmount : undefined,
    sales_account_id: toCrmNumericOrStringId(crmAccountId),
    deal_stage_id: toCrmNumericOrStringId(stageId),
    custom_field: {
      cf_sm_inquiry_id: inquiry.inquiry_id,
      cf_sm_service_family: inquiry.service_family,
      cf_sm_milestone: milestone,
    },
  };

  let dealRes;
  if (inquiry.crm_deal_id) {
    dealRes = await freshsalesRequest({
      domain: cfg.domain,
      apiKey: cfg.apiKey,
      path: 'deals/upsert',
      body: {
        unique_identifier: { id: toCrmNumericOrStringId(inquiry.crm_deal_id) },
        deal: dealPayload,
      },
    });
  } else {
    dealRes = await freshsalesRequest({
      domain: cfg.domain,
      apiKey: cfg.apiKey,
      path: 'deals',
      body: {
        deal: {
          ...dealPayload,
          contacts_added_list: crmContactId ? [toCrmNumericOrStringId(crmContactId)] : undefined,
        },
      },
    });
  }

  if (!dealRes.ok) return dealRes;
  const crmDealId = String(dealRes.data?.deal?.id || inquiry.crm_deal_id || '');

  return {
    ok: true,
    crmDealId,
    crmAccountId,
    crmContactId,
    crmNoteId,
    crmPropertyNoteId,
  };
}
