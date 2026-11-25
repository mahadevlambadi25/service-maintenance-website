(() => {
  'use strict';

  const isPreview = document.body.dataset.isPreview === '1';

  function getConsentState() {
    return document.body.dataset.consent || 'undecided';
  }

  function hasAnalyticsConsent() {
    return !isPreview && getConsentState() === 'analytics_accepted';
  }

  // Capture acquisition UTMs once in sessionStorage (never overwritten by on-site campaign clicks!)
  const UTM_ALLOWLIST = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content'];
  try {
    const params = new URLSearchParams(window.location.search);
    const existing = JSON.parse(sessionStorage.getItem('sm_acq_utms') || '{}');
    let changed = false;
    for (const k of UTM_ALLOWLIST) {
      const val = params.get(k);
      if (val && !existing[k]) {
        existing[k] = val.trim().slice(0, 80).toLowerCase();
        changed = true;
      }
    }
    if (!sessionStorage.getItem('sm_first_landing')) {
      sessionStorage.setItem('sm_first_landing', window.location.pathname);
    }
    if (changed) {
      sessionStorage.setItem('sm_acq_utms', JSON.stringify(existing));
    }
  } catch {}

  function getAcquisitionUtms() {
    try {
      return JSON.parse(sessionStorage.getItem('sm_acq_utms') || '{}');
    } catch {
      return {};
    }
  }

  function sendAnalytics(eventName, extra = {}) {
    if (isPreview) return;
    if (!hasAnalyticsConsent() && eventName !== 'download_capabilities') return;
    const utms = getAcquisitionUtms();
    const payload = {
      event_name: eventName,
      page_type: document.body.dataset.pageType || 'public',
      consent_mode: getConsentState(),
      acquisition_utm_source: utms.utm_source || null,
      acquisition_utm_medium: utms.utm_medium || null,
      acquisition_utm_campaign: utms.utm_campaign || null,
      acquisition_utm_content: utms.utm_content || null,
      ...extra,
    };
    fetch('/api/analytics/event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      keepalive: true,
    }).catch(() => {});
  }

  // Mobile Menu Toggle
  const navToggle = document.getElementById('nav-toggle');
  const primaryNav = document.getElementById('primary-navigation');
  if (navToggle && primaryNav) {
    navToggle.addEventListener('click', () => {
      const expanded = navToggle.getAttribute('aria-expanded') === 'true';
      navToggle.setAttribute('aria-expanded', String(!expanded));
      primaryNav.classList.toggle('is-open', !expanded);
    });
  }

  // Consent Banner & Dialog (with closedby fallback per modern-web-guidance)
  const consentBanner = document.getElementById('consent-banner');
  const consentDialog = document.getElementById('consent-dialog');
  const openConsentBtn = document.getElementById('open-consent-dialog');
  const customizeBtn = document.getElementById('consent-customize-btn');
  const consentCloseBtn = document.getElementById('consent-close-btn');
  const consentForm = document.getElementById('consent-dialog-form');
  const analyticsToggle = document.getElementById('consent-analytics');

  async function saveConsent(choice) {
    document.body.dataset.consent = choice;
    if (consentBanner) consentBanner.remove();
    if (analyticsToggle) analyticsToggle.checked = choice === 'analytics_accepted';
    await fetch('/api/consent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ consent: choice }),
    }).catch(() => {});
  }

  document.querySelectorAll('[data-consent-action]').forEach((btn) => {
    btn.addEventListener('click', () => saveConsent(btn.dataset.consentAction));
  });

  [openConsentBtn, customizeBtn].forEach((btn) => {
    if (btn && consentDialog) {
      btn.addEventListener('click', () => consentDialog.showModal());
    }
  });

  if (consentCloseBtn && consentDialog) {
    consentCloseBtn.addEventListener('click', () => consentDialog.close());
  }

  if (consentForm && consentDialog) {
    consentForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const accepted = analyticsToggle?.checked ? 'analytics_accepted' : 'essential_only';
      await saveConsent(accepted);
      consentDialog.close();
    });
  }

  if (consentDialog && !('closedBy' in HTMLDialogElement.prototype)) {
    let pressedOutside = false;
    const isOutside = (e) => {
      const r = consentDialog.getBoundingClientRect();
      return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    };
    consentDialog.addEventListener('pointerdown', (e) => { pressedOutside = isOutside(e); });
    consentDialog.addEventListener('pointerup', (e) => { if (pressedOutside && isOutside(e)) consentDialog.close(); });
  }

  // Click tracking for phone, email, capabilities PDF
  document.addEventListener('click', (e) => {
    const link = e.target.closest('[data-track]');
    if (link) {
      sendAnalytics(link.dataset.track);
    }
    const campCta = e.target.closest('[data-campaign-cta]');
    if (campCta) {
      const container = campCta.closest('[data-campaign-id]');
      if (container) {
        try {
          sessionStorage.setItem('sm_last_onsite_campaign', JSON.stringify({
            on_site_campaign_id: container.dataset.campaignId,
            placement_id: container.dataset.placementId,
            content_revision: Number(container.dataset.revision || 1),
          }));
        } catch {}
        sendAnalytics('campaign_click', {
          on_site_campaign_id: container.dataset.campaignId,
          placement_id: container.dataset.placementId,
          content_revision: Number(container.dataset.revision || 1),
        });
      }
    }
  });

  // Page-specific view events
  const svcEl = document.querySelector('[data-service-id]');
  if (svcEl) sendAnalytics('view_service', { service_id: svcEl.dataset.serviceId });
  const projEl = document.querySelector('[data-project-id]');
  if (projEl) sendAnalytics('view_project', { project_id: projEl.dataset.projectId });
  const jobEl = document.querySelector('[data-job-id]');
  if (jobEl) sendAnalytics('view_job', { job_id: jobEl.dataset.jobId });

  // PRD 18.04: campaign_view fires when >= 50% visible for 1 continuous second while page is visible
  const observedCampaigns = new Set();
  document.querySelectorAll('[data-campaign-id]').forEach((el) => {
    if (!('IntersectionObserver' in window)) return;
    let timer = null;
    const obs = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting && entry.intersectionRatio >= 0.5 && document.visibilityState === 'visible') {
          if (!timer && !observedCampaigns.has(el.dataset.campaignId)) {
            timer = setTimeout(() => {
              if (document.visibilityState === 'visible' && !observedCampaigns.has(el.dataset.campaignId)) {
                observedCampaigns.add(el.dataset.campaignId);
                sendAnalytics('campaign_view', {
                  on_site_campaign_id: el.dataset.campaignId,
                  placement_id: el.dataset.placementId,
                  content_revision: Number(el.dataset.revision || 1),
                });
              }
            }, 1000);
          }
        } else if (timer) {
          clearTimeout(timer);
          timer = null;
        }
      }
    }, { threshold: 0.5 });
    obs.observe(el);
  });

  // =====================================================================
  // Form Enhancement: ARIA Sync + Validation + Conditional + Idempotency
  // =====================================================================
  const announcer = document.getElementById('live-announcer');
  let announceTimer;
  const flagged = new WeakSet();
  const announced = new WeakSet();

  function linkError(el, shown) {
    const errorId = el.dataset.error;
    if (!errorId) return;
    const ids = (el.getAttribute('aria-describedby') || '').split(/\s+/).filter((id) => id && id !== errorId);
    if (shown) ids.push(errorId);
    if (ids.length) el.setAttribute('aria-describedby', ids.join(' '));
    else el.removeAttribute('aria-describedby');
  }

  function syncAria(el, announce = false) {
    if (!el.matches?.('input, select, textarea')) return;
    const invalid = el.matches(':user-invalid') || el.classList.contains('user-invalid-fallback');
    if (invalid) {
      if (announce && !announced.has(el) && announcer) {
        const errNode = document.getElementById(el.dataset.error);
        if (errNode) {
          clearTimeout(announceTimer);
          announceTimer = setTimeout(() => {
            announcer.textContent = errNode.textContent.trim();
          }, 300);
        }
        announced.add(el);
      }
      el.setAttribute('aria-invalid', 'true');
      linkError(el, true);
      flagged.add(el);
    } else if (flagged.has(el) || el.getAttribute('aria-invalid') !== 'true') {
      el.setAttribute('aria-invalid', 'false');
      linkError(el, false);
      flagged.delete(el);
      announced.delete(el);
    }
  }

  document.querySelectorAll('input, select, textarea').forEach((el) => syncAria(el));
  document.addEventListener('blur', (e) => syncAria(e.target, true), true);
  document.addEventListener('input', (e) => {
    if (e.target.hasAttribute('aria-invalid')) {
      e.target.classList.remove('user-invalid-fallback');
      syncAria(e.target);
    }
  });
  document.addEventListener('change', (e) => syncAria(e.target, true), true);

  // Manage forms (#proposal-form, #service-request-form, #job-apply-form)
  const activeForm = document.querySelector('form[data-form-type]');
  if (activeForm) {
    const formType = activeForm.dataset.formType;
    const idempInput = activeForm.querySelector('#idempotency_key');
    if (idempInput && !idempInput.value) {
      idempInput.value = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    }

    let formStarted = false;
    activeForm.addEventListener('input', () => {
      if (!formStarted) {
        formStarted = true;
        sendAnalytics(formType === 'application' ? 'application_start' : 'form_start', { form_id: formType });
      }
    }, { once: true });

    // Conditional toggles for preferred contact method
    const emailInput = activeForm.querySelector('input[name="email"]');
    const phoneInput = activeForm.querySelector('input[name="telephone"]');
    const updateContactRequired = () => {
      const checked = activeForm.querySelector('input[name="preferred_contact_method"]:checked');
      if (!checked || !emailInput || !phoneInput) return;
      if (checked.value === 'email') {
        emailInput.required = true;
        phoneInput.required = false;
      } else {
        emailInput.required = false;
        phoneInput.required = true;
      }
    };
    activeForm.querySelectorAll('input[name="preferred_contact_method"]').forEach((r) => {
      r.addEventListener('change', updateContactRequired);
    });
    updateContactRequired();

    // Proposal conditional panels
    const serviceSel = activeForm.querySelector('#service_needed');
    const tiPanel = document.getElementById('ti-conditional-fields');
    const rcPanel = document.getElementById('recurring-conditional-fields');
    const multiCb = document.getElementById('multiple_properties');
    const multiPanel = document.getElementById('multi-prop-fields');
    const timingSel = document.getElementById('desired_timing');
    const tsNote = document.getElementById('time-sensitive-note');

    const updateConditionals = () => {
      if (serviceSel && tiPanel && rcPanel) {
        const v = serviceSel.value;
        tiPanel.hidden = !(v === 'tenant-improvements' || v === 'tenant-move-outs');
        rcPanel.hidden = !(v === 'day-porter' || v === 'recurring-property-care');
      }
      if (multiCb && multiPanel) {
        multiPanel.hidden = !multiCb.checked;
      }
      if (timingSel && tsNote) {
        tsNote.hidden = timingSel.value !== 'time-sensitive';
      }
    };
    serviceSel?.addEventListener('change', updateConditionals);
    multiCb?.addEventListener('change', updateConditionals);
    timingSel?.addEventListener('change', updateConditionals);
    updateConditionals();

    // Client-side file pre-check for proposal attachments
    const attachInput = document.getElementById('attachments');
    const uploadStatus = document.getElementById('upload-status');
    if (attachInput && uploadStatus) {
      attachInput.addEventListener('change', () => {
        const files = Array.from(attachInput.files || []);
        if (files.length > 5) {
          uploadStatus.textContent = 'Maximum 5 files allowed. Please choose 5 or fewer files.';
          return;
        }
        const total = files.reduce((s, f) => s + f.size, 0);
        if (total > 25 * 1024 * 1024) {
          uploadStatus.textContent = 'Total selected files exceed 25 MB limit.';
          return;
        }
        uploadStatus.textContent = files.length ? `${files.length} file(s) ready (${(total / (1024 * 1024)).toFixed(2)} MB).` : '';
      });
    }

    // Intercept submit for durable AJAX submission with error summary & failure preservation
    activeForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const summary = document.getElementById('form-error-summary');
      const errorList = document.getElementById('form-error-list');
      const serverFailBanner = document.getElementById('form-server-failure');
      const jobClosedBanner = document.getElementById('job-closed-banner');
      if (summary) summary.hidden = true;
      if (serverFailBanner) serverFailBanner.hidden = true;
      if (jobClosedBanner) jobClosedBanner.hidden = true;

      // Validate HTML constraints first
      const invalidFields = [];
      for (const el of activeForm.elements) {
        if (!el.willValidate) continue;
        if (!el.checkValidity()) {
          el.classList.add('user-invalid-fallback');
          syncAria(el);
          invalidFields.push(el);
        }
      }

      if (invalidFields.length > 0 && summary && errorList) {
        errorList.innerHTML = '';
        for (const el of invalidFields) {
          const li = document.createElement('li');
          const a = document.createElement('a');
          a.href = `#${el.id}`;
          const labelText = el.labels?.[0]?.textContent?.replace('*', '').trim() || el.name;
          a.textContent = `${labelText}: ${el.validationMessage}`;
          a.addEventListener('click', (ev) => { ev.preventDefault(); el.focus(); });
          li.appendChild(a);
          errorList.appendChild(li);
        }
        summary.hidden = false;
        summary.focus();
        sendAnalytics('form_error', { form_id: formType, error_code: 'client_validation' });
        return;
      }

      const submitBtn = activeForm.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.dataset.origText = submitBtn.textContent;
        submitBtn.textContent = 'Submitting...';
      }

      try {
        const fd = new FormData(activeForm);
        const utms = getAcquisitionUtms();
        fd.append('acquisition_utms_json', JSON.stringify(utms));
        fd.append('landing_page', sessionStorage.getItem('sm_first_landing') || window.location.pathname);
        fd.append('submitting_page', window.location.pathname);
        const onSite = sessionStorage.getItem('sm_last_onsite_campaign');
        if (onSite) fd.append('on_site_campaign_json', onSite);

        const res = await fetch(activeForm.action, {
          method: 'POST',
          body: fd,
          headers: { Accept: 'application/json' },
        });
        const data = await res.json().catch(() => ({}));

        if (res.status === 201 || res.status === 200) {
          window.location.assign(data.redirect_url || '/thank-you/');
          return;
        }

        if (res.status === 409 && data.code === 'job_closed') {
          if (jobClosedBanner) {
            jobClosedBanner.hidden = false;
            jobClosedBanner.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
          return;
        }

        if (res.status === 422 && data.errors && summary && errorList) {
          errorList.innerHTML = '';
          for (const [field, msg] of Object.entries(data.errors)) {
            const target = activeForm.querySelector(`[name="${field}"]`);
            if (target) {
              target.classList.add('user-invalid-fallback');
              syncAria(target);
            }
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.href = target ? `#${target.id}` : '#main-content';
            a.textContent = msg;
            li.appendChild(a);
            errorList.appendChild(li);
          }
          summary.hidden = false;
          summary.focus();
          sendAnalytics('form_error', { form_id: formType, error_code: 'server_validation' });
          return;
        }

        // Storage outage / 503 / 429 / 413 — preserve safe entries and offer fallback!
        if (serverFailBanner) {
          if (data.message) {
            serverFailBanner.innerHTML = `<strong>Submission not confirmed:</strong> ${data.message}`;
          }
          serverFailBanner.hidden = false;
          serverFailBanner.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        sendAnalytics('form_error', { form_id: formType, error_code: `http_${res.status}` });
      } catch {
        if (serverFailBanner) {
          serverFailBanner.hidden = false;
          serverFailBanner.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = submitBtn.dataset.origText || 'Submit';
        }
      }
    });
  }
})();
