(() => {
  'use strict';

  const csrfToken = document.body.dataset.csrf || '';
  const announcer = document.getElementById('admin-announcer');
  const alertBox = document.getElementById('admin-inline-alert');
  const alertText = document.getElementById('admin-inline-alert-text');
  const alertCloseBtn = document.getElementById('admin-inline-alert-close');
  let lastTriggerEl = null;

  function announce(msg) {
    if (typeof document.ariaNotify === 'function') {
      try {
        document.ariaNotify(msg);
      } catch {}
    }
    if (announcer) announcer.textContent = msg;
  }

  function showNotification(msg, kind = 'error', focusBanner = false) {
    if (!alertBox || !alertText) {
      announce(msg);
      return;
    }
    alertBox.classList.remove('admin-inline-alert--error', 'admin-inline-alert--success');
    if (kind === 'error') {
      alertBox.setAttribute('role', 'alert');
      alertBox.classList.add('admin-inline-alert--error');
    } else {
      alertBox.setAttribute('role', 'status');
      if (kind === 'success') alertBox.classList.add('admin-inline-alert--success');
    }
    alertText.textContent = msg;
    alertBox.hidden = false;
    announce(msg);
    if (focusBanner) {
      alertBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      alertBox.focus();
    }
  }

  function queueReloadWithFlash(msg, kind = 'success') {
    try {
      sessionStorage.setItem('sm_admin_flash', JSON.stringify({ msg, kind }));
    } catch {}
    location.reload();
  }

  try {
    const rawFlash = sessionStorage.getItem('sm_admin_flash');
    if (rawFlash) {
      sessionStorage.removeItem('sm_admin_flash');
      const parsed = JSON.parse(rawFlash);
      if (parsed && parsed.msg) {
        showNotification(parsed.msg, parsed.kind || 'success', false);
      }
    }
  } catch {}

  alertCloseBtn?.addEventListener('click', () => {
    if (alertBox) alertBox.hidden = true;
    if (lastTriggerEl && typeof lastTriggerEl.focus === 'function') {
      lastTriggerEl.focus();
      lastTriggerEl = null;
    }
  });

  // Mobile Sidebar Navigation Toggle
  const navToggle = document.getElementById('admin-nav-toggle');
  const navPanel = document.getElementById('admin-nav-panel');
  if (navToggle && navPanel) {
    navToggle.addEventListener('click', () => {
      const expanded = navToggle.getAttribute('aria-expanded') === 'true';
      navToggle.setAttribute('aria-expanded', String(!expanded));
      navPanel.classList.toggle('is-open', !expanded);
    });
  }

  // Native Confirmation Modal Dialog Helper
  const confirmDialog = document.getElementById('admin-confirm-dialog');
  const confirmTitle = document.getElementById('admin-confirm-title');
  const confirmMsg = document.getElementById('admin-confirm-message');
  const confirmDetails = document.getElementById('admin-confirm-details');
  const confirmCancel = document.getElementById('admin-confirm-cancel');
  const confirmProceed = document.getElementById('admin-confirm-proceed');
  let pendingConfirmAction = null;

  confirmCancel?.addEventListener('click', () => {
    confirmDialog?.close('cancel');
  });

  confirmProceed?.addEventListener('click', async () => {
    if (!pendingConfirmAction) {
      confirmDialog?.close('cancel');
      return;
    }
    confirmProceed.disabled = true;
    confirmProceed.setAttribute('aria-busy', 'true');
    try {
      await pendingConfirmAction();
    } finally {
      confirmProceed.disabled = false;
      confirmProceed.removeAttribute('aria-busy');
      pendingConfirmAction = null;
      confirmDialog?.close('confirm');
    }
  });

  confirmDialog?.addEventListener('close', () => {
    confirmDialog.returnValue = '';
    pendingConfirmAction = null;
  });

  function requestConfirmation({ title, message, detailsNode = null, confirmLabel = 'Confirm & Proceed' }, onConfirm) {
    if (!confirmDialog || typeof confirmDialog.showModal !== 'function') {
      onConfirm();
      return;
    }
    confirmTitle.textContent = title || 'Confirm Action';
    confirmMsg.textContent = message || 'Are you sure you want to proceed?';
    if (confirmProceed) confirmProceed.textContent = confirmLabel;
    if (confirmDetails) {
      confirmDetails.textContent = '';
      if (detailsNode) {
        confirmDetails.appendChild(detailsNode);
        confirmDetails.hidden = false;
      } else {
        confirmDetails.hidden = true;
      }
    }
    pendingConfirmAction = onConfirm;
    confirmDialog.showModal();
  }

  // 1. Page Editor Autosave, SEO Character Guides, Unsaved-Change Warning & In-Place Panel Swap
  let isDirty = false;
  let autosaveTimer = null;
  let beforeUnloadBound = false;

  function initPageEditorBindings() {
    const editorForm = document.getElementById('page-editor-form');
    const autosaveEl = document.getElementById('autosave-status');
    isDirty = false;
    clearTimeout(autosaveTimer);

    document.querySelectorAll('[data-char-target]').forEach((inputEl) => {
      const counterEl = document.getElementById(inputEl.dataset.charTarget);
      const maxRec = Number(inputEl.dataset.charRec || 0);
      if (!counterEl) return;
      const syncCounter = () => {
        const len = inputEl.value.length;
        counterEl.textContent = maxRec ? `${len} / ${maxRec} recommended chars` : `${len} chars`;
      };
      inputEl.addEventListener('input', syncCounter);
      syncCounter();
    });

    if (!editorForm) return;

    const saveDraft = async (silent = true) => {
      if (typeof editorForm.reportValidity === 'function' && !silent && !editorForm.reportValidity()) {
        return false;
      }
      if (autosaveEl) autosaveEl.textContent = 'Saving...';
      const fd = new FormData(editorForm);
      const body = Object.fromEntries(fd.entries());
      try {
        const res = await fetch(editorForm.dataset.autosaveUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (res.status === 409) {
          if (autosaveEl) autosaveEl.textContent = 'Conflict: newer revision exists';
          showNotification(
            data.message || 'Another user saved a newer revision. Compare revisions or reload before overwriting.',
            'error',
            true
          );
          return false;
        }
        if (!res.ok) {
          if (autosaveEl) autosaveEl.textContent = 'Save failed';
          if (!silent) showNotification(data.message || 'Save failed.', 'error', true);
          return false;
        }
        isDirty = false;
        if (data.revision_number) {
          const revInput = editorForm.querySelector('input[name="expected_revision"]');
          if (revInput) revInput.value = String(data.revision_number);
        }
        if (autosaveEl) autosaveEl.textContent = `Saved (v${data.revision_number})`;
        if (!silent) showNotification(`Draft revision v${data.revision_number} saved cleanly.`, 'success', false);
        else announce('Draft saved');
        return true;
      } catch {
        if (autosaveEl) autosaveEl.textContent = 'Save failed (network)';
        if (!silent) showNotification('Network error while saving draft. Your edits stay open here.', 'error', true);
        return false;
      }
    };

    editorForm.addEventListener('input', () => {
      isDirty = true;
      if (autosaveEl) autosaveEl.textContent = 'Unsaved changes';
      clearTimeout(autosaveTimer);
      autosaveTimer = setTimeout(() => saveDraft(true), 2500);
    });

    if (!beforeUnloadBound) {
      beforeUnloadBound = true;
      window.addEventListener('beforeunload', (e) => {
        if (isDirty) {
          e.preventDefault();
          e.returnValue = '';
        }
      });
    }

    document.getElementById('btn-save-draft')?.addEventListener('click', (e) => {
      lastTriggerEl = e.currentTarget;
      saveDraft(false);
    });

    document.getElementById('btn-submit-review')?.addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      lastTriggerEl = btn;
      btn.disabled = true;
      btn.setAttribute('aria-busy', 'true');
      try {
        await saveDraft(true);
        const res = await fetch(btn.dataset.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify({ csrf_token: csrfToken }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          isDirty = false;
          queueReloadWithFlash('Revision submitted for publisher review.');
        } else {
          showNotification(data.message || 'Could not submit for review.', 'error', true);
        }
      } finally {
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
      }
    });

    document.getElementById('btn-publish-page')?.addEventListener('click', (e) => {
      const btn = e.currentTarget;
      lastTriggerEl = btn;
      requestConfirmation(
        {
          title: 'Publish Current Revision Live?',
          message: btn.dataset.confirm || 'This approves the current draft revision and publishes it live to the public website immediately.',
          confirmLabel: 'Approve & Publish Live',
        },
        async () => {
          const res = await fetch(btn.dataset.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify({ csrf_token: csrfToken }),
          });
          const data = await res.json().catch(() => ({}));
          if (res.ok) {
            isDirty = false;
            queueReloadWithFlash(`Published live to ${data.public_url || 'public site'}.`);
          } else {
            showNotification(data.message || 'Publish failed.', 'error', true);
          }
        }
      );
    });

    document.querySelectorAll('.js-restore-rev').forEach((btn) => {
      btn.addEventListener('click', () => {
        lastTriggerEl = btn;
        requestConfirmation(
          {
            title: `Restore v${btn.dataset.rev} to Reviewable Draft?`,
            message: 'Restoring creates a new Draft revision without immediately publishing or reviving withdrawn claims.',
            confirmLabel: 'Restore to Draft',
          },
          async () => {
            const res = await fetch(btn.dataset.url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
              body: JSON.stringify({ revision_number: Number(btn.dataset.rev), csrf_token: csrfToken }),
            });
            const data = await res.json().catch(() => ({}));
            if (res.ok) {
              isDirty = false;
              queueReloadWithFlash(`Restored revision v${btn.dataset.rev} into new draft v${data.revision_number}.`);
            } else {
              showNotification(data.message || 'Restore failed.', 'error', true);
            }
          }
        );
      });
    });
  }

  initPageEditorBindings();

  document.addEventListener('click', async (e) => {
    const swapLink = e.target.closest('a[data-panel-swap]');
    if (!swapLink || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const selector = swapLink.dataset.panelSwap;
    const targetPanel = document.querySelector(selector);
    if (!targetPanel) return;

    e.preventDefault();
    const doSwap = async () => {
      const cleanUrl = swapLink.href.split('#')[0];
      targetPanel.classList.add('is-loading');
      targetPanel.setAttribute('aria-busy', 'true');
      try {
        const res = await fetch(cleanUrl, { credentials: 'same-origin' });
        if (!res.ok) {
          location.href = swapLink.href;
          return;
        }
        const html = await res.text();
        const doc = new DOMParser().parseFromString(html, 'text/html');
        const nextPanel = doc.querySelector(selector);
        if (!nextPanel) {
          location.href = swapLink.href;
          return;
        }
        targetPanel.replaceWith(nextPanel);
        const pageId = swapLink.dataset.pageId;
        if (pageId) {
          document.querySelectorAll('[data-page-id].is-selected').forEach((el) => el.classList.remove('is-selected'));
          document.querySelectorAll(`[data-page-id="${CSS.escape(pageId)}"]`).forEach((el) => {
            if (el.tagName === 'TR' || el.classList.contains('admin-mobile-card') || el.classList.contains('admin-page-card')) {
              el.classList.add('is-selected');
            }
          });
        }
        if (window.history && typeof window.history.replaceState === 'function') {
          window.history.replaceState(null, '', cleanUrl);
        }
        initPageEditorBindings();
        nextPanel.scrollTop = 0;
        if (window.innerWidth < 1120) {
          nextPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        announce('Loaded selected page into editor panel');
      } catch {
        location.href = swapLink.href;
      }
    };

    if (isDirty) {
      requestConfirmation(
        {
          title: 'Discard Unsaved Draft Changes?',
          message: 'You have unsaved edits in the current page. Switch pages anyway?',
          confirmLabel: 'Switch Page',
        },
        doSwap
      );
      return;
    }

    await doSwap();
  });

  // 2. Native Confirmation Dialog for Media Rights Withdrawal (shows affected placements first!)
  document.addEventListener('click', async (e) => {
    const withdrawBtn = e.target.closest('.js-withdraw-media-btn');
    if (!withdrawBtn || !confirmDialog) return;
    lastTriggerEl = withdrawBtn;
    withdrawBtn.disabled = true;

    try {
      const usageRes = await fetch(withdrawBtn.dataset.usageUrl);
      const usageData = await usageRes.json().catch(() => ({}));
      const fname = withdrawBtn.dataset.filename || 'this media asset';

      const msg = usageRes.ok && usageData.totalAffected > 0
        ? `Warning: Withdrawing rights will immediately remove this image from ${usageData.totalAffected} active placement(s) across projects and campaigns.`
        : 'Withdrawing rights disables public delivery for this asset immediately.';

      let list = null;
      if (usageRes.ok && usageData.totalAffected > 0) {
        list = document.createElement('ul');
        list.style.margin = '0';
        list.style.paddingInlineStart = '1.2rem';
        for (const p of usageData.affected.coverProjects || []) {
          const li = document.createElement('li');
          li.textContent = `Project Cover: ${p.title} (${p.activation_state})`;
          list.appendChild(li);
        }
        for (const g of usageData.affected.galleryRefs || []) {
          const li = document.createElement('li');
          li.textContent = `Project Gallery: ${g.project_title} (${g.activation_state})`;
          list.appendChild(li);
        }
        for (const b of usageData.affected.pairRefs || []) {
          const li = document.createElement('li');
          li.textContent = `Before/After Pair "${b.pair_title}" in ${b.project_title}`;
          list.appendChild(li);
        }
        for (const c of usageData.affected.campaignRefs || []) {
          const li = document.createElement('li');
          li.textContent = `Campaign "${c.internal_title}" (${c.placement_slot} / ${c.activation_state})`;
          list.appendChild(li);
        }
      }

      requestConfirmation(
        {
          title: `Withdraw Rights for "${fname}"?`,
          message: msg,
          detailsNode: list,
          confirmLabel: 'Withdraw Rights',
        },
        async () => {
          const res = await fetch(withdrawBtn.dataset.withdrawUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify({ csrf_token: csrfToken }),
          });
          const data = await res.json().catch(() => ({}));
          if (res.ok) {
            queueReloadWithFlash(data.message || 'Asset rights withdrawn.');
          } else {
            showNotification(data.message || 'Withdrawal failed.', 'error', true);
          }
        }
      );
    } catch {
      showNotification('Could not check media placement dependencies.', 'error', true);
    } finally {
      withdrawBtn.disabled = false;
    }
  });

  // 3. Action Buttons (.js-action-btn) with optional data-confirm modal
  async function runActionButton(btn) {
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    try {
      const res = await fetch(btn.dataset.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ csrf_token: csrfToken }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        if (data.setup_url) {
          showNotification(`${data.message} Share securely with the user: ${window.location.origin}${data.setup_url}`, 'success', true);
          return;
        }
        queueReloadWithFlash(data.message || btn.dataset.successMsg || 'Action completed successfully.');
      } else {
        showNotification(data.message || 'Action failed.', 'error', true);
      }
    } catch {
      showNotification('Network error while performing action.', 'error', true);
    } finally {
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
    }
  }

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.js-action-btn');
    if (!btn) return;
    lastTriggerEl = btn;
    if (btn.dataset.confirm) {
      requestConfirmation(
        {
          title: btn.dataset.confirmTitle || 'Confirm Action',
          message: btn.dataset.confirm,
          confirmLabel: btn.dataset.confirmLabel || 'Confirm & Proceed',
        },
        () => runActionButton(btn)
      );
      return;
    }
    runActionButton(btn);
  });

  // 4. Generic AJAX Forms (.js-ajax-form) supporting multi-checkbox arrays + optional data-confirm
  async function submitAjaxForm(form) {
    const submitBtn = form.querySelector('button[type="submit"]');
    lastTriggerEl = submitBtn || form;
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.setAttribute('aria-busy', 'true');
    }
    try {
      const fd = new FormData(form);
      const body = {};
      const arrayNames = new Set(
        Array.from(form.querySelectorAll('input[type="checkbox"][data-checkbox-array], input[type="checkbox"][name="extra_roles"]'))
          .map((cb) => cb.name)
      );
      for (const [k, v] of fd.entries()) {
        if (arrayNames.has(k)) continue;
        body[k] = v;
      }
      for (const name of arrayNames) {
        body[name] = fd.getAll(name);
      }
      form.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
        if (arrayNames.has(cb.name)) return;
        body[cb.name] = cb.checked;
      });

      const res = await fetch(form.action, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (data.setup_url && form.id === 'create-user-form') {
        const box = document.getElementById('onboarding-link-box');
        const inp = document.getElementById('onboarding-link-input');
        const meta = document.getElementById('onboarding-link-meta');
        if (box && inp && meta) {
          const fullUrl = data.full_setup_url && data.full_setup_url.startsWith('http')
            ? data.full_setup_url
            : `${window.location.origin}${data.setup_url}`;
          inp.value = fullUrl;
          meta.textContent = `Single-use onboarding link (expires ${data.expires_at || 'soon'}). Share securely—it will not be shown again.`;
          box.hidden = false;
          showNotification(data.message || 'Onboarding link ready to copy.', res.ok ? 'success' : 'error', true);
          return;
        }
      }
      if (res.ok) {
        queueReloadWithFlash(data.message || form.dataset.successMsg || 'Changes saved successfully.');
      } else {
        showNotification(data.message || 'Operation failed.', 'error', true);
      }
    } catch {
      showNotification('Request failed due to network interruption.', 'error', true);
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.removeAttribute('aria-busy');
      }
    }
  }

  document.querySelectorAll('.js-ajax-form').forEach((form) => {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (form.dataset.confirm) {
        requestConfirmation(
          {
            title: form.dataset.confirmTitle || 'Confirm Update',
            message: form.dataset.confirm,
            confirmLabel: form.dataset.confirmLabel || 'Save Changes',
          },
          () => submitAjaxForm(form)
        );
        return;
      }
      submitAjaxForm(form);
    });
  });

  function wireCopyButton(btnId, inputId) {
    const btn = document.getElementById(btnId);
    const inp = document.getElementById(inputId);
    if (!btn || !inp) return;
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(inp.value);
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy Setup Link'; }, 2000);
      } catch {
        inp.select();
        document.execCommand('copy');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy Setup Link'; }, 2000);
      }
    });
  }
  wireCopyButton('btn-copy-onboarding-link', 'onboarding-link-input');
  wireCopyButton('btn-copy-edit-onboarding-link', 'edit-onboarding-link-input');

  document.addEventListener('click', async (e) => {
    const inviteBtn = e.target.closest('.js-invite-btn');
    if (!inviteBtn) return;
    lastTriggerEl = inviteBtn;
    const delivery = inviteBtn.dataset.delivery || 'manual';
    inviteBtn.disabled = true;
    inviteBtn.setAttribute('aria-busy', 'true');
    try {
      const res = await fetch(inviteBtn.dataset.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ csrf_token: csrfToken, delivery_method: delivery }),
      });
      const data = await res.json().catch(() => ({}));
      if (data.setup_url) {
        const box = document.getElementById('edit-onboarding-link-box');
        const inp = document.getElementById('edit-onboarding-link-input');
        const meta = document.getElementById('edit-onboarding-link-meta');
        if (box && inp && meta) {
          const fullUrl = data.full_setup_url && data.full_setup_url.startsWith('http')
            ? data.full_setup_url
            : `${window.location.origin}${data.setup_url}`;
          inp.value = fullUrl;
          meta.textContent = `Single-use link (${data.purpose || 'setup'}, expires ${data.expires_at || 'soon'}). Previous unused links were invalidated.`;
          box.hidden = false;
        }
      }
      showNotification(data.message || (res.ok ? 'Invitation processed.' : 'Invitation failed.'), res.ok ? 'success' : 'error', true);
    } catch {
      showNotification('Network error while issuing setup link.', 'error', true);
    } finally {
      inviteBtn.disabled = false;
      inviteBtn.removeAttribute('aria-busy');
    }
  });

  const editUserForm = document.getElementById('edit-user-form');
  if (editUserForm) {
    editUserForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const fd = new FormData(editUserForm);
      const origName = editUserForm.dataset.origName || '';
      const origRole = editUserForm.dataset.origRole || '';
      const origActive = editUserForm.dataset.origActive || '1';
      let origExtra = [];
      try {
        origExtra = JSON.parse(editUserForm.dataset.origExtra || '[]');
      } catch (_err) {
        origExtra = [];
      }

      const nextName = String(fd.get('full_name') || '').trim();
      const nextRole = String(fd.get('role') || '');
      const nextActive = String(fd.get('active') || '');
      const nextExtra = fd.getAll('extra_roles').map(String);
      const hasNewPassword = Boolean(String(fd.get('new_password') || '').trim());

      const origSet = new Set([origRole, ...origExtra].filter(Boolean));
      const nextSet = new Set([nextRole, ...nextExtra].filter(Boolean));
      const addedRoles = [...nextSet].filter((r) => !origSet.has(r));
      const removedRoles = [...origSet].filter((r) => !nextSet.has(r));
      const rolesChanged = addedRoles.length > 0 || removedRoles.length > 0 || nextRole !== origRole;
      const statusChanged = nextActive !== origActive;
      const sensitiveRoles = new Set(['Platform Administrator', 'Hiring Owner', 'Hiring Reviewer']);
      const grantsSensitive = addedRoles.some((r) => sensitiveRoles.has(r)) || (nextRole !== origRole && sensitiveRoles.has(nextRole));

      if (grantsSensitive) {
        requestConfirmation(
          {
            title: 'Confirm Sensitive Privilege Grant',
            message: `Granting elevated role access (${addedRoles.filter((r) => sensitiveRoles.has(r)).join(', ') || nextRole}) expands administrative or protected recruiting permissions and revokes active sessions immediately.`,
            confirmLabel: 'Grant Elevated Access',
          },
          () => submitAjaxForm(editUserForm)
        );
        return;
      }

      if (rolesChanged || statusChanged || hasNewPassword) {
        const changes = [];
        if (rolesChanged) changes.push(`roles (${nextRole})`);
        if (statusChanged) changes.push(nextActive === '1' ? 'account activation' : 'account deactivation');
        if (hasNewPassword) changes.push('password reset');
        requestConfirmation(
          {
            title: 'Confirm Account Access Update',
            message: `Save ${changes.join(', ')} for ${nextName || origName || 'this user'}? Role or deactivation changes revoke active sessions immediately.`,
            confirmLabel: 'Save Account Changes',
          },
          () => submitAjaxForm(editUserForm)
        );
        return;
      }

      submitAjaxForm(editUserForm);
    });
  }

  // 5. Multipart Forms (.js-multipart-form, e.g., Resume Replacement)
  document.querySelectorAll('.js-multipart-form').forEach((form) => {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = form.querySelector('button[type="submit"]');
      lastTriggerEl = submitBtn || form;
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.setAttribute('aria-busy', 'true');
      }
      try {
        const fd = new FormData(form);
        const res = await fetch(form.action, {
          method: 'POST',
          headers: { 'X-CSRF-Token': csrfToken },
          body: fd,
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          queueReloadWithFlash('File uploaded cleanly.');
        } else {
          showNotification(data.message || 'File upload failed.', 'error', true);
        }
      } catch {
        showNotification('File upload interrupted. Please retry.', 'error', true);
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.removeAttribute('aria-busy');
        }
      }
    });
  });

  // Lead Details Modal (#admin-lead-dialog)
  const leadDialog = document.getElementById('admin-lead-dialog');
  const leadDialogClose = document.getElementById('lead-dialog-close');
  leadDialogClose?.addEventListener('click', () => leadDialog?.close());
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.js-lead-detail-btn');
    if (!btn || !leadDialog) return;
    let lead = null;
    try {
      lead = JSON.parse(btn.dataset.lead || '{}');
    } catch {
      return;
    }
    const titleEl = document.getElementById('lead-dialog-title');
    const kindEl = document.getElementById('lead-dialog-kind');
    const dl = document.getElementById('lead-dialog-dl');
    if (titleEl) titleEl.textContent = lead.org_name || 'Inquiry Details';
    if (kindEl) kindEl.textContent = `${lead.kind || 'Inquiry'} · ${(lead.inquiry_id || '').slice(0, 8)}`;
    if (dl) {
      dl.innerHTML = '';
      const addItem = (label, val, { full = false, href = '' } = {}) => {
        const wrap = document.createElement('div');
        if (full) wrap.className = 'lead-detail-dl__full';
        const dt = document.createElement('dt');
        dt.textContent = label;
        const dd = document.createElement('dd');
        if (href && val) {
          const a = document.createElement('a');
          a.href = href;
          a.textContent = val;
          dd.appendChild(a);
        } else {
          dd.textContent = val || '—';
        }
        wrap.appendChild(dt);
        wrap.appendChild(dd);
        dl.appendChild(wrap);
      };
      addItem('Contact Name', lead.name);
      addItem('Preferred Method', lead.preferred_contact_method);
      addItem('Email', lead.email, { href: lead.email ? `mailto:${lead.email}` : '' });
      addItem('Telephone', lead.telephone, { href: lead.telephone ? `tel:${lead.telephone}` : '' });
      addItem('Service Requested', lead.service);
      addItem('Property Location', lead.prop_loc);
      addItem('Property Type', lead.property_type);
      addItem('Desired Timing', lead.desired_timing);
      addItem('Pipeline Stage', `${lead.classification} · ${lead.status}`);
      addItem('Received (Phoenix)', lead.received_at);
      addItem('Project Description', lead.description, { full: true });
    }
    if (typeof leadDialog.showModal === 'function') leadDialog.showModal();
  });

  // ============================================================
  // Phase 1: Projects & Media (Dropzone, 4-Step Create, 5-Tab Edit)
  // ============================================================
  const wireDropzone = (inputEl, previewContainer, onSelect) => {
    if (!inputEl || !previewContainer) return;
    const box = inputEl.closest('.dropzone-box');
    const renderFiles = (files) => {
      previewContainer.innerHTML = '';
      const arr = Array.from(files || []);
      if (arr.length === 0) {
        previewContainer.hidden = true;
        return;
      }
      previewContainer.hidden = false;
      arr.forEach((f) => {
        const card = document.createElement('div');
        card.className = 'dropzone-preview-item';
        const img = document.createElement('img');
        img.alt = f.name;
        const reader = new FileReader();
        reader.onload = () => {
          img.src = String(reader.result || '');
        };
        reader.readAsDataURL(f);
        const name = document.createElement('span');
        name.textContent = f.name;
        name.style.overflow = 'hidden';
        name.style.textOverflow = 'ellipsis';
        name.style.whiteSpace = 'nowrap';
        card.appendChild(img);
        card.appendChild(name);
        previewContainer.appendChild(card);
      });
    };
    inputEl.addEventListener('change', () => {
      renderFiles(inputEl.files);
      if (onSelect) onSelect(inputEl.files);
    });
    if (box) {
      box.addEventListener('dragover', (e) => {
        e.preventDefault();
        box.classList.add('is-dragover');
      });
      box.addEventListener('dragleave', () => box.classList.remove('is-dragover'));
      box.addEventListener('drop', (e) => {
        e.preventDefault();
        box.classList.remove('is-dragover');
        if (e.dataTransfer?.files?.length) {
          inputEl.files = e.dataTransfer.files;
          renderFiles(inputEl.files);
          if (onSelect) onSelect(inputEl.files);
        }
      });
    }
  };

  // Wire reusable dropzone upload forms (#media-upload-form, #proj-media-upload-form)
  document.querySelectorAll('.js-media-dropzone-form').forEach((form) => {
    const fileInput = form.querySelector('input[type="file"]');
    const previewBox = form.querySelector('.dropzone-previews');
    const feedback = form.querySelector('[id$="-upload-feedback"]');
    const submitBtn = form.querySelector('button[type="submit"]');
    wireDropzone(fileInput, previewBox);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        if (feedback) feedback.textContent = 'Select at least one photo first.';
        showNotification('Select at least one photo before uploading.', 'error', true);
        return;
      }
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.setAttribute('aria-busy', 'true');
      }
      if (feedback) feedback.textContent = 'Uploading photos and stripping EXIF/GPS metadata...';
      try {
        const fd = new FormData(form);
        const rawFiles = Array.from(fileInput.files || []).filter((f) => f && f.size > 0);
        let res;
        const presignRes = await fetch('/admin/api/media/presign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify({
            csrf_token: csrfToken,
            files: rawFiles.map((f) => ({ name: f.name, size: f.size, type: f.type || 'application/octet-stream' })),
          }),
        });
        const presignData = await presignRes.json().catch(() => ({}));
        if (!presignRes.ok) {
          throw new Error(presignData.message || 'Upload pre-check failed.');
        }
        if (presignData.mode === 's3_presigned_put' && Array.isArray(presignData.uploads)) {
          if (feedback) feedback.textContent = 'Uploading original image(s) directly to object storage...';
          const stagedFiles = [];
          for (let idx = 0; idx < presignData.uploads.length; idx++) {
            const u = presignData.uploads[idx];
            const fileObj = rawFiles[idx];
            const putRes = await fetch(u.url, {
              method: 'PUT',
              headers: u.headers || { 'Content-Type': fileObj.type || 'application/octet-stream' },
              body: fileObj,
            });
            if (!putRes.ok) throw new Error(`Direct S3 upload failed for ${fileObj.name} (${putRes.status}).`);
            stagedFiles.push({ stagingKey: u.stagingKey, originalName: u.originalName });
          }
          if (feedback) feedback.textContent = 'Processing EXIF orientation and responsive WebP/JPEG variants...';
          res = await fetch('/admin/api/media/finalize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            body: JSON.stringify({
              csrf_token: csrfToken,
              alt_text: String(fd.get('alt_text') || ''),
              rights_owner: String(fd.get('rights_owner') || 'Internal'),
              staged_files: stagedFiles,
            }),
          });
        } else {
          res = await fetch(form.action, {
            method: 'POST',
            body: fd,
            headers: { 'x-csrf-token': csrfToken, Accept: 'application/json' },
            credentials: 'same-origin',
          });
        }
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          const uploadedCount = data.accepted?.length ?? data.assets?.length ?? 0;
          const msg = data.message || `Uploaded ${uploadedCount} photo(s). Rejected: ${data.rejected?.length || 0}.`;
          if (data.rejected?.length) {
            showNotification(`${msg} Rejected: ${data.rejected.map((r) => `${r.name} (${r.message})`).join('; ')}`, 'error', true);
            return;
          }
          queueReloadWithFlash(msg);
        } else {
          const errMsg = data.message || 'Upload failed.';
          if (feedback) feedback.textContent = errMsg;
          showNotification(errMsg, 'error', true);
        }
      } catch (err) {
        const netMsg = err?.message || 'Upload interrupted. Safe to retry.';
        if (feedback) feedback.textContent = netMsg;
        showNotification(netMsg, 'error', true);
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.removeAttribute('aria-busy');
        }
      }
    });
  });

  // Guided 4-Step Create Project Wizard
  const createWizard = document.getElementById('project-create-wizard');
  if (createWizard) {
    const steps = Array.from(createWizard.querySelectorAll('.wizard-step[data-wiz-step]'));
    const indicators = Array.from(document.querySelectorAll('#project-create-stepper [data-wiz-ind]'));
    const errBox = document.getElementById('project-create-error');
    const errText = document.getElementById('project-create-error-text');
    const titleInput = document.getElementById('wiz-title');
    const slugInput = document.getElementById('wiz-slug');
    let slugTouched = false;
    let wizStep = 1;

    slugInput?.addEventListener('input', () => {
      slugTouched = true;
    });
    titleInput?.addEventListener('input', () => {
      if (!slugTouched && slugInput) {
        slugInput.value = titleInput.value
          .toLowerCase()
          .trim()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '')
          .slice(0, 80);
      }
    });

    wireDropzone(document.getElementById('wiz-before-file'), document.getElementById('wiz-before-preview'));
    wireDropzone(document.getElementById('wiz-after-file'), document.getElementById('wiz-after-preview'));

    const renderWizReview = () => {
      const box = document.getElementById('wiz-review-box');
      if (!box) return;
      const g = (id) => (document.getElementById(id)?.value || '').trim();
      const bFile = document.getElementById('wiz-before-file')?.files?.[0]?.name;
      const aFile = document.getElementById('wiz-after-file')?.files?.[0]?.name;
      box.innerHTML = '';
      const dl = document.createElement('dl');
      dl.className = 'lead-detail-dl';
      [
        ['Project Title', g('wiz-title')],
        ['Property Type', g('wiz-prop')],
        ['Location', g('wiz-city')],
        ['Completion Date', g('wiz-comp')],
        ['Challenge', g('wiz-chal')],
        ['Agreed Scope', g('wiz-scope')],
        ['Before Photo', bFile || 'None selected'],
        ['After Photo', aFile || 'None selected'],
      ].forEach(([k, v]) => {
        const w = document.createElement('div');
        const dt = document.createElement('dt');
        dt.textContent = k;
        const dd = document.createElement('dd');
        dd.textContent = v || '—';
        w.appendChild(dt);
        w.appendChild(dd);
        dl.appendChild(w);
      });
      box.appendChild(dl);
    };

    const showWizStep = (n) => {
      wizStep = n;
      if (errBox) errBox.hidden = true;
      steps.forEach((s) => {
        s.hidden = Number(s.dataset.wizStep) !== n;
      });
      indicators.forEach((ind) => {
        const idx = Number(ind.dataset.wizInd);
        ind.dataset.state = idx < n ? 'done' : idx === n ? 'active' : 'upcoming';
        if (idx === n) ind.setAttribute('aria-current', 'step');
        else ind.removeAttribute('aria-current');
      });
      if (n === 4) renderWizReview();
    };

    const validateWizStep = (n) => {
      const stepEl = steps.find((s) => Number(s.dataset.wizStep) === n);
      if (!stepEl) return true;
      for (const el of stepEl.querySelectorAll('input, select, textarea')) {
        if (!el.willValidate) continue;
        if (!el.checkValidity()) {
          if (errBox && errText) {
            const label = el.labels?.[0]?.textContent?.replace('*', '').trim() || el.name;
            errText.textContent = `${label}: ${el.validationMessage}`;
            errBox.hidden = false;
          }
          el.focus();
          return false;
        }
      }
      return true;
    };

    createWizard.addEventListener('click', (e) => {
      const next = e.target.closest('[data-wiz-next]');
      if (next) {
        if (validateWizStep(wizStep)) showWizStep(Number(next.dataset.wizNext));
        return;
      }
      const prev = e.target.closest('[data-wiz-prev]');
      if (prev) showWizStep(Number(prev.dataset.wizPrev));
    });

    const submitCreateProject = async (opts = {}) => {
      const isEarly = Boolean(opts.allowEarlyStep1);
      if (!validateWizStep(1)) return;
      if (!isEarly && !validateWizStep(2)) return;

      const submitBtn = document.getElementById('wiz-submit-btn');
      const earlyBtn = document.getElementById('wiz-save-draft-early');
      const step1DraftBtn = document.getElementById('wiz-save-draft-step1');
      if (submitBtn) submitBtn.disabled = true;
      if (earlyBtn) earlyBtn.disabled = true;
      if (step1DraftBtn) step1DraftBtn.disabled = true;

      try {
        const fd = new FormData(createWizard);
        const body = Object.fromEntries(fd.entries());
        if (!body.challenge) body.challenge = 'Initial project draft initiated.';
        if (!body.agreed_scope) body.agreed_scope = 'Scope to be finalized in project details.';
        if (!body.completed_work) body.completed_work = 'Work details in progress.';

        const res = await fetch('/admin/api/projects', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken, Accept: 'application/json' },
          body: JSON.stringify(body),
          credentials: 'same-origin',
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.project_id) {
          throw new Error(data.message || 'Could not create project draft.');
        }
        const projectId = data.project_id;

        // Also persist permissions/result fields if filled
        if (!isEarly) {
          await fetch(`/admin/api/projects/${encodeURIComponent(projectId)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken, Accept: 'application/json' },
            body: JSON.stringify({
              title: body.title,
              property_type: body.property_type,
              city_region: body.city_region,
              completion_date: body.completion_date,
              challenge: body.challenge,
              agreed_scope: body.agreed_scope,
              completed_work: body.completed_work,
              verified_result: body.verified_result || 'Completed agreed scope',
              self_performed_notes: body.self_performed_notes || 'In-house work',
              coordinated_notes: body.coordinated_notes || 'Coordinated trades where applicable',
              related_services: body.related_services || '',
              naming_decision: body.naming_decision || 'anonymized',
              completion_documented: Boolean(document.getElementById('wiz-doc')?.checked),
              client_permission_verified: Boolean(document.getElementById('wiz-perm')?.checked),
              is_private_test: Boolean(document.getElementById('wiz-test')?.checked),
            }),
            credentials: 'same-origin',
          });
        }

        // Upload optional Before/After photos and create pair if both provided
        const bFile = document.getElementById('wiz-before-file')?.files?.[0];
        const aFile = document.getElementById('wiz-after-file')?.files?.[0];
        const uploadSingle = async (file, alt) => {
          const ufd = new FormData();
          ufd.append('csrf_token', csrfToken);
          ufd.append('rights_owner', 'Service Maintenance / Client Approved');
          ufd.append('alt_text', alt);
          ufd.append('photos', file);
          const ur = await fetch('/admin/api/media/upload', {
            method: 'POST',
            body: ufd,
            headers: { 'x-csrf-token': csrfToken, Accept: 'application/json' },
            credentials: 'same-origin',
          });
          const ud = await ur.json().catch(() => ({}));
          return ud.accepted?.[0]?.asset_id || ud.assets?.[0]?.asset_id || null;
        };

        let beforeId = null;
        let afterId = null;
        if (bFile) beforeId = await uploadSingle(bFile, `${body.title} — Before`);
        if (aFile) afterId = await uploadSingle(aFile, `${body.title} — After`);
        if (beforeId && afterId) {
          await fetch(`/admin/api/projects/${encodeURIComponent(projectId)}/pairs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken, Accept: 'application/json' },
            body: JSON.stringify({
              pair_title: document.getElementById('wiz-pair-title')?.value.trim() || `${body.title} Comparison`,
              before_asset_id: beforeId,
              after_asset_id: afterId,
              before_caption: document.getElementById('wiz-before-cap')?.value.trim() || 'Before work',
              after_caption: document.getElementById('wiz-after-cap')?.value.trim() || 'After completion',
            }),
            credentials: 'same-origin',
          });
        }

        window.location.assign(`/admin/projects?view=edit&id=${encodeURIComponent(projectId)}`);
      } catch (err) {
        if (errBox && errText) {
          errText.textContent = err?.message || 'Error creating project draft.';
          errBox.hidden = false;
        }
        if (submitBtn) submitBtn.disabled = false;
        if (earlyBtn) earlyBtn.disabled = false;
        const step1Btn = document.getElementById('wiz-save-draft-step1');
        if (step1Btn) step1Btn.disabled = false;
      }
    };

    document.getElementById('wiz-save-draft-step1')?.addEventListener('click', () => submitCreateProject({ allowEarlyStep1: true }));
    document.getElementById('wiz-save-draft-early')?.addEventListener('click', () => submitCreateProject({ allowEarlyStep1: false }));
    createWizard.addEventListener('submit', (e) => {
      e.preventDefault();
      submitCreateProject({ allowEarlyStep1: false });
    });
  }

  // 5-Tab Edit Project Controller + Dirty Guard + Live Thumbnails
  const projectEditForm = document.getElementById('project-edit-form');
  if (projectEditForm) {
    const tabBtns = Array.from(document.querySelectorAll('#project-edit-tabs [data-project-tab]'));
    const tabPanels = Array.from(document.querySelectorAll('.project-tab-panel[data-project-panel]'));
    const dirtyBadge = document.getElementById('project-dirty-badge');
    let projectDirty = false;

    const switchProjectTab = (name) => {
      tabBtns.forEach((b) => b.classList.toggle('is-active', b.dataset.projectTab === name));
      tabPanels.forEach((p) => {
        p.hidden = p.dataset.projectPanel !== name;
      });
    };

    document.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-project-tab], .js-switch-project-tab');
      if (!btn) return;
      const target = btn.dataset.projectTab || btn.dataset.targetTab;
      if (target) switchProjectTab(target);
    });

    projectEditForm.addEventListener('input', () => {
      projectDirty = true;
      if (dirtyBadge) dirtyBadge.hidden = false;
    });
    projectEditForm.addEventListener('change', () => {
      projectDirty = true;
      if (dirtyBadge) dirtyBadge.hidden = false;
    });
    projectEditForm.addEventListener('submit', () => {
      projectDirty = false;
      if (dirtyBadge) dirtyBadge.hidden = true;
    });
    window.addEventListener('beforeunload', (e) => {
      if (projectDirty) {
        e.preventDefault();
        e.returnValue = '';
      }
    });

    // Live Cover Photo thumbnail preview
    const coverSel = document.getElementById('sp-cover');
    const coverPrev = document.getElementById('sp-cover-preview');
    coverSel?.addEventListener('change', () => {
      if (!coverPrev) return;
      coverPrev.src = coverSel.value ? `/admin/api/media/preview/${encodeURIComponent(coverSel.value)}` : '/assets/brand-mark.svg';
    });

    // Live Before/After pair thumbnail previews
    document.querySelectorAll('.js-pair-preview-sel').forEach((sel) => {
      sel.addEventListener('change', () => {
        const img = document.getElementById(sel.dataset.previewTarget);
        if (img && sel.value) img.src = `/admin/api/media/preview/${encodeURIComponent(sel.value)}`;
      });
    });
  }
})();
