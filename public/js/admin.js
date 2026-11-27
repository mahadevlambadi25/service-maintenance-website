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
            if (el.tagName === 'TR' || el.classList.contains('admin-mobile-card')) {
              el.classList.add('is-selected');
            }
          });
        }
        if (window.history && typeof window.history.replaceState === 'function') {
          window.history.replaceState(null, '', cleanUrl);
        }
        initPageEditorBindings();
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

  // 6. Batch Media Upload (#media-upload-form)
  const mediaForm = document.getElementById('media-upload-form');
  const mediaFeedback = document.getElementById('media-upload-feedback');
  if (mediaForm) {
    mediaForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = mediaForm.querySelector('button[type="submit"]');
      lastTriggerEl = submitBtn || mediaForm;
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.setAttribute('aria-busy', 'true');
      }
      if (mediaFeedback) mediaFeedback.textContent = 'Uploading, validating signatures, and stripping metadata...';
      try {
        const fd = new FormData(mediaForm);
        const fileInput = mediaForm.querySelector('input[type="file"]');
        const rawFiles = Array.from(fileInput?.files || []).filter((f) => f && f.size > 0);
        let res;

        if (rawFiles.length > 0) {
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
            if (mediaFeedback) mediaFeedback.textContent = 'Uploading original image(s) directly to object storage...';
            const stagedFiles = [];
            for (let idx = 0; idx < presignData.uploads.length; idx++) {
              const u = presignData.uploads[idx];
              const fileObj = rawFiles[idx];
              const putRes = await fetch(u.url, {
                method: 'PUT',
                headers: u.headers || { 'Content-Type': fileObj.type || 'application/octet-stream' },
                body: fileObj,
              });
              if (!putRes.ok) {
                throw new Error(`Direct S3 upload failed for ${fileObj.name} (${putRes.status}).`);
              }
              stagedFiles.push({ stagingKey: u.stagingKey, originalName: u.originalName });
            }
            if (mediaFeedback) mediaFeedback.textContent = 'Processing EXIF orientation and responsive WebP/JPEG variants...';
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
            res = await fetch(mediaForm.action, {
              method: 'POST',
              headers: { 'X-CSRF-Token': csrfToken },
              body: fd,
            });
          }
        } else {
          res = await fetch(mediaForm.action, {
            method: 'POST',
            headers: { 'X-CSRF-Token': csrfToken },
            body: fd,
          });
        }
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          const msg = `Uploaded ${data.accepted?.length || 0} file(s). Rejected: ${data.rejected?.length || 0}.`;
          if (mediaFeedback) mediaFeedback.textContent = msg;
          if (data.rejected?.length) {
            showNotification(
              `${msg} Rejected: ${data.rejected.map((r) => `${r.name} (${r.message})`).join('; ')}`,
              'error',
              true
            );
            return;
          }
          queueReloadWithFlash(msg);
        } else {
          const errMsg = data.message || 'Upload failed.';
          if (mediaFeedback) mediaFeedback.textContent = errMsg;
          showNotification(errMsg, 'error', true);
        }
      } catch {
        const netMsg = 'Upload interrupted. Safe to retry.';
        if (mediaFeedback) mediaFeedback.textContent = netMsg;
        showNotification(netMsg, 'error', true);
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.removeAttribute('aria-busy');
        }
      }
    });
  }
})();
