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

  // 1. Page Editor Autosave & Unsaved-Change Warning
  const editorForm = document.getElementById('page-editor-form');
  const autosaveEl = document.getElementById('autosave-status');
  let isDirty = false;
  let autosaveTimer = null;

  if (editorForm) {
    const saveDraft = async (silent = true) => {
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
          return;
        }
        if (!res.ok) {
          if (autosaveEl) autosaveEl.textContent = 'Save failed';
          if (!silent) showNotification(data.message || 'Save failed.', 'error', true);
          return;
        }
        isDirty = false;
        if (data.revision_number) {
          const revInput = editorForm.querySelector('input[name="expected_revision"]');
          if (revInput) revInput.value = String(data.revision_number);
        }
        if (autosaveEl) autosaveEl.textContent = `Saved (v${data.revision_number})`;
        announce('Draft saved');
      } catch {
        if (autosaveEl) autosaveEl.textContent = 'Save failed (network)';
        if (!silent) showNotification('Network error while saving draft. Your edits stay open here.', 'error', true);
      }
    };

    editorForm.addEventListener('input', () => {
      isDirty = true;
      if (autosaveEl) autosaveEl.textContent = 'Unsaved changes';
      clearTimeout(autosaveTimer);
      autosaveTimer = setTimeout(() => saveDraft(true), 2500);
    });

    window.addEventListener('beforeunload', (e) => {
      if (isDirty) {
        e.preventDefault();
        e.returnValue = '';
      }
    });

    document.getElementById('btn-save-draft')?.addEventListener('click', (e) => {
      lastTriggerEl = e.currentTarget;
      saveDraft(false);
    });

    document.getElementById('btn-submit-review')?.addEventListener('click', async (e) => {
      lastTriggerEl = e.currentTarget;
      await saveDraft(true);
      const res = await fetch(e.currentTarget.dataset.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ csrf_token: csrfToken }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        isDirty = false;
        location.reload();
      } else {
        showNotification(data.message || 'Could not submit for review.', 'error', true);
      }
    });

    document.getElementById('btn-publish-page')?.addEventListener('click', async (e) => {
      lastTriggerEl = e.currentTarget;
      const res = await fetch(e.currentTarget.dataset.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ csrf_token: csrfToken }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        isDirty = false;
        location.reload();
      } else {
        showNotification(data.message || 'Publish failed.', 'error', true);
      }
    });

    document.querySelectorAll('.js-restore-rev').forEach((btn) => {
      btn.addEventListener('click', async () => {
        lastTriggerEl = btn;
        const res = await fetch(btn.dataset.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify({ revision_number: Number(btn.dataset.rev), csrf_token: csrfToken }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          isDirty = false;
          location.reload();
        } else {
          showNotification(data.message || 'Restore failed.', 'error', true);
        }
      });
    });
  }

  // 2. Native Confirmation Dialog for Media Rights Withdrawal (shows affected placements first!)
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
    try {
      await pendingConfirmAction();
    } finally {
      confirmProceed.disabled = false;
      pendingConfirmAction = null;
      confirmDialog?.close('confirm');
    }
  });

  confirmDialog?.addEventListener('close', () => {
    confirmDialog.returnValue = '';
    pendingConfirmAction = null;
  });

  document.addEventListener('click', async (e) => {
    const withdrawBtn = e.target.closest('.js-withdraw-media-btn');
    if (!withdrawBtn || !confirmDialog) return;
    lastTriggerEl = withdrawBtn;
    withdrawBtn.disabled = true;

    try {
      const usageRes = await fetch(withdrawBtn.dataset.usageUrl);
      const usageData = await usageRes.json().catch(() => ({}));
      const fname = withdrawBtn.dataset.filename || 'this media asset';

      confirmTitle.textContent = `Withdraw Rights for "${fname}"?`;
      confirmMsg.textContent = usageRes.ok && usageData.totalAffected > 0
        ? `Warning: Withdrawing rights will immediately remove this image from ${usageData.totalAffected} active placement(s) across projects and campaigns.`
        : 'Withdrawing rights disables public delivery for this asset immediately.';

      if (confirmDetails) {
        confirmDetails.textContent = '';
        if (usageRes.ok && usageData.totalAffected > 0) {
          const list = document.createElement('ul');
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
          confirmDetails.appendChild(list);
          confirmDetails.hidden = false;
        } else {
          confirmDetails.hidden = true;
        }
      }

      pendingConfirmAction = async () => {
        const res = await fetch(withdrawBtn.dataset.withdrawUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify({ csrf_token: csrfToken }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          location.reload();
        } else {
          showNotification(data.message || 'Withdrawal failed.', 'error', true);
        }
      };

      confirmDialog.showModal();
    } catch {
      showNotification('Could not check media placement dependencies.', 'error', true);
    } finally {
      withdrawBtn.disabled = false;
    }
  });

  // 3. Action Buttons (.js-action-btn)
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.js-action-btn');
    if (!btn) return;
    lastTriggerEl = btn;
    btn.disabled = true;
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
        if (data.message) announce(data.message);
        location.reload();
      } else {
        showNotification(data.message || 'Action failed.', 'error', true);
      }
    } catch {
      showNotification('Network error while performing action.', 'error', true);
    } finally {
      btn.disabled = false;
    }
  });

  // 4. Generic AJAX Forms (.js-ajax-form)
  document.querySelectorAll('.js-ajax-form').forEach((form) => {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      lastTriggerEl = form.querySelector('button[type="submit"]') || form;
      const fd = new FormData(form);
      const body = {};
      for (const [k, v] of fd.entries()) body[k] = v;
      form.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
        body[cb.name] = cb.checked;
      });
      try {
        const res = await fetch(form.action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
          body: JSON.stringify(body),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          location.reload();
        } else {
          showNotification(data.message || 'Operation failed.', 'error', true);
        }
      } catch {
        showNotification('Request failed due to network interruption.', 'error', true);
      }
    });
  });

  // 5. Multipart Forms (.js-multipart-form, e.g., Resume Replacement)
  document.querySelectorAll('.js-multipart-form').forEach((form) => {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      lastTriggerEl = form.querySelector('button[type="submit"]') || form;
      try {
        const fd = new FormData(form);
        const res = await fetch(form.action, {
          method: 'POST',
          headers: { 'X-CSRF-Token': csrfToken },
          body: fd,
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok) {
          location.reload();
        } else {
          showNotification(data.message || 'File upload failed.', 'error', true);
        }
      } catch {
        showNotification('File upload interrupted. Please retry.', 'error', true);
      }
    });
  });

  // 6. Batch Media Upload (#media-upload-form)
  const mediaForm = document.getElementById('media-upload-form');
  const mediaFeedback = document.getElementById('media-upload-feedback');
  if (mediaForm) {
    mediaForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      lastTriggerEl = mediaForm.querySelector('button[type="submit"]') || mediaForm;
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
          location.reload();
        } else {
          const errMsg = data.message || 'Upload failed.';
          if (mediaFeedback) mediaFeedback.textContent = errMsg;
          showNotification(errMsg, 'error', true);
        }
      } catch {
        const netMsg = 'Upload interrupted. Safe to retry.';
        if (mediaFeedback) mediaFeedback.textContent = netMsg;
        showNotification(netMsg, 'error', true);
      }
    });
  }
})();
