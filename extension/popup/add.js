// The "add account" view: QR from the current tab, QR from an image (file, drop, paste),
// otpauth:// links, and manual entry of a setup key.
import * as otpauth from '../lib/otpauth.js';
import { decodeQR, QRError } from '../lib/qr.js';
import * as session from './session.js';
import { t } from './i18n.js';
import { $, setText, withBusy, reason } from './ui.js';

export function createAddView({ isTab, done }) {
  const errorEl = $('#add-error');
  const statusEl = $('#add-status');
  const scanTabBtn = $('#scan-tab-btn');
  const scanFileBtn = $('#scan-file-btn');
  const dropZone = $('#drop-zone');
  const fileInput = $('#scan-file-input');
  const uriEl = $('#add-uri');
  const uriSubmit = $('#add-uri-submit');
  const manualForm = $('#manual-form');
  const manualSubmit = $('#manual-submit');
  const issuerEl = $('#manual-issuer');
  const labelEl = $('#manual-label');
  const secretEl = $('#manual-secret');
  const algorithmEl = $('#manual-algorithm');
  const digitsEl = $('#manual-digits');
  const periodEl = $('#manual-period');
  const advancedEl = manualForm.querySelector('details');

  const isActive = () => document.body.dataset.state === 'add';
  // Work started while unlocked writes nothing back into the view once the vault locks
  // (lock clears these fields; a pending scan or save must not refill them).
  const live = (gen) => session.isUnlocked() && session.generation() === gen;

  scanTabBtn.addEventListener('click', scanTab);
  scanFileBtn.addEventListener('click', scanFile);

  fileInput.addEventListener('change', () => {
    const files = [...fileInput.files];
    fileInput.value = '';
    if (files.length) addFromImages(files);
  });

  // Never let a dropped file navigate the page away; accept image drops while adding.
  document.addEventListener('dragover', (event) => {
    event.preventDefault();
    const accept = isActive() && event.dataTransfer && [...event.dataTransfer.types].includes('Files');
    if (event.dataTransfer) event.dataTransfer.dropEffect = accept ? 'copy' : 'none';
    dropZone.classList.toggle('dragover', Boolean(accept));
  });
  document.addEventListener('dragleave', (event) => {
    if (event.relatedTarget === null) dropZone.classList.remove('dragover');
  });
  document.addEventListener('drop', (event) => {
    event.preventDefault();
    dropZone.classList.remove('dragover');
    if (isActive() && event.dataTransfer && event.dataTransfer.files.length) {
      addFromImages([...event.dataTransfer.files]);
    }
  });

  document.addEventListener('paste', (event) => {
    if (!isActive() || !event.clipboardData) return;
    const images = [...event.clipboardData.files].filter(isImage);
    if (images.length === 0) return;
    event.preventDefault();
    addFromImages(images);
  });

  uriSubmit.addEventListener('click', addFromLinks);

  manualForm.addEventListener('submit', (event) => {
    event.preventDefault();
    addManual();
  });

  async function scanTab() {
    const gen = session.generation();
    clearMessages();
    if (isTab) {
      // Opened as a full tab (not from the toolbar icon): there is no web page to capture.
      fail(t('errScanTabNeedsPopup'));
      return;
    }
    await withBusy(scanTabBtn, null, async () => {
      setText(statusEl, t('scanning'));
      let image;
      try {
        // activeTab grants this after the user clicked the toolbar icon.
        image = await chrome.tabs.captureVisibleTab(undefined, { format: 'png' });
      } catch (error) {
        if (!live(gen)) return;
        // No activeTab grant for this tab (e.g. it navigated since the popup opened) versus a
        // page Chrome never lets extensions capture (browser pages, extension stores).
        fail(t(/activeTab/.test(reason(error)) ? 'errCaptureNoAccess' : 'errCaptureFailed'));
        return;
      }
      if (!live(gen)) return;
      let account;
      try {
        account = parseOtpauth(await decodeQR(image), 'qr');
      } catch (error) {
        if (live(gen)) fail(messageFor(error, 'tab'));
        return;
      }
      if (!live(gen)) return;
      await commit(gen, [account]);
    });
  }

  async function scanFile() {
    clearMessages();
    if (isTab) {
      fileInput.click();
      return;
    }
    // A file chooser can close the popup on some platforms; continue in a full tab instead.
    await chrome.tabs.create({ url: chrome.runtime.getURL('popup/popup.html#add-file') });
    window.close();
  }

  async function addFromImages(files) {
    const gen = session.generation();
    clearMessages();
    const images = files.filter(isImage);
    if (images.length === 0) {
      fail(t('errNotImage'));
      return;
    }
    setText(statusEl, t('scanning'));
    const found = [];
    const problems = [];
    for (const file of images) {
      try {
        found.push(parseOtpauth(await decodeQR(file), 'qr'));
      } catch (error) {
        const message = messageFor(error, 'image');
        problems.push(images.length > 1 && file.name ? `${file.name}: ${message}` : message);
      }
      if (!live(gen)) return;
    }
    if (found.length === 0) {
      fail(problems.join('\n'));
      return;
    }
    await commit(gen, found, problems);
  }

  async function addFromLinks() {
    const gen = session.generation();
    clearMessages();
    const found = [];
    const problems = [];
    const failedLines = [];
    uriEl.value.split(/\r?\n/).forEach((raw, index) => {
      const line = raw.trim();
      if (!line) return;
      try {
        found.push(parseOtpauth(line, 'link'));
      } catch (error) {
        problems.push(t('errLine', [index + 1, messageFor(error, 'link')]));
        failedLines.push(line);
      }
    });
    if (found.length === 0 && problems.length === 0) {
      fail(t('errNoLinks'));
      uriEl.focus();
      return;
    }
    if (found.length === 0) {
      fail(problems.join('\n'));
      return;
    }
    await withBusy(uriSubmit, t('adding'), async () => {
      // Keep only the lines that still need fixing.
      if ((await commit(gen, found, problems)) && live(gen)) uriEl.value = failedLines.join('\n');
    });
  }

  async function addManual() {
    const gen = session.generation();
    clearMessages();
    if (!issuerEl.value.trim() && !labelEl.value.trim()) {
      fail(t('errNameRequired'));
      issuerEl.focus();
      return;
    }
    if (!secretEl.value.trim()) {
      fail(t('errSecretRequired'));
      secretEl.focus();
      return;
    }
    let account;
    try {
      account = otpauth.normalize({
        issuer: issuerEl.value.trim(),
        label: labelEl.value.trim(),
        secret: secretEl.value,
        algorithm: algorithmEl.value,
        digits: Number(digitsEl.value),
        period: Number(periodEl.value),
      });
    } catch (error) {
      fail(t('errManual', reason(error)));
      return;
    }
    await withBusy(manualSubmit, t('adding'), async () => {
      if (await commit(gen, [account])) resetManual();
    });
  }

  // Saves the accounts. Navigates back to the list when everything was added; stays here
  // (showing what was added and what failed) otherwise. → true when anything was added.
  // `gen` is the session generation the user action started in; a lock since then makes
  // this a silent no-op (the lock already reset the view).
  async function commit(gen, accounts, problems = []) {
    if (!live(gen)) return false;
    let result;
    try {
      result = await session.addAccounts(accounts);
    } catch (error) {
      if (live(gen) && error.code !== 'locked') fail(t('errSaveFailed', reason(error)));
      return false;
    }
    if (!live(gen)) return false;
    if (result.added === 0) {
      const onlyDuplicates = result.duplicates > 0 && result.invalid === 0;
      fail([onlyDuplicates ? t('errAllDuplicates') : summary(result), ...problems].join('\n'));
      return false;
    }
    if (problems.length > 0) {
      setText(statusEl, summary(result));
      fail(problems.join('\n'));
      return true;
    }
    setText(statusEl, '');
    await done(result);
    return true;
  }

  // text = decoded QR content or one pasted line; source ∈ 'qr' | 'link' (for the message).
  function parseOtpauth(text, source) {
    const value = String(text ?? '').trim();
    if (/^otpauth-migration:/i.test(value)) throw new AddError(t('errMigration'));
    if (!/^otpauth:/i.test(value)) throw new AddError(t(source === 'qr' ? 'errNotOtpauth' : 'errNotOtpauthLink'));
    try {
      return otpauth.parse(value);
    } catch (error) {
      throw new AddError(t('errInvalidLink', reason(error)));
    }
  }

  function messageFor(error, source) {
    if (error instanceof AddError) return error.message;
    if (error instanceof QRError) {
      if (error.code === 'no-qr') return t(source === 'tab' ? 'errNoQrTab' : 'errNoQrImage');
      if (error.code === 'bad-image') return t('errBadImage');
      return t('errDecoderMissing');
    }
    return reason(error);
  }

  function fail(message) {
    setText(errorEl, message);
    if (message) errorEl.scrollIntoView({ block: 'nearest' });
    if (!statusEl.textContent || statusEl.textContent === t('scanning')) setText(statusEl, '');
  }

  function clearMessages() {
    setText(errorEl, '');
    setText(statusEl, '');
  }

  function resetManual() {
    manualForm.reset();
    advancedEl.open = false;
  }

  // Empties every field and message that can hold a secret or an account name.
  function clearSensitive() {
    clearMessages();
    uriEl.value = '';
    fileInput.value = '';
    resetManual();
    dropZone.classList.remove('dragover');
  }

  function open({ fileMode = false } = {}) {
    clearSensitive();
    document.body.classList.toggle('file-mode', fileMode);
    (fileMode ? fileInput : isTab ? uriEl : scanTabBtn).focus();
  }

  return { open, clearSensitive };
}

// result = session.addAccounts() → { added, duplicates, invalid }
export function summary({ added, duplicates = 0, invalid = 0 }) {
  const parts = [t('addedCount', added)];
  if (duplicates > 0) parts.push(t('skippedCount', duplicates));
  if (invalid > 0) parts.push(t('invalidCount', invalid));
  return parts.join(' ');
}

function isImage(file) {
  return Boolean(file) && typeof file.type === 'string' && file.type.startsWith('image/');
}

class AddError extends Error {}
