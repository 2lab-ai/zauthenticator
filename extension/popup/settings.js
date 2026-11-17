// Settings: encrypted backup export/import, the auto-fill sites (bindings), and an "about" block.
import * as passkey from './passkey.js';
import * as session from './session.js';
import { t } from './i18n.js';
import { $, setText, withBusy, reason } from './ui.js';
import { backupFileName, looksLikeRecord, text } from './format.js';
import { openOwnView } from '../lib/nav.js';

// A backup is one vault record; anything larger is refused before it is read. A vault at its
// 1 MiB ciphertext cap (lib/vault.js) exports about 1.37 MiB (base64 plus the record fields).
const MAX_BACKUP_BYTES = 2 * 1024 * 1024;

export function createSettingsView({ isTab, done, onOrphan }) {
  const exportBtn = $('#export-btn');
  const exportStatus = $('#export-status');
  const importForm = $('#import-form');
  const importFile = $('#import-file');
  const importPass = $('#import-pass');
  const importSubmit = $('#import-submit');
  const importError = $('#import-error');
  const openTabRow = $('#open-tab-row');
  const versionEl = $('#version');
  const bindingsEl = $('#bindings');
  const bindingsEmpty = $('#bindings-empty');
  const bindingsError = $('#bindings-error');
  const bindingTemplate = $('#binding-template');
  const passkeySection = createPasskeySection({ isTab, onOrphan });

  exportBtn.addEventListener('click', exportBackup);

  bindingsEl.addEventListener('click', (event) => {
    const button = event.target.closest('.binding-remove');
    const row = button && button.closest('.binding');
    if (row) removeBinding(row, button);
  });

  importForm.addEventListener('submit', (event) => {
    event.preventDefault();
    importBackup();
  });

  $('#open-tab-btn').addEventListener('click', async () => {
    await openOwnView('settings');
    window.close();
  });

  // Export strips the device-bound passkey slot without changing the live vault.
  async function exportBackup() {
    setText(exportStatus, '');
    const record = await session.exportRecord();
    if (!record) return;
    const blob = new Blob([`${JSON.stringify(record, null, 2)}\n`], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = backupFileName();
    link.hidden = true;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    setText(exportStatus, t('exported', link.download));
  }

  async function importBackup() {
    // Nothing is written back into the view once the vault locks (lock cleared the form).
    const gen = session.generation();
    const live = () => session.isUnlocked() && session.generation() === gen;
    setText(importError, '');
    const file = importFile.files[0];
    if (!file) {
      setText(importError, t('errImportNoFile'));
      importFile.focus();
      return;
    }
    if (file.size > MAX_BACKUP_BYTES) {
      setText(importError, t('errImportTooLarge'));
      return;
    }
    if (!importPass.value) {
      setText(importError, t('errImportNoPass'));
      importPass.focus();
      return;
    }
    const passphrase = importPass.value;
    let record;
    try {
      record = JSON.parse(await file.text());
    } catch {
      record = null;
    }
    if (!live()) return;
    if (!looksLikeRecord(record)) {
      setText(importError, t('errImportFile'));
      return;
    }
    await withBusy(importSubmit, t('importing'), async () => {
      let incoming;
      try {
        incoming = await session.readBackup(record, passphrase);
      } catch (error) {
        if (!live() || error.code === 'locked') return;
        if (error.code === 'not-backup') setText(importError, t('errImportFile'));
        else setText(importError, session.isBadPassphrase(error) ? t('errImportPass') : t('errImportFailed', reason(error)));
        importPass.select();
        return;
      }
      if (!live()) return;
      let result;
      try {
        // Validated, merged into the current vault and sealed with the current key.
        result = await session.addAccounts(incoming);
      } catch (error) {
        if (live() && error.code !== 'locked') setText(importError, t('errSaveFailed', reason(error)));
        return;
      }
      if (!live()) return;
      importForm.reset();
      await done(result);
    });
  }

  // The auto-fill sites, by origin, each with the account it fills. Nothing while locked.
  function renderBindings() {
    const accounts = new Map(session.accounts().map((a) => [a.id, a]));
    const rows = [...session.bindings()]
      .sort((a, b) => (a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0))
      .map((binding) => {
        const row = bindingTemplate.content.firstElementChild.cloneNode(true);
        row.dataset.origin = binding.origin;
        // Origins and account names are shown as text only, never markup.
        const originEl = row.querySelector('.binding-origin');
        const accountEl = row.querySelector('.binding-account');
        setText(originEl, binding.origin);
        const account = accounts.get(binding.accountId);
        setText(accountEl, account ? accountTitle(account) : t('bindingNoAccount'));
        // Cut off with an ellipsis when long; the tooltip shows all of it.
        originEl.title = originEl.textContent;
        accountEl.title = accountEl.textContent;
        row.querySelector('.binding-remove').setAttribute('aria-label', t('bindingRemoveLabel', binding.origin));
        return row;
      });
    bindingsEl.replaceChildren(...rows);
    bindingsEmpty.hidden = rows.length > 0;
  }

  // Removing a binding also ends the site's auto-fill and its site access: the service worker
  // reconciles both when the vault changes (lib/autofill-worker.js).
  async function removeBinding(row, button) {
    const gen = session.generation();
    const live = () => session.isUnlocked() && session.generation() === gen;
    setText(bindingsError, '');
    button.disabled = true;
    try {
      await session.removeBinding(row.dataset.origin);
    } catch (error) {
      if (!live()) return;
      button.disabled = false;
      if (error.code !== 'locked') setText(bindingsError, t('bindingRemoveFailed', reason(error)));
      return;
    }
    if (!live()) return;
    const index = [...bindingsEl.children].indexOf(row);
    renderBindings();
    const next = bindingsEl.children[Math.min(index, bindingsEl.children.length - 1)];
    (next ? next.querySelector('.binding-remove') : $('#settings-back')).focus();
  }

  // Empties the backup file, its passphrase, the auto-fill sites and every status line (used on
  // lock).
  function clearSensitive() {
    passkeySection.clear();
    setText(exportStatus, '');
    setText(importError, '');
    importForm.reset();
    bindingsEl.replaceChildren();
    setText(bindingsError, '');
  }

  function open() {
    clearSensitive();
    renderBindings();
    passkeySection.open();
    openTabRow.hidden = isTab;
    setText(versionEl, t('versionLabel', chrome.runtime.getManifest().version));
    $('#settings-back').focus();
  }

  // The vault changed in another page: show its bindings.
  function refresh() {
    setText(bindingsError, '');
    renderBindings();
    passkeySection.refresh();
  }

  return { open, refresh, clearSensitive };
}

// Set when an enrollment created a passkey on the phone or key but its page could no longer say so
// (the vault locked or changed while the ceremony ran). It holds no secret, only that the notice
// is owed; the next visible view shows it once (popup.js, or open() below).
let orphanOwed = false;

// → true once per owed notice.
export function takeOrphanNotice() {
  const owed = orphanOwed;
  orphanOwed = false;
  return owed;
}

// The passkey block of Settings (spec 04 Flows): enroll and remove run only in the full tab; the
// toolbar popup only offers to open that tab. `sessions` and `ceremony` default to the real
// modules and are parameters so the block can be exercised without a browser.
export function createPasskeySection({ isTab, onOrphan = () => {}, sessions = session, ceremony = passkey }) {
  const passkeyForm = $('#passkey-form');
  const passkeyPass = $('#passkey-pass');
  const passkeyLabel = $('#passkey-label');
  const passkeyStatus = $('#passkey-status');
  const passkeyError = $('#passkey-error');
  let passkeyToken = 0;
  let passkeyBusy = false;
  let currentSlot = null;

  $('#passkey-open-tab').addEventListener('click', async () => {
    await openOwnView('settings');
    window.close();
  });
  passkeyForm.addEventListener('submit', (event) => { event.preventDefault(); enroll(); });
  $('#passkey-remove').addEventListener('click', () => {
    $('#passkey-confirm').hidden = false;
    $('#passkey-remove-confirm').focus();
  });
  $('#passkey-remove-cancel').addEventListener('click', () => {
    $('#passkey-confirm').hidden = true;
    $('#passkey-remove').focus();
  });
  $('#passkey-remove-confirm').addEventListener('click', removePasskey);

  function passkeyMessage(error) {
    if (error.code === 'cancelled') return t('passkeyCancelled');
    if (error.code === 'no-prf') return t('passkeyNoPrf');
    if (error.code === 'mismatch') return t('passkeyMismatch');
    if (error.code === 'changed' || error.code === 'locked') return t('passkeyChanged');
    if (sessions.isBadPassphrase(error)) return t('errWrongPass');
    return t('passkeyFailed');
  }

  async function renderPasskey() {
    const token = ++passkeyToken;
    try {
      const [available, state] = await Promise.all([ceremony.support(), sessions.passkeyState()]);
      if (token !== passkeyToken || !sessions.isUnlocked()) return;
      currentSlot = state.slot;
      $('#passkey-section').hidden = available === 'no' && !currentSlot;
      $('#passkey-popup').hidden = isTab;
      $('#passkey-tab').hidden = !isTab;
      passkeyForm.hidden = Boolean(currentSlot) || available === 'no';
      $('#passkey-registered').hidden = !currentSlot;
      setText($('#passkey-name'), currentSlot ? currentSlot.label || t('passkeyUnnamed') : '');
      // A form that is not on screen (a passkey enrolled elsewhere, no PRF support, the toolbar
      // popup) keeps no typed passphrase or label.
      if ($('#passkey-section').hidden || $('#passkey-tab').hidden || passkeyForm.hidden) passkeyForm.reset();
    } catch {
      if (token === passkeyToken) {
        $('#passkey-section').hidden = true;
        passkeyForm.reset();
      }
    }
  }

  async function enroll() {
    if (passkeyBusy || !sessions.isUnlocked()) return;
    const password = passkeyPass.value;
    const label = passkeyLabel.value;
    if (!password) { setText(passkeyError, t('errEmptyPass')); passkeyPass.focus(); return; }
    passkeyBusy = true;
    const token = passkeyToken;
    const gen = sessions.generation();
    const live = () => token === passkeyToken && sessions.isUnlocked() && sessions.generation() === gen;
    $('#passkey-add').disabled = true;
    setText(passkeyError, '');
    setText(passkeyStatus, t('passkeyWorking'));
    let orphan = false;
    try {
      const capture = await sessions.captureForCeremony();
      await sessions.checkPassphrase(password);
      const checked = await sessions.captureForCeremony();
      if (capture.rev !== checked.rev || capture.lockGen !== checked.lockGen || JSON.stringify(capture.identity) !== JSON.stringify(checked.identity)) throw { code: 'changed' };
      if (!live()) return;
      const prfSalt = crypto.getRandomValues(new Uint8Array(32));
      const result = await ceremony.enrollCeremony({ prfSalt });
      orphan = true;
      if (!live()) return;
      await sessions.enrollPasskey(capture, password, { ...result, prfSalt, label });
      orphan = false;
      if (!live()) return;
      passkeyForm.reset();
      await renderPasskey();
      setText(passkeyStatus, t('passkeyAdded'));
    } catch (error) {
      if (error?.orphan) orphan = true;
      if (live()) setText(passkeyError, `${passkeyMessage(error)}${orphan ? ` ${t('passkeyOrphan')}` : ''}`);
    } finally {
      // A passkey may now exist on the phone or key with nothing stored here, and this page can no
      // longer say so: the notice is kept for the next view that is shown.
      if (orphan && !live()) {
        orphanOwed = true;
        try {
          onOrphan();
        } catch {
          // the notice stays owed
        }
      }
      // The passphrase never outlives the attempt; a clear() or a re-render since (a new token)
      // already emptied the form, and a form opened since may hold new input.
      if (token === passkeyToken) passkeyPass.value = '';
      passkeyBusy = false;
      $('#passkey-add').disabled = false;
      if (live()) setText(passkeyStatus, '');
    }
  }

  async function removePasskey() {
    if (passkeyBusy || !currentSlot || !sessions.isUnlocked()) return;
    passkeyBusy = true;
    const token = passkeyToken;
    const gen = sessions.generation();
    const live = () => token === passkeyToken && sessions.isUnlocked() && sessions.generation() === gen;
    $('#passkey-remove-confirm').disabled = true;
    setText(passkeyError, '');
    try {
      await sessions.removePasskey(currentSlot.cred);
      if (!live()) return;
      $('#passkey-confirm').hidden = true;
      await renderPasskey();
      setText(passkeyStatus, t('passkeyRemoved'));
    } catch (error) {
      if (live()) setText(passkeyError, passkeyMessage(error));
    } finally {
      passkeyBusy = false;
      $('#passkey-remove-confirm').disabled = false;
    }
  }

  function clear() {
    passkeyToken++;
    currentSlot = null;
    passkeyForm.reset();
    $('#passkey-confirm').hidden = true;
    $('#passkey-section').hidden = true;
    setText(passkeyStatus, '');
    setText(passkeyError, '');
    setText($('#passkey-name'), '');
  }

  async function open() {
    await renderPasskey();
    if (!$('#passkey-section').hidden && takeOrphanNotice()) setText(passkeyError, t('passkeyOrphan'));
  }

  function refresh() {
    if (!passkeyBusy) return renderPasskey();
    return Promise.resolve();
  }

  return { open, refresh, clear };
}

// The locked view's "Unlock with passkey" (spec 04 Flows). Never runs a ceremony in the toolbar
// popup, which closes when the browser's passkey dialog takes focus: there the click opens the
// unlock window, whose click (or a tab's) runs it. `sessions` and `ceremony` are parameters so the
// controller can be exercised without a browser.
export function createPasskeyUnlock({ inPopup, openWindow, onUnlocked, sessions = session, ceremony = passkey }) {
  const button = $('#unlock-passkey');
  const statusEl = $('#unlock-passkey-status');
  const errorEl = $('#unlock-passkey-error');
  const locked = () => document.body.dataset.state === 'locked';
  // Two counters. viewToken orders the button's visibility checks, which run on every show of the
  // locked view, storage hints included. ceremonyToken changes only when this page unlocks or
  // wipes itself (clear()); a hint that changes nothing must not drop a ceremony in flight, and
  // whether its result may still be used is decided by the session commit (rev, lockGen).
  let viewToken = 0;
  let ceremonyToken = 0;
  let busy = false;

  button.addEventListener('click', start);

  async function refresh() {
    const current = ++viewToken;
    try {
      const [available, state] = await Promise.all([ceremony.support(), sessions.passkeyState()]);
      if (current === viewToken && locked()) button.hidden = available === 'no' || !state.slot;
    } catch {
      if (current === viewToken) button.hidden = true;
    }
  }

  async function start() {
    if (busy || !locked()) return;
    if (inPopup) {
      await openWindow();
      window.close();
      return;
    }
    busy = true;
    const current = ceremonyToken;
    const live = () => current === ceremonyToken && locked();
    // A result this page can no longer use ends visibly: on the locked view it says the vault
    // changed (never what was returned); elsewhere the page has moved on and says nothing.
    const discarded = () => {
      if (locked()) setText(errorEl, t('passkeyChanged'));
    };
    button.disabled = true;
    setText(errorEl, '');
    setText(statusEl, t('passkeyWorking'));
    try {
      const capture = await sessions.captureForCeremony();
      if (!live()) return discarded();
      if (!capture.slot) {
        button.hidden = true;
        return discarded();
      }
      const prf = await ceremony.unlockCeremony(capture.slot);
      if (!live()) return discarded();
      await sessions.unlockWithPasskey(capture, prf);
      if (live() && sessions.isUnlocked()) await onUnlocked();
    } catch (error) {
      if (live()) setText(errorEl, t(unlockMessageKey(error)));
      else discarded();
    } finally {
      busy = false;
      button.disabled = false;
      // Only this ceremony's own line; an orphan notice shown meanwhile stays.
      if (statusEl.textContent === t('passkeyWorking')) setText(statusEl, '');
    }
  }

  function clear() {
    viewToken++;
    ceremonyToken++;
    button.hidden = true;
    setText(statusEl, '');
    setText(errorEl, '');
  }

  return { refresh, clear };
}

function unlockMessageKey(error) {
  const code = error?.code;
  if (code === 'cancelled') return 'passkeyCancelled';
  if (code === 'no-prf') return 'passkeyNoPrf';
  if (code === 'mismatch') return 'passkeyMismatch';
  if (code === 'changed' || code === 'locked' || code === 'no-vault') return 'passkeyChanged';
  return 'passkeyFailed';
}

// "issuer · label", either alone when the other is empty (the bind window and the auto-fill
// sites; lib/autofill-worker.js titles its menu items the same way).
export function accountTitle(account) {
  const issuer = text(account.issuer).trim();
  const label = text(account.label).trim();
  return (issuer && label ? `${issuer} · ${label}` : issuer || label) || t('menuUnnamed');
}
