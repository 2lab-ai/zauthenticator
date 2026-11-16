// Settings: encrypted backup export/import, the auto-fill sites (bindings), and an "about" block.
import * as store from '../lib/store.js';
import * as session from './session.js';
import { t } from './i18n.js';
import { $, setText, withBusy, reason } from './ui.js';
import { backupFileName, looksLikeRecord, text } from './format.js';
import { openOwnView } from '../lib/nav.js';

// A backup is one vault record; anything larger is refused before it is read. A vault at its
// 1 MiB ciphertext cap (lib/vault.js) exports about 1.37 MiB (base64 plus the record fields).
const MAX_BACKUP_BYTES = 2 * 1024 * 1024;

export function createSettingsView({ isTab, done }) {
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

  // The stored record is already ciphertext; the backup is that record verbatim.
  async function exportBackup() {
    setText(exportStatus, '');
    const record = await store.getRecord();
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
        setText(row.querySelector('.binding-origin'), binding.origin);
        const account = accounts.get(binding.accountId);
        setText(row.querySelector('.binding-account'), account ? accountTitle(account) : t('bindingNoAccount'));
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
    setText(exportStatus, '');
    setText(importError, '');
    importForm.reset();
    bindingsEl.replaceChildren();
    setText(bindingsError, '');
  }

  function open() {
    clearSensitive();
    renderBindings();
    openTabRow.hidden = isTab;
    setText(versionEl, t('versionLabel', chrome.runtime.getManifest().version));
    $('#settings-back').focus();
  }

  // The vault changed in another page: show its bindings.
  function refresh() {
    setText(bindingsError, '');
    renderBindings();
  }

  return { open, refresh, clearSensitive };
}

// "issuer · label", either alone when the other is empty (the bind window and the auto-fill
// sites; lib/autofill-worker.js titles its menu items the same way).
export function accountTitle(account) {
  const issuer = text(account.issuer).trim();
  const label = text(account.label).trim();
  return (issuer && label ? `${issuer} · ${label}` : issuer || label) || t('menuUnnamed');
}
