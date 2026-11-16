// Settings: encrypted backup export/import and an "about" block.
import * as store from '../lib/store.js';
import * as session from './session.js';
import { t } from './i18n.js';
import { $, setText, withBusy, reason } from './ui.js';
import { backupFileName, looksLikeRecord } from './format.js';
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

  exportBtn.addEventListener('click', exportBackup);

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

  // Empties the backup file, its passphrase and every status line (used on lock).
  function clearSensitive() {
    setText(exportStatus, '');
    setText(importError, '');
    importForm.reset();
  }

  function open() {
    clearSensitive();
    openTabRow.hidden = isTab;
    setText(versionEl, t('versionLabel', chrome.runtime.getManifest().version));
    $('#settings-back').focus();
  }

  return { open, clearSensitive };
}
