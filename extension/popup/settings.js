// Settings: encrypted backup export/import and an "about" block.
import * as store from '../lib/store.js';
import * as session from './session.js';
import { t } from './i18n.js';
import { $, setText, withBusy, reason } from './ui.js';
import { backupFileName, looksLikeRecord } from './format.js';

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
    await chrome.tabs.create({ url: chrome.runtime.getURL('popup/popup.html#settings') });
    window.close();
  });

  $('#source-btn').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getManifest().homepage_url });
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
    setText(importError, '');
    const file = importFile.files[0];
    if (!file) {
      setText(importError, t('errImportNoFile'));
      importFile.focus();
      return;
    }
    if (!importPass.value) {
      setText(importError, t('errImportNoPass'));
      importPass.focus();
      return;
    }
    let record;
    try {
      record = JSON.parse(await file.text());
    } catch {
      record = null;
    }
    if (!looksLikeRecord(record)) {
      setText(importError, t('errImportFile'));
      return;
    }
    await withBusy(importSubmit, t('importing'), async () => {
      let incoming;
      try {
        incoming = await session.readBackup(record, importPass.value);
      } catch (error) {
        setText(importError, session.isBadPassphrase(error) ? t('errImportPass') : t('errImportFailed', reason(error)));
        importPass.select();
        return;
      }
      let result;
      try {
        // Merged into the current vault and sealed with the current key.
        result = await session.addAccounts(incoming);
      } catch (error) {
        setText(importError, t('errSaveFailed', reason(error)));
        return;
      }
      importForm.reset();
      await done(result);
    });
  }

  function open() {
    setText(exportStatus, '');
    setText(importError, '');
    importForm.reset();
    openTabRow.hidden = isTab;
    setText(versionEl, t('versionLabel', chrome.runtime.getManifest().version));
    $('#settings-back').focus();
  }

  return { open };
}
