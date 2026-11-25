// Export accounts (issue #5): choose one or more, then copy their otpauth:// links (one per line,
// what the Add view imports) or show QR codes. One account gives its otpauth QR, which any
// authenticator scans. Several give Google Authenticator transfer QRs (lib/migration.js:
// Transfer accounts → Import accounts), in batches; an account that format cannot hold (a period
// other than 30 s, 7 digits) follows as its own otpauth QR. "One QR per account" shows every
// account as an otpauth QR instead.
//
// Links and QR codes hold the secret keys, so a vault with a passphrase asks for it again before
// the list shows. Everything shown is dropped when the view is left or the vault locks. The QR is
// drawn on a canvas in this page; nothing leaves the device but what the user copies or shows.
import * as session from './session.js';
import { format } from '../lib/otpauth.js';
import { encodeQR } from '../lib/qrencode.js';
import { migrationBatches, migrationIssue } from '../lib/migration.js';
import { t } from './i18n.js';
import { $, setText, reason, withBusy } from './ui.js';
import { text } from './format.js';

// The QR is drawn at this many CSS pixels at most (modules plus the 4-module quiet zone each side).
const QR_MAX_PX = 240;
const QUIET = 4;

export function createExportView({ back }) {
  const gate = $('#xp-gate');
  const gatePass = $('#xp-gate-pass');
  const gateError = $('#xp-gate-error');
  const body = $('#xp-body');
  const listEl = $('#xp-list');
  const allBox = $('#xp-all');
  const countEl = $('#xp-count');
  const statusEl = $('#xp-status');
  const errorEl = $('#xp-error');
  const qrArea = $('#xp-qr');
  const modeEl = $('#xp-mode');
  const canvas = $('#xp-canvas');
  let selected = new Set(); // account ids
  let codes = [];           // [{ uri, title, names, how }] on display
  let index = 0;
  let token = 0;            // changes on clear(): work started before writes nothing back

  $('#xp-back').addEventListener('click', back);
  gate.addEventListener('submit', (event) => {
    event.preventDefault();
    unlockGate();
  });
  allBox.addEventListener('change', () => {
    selected = allBox.checked ? new Set(session.accounts().map((a) => a.id)) : new Set();
    for (const box of listEl.querySelectorAll('input')) box.checked = selected.has(box.value);
    selectionChanged();
  });
  listEl.addEventListener('change', (event) => {
    const box = event.target.closest('input[type="checkbox"]');
    if (!box) return;
    if (box.checked) selected.add(box.value);
    else selected.delete(box.value);
    selectionChanged();
  });
  $('#xp-copy').addEventListener('click', copyLinks);
  $('#xp-show').addEventListener('click', () => showCodes());
  modeEl.addEventListener('change', () => showCodes());
  $('#xp-prev').addEventListener('click', () => draw(index - 1));
  $('#xp-next').addEventListener('click', () => draw(index + 1));
  $('#xp-hide').addEventListener('click', hideCodes);

  function open() {
    clear();
    if (session.hasPassphrase()) {
      gate.hidden = false;
      gatePass.focus();
    } else {
      showList();
    }
  }

  async function unlockGate() {
    const mine = token;
    const gen = session.generation();
    setText(gateError, '');
    const pass = gatePass.value;
    if (!pass) {
      setText(gateError, t('errEmptyPass'));
      gatePass.focus();
      return;
    }
    try {
      await withBusy($('#xp-gate-submit'), null, () => session.checkPassphrase(pass));
    } catch (error) {
      if (mine !== token || session.generation() !== gen || error.code === 'locked') return;
      setText(gateError, session.isBadPassphrase(error) ? t('errWrongPass') : t('passFailed', reason(error)));
      gatePass.select();
      return;
    }
    if (mine !== token || session.generation() !== gen) return;
    gate.reset();
    showList();
  }

  function showList() {
    gate.hidden = true;
    body.hidden = false;
    const rows = session.accounts().map((account) => {
      const li = document.createElement('li');
      const label = document.createElement('label');
      const box = document.createElement('input');
      box.type = 'checkbox';
      box.value = account.id;
      const name = document.createElement('span');
      name.className = 'xp-name';
      // Names are shown as text only, never markup.
      setText(name, title(account));
      name.title = name.textContent;
      label.append(box, name);
      li.append(label);
      return li;
    });
    listEl.replaceChildren(...rows);
    selectionChanged();
    allBox.focus();
  }

  function chosen() {
    return session.accounts().filter((a) => selected.has(a.id));
  }

  function selectionChanged() {
    const total = session.accounts().length;
    allBox.checked = total > 0 && selected.size === total;
    allBox.indeterminate = selected.size > 0 && selected.size < total;
    setText(countEl, t('xpCount', [selected.size, total]));
    $('#xp-copy').disabled = selected.size === 0;
    $('#xp-show').disabled = selected.size === 0;
    modeEl.hidden = selected.size < 2;
    setText(statusEl, '');
    setText(errorEl, '');
    hideCodes();
  }

  // → { links: [{ account, uri }], invalid } for the chosen accounts, in list order.
  function linksOf(accounts) {
    const links = [];
    let invalid = 0;
    for (const account of accounts) {
      try {
        links.push({ account, uri: format(account) });
      } catch {
        invalid++;
      }
    }
    return { links, invalid };
  }

  async function copyLinks() {
    const mine = token;
    setText(statusEl, '');
    setText(errorEl, '');
    const { links, invalid } = linksOf(chosen());
    if (links.length === 0) {
      setText(errorEl, t('xpNoneValid'));
      return;
    }
    try {
      await navigator.clipboard.writeText(links.map((l) => l.uri).join('\n'));
    } catch {
      if (mine === token) setText(errorEl, t('copyFailed'));
      return;
    }
    if (mine !== token) return;
    setText(statusEl, `${t('xpCopied', links.length)}${invalid ? ` ${t('xpSkippedInvalid', invalid)}` : ''}`);
  }

  function showCodes() {
    setText(errorEl, '');
    const { links, invalid } = linksOf(chosen());
    if (links.length === 0) {
      setText(errorEl, t('xpNoneValid'));
      return;
    }
    const each = modeEl.querySelector('input:checked')?.value === 'each';
    codes = [];
    if (links.length === 1 || each) {
      for (const { account, uri } of links) codes.push(single(account, uri, null));
    } else {
      const fits = links.filter((l) => migrationIssue(l.account) === null);
      const rest = links.filter((l) => migrationIssue(l.account) !== null);
      if (fits.length > 0) {
        const batches = migrationBatches(fits.map((l) => l.account));
        let start = 0;
        for (const batch of batches) {
          const names = fits.slice(start, start + batch.count).map((l) => title(l.account));
          start += batch.count;
          codes.push({
            uri: batch.uri,
            title: t('xpGoogleTitle', [batch.index + 1, batch.size]),
            names,
            how: t('xpGoogleHow'),
          });
        }
      }
      for (const { account, uri } of rest) codes.push(single(account, uri, migrationIssue(account)));
    }
    setText(statusEl, invalid ? t('xpSkippedInvalid', invalid) : '');
    qrArea.hidden = false;
    draw(0);
  }

  function single(account, uri, issue) {
    const how = issue ? `${t(issue === 'period' ? 'xpNotGooglePeriod' : 'xpNotGoogleDigits')} ${t('xpSingleHow')}` : t('xpSingleHow');
    return { uri, title: t('xpSingleTitle'), names: [title(account)], how };
  }

  function draw(next) {
    if (codes.length === 0) return;
    index = Math.max(0, Math.min(codes.length - 1, next));
    const code = codes[index];
    let matrix;
    try {
      matrix = encodeQR(code.uri);
    } catch (error) {
      setText(errorEl, t('xpQrFailed', reason(error)));
      return;
    }
    const cells = matrix.size + QUIET * 2;
    const scale = Math.max(2, Math.floor(QR_MAX_PX / cells));
    canvas.width = cells * scale;
    canvas.height = cells * scale;
    canvas.style.width = `${cells * scale}px`;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#000000';
    for (let row = 0; row < matrix.size; row++) {
      for (let col = 0; col < matrix.size; col++) {
        if (matrix.modules[row * matrix.size + col]) ctx.fillRect((col + QUIET) * scale, (row + QUIET) * scale, scale, scale);
      }
    }
    canvas.dataset.uriLength = String(code.uri.length);
    canvas.setAttribute('aria-label', t('xpQrLabel', code.names.join(', ')));
    setText($('#xp-qr-title'), code.title);
    setText($('#xp-qr-names'), code.names.join(', '));
    setText($('#xp-qr-how'), code.how);
    setText($('#xp-page'), t('xpPage', [index + 1, codes.length]));
    $('#xp-prev').disabled = index === 0;
    $('#xp-next').disabled = index === codes.length - 1;
    $('#xp-prev').closest('.xp-nav').hidden = codes.length < 2;
  }

  // Drops the drawn code and every URI held for it.
  function hideCodes() {
    codes = [];
    index = 0;
    qrArea.hidden = true;
    canvas.width = 8;
    canvas.height = 8;
    canvas.removeAttribute('aria-label');
    delete canvas.dataset.uriLength;
    setText($('#xp-qr-title'), '');
    setText($('#xp-qr-names'), '');
    setText($('#xp-qr-how'), '');
  }

  // On leaving the view and on lock: no passphrase, name, link or QR stays.
  function clear() {
    token++;
    hideCodes();
    gate.reset();
    gate.hidden = true;
    body.hidden = true;
    setText(gateError, '');
    setText(statusEl, '');
    setText(errorEl, '');
    listEl.replaceChildren();
    selected = new Set();
    allBox.checked = false;
    allBox.indeterminate = false;
    modeEl.querySelector('input[value="google"]').checked = true;
  }

  return { open, clear };
}

function title(account) {
  const issuer = text(account.issuer).trim();
  const label = text(account.label).trim();
  return (issuer && label ? `${issuer} · ${label}` : issuer || label) || t('menuUnnamed');
}
