// Settings → Passphrase (issue #4): change it, remove it, or set one again on a vault without.
// Removing asks first for the current passphrase (a wrong one is said at once), then shows the red
// two-step confirmation (confirm.js); only after both does the vault move to the device key.
import * as session from './session.js';
import { t } from './i18n.js';
import { $, setText, reason } from './ui.js';
import { createAlarm } from './confirm.js';

const MIN_PASSPHRASE_LENGTH = 8;

export function createPassphraseSection({ onChanged = () => {} } = {}) {
  const form = $('#pass-form');
  const currentEl = $('#pass-current');
  const newEl = $('#pass-new');
  const new2El = $('#pass-new2');
  const changeBtn = $('#pass-change');
  const removeBtn = $('#pass-remove');
  const statusEl = $('#pass-status');
  const errorEl = $('#pass-error');
  const alarm = createAlarm($('#pass-alarm'));
  let busy = false;
  let token = 0; // changes on clear(): work started before never writes into the view again

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    change();
  });
  removeBtn.addEventListener('click', remove);
  for (const input of [currentEl, newEl, new2El]) input.addEventListener('input', () => setText(errorEl, ''));

  // The view follows the vault: with a passphrase, change or remove it; without, set one.
  function render() {
    const has = session.hasPassphrase();
    $('#pass-current-field').hidden = !has;
    $('#pass-hint').hidden = !has;
    $('#pass-none').hidden = has;
    removeBtn.hidden = !has;
    setText(changeBtn, t(has ? 'passChangeBtn' : 'passSetBtn'));
  }

  function live(gen, mine) {
    return mine === token && session.isUnlocked() && session.generation() === gen;
  }

  function message(error) {
    if (session.isBadPassphrase(error)) return t('errWrongPass');
    if (error?.code === 'weak-passphrase') return t('errTooShort', MIN_PASSPHRASE_LENGTH);
    return t('passFailed', reason(error));
  }

  async function change() {
    if (busy || !session.isUnlocked()) return;
    setText(errorEl, '');
    setText(statusEl, '');
    const has = session.hasPassphrase();
    const current = currentEl.value;
    const next = newEl.value;
    if (has && !current) {
      setText(errorEl, t('errEmptyPass'));
      currentEl.focus();
      return;
    }
    if ([...next].length < MIN_PASSPHRASE_LENGTH) {
      setText(errorEl, t('errTooShort', MIN_PASSPHRASE_LENGTH));
      newEl.focus();
      return;
    }
    if (next !== new2El.value) {
      setText(errorEl, t('errMismatch'));
      new2El.focus();
      return;
    }
    await run(changeBtn, () => session.changePassphrase(has ? current : null, next),
      (result) => t(!has ? 'passSet' : result.hadPasskey ? 'passChangedPasskey' : 'passChanged'));
  }

  async function remove() {
    if (busy || !session.isUnlocked() || !session.hasPassphrase()) return;
    setText(errorEl, '');
    setText(statusEl, '');
    const current = currentEl.value;
    if (!current) {
      setText(errorEl, t('passRemoveNeedsCurrent'));
      currentEl.focus();
      return;
    }
    const gen = session.generation();
    const mine = token;
    busy = true;
    try {
      await session.checkPassphrase(current);
    } catch (error) {
      if (live(gen, mine) && error.code !== 'locked') {
        setText(errorEl, message(error));
        currentEl.select();
      }
      return;
    } finally {
      busy = false;
    }
    if (!live(gen, mine)) return;
    const yes = await alarm.ask([
      { title: t('passRemoveWarnTitle'), text: t('passRemoveWarnText'), ok: t('alarmContinue') },
      { title: t('passRemoveFinalTitle'), text: t('passRemoveFinalText'), ok: t('passRemoveBtn') },
    ]);
    if (!live(gen, mine)) return;
    if (!yes) {
      removeBtn.focus();
      return;
    }
    await run(removeBtn, () => session.removePassphrase(current),
      (result) => t(result.hadPasskey ? 'passRemovedPasskey' : 'passRemoved'));
  }

  async function run(button, task, done) {
    const gen = session.generation();
    const mine = token;
    busy = true;
    changeBtn.disabled = true;
    removeBtn.disabled = true;
    try {
      const result = await task();
      // Stored. The typed passphrases never outlive the attempt.
      form.reset();
      onChanged(result);
      if (!live(gen, mine)) return;
      render();
      setText(statusEl, done(result));
      button.focus();
    } catch (error) {
      if (live(gen, mine) && error.code !== 'locked') setText(errorEl, message(error));
    } finally {
      busy = false;
      changeBtn.disabled = false;
      removeBtn.disabled = false;
    }
  }

  // On lock and before every open: no passphrase, confirmation or message stays.
  function clear() {
    token++;
    alarm.cancel();
    form.reset();
    setText(statusEl, '');
    setText(errorEl, '');
  }

  function open() {
    clear();
    render();
  }

  return { open, render, clear };
}
