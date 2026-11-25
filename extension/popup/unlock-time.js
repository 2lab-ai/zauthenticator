// The list view's unlock time: when the vault locks, and Extend. Opening or using the extension
// already moves the lock time to at least 15 minutes from now (session.touch(), the idle limit);
// Extend keeps it unlocked for 1 hour, 24 hours or 7 days (for example while an AI agent uses the
// browser), after the red two-step confirmation. "Back to 15 minutes" drops an extension at once.
import * as session from './session.js';
import { t, uiLang } from './i18n.js';
import { $, setText, announce, reason } from './ui.js';
import { createAlarm } from './confirm.js';

// How often the shown lock time is read again (activity in any page moves it).
const REFRESH_MS = 10 * 1000;
const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function createUnlockTime({ onExpired = () => {} } = {}) {
  const bar = $('#unlock-bar');
  const leftEl = $('#unlock-left');
  const extendBtn = $('#extend-btn');
  const panel = $('#extend-panel');
  const choices = $('#extend-choices');
  const resetBtn = $('#extend-reset');
  const errorEl = $('#extend-error');
  const alarm = createAlarm($('#extend-alarm'));
  let state = null; // { lockAt, until } of the stored session, or null
  let token = 0;    // the latest read; an earlier one is dropped
  let busy = false;
  let paintTimer = 0;
  let refreshTimer = 0;

  extendBtn.addEventListener('click', () => setOpen(panel.hidden));
  choices.addEventListener('click', (event) => {
    const choice = event.target.closest('.extend-choice');
    if (choice) choose(Number(choice.dataset.ms));
  });
  resetBtn.addEventListener('click', () => apply(0));

  async function refresh() {
    const current = ++token;
    let next = null;
    try {
      next = await session.unlockState();
    } catch {
      next = null;
    }
    if (current !== token) return;
    state = next;
    paint();
  }

  function paint(now = Date.now()) {
    bar.hidden = !state;
    if (!state) {
      setOpen(false);
      setText(leftEl, '');
      return;
    }
    // No passphrase: it never locks for time, and there is nothing to extend.
    extendBtn.hidden = state.device;
    bar.classList.toggle('extended', Boolean(state.until) || state.device);
    if (state.device) {
      setOpen(false);
      setText(leftEl, t('unlockDevice'));
      return;
    }
    const left = state.lockAt - now;
    if (left <= 0) onExpired();
    const key = state.until ? 'unlockLeftExtended' : 'unlockLeft';
    setText(leftEl, t(key, [formatLeft(Math.max(0, left)), formatAt(state.lockAt, now)]));
    resetBtn.hidden = !state.until;
  }

  function setOpen(open) {
    if (!open) alarm.cancel();
    panel.hidden = !open;
    extendBtn.setAttribute('aria-expanded', String(open));
    if (open) setText(errorEl, '');
  }

  async function choose(ms) {
    if (busy || !session.EXTEND_CHOICES_MS.includes(ms)) return;
    const label = choiceLabel(ms);
    const at = formatAt(Date.now() + ms, Date.now());
    choices.hidden = true;
    resetBtn.hidden = true;
    let yes;
    try {
      yes = await alarm.ask([
        { title: t('extendWarnTitle', label), text: t('extendWarnText', at), ok: t('alarmContinue') },
        { title: t('extendFinalTitle'), text: t('extendFinalText', [label, at]), ok: t('extendFinalOk', label) },
      ]);
    } finally {
      choices.hidden = false;
      resetBtn.hidden = !(state && state.until);
    }
    if (yes) await apply(ms);
    else if (!panel.hidden) choices.querySelector(`[data-ms="${ms}"]`)?.focus();
  }

  async function apply(ms) {
    if (busy) return;
    busy = true;
    setText(errorEl, '');
    const gen = session.generation();
    try {
      const next = await session.extendUnlock(ms);
      if (session.generation() !== gen) return;
      token++;
      state = next;
      paint();
      setOpen(false);
      announce(ms ? t('extendDone', formatAt(next.lockAt, Date.now())) : t('extendResetDone'));
      extendBtn.focus();
    } catch (error) {
      if (session.generation() !== gen || error.code === 'locked') return;
      setText(errorEl, t('extendFailed', reason(error)));
    } finally {
      busy = false;
    }
  }

  function start() {
    stop();
    refresh();
    paintTimer = setInterval(() => paint(), 1000);
    refreshTimer = setInterval(refresh, REFRESH_MS);
  }

  function stop() {
    clearInterval(paintTimer);
    clearInterval(refreshTimer);
  }

  // On lock: nothing about the session stays on the page.
  function clear() {
    stop();
    token++;
    state = null;
    setOpen(false);
    bar.hidden = true;
    setText(leftEl, '');
    setText(errorEl, '');
  }

  return { start, stop, refresh, clear };
}

function choiceLabel(ms) {
  if (ms === HOUR) return t('extend1h');
  if (ms === DAY) return t('extend24h');
  return t('extend7d');
}

// Time left: "14:32" under an hour, "5 h 12 min" under a day, "6 d 23 h" beyond.
export function formatLeft(ms) {
  if (ms < HOUR) {
    const seconds = Math.floor(ms / 1000);
    return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
  }
  if (ms < DAY) return t('durationHM', [Math.floor(ms / HOUR), Math.floor((ms % HOUR) / MINUTE)]);
  return t('durationDH', [Math.floor(ms / DAY), Math.floor((ms % DAY) / HOUR)]);
}

// The lock time as a clock time, with the date when it is not today.
export function formatAt(at, now = Date.now()) {
  const sameDay = new Date(at).toDateString() === new Date(now).toDateString();
  const options = sameDay
    ? { hour: 'numeric', minute: '2-digit' }
    : { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' };
  return new Intl.DateTimeFormat(uiLang(), options).format(at);
}
