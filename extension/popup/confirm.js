// The red two-step confirmation in front of a risky change (a long unlock time, removing the
// passphrase): a warning, then a final check, in red. Only the second "yes" goes ahead; Cancel or
// Escape at either step ends it with nothing done. Each step starts with Cancel focused and its
// red button briefly disabled, so a held Enter or a double click cannot pass both steps.
import { t } from './i18n.js';
import { setText } from './ui.js';

// How long the red button of a new step stays disabled.
const ARM_MS = 600;

// root holds .alarm-step, .alarm-title, .alarm-text, .alarm-cancel and .alarm-ok (popup.html).
// → { ask(steps), cancel(), isOpen() }; ask([{ title, text, ok }, ...]) resolves true once every
// step was confirmed, false when cancelled (also by a later ask() or by cancel()).
export function createAlarm(root) {
  const stepEl = root.querySelector('.alarm-step');
  const titleEl = root.querySelector('.alarm-title');
  const textEl = root.querySelector('.alarm-text');
  const cancelBtn = root.querySelector('.alarm-cancel');
  const okBtn = root.querySelector('.alarm-ok');
  let pending = null; // { resolve, steps, index }
  let armTimer = 0;

  okBtn.addEventListener('click', () => {
    if (!pending || okBtn.disabled) return;
    if (pending.index + 1 < pending.steps.length) {
      pending.index++;
      paint();
    } else {
      finish(true);
    }
  });
  cancelBtn.addEventListener('click', () => finish(false));
  root.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || !pending) return;
    event.preventDefault();
    event.stopPropagation();
    finish(false);
  });

  function paint() {
    const step = pending.steps[pending.index];
    root.dataset.step = String(pending.index + 1);
    setText(stepEl, t('alarmStep', [pending.index + 1, pending.steps.length]));
    setText(titleEl, step.title);
    setText(textEl, step.text);
    setText(okBtn, step.ok);
    root.hidden = false;
    clearTimeout(armTimer);
    okBtn.disabled = true;
    armTimer = setTimeout(() => { okBtn.disabled = false; }, ARM_MS);
    cancelBtn.focus();
  }

  function ask(steps) {
    finish(false);
    return new Promise((resolve) => {
      pending = { resolve, steps, index: 0 };
      paint();
    });
  }

  function finish(result) {
    clearTimeout(armTimer);
    if (!pending) return;
    const { resolve } = pending;
    pending = null;
    root.hidden = true;
    delete root.dataset.step;
    setText(titleEl, '');
    setText(textEl, '');
    resolve(result);
  }

  return { ask, cancel: () => finish(false), isOpen: () => pending !== null };
}
