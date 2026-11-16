// DOM helpers shared by the popup views.

export function $(selector, root = document) {
  const el = root.querySelector(selector);
  if (!el) throw new Error(`missing element ${selector}`);
  return el;
}

let announceTimer = 0;

// Polite screen-reader announcement (copy confirmations, results).
export function announce(message) {
  const live = $('#live');
  clearTimeout(announceTimer);
  live.textContent = '';
  // A separate task so repeated identical messages are announced again.
  announceTimer = setTimeout(() => {
    live.textContent = message;
  }, 30);
}

// Drops the current and any pending announcement (they can name an account; used on lock).
export function clearAnnouncement() {
  clearTimeout(announceTimer);
  $('#live').textContent = '';
}

export function setText(el, message) {
  el.textContent = message ?? '';
}

// Disables a button while `task` runs and shows `busyLabel` in place of its text.
export async function withBusy(button, busyLabel, task) {
  const label = button.textContent;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  if (busyLabel) button.textContent = busyLabel;
  try {
    return await task();
  } finally {
    button.disabled = false;
    button.removeAttribute('aria-busy');
    if (busyLabel) button.textContent = label;
  }
}

// Short human-readable reason from an exception raised by a core module.
export function reason(error) {
  if (!error) return '';
  const text = typeof error.message === 'string' ? error.message : String(error);
  return text.length > 160 ? `${text.slice(0, 157)}…` : text;
}
