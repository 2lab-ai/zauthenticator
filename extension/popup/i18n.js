// UI strings come from _locales/<lang>/messages.json via chrome.i18n. Markup carries keys:
//   data-i18n="key"              → textContent
//   data-i18n-placeholder="key"  → placeholder
//   data-i18n-label="key"        → aria-label (and title on icon-only buttons)

export function t(key, substitutions) {
  const subs = substitutions === undefined ? undefined : [].concat(substitutions).map(String);
  const text = chrome.i18n.getMessage(key, subs);
  return text || key;
}

export function localize(root) {
  for (const el of root.querySelectorAll('[data-i18n]')) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const el of root.querySelectorAll('[data-i18n-placeholder]')) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
  for (const el of root.querySelectorAll('[data-i18n-label]')) {
    const text = t(el.dataset.i18nLabel);
    el.setAttribute('aria-label', text);
    if (el.classList.contains('icon-btn')) el.title = text;
  }
}

// The locale Chrome actually picked (falls back to the default locale), for <html lang>.
export function uiLang() {
  return chrome.i18n.getMessage('lang') || 'en';
}
