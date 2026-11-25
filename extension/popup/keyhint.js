// Passphrase fields show which input source the keys produce and whether Caps Lock is on
// (issue #6): "Input source: Korean (Hangul) · Caps Lock off".
//
// The source is read from what a key produced: the Unicode script of that one character (Latin,
// Hangul, Cyrillic, ...) or that an input method is composing. Only that class is kept and shown,
// never the character: nothing typed leaves the field. Digits, punctuation and spaces say nothing
// about the source and leave the last class standing. The source and Caps Lock belong to the
// keyboard, not to a field, so every passphrase field shows the same state; the line shows while a
// field has focus.
import { t } from './i18n.js';

// The class of one produced character. Order matters only for scripts that overlap (none here).
const SCRIPTS = [
  ['latin', /\p{Script=Latin}/u],
  ['hangul', /\p{Script=Hangul}/u],
  ['kana', /[\p{Script=Hiragana}\p{Script=Katakana}]/u],
  ['han', /\p{Script=Han}/u],
  ['cyrillic', /\p{Script=Cyrillic}/u],
  ['greek', /\p{Script=Greek}/u],
  ['arabic', /\p{Script=Arabic}/u],
  ['hebrew', /\p{Script=Hebrew}/u],
  ['thai', /\p{Script=Thai}/u],
];
const NEUTRAL = /^[\p{N}\p{P}\p{S}\p{Z}\s]$/u;

/** → the source class of one character ('latin', 'hangul', ..., 'other'), or null when it tells nothing. */
export function classifyText(text) {
  if (typeof text !== 'string') return null;
  const chars = [...text];
  if (chars.length !== 1) return null;
  if (NEUTRAL.test(chars[0])) return null;
  for (const [name, pattern] of SCRIPTS) if (pattern.test(chars[0])) return name;
  return 'other';
}

/** → the source class a keydown shows: 'ime' while an input method composes, a script class for a
 * printable key, or null (a modifier, an arrow, a digit...). */
export function classifyKey(event) {
  if (!event) return null;
  if (event.isComposing || event.key === 'Process' || event.keyCode === 229) return 'ime';
  return classifyText(event.key);
}

/** → true or false from any keyboard or pointer event that reports modifiers, else null. */
export function capsOf(event) {
  return typeof event?.getModifierState === 'function' ? event.getModifierState('CapsLock') : null;
}

// Adds a hint line under every passphrase field in root and keeps them current.
export function attachKeyHints(root = document) {
  let source = null; // the last class seen, or null before any
  let caps = null;   // true | false | null (not known yet)
  const fields = [...root.querySelectorAll('input[type="password"]')];
  const lines = new Map();
  for (const input of fields) {
    const line = document.createElement('p');
    line.className = 'key-hint';
    line.id = `${input.id}-keyhint`;
    line.hidden = true;
    const sourceEl = document.createElement('span');
    sourceEl.className = 'key-source';
    const capsEl = document.createElement('span');
    capsEl.className = 'key-caps';
    line.append(sourceEl, document.createTextNode(' · '), capsEl);
    input.after(line);
    const described = input.getAttribute('aria-describedby');
    input.setAttribute('aria-describedby', described ? `${described} ${line.id}` : line.id);
    lines.set(input, { line, sourceEl, capsEl });
  }

  const focused = () => (lines.has(document.activeElement) ? document.activeElement : null);

  function paint() {
    const input = focused();
    for (const [field, parts] of lines) {
      parts.line.hidden = field !== input;
      if (field !== input) continue;
      parts.sourceEl.textContent = t('keySource', t(source ? `keySource_${source}` : 'keySourceUnknown'));
      parts.capsEl.textContent = t(caps === true ? 'capsOn' : caps === false ? 'capsOff' : 'capsUnknown');
      parts.line.classList.toggle('caps-on', caps === true);
      parts.line.dataset.source = source ?? '';
      parts.line.dataset.caps = caps === null ? '' : String(caps);
    }
  }

  const sawCaps = (event) => {
    const state = capsOf(event);
    if (state !== null) caps = state;
  };
  document.addEventListener('keydown', (event) => {
    sawCaps(event);
    const cls = classifyKey(event);
    if (cls && lines.has(event.target)) source = cls;
    if (focused()) paint();
  }, true);
  document.addEventListener('keyup', (event) => {
    sawCaps(event);
    if (focused()) paint();
  }, true);
  document.addEventListener('pointerdown', (event) => {
    sawCaps(event);
  }, true);
  // What an input method (or a keyboard without key events) inserted: only its class is kept.
  document.addEventListener('input', (event) => {
    if (!lines.has(event.target)) return;
    if (event.isComposing || event.inputType === 'insertCompositionText') source = 'ime';
    else {
      const cls = classifyText(typeof event.data === 'string' ? [...event.data].at(-1) : null);
      if (cls) source = cls;
    }
    paint();
  }, true);
  document.addEventListener('compositionstart', (event) => {
    if (!lines.has(event.target)) return;
    source = 'ime';
    paint();
  }, true);
  document.addEventListener('focusin', paint, true);
  document.addEventListener('focusout', () => setTimeout(paint, 0), true);

  return { paint };
}
