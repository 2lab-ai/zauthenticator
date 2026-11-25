// popup/keyhint.js: the input-source class of a key or an inserted character, and Caps Lock.
import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyKey, classifyText, capsOf } from '../extension/popup/keyhint.js';

test('a produced character gives its script; digits, punctuation and spaces give nothing', () => {
  const cases = [
    ['a', 'latin'], ['Z', 'latin'], ['é', 'latin'], ['ß', 'latin'],
    ['ㅎ', 'hangul'], ['한', 'hangul'], ['ㅏ', 'hangul'],
    ['あ', 'kana'], ['カ', 'kana'], ['漢', 'han'],
    ['ж', 'cyrillic'], ['λ', 'greek'], ['ب', 'arabic'], ['ש', 'hebrew'], ['ก', 'thai'],
    ['ᚠ', 'other'],
    ['1', null], ['!', null], [' ', null], ['€', null], ['·', null],
    ['', null], ['ab', null], [undefined, null], [7, null],
  ];
  for (const [input, want] of cases) assert.equal(classifyText(input), want, JSON.stringify(input));
  // One code point, even outside the BMP.
  assert.equal(classifyText('𠀀'), 'han');
});

test('keys: an input method composing reads as ime; named keys give nothing', () => {
  assert.equal(classifyKey({ key: 'Process', keyCode: 229 }), 'ime');
  assert.equal(classifyKey({ key: 'ㅁ', keyCode: 229 }), 'ime');
  assert.equal(classifyKey({ key: 'a', isComposing: true }), 'ime');
  assert.equal(classifyKey({ key: 'a', keyCode: 65 }), 'latin');
  assert.equal(classifyKey({ key: 'ㅁ', keyCode: 65 }), 'hangul');
  for (const key of ['Shift', 'CapsLock', 'Enter', 'ArrowLeft', 'Backspace', 'HangulMode', 'Tab', '5']) {
    assert.equal(classifyKey({ key, keyCode: 0 }), null, key);
  }
  assert.equal(classifyKey(null), null);
});

test('Caps Lock is read from any event that reports modifiers', () => {
  assert.equal(capsOf({ getModifierState: (k) => k === 'CapsLock' }), true);
  assert.equal(capsOf({ getModifierState: () => false }), false);
  assert.equal(capsOf({}), null);
  assert.equal(capsOf(null), null);
});
