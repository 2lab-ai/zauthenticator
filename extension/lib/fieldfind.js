// One-time-code field detection for auto-fill (.prd/03-autofill.md S3).
//
// A classic script with no import or export, so one file serves both places: lib/autofill-worker.js
// registers it ahead of content/autofill.js, in the same isolated world, where it defines the one
// global zauthFieldFind; test/fieldfind.test.mjs loads the same file as a module.
//
// findOtpField() holds the rules and reads plain field descriptions (attribute maps), so it needs
// no DOM. findInDocument() describes the page's <input> elements and maps the answer back to them.
'use strict';

(() => {
  const MIN_DIGITS = 6;
  const MAX_DIGITS = 8;
  // Rule 2, matched against name, id, aria-label and placeholder.
  const NAME_PATTERN = /(otp|totp|2fa|mfa|one.?time|verification|auth(entication)?.?code|security.?code)/i;
  const NAMED_ATTRIBUTES = ['name', 'id', 'aria-label', 'placeholder'];
  // The input types a code is typed into. Password, email, search, hidden and every other type
  // never match.
  const CODE_TYPES = new Set(['', 'text', 'tel', 'number']);
  // The attributes the rules read; describe() copies exactly these.
  const ATTRIBUTES = ['type', 'autocomplete', 'inputmode', 'maxlength', ...NAMED_ATTRIBUTES];

  // A field description:
  //   { attrs: { <lower-case attribute name>: string }, value: string, disabled: boolean,
  //     readOnly: boolean, visible: boolean, group: any }
  // `group` is compared with ===; boxes of one split code share it (see groupOf()).

  function attribute(field, name) {
    const value = field && field.attrs ? field.attrs[name] : undefined;
    return typeof value === 'string' ? value : '';
  }

  // → the maxlength as a whole number, or -1 when it is absent or not a number.
  function maxLength(field) {
    const raw = attribute(field, 'maxlength').trim();
    return /^\d+$/.test(raw) ? Number(raw) : -1;
  }

  function isCodeType(field) {
    return CODE_TYPES.has(attribute(field, 'type').trim().toLowerCase());
  }

  // Shown on the page and of a type a code is typed into.
  function isShownCodeInput(field) {
    return field.visible === true && isCodeType(field);
  }

  // Shown, enabled, writable and empty: a field auto-fill may write into.
  function isFillable(field) {
    return isShownCodeInput(field) && field.disabled !== true && field.readOnly !== true && field.value === '';
  }

  // A field that can take a whole code: no maxlength, or one of at least MIN_DIGITS.
  function takesWholeCode(field) {
    const max = maxLength(field);
    return max === -1 || max >= MIN_DIGITS;
  }

  const SINGLE_FIELD_RULES = [
    // 1. autocomplete="one-time-code" (the attribute is a token list).
    (field) => attribute(field, 'autocomplete').toLowerCase().split(/\s+/).includes('one-time-code'),
    // 2. a name, id, label or placeholder that names a code.
    (field) => NAMED_ATTRIBUTES.some((name) => NAME_PATTERN.test(attribute(field, name))),
    // 3. a numeric field sized for a code.
    (field) => {
      const numeric = attribute(field, 'inputmode').trim().toLowerCase() === 'numeric' ||
        ['tel', 'number'].includes(attribute(field, 'type').trim().toLowerCase());
      const max = maxLength(field);
      return numeric && max >= MIN_DIGITS && max <= MAX_DIGITS;
    },
  ];

  // 4. The first run of MIN_DIGITS..MAX_DIGITS single-character boxes in one group, every box
  // fillable. Inputs that are not shown or not of a code type (a hidden input that holds the
  // joined value) are passed over; any other input ends a run. → indices, or null
  function boxRun(fields) {
    let run = [];
    const qualifies = () =>
      run.length >= MIN_DIGITS && run.length <= MAX_DIGITS && run.every((i) => isFillable(fields[i]));
    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      if (!isShownCodeInput(field)) continue;
      const isBox = maxLength(field) === 1;
      if (isBox && run.length > 0 && fields[run[0]].group === field.group) {
        run.push(i);
        continue;
      }
      if (qualifies()) return run;
      run = isBox ? [i] : [];
    }
    return qualifies() ? run : null;
  }

  // The rules in order; within a rule the first field in document order wins.
  // → [index] for one field, the indices of a box run, or null
  function findOtpField(fields) {
    const list = Array.isArray(fields) ? fields.filter((f) => f !== null && typeof f === 'object') : [];
    for (const rule of SINGLE_FIELD_RULES) {
      const index = list.findIndex((field) => isFillable(field) && takesWholeCode(field) && rule(field));
      if (index !== -1) return [fields.indexOf(list[index])];
    }
    const run = boxRun(list);
    return run ? run.map((i) => fields.indexOf(list[i])) : null;
  }

  // ---- DOM adapter ----

  // Boxes of a split code sit side by side in one parent, or each in its own wrapper inside one
  // parent: an input that is the only input of its parent is grouped by the grandparent.
  function groupOf(el) {
    const parent = el.parentElement;
    if (parent && parent.parentElement && parent.querySelectorAll('input').length === 1) return parent.parentElement;
    return parent;
  }

  function isVisible(el) {
    if (typeof el.checkVisibility === 'function') {
      // checkVisibilityCSS is the older spelling of visibilityProperty.
      return el.checkVisibility({ visibilityProperty: true, checkVisibilityCSS: true });
    }
    return el.getClientRects().length > 0;
  }

  function describe(el) {
    const attrs = {};
    for (const name of ATTRIBUTES) {
      const value = el.getAttribute(name);
      if (value !== null) attrs[name] = value;
    }
    return {
      attrs,
      value: typeof el.value === 'string' ? el.value : '',
      disabled: el.matches(':disabled'),
      readOnly: el.readOnly === true,
      visible: isVisible(el),
      group: groupOf(el),
    };
  }

  // → the <input> element(s) to fill in `root` (a document), or null
  function findInDocument(root) {
    const inputs = Array.from(root.querySelectorAll('input'));
    const found = findOtpField(inputs.map(describe));
    return found ? found.map((i) => inputs[i]) : null;
  }

  globalThis.zauthFieldFind = Object.freeze({ MIN_DIGITS, MAX_DIGITS, findOtpField, findInDocument, groupOf });
})();
