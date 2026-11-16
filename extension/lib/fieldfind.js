// One-time-code field detection for auto-fill (.prd/03-autofill.md S3).
//
// A classic script with no import or export, so one file serves both places: lib/autofill-worker.js
// registers it ahead of content/autofill.js, in the same isolated world, where it defines the one
// global zauthFieldFind; test/fieldfind.test.mjs loads the same file as a module.
//
// findOtpField() holds the rules and reads plain field descriptions (attribute maps), so it needs
// no DOM. findInDocument() describes the page's <input> elements and maps the answer back to them.
//
// The field found is filled with no click from the user, so every rule needs a sign that the page
// asks for a one-time code: autocomplete="one-time-code", or a name, id, label or placeholder that
// names one (OTP, 2FA, verification code, ...). A field that is only sized like a code (a PIN, a
// short number, boxes with no such sign) is never filled by itself; the right-click menu fills it
// when the user asks.
'use strict';

(() => {
  const MIN_DIGITS = 6;
  const MAX_DIGITS = 8;
  const NAMED_ATTRIBUTES = ['name', 'id', 'aria-label', 'placeholder'];
  // A name split into words: at anything that is not a letter or digit, at camelCase humps
  // (otpCode, OTPCode) and where letters meet digits (otp1; 2fa stays whole).
  const WORD_BREAK = /[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=[0-9])/;
  // Rules 2 and 3, matched against name, id, aria-label and placeholder: one of these words, or one
  // of the phrases (any separator or none between their parts).
  const CODE_WORDS = new Set(['otp', 'totp', 'mfa', '2fa']);
  const CODE_PHRASES = [/one.?time.?(code|pass|password|pin)/i, /verification.?code/i, /auth(entication)?.?code/i];
  // Rules 2 and 3 pass over a field whose name, id, aria-label, placeholder or autocomplete has one
  // of these words (whole words, split as above; the last five are common one-word spellings):
  // other short numbers a page asks for. Rule 3 also skips a run of boxes whose group's aria-label
  // or id has one ("Verification code sent to your phone").
  const OTHER_NUMBER_WORDS = new Set([
    'zip', 'postal', 'phone', 'tel', 'mobile', 'amount', 'price', 'card', 'cc', 'cvv', 'cvc', 'csc',
    'birth', 'bday', 'dob', 'date', 'year', 'month', 'day', 'search', 'account', 'qty', 'quantity',
    'captcha', 'zipcode', 'postcode', 'telephone', 'birthday', 'birthdate',
  ]);
  // ... and a field whose autocomplete asks for anything else than a one-time code (empty, on and
  // off say nothing about the field).
  const NEUTRAL_AUTOCOMPLETE = ['', 'on', 'off', 'one-time-code'];
  const EXCLUSION_ATTRIBUTES = [...NAMED_ATTRIBUTES, 'autocomplete'];
  // The input types a code is typed into. Password, email, search, hidden and every other type
  // never match.
  const CODE_TYPES = new Set(['', 'text', 'tel', 'number']);
  // The attributes the rules read; describe() copies exactly these.
  const ATTRIBUTES = ['type', 'autocomplete', 'inputmode', 'maxlength', ...NAMED_ATTRIBUTES];
  // Rule 3 also reads these attributes of the element that groups the boxes (a row labelled
  // "Enter verification code"), for a sign of a code and for a word for another number;
  // describe() copies them into attrs under GROUP_PREFIX + the name, so the rules need no DOM.
  // Rule 2 does not read them: the group of a lone field is an ancestor further out (see
  // groupOf()), and its label says nothing sure about that one field.
  const GROUP_ATTRIBUTES = ['aria-label', 'id'];
  const GROUP_PREFIX = 'group-';

  // A field description:
  //   { attrs: { <lower-case attribute name>: string }, value: string, disabled: boolean,
  //     readOnly: boolean, visible: boolean, group: any }
  // attrs also holds 'group-aria-label' and 'group-id' when the group element has them.
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

  // Not shown on the page, or type=hidden.
  function isHiddenInput(field) {
    return field.visible !== true || attribute(field, 'type').trim().toLowerCase() === 'hidden';
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

  // The lower-case words of an attribute value (see WORD_BREAK).
  function words(value) {
    return value.split(WORD_BREAK).filter((word) => word !== '').map((word) => word.toLowerCase());
  }

  function namesCode(value) {
    return words(value).some((word) => CODE_WORDS.has(word)) || CODE_PHRASES.some((phrase) => phrase.test(value));
  }

  // Named for another number, or marked by autocomplete as another kind of value: rules 2 and 3
  // never take it.
  function isOtherField(field) {
    if (!NEUTRAL_AUTOCOMPLETE.includes(attribute(field, 'autocomplete').trim().toLowerCase())) return true;
    return EXCLUSION_ATTRIBUTES.some((name) => words(attribute(field, name)).some((word) => OTHER_NUMBER_WORDS.has(word)));
  }

  // autocomplete="one-time-code" (the attribute is a token list).
  function isMarkedOneTimeCode(field) {
    return attribute(field, 'autocomplete').toLowerCase().split(/\s+/).includes('one-time-code');
  }

  // A name, id, label or placeholder that names a code.
  function isNamedForCode(field) {
    return NAMED_ATTRIBUTES.some((name) => namesCode(attribute(field, name)));
  }

  // The label or id of the field's group (copied by describe()) names a code.
  function isInGroupNamedForCode(field) {
    return GROUP_ATTRIBUTES.some((name) => namesCode(attribute(field, GROUP_PREFIX + name)));
  }

  // The label or id of the field's group has a word for another number (rule 3 only).
  function isInGroupNamedForOther(field) {
    return GROUP_ATTRIBUTES.some((name) => words(attribute(field, GROUP_PREFIX + name)).some((word) => OTHER_NUMBER_WORDS.has(word)));
  }

  const SINGLE_FIELD_RULES = [
    // 1. autocomplete="one-time-code", whatever else the field says.
    isMarkedOneTimeCode,
    // 2. a name, id, label or placeholder that names a code.
    (field) => !isOtherField(field) && isNamedForCode(field),
  ];

  // 3. The first run of MIN_DIGITS..MAX_DIGITS single-character boxes in one group, every box
  // fillable and none named for another number, in a group whose aria-label and id name no other
  // number, that says it holds a code: a box marked one-time-code, a box whose name, id, label or
  // placeholder names a code, or a group whose aria-label or id does. Hidden inputs (type=hidden or
  // not shown, such as one that holds the joined value) are passed over, and say nothing for the
  // run; any other input ends a run, a shown password or email field too. A run with no such sign
  // (a PIN typed into boxes) or in a group named for another number is skipped, and the next one
  // is looked at.
  // → indices, or null
  function boxRun(fields) {
    let run = [];
    const qualifies = () =>
      run.length >= MIN_DIGITS &&
      run.length <= MAX_DIGITS &&
      run.every((i) => isFillable(fields[i]) && !isOtherField(fields[i]) && !isInGroupNamedForOther(fields[i])) &&
      run.some((i) => isMarkedOneTimeCode(fields[i]) || isNamedForCode(fields[i]) || isInGroupNamedForCode(fields[i]));
    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      if (isHiddenInput(field)) continue;
      const isBox = isCodeType(field) && maxLength(field) === 1;
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
    const group = groupOf(el);
    for (const name of GROUP_ATTRIBUTES) {
      const value = group ? group.getAttribute(name) : null;
      const key = GROUP_PREFIX + name;
      if (value !== null) attrs[key] = value;
    }
    return {
      attrs,
      value: typeof el.value === 'string' ? el.value : '',
      disabled: el.matches(':disabled'),
      readOnly: el.readOnly === true,
      visible: isVisible(el),
      group,
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
