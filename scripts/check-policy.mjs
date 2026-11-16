#!/usr/bin/env node
// Static trust gate for extension/ (npm run check). Rules: .prd/02-architecture.md "Trust gate"
// and "Round 2 contract changes", tightened by MANIFEST_POLICY and the pattern lists below.
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
// (window.open, location assignment, chrome.tabs/windows calls that open anything but
// chrome.runtime.getURL(...), links, forms and frames that leave the extension); the only pages
// the extension opens are its own. The gate reads source text; it is a tripwire for the
// repository's own sources, not a JavaScript parser or a sandbox.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(SCRIPT), '..');

// ---- Manifest policy (v0.1) -------------------------------------------------------------------
// The one place that says what the manifest may ask for. Widening it is a deliberate, reviewed
// change; the planned auto-fill feature (.prd/03-autofill.md) is expected to be the next one.
// The self-test pins every value here against PINNED_POLICY, a copy written out by hand, so a
// change has to be made in both places.
const MANIFEST_POLICY = Object.freeze({
  // `permissions` must be a subset of this list.
  allowedPermissions: ['storage', 'activeTab'],
  // Must be absent or an empty array; a non-empty value fails the `permissions` rule.
  absentOrEmptyKeys: ['optional_permissions', 'optional_host_permissions'],
  // Must be absent; any value, even an empty one, fails the `manifest-keys` rule.
  forbiddenKeys: [
    'host_permissions',
    'content_scripts',
    'externally_connectable',
    'update_url',
    'key',
    'web_accessible_resources',
    'background',
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
});
const HOMEPAGE_URL = MANIFEST_POLICY.homepageUrl;
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
  ['chrome.tabs.duplicate/goBack/goForward', /\bchrome\s*\.\s*tabs\s*(?:\?\.|\.)\s*(?:duplicate|goBack|goForward)\b/g],
  ['setUninstallURL', /\bsetUninstallURL\b/g],
  // chrome.tabs / chrome.windows used other than as chrome.tabs.<method>: an alias or computed
  // access would hide a create()/update() call from the url check.
  ['chrome.tabs/windows alias', /\bchrome\s*\.\s*(?:tabs|windows)\b(?!\s*(?:\?\.|\.)\s*[A-Za-z_$])/g],
  ['<meta http-equiv=refresh>', /<meta\b[^>]*\bhttp-equiv\s*=\s*["']?\s*refresh/gi],
  // Not preceded by an identifier, so a JSDoc type such as Promise<object> is not an element.
  ['frame/embed/object element', /(?<![\w$])<(?:iframe|frame|frameset|embed|object|portal|fencedframe)\b/gi],
];
// open(<args>) as a call of the global, not a member call (x.open(...)), not a declaration.
const BARE_OPEN = /(?<![\w$.])(?<!\.\s+)(?<!\bfunction\s*\*?\s*)\bopen\s*(?:\?\.\s*)?\((?=\s*[^\s)])/g;
const TAB_CALL = /\bchrome\s*\.\s*(tabs|windows)\s*(?:\?\.|\.)\s*(create|update)\s*(?:\?\.\s*)?\(/g;
const GET_URL = /^\s*chrome\s*\.\s*runtime\s*\.\s*getURL\s*\(/;
const FORBIDDEN_CSP_TOKENS = ["'unsafe-eval'", "'unsafe-inline'", "'wasm-unsafe-eval'"];

const RULES = [
  'extension-dir',
  'manifest',
  'permissions',
  'manifest-keys',
  'homepage-url',
  'csp',
  'file-types',
  'network-api',
  'dynamic-code',
  'remote-url',
  'css-remote',
  'navigation',
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

// → { directives: Map(name → sorted lower-case sources), duplicates: [name] }
function parseCsp(policy) {
  const directives = new Map();
  const duplicates = [];
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
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
  const problems = actual.duplicates.map((name) => `duplicate ${name} directive`);
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

function sha256(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
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

// Why the arguments of a chrome.tabs/windows create/update call may open a page other than the
// extension's own, or null when every url is chrome.runtime.getURL(...).
function urlArgumentProblem(args, urlOptional) {
  if (args.includes('...')) return 'uses a spread, so its url cannot be checked';
  if (!args.includes('{')) return 'has no object literal, so its url cannot be checked';
  if (/[{,]\s*url\s*[,}]/.test(args)) return 'uses a shorthand url property, so its url cannot be checked';
  if (/\[\s*['"`]url['"`]\s*\]/.test(args)) return 'uses a computed url property, so its url cannot be checked';
  const keys = [...args.matchAll(/(?:^|[{,\s])(?:url|'url'|"url")\s*:/g)];
  if (keys.length === 0) return urlOptional ? null : 'has no url (opens the new tab page)';
  for (const key of keys) {
    if (!GET_URL.test(args.slice(key.index + key[0].length))) return 'has a url that is not chrome.runtime.getURL(...)';
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

function navigationHits(text, label) {
  const hits = findAll(text, NAVIGATION_PATTERNS, label);

  BARE_OPEN.lastIndex = 0;
  for (const m of text.matchAll(BARE_OPEN)) {
    const call = callArguments(text, m.index + m[0].length - 1);
    // open(...) { ... } is a method definition, not a call.
    if (call && /^\s*\{/.test(text.slice(call.end + 1))) continue;
    hits.push(`${label}:${lineOf(text, m.index)} open( (global call)`);
  }

  TAB_CALL.lastIndex = 0;
  for (const m of text.matchAll(TAB_CALL)) {
    const [, area, method] = m;
    if (area === 'windows' && method === 'update') continue; // takes no url
    const call = callArguments(text, m.index + m[0].length - 1);
    const problem = call ? urlArgumentProblem(call.args, area === 'tabs' && method === 'update') : 'is not a balanced call';
    if (problem) hits.push(`${label}:${lineOf(text, m.index)} chrome.${area}.${method}( ${problem}`);
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

// sha256sum lists paths relative to vendor/; './x', 'vendor/x' and 'a/../x' all name vendor/x.
// → 'vendor/<path>', or null for a path that leaves vendor/.
function normalizeSumsPath(name) {
  let p = path.posix.normalize(name.replace(/\\/g, '/'));
  if (p.startsWith('vendor/')) p = p.slice('vendor/'.length);
  if (p === '.' || p === '..' || p.startsWith('../') || p.startsWith('/')) return null;
  return `vendor/${p}`;
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
    .forEach((raw, i) => {
      const line = raw.replace(/\r$/, '');
      if (line.trim() === '' || line.startsWith('#')) return; // sha256sum -c skips '#' comment lines too
      const m = line.match(/^([0-9a-fA-F]{64}) [ *](.+)$/);
      if (!m) {
        problems.push(`${label(SUMS_PATH)}:${i + 1} malformed line`);
        return;
      }
      const rel = normalizeSumsPath(m[2]);
      if (!rel) {
        problems.push(`${label(SUMS_PATH)}:${i + 1} path ${JSON.stringify(m[2])} is outside vendor/`);
        return;
      }
      // A second entry for the same file must not win (or lose) silently.
      if (listed.has(rel)) {
        problems.push(`${label(SUMS_PATH)}:${i + 1} lists ${rel} again (first at line ${listed.get(rel).line})`);
        return;
      }
      listed.set(rel, { hash: m[1].toLowerCase(), line: i + 1 });
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

    const { allowedPermissions, absentOrEmptyKeys, forbiddenKeys } = MANIFEST_POLICY;
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
    record(
      'permissions',
      permProblems.length === 0,
      permProblems.length === 0
        ? `[${perms.join(', ')}] within {${allowedPermissions.join(', ')}}; ${absentOrEmptyKeys.join(', ')} absent or empty`
        : permProblems.join('; '),
    );

    const present = forbiddenKeys.filter((k) => Object.hasOwn(manifest, k));
    record('manifest-keys', present.length === 0, present.length === 0 ? `none of ${forbiddenKeys.join(', ')}` : `forbidden: ${present.join(', ')}`);

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
    for (const rule of ['permissions', 'manifest-keys', 'homepage-url', 'csp']) record(rule, false, 'manifest.json unreadable');
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
  const inline = [];
  for (const f of scanned) {
    const text = fs.readFileSync(f.abs, 'utf8');
    network.push(...findAll(text, NETWORK_PATTERNS, label(f.rel)));
    dynamic.push(...findAll(text, DYNAMIC_CODE_PATTERNS, label(f.rel)));
    urls.push(...findAll(text, URL_PATTERNS, label(f.rel)));
    navigation.push(...navigationHits(text, label(f.rel)));
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
    navigation.length === 0 ? `no navigation sink, and chrome.tabs/windows open only chrome.runtime.getURL(...), in ${scope}` : navigation.join('; '),
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
  allowedPermissions: ['activeTab', 'storage'],
  absentOrEmptyKeys: ['optional_host_permissions', 'optional_permissions'],
  forbiddenKeys: [
    'background',
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
};

// Differences between two policies, [] when equal. Lists compare as sorted copies (so a
// duplicate entry is a difference), everything else exactly.
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
  ['absentOrEmptyKeys', (p) => p.absentOrEmptyKeys.pop()],
  ['forbiddenKeys', (p) => (p.forbiddenKeys = p.forbiddenKeys.filter((k) => k !== 'background'))],
  ['homepageUrl', (p) => (p.homepageUrl = 'https://github.com/2lab-ai/zauthenticator/')],
  ['extensionPagesCsp', (p) => (p.extensionPagesCsp = p.extensionPagesCsp.replace("img-src 'self' data: blob:", 'img-src *'))],
  ['newField', (p) => (p.newField = [])],
];

const ONE_PIXEL_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
);

const APPROVED_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// The clean fixture carries the shapes the real extension uses that must NOT trip a rule
// (member .open() calls, open() declarations and method shorthand, location reads,
// chrome.tabs calls on chrome.runtime.getURL, plain forms, JSDoc generics, CSS data: urls).
function cleanFixture() {
  return {
    manifest: {
      manifest_version: 3,
      name: 'zauthenticator',
      version: '0.1.0',
      permissions: ['storage', 'activeTab'],
      action: { default_popup: 'popup/popup.html' },
      content_security_policy: { extension_pages: APPROVED_CSP },
    },
    files: {
      'lib/base32.js': "export function decode(str) { return new Uint8Array(str.length); }\n",
      'lib/totp.js':
        "// RFC 6238 over WebCrypto\nexport async function hotp(key) {\n  return crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);\n}\n",
      'lib/store.js': "export async function load() { return chrome.storage.local.get('vault'); }\n",
      'lib/qr.js': "import jsQR from '../vendor/jsQR.js';\nexport function decode(img) { return jsQR(img.data, img.width, img.height); }\n",
      'lib/vault.js':
        "/**\n * - 'corrupt'  malformed record or key; open() with a key that does not authenticate\n * @returns {Promise<object>} new record\n */\nexport async function open(rawKey, record) {\n  return { rawKey, record };\n}\n",
      'popup/popup.html':
        '<!doctype html>\n<html>\n<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark"><link rel="stylesheet" href="popup.css"></head>\n<body data-state="setup">\n<a href="#top">Top</a> <a class="x" href="settings.html">Settings</a>\n<form id="setup-form" class="stack" novalidate>\n<input id="setup-pass" type="password">\n<button type="submit" id="setup-submit">Create</button>\n</form>\n<dialog><form method="dialog"><button>Close</button></form></dialog>\n<button id="lock-btn" type="button">Lock</button>\n<script type="module" src="popup.js"></script>\n</body>\n</html>\n',
      'popup/popup.css':
        'body { font: 13px system-ui; }\n.brand { background: url(../icons/16.png) no-repeat; }\n.check { background-image: url("data:image/svg+xml,%3Csvg%3E%3C/svg%3E"); }\n@media (prefers-color-scheme: dark) { body { color: white; } }\n',
      'popup/popup.js': [
        "import * as vault from '../lib/vault.js';",
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
        "  await chrome.tabs.create({ url: chrome.runtime.getURL('popup/popup.html#add-file') });",
        '  await chrome.tabs.create({',
        "    url: chrome.runtime.getURL('popup/popup.html#settings'), // a full tab",
        '    active: true,',
        '  });',
        '  await chrome.tabs.update(maybe.id, { active: true });',
        "  await chrome.tabs.update(maybe.id, { url: chrome.runtime.getURL('popup/popup.html') });",
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
  background: { service_worker: 'lib/store.js', type: 'module' },
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
  ['ok-word-boundaries', addJs('lib/words.js', '// prefetch(x) retrieval(y) refetch(z) reopen(x) geolocation = 1\nconst fetched = 1; const evaluate = () => 0; const opener = window.opener;\n'), []],
  ['ok-ds-store-ignored', (fx) => (fx.files['popup/.DS_Store'] = Buffer.from([0, 0, 0, 1, 66, 117, 100, 49])), []],
  [
    'ok-sums-binary-marker-and-dot-slash',
    (fx) => {
      fx.sums = 'deferred';
    },
    [],
  ],
  [
    'ok-sums-comment-line',
    (fx) => {
      fx.sums = 'comment';
    },
    [],
  ],
  ['bad-manifest-json', (fx) => (fx.manifestRaw = '{ "manifest_version": 3, '), ['manifest', 'permissions', 'manifest-keys', 'homepage-url', 'csp']],
  ['bad-manifest-v2', (fx) => (fx.manifest.manifest_version = 2), ['manifest']],
  ['perm-tabs', (fx) => fx.manifest.permissions.push('tabs'), ['permissions']],
  ['perm-not-array', (fx) => (fx.manifest.permissions = 'storage'), ['permissions']],
  ['perm-optional-permissions', (fx) => (fx.manifest.optional_permissions = ['downloads']), ['permissions']],
  ['perm-optional-host-permissions', (fx) => (fx.manifest.optional_host_permissions = ['*://*/*']), ['permissions']],
  ['perm-optional-not-array', (fx) => (fx.manifest.optional_permissions = 'tabs'), ['permissions']],
  [
    'ok-optional-permissions-empty',
    (fx) => {
      fx.manifest.optional_permissions = [];
      fx.manifest.optional_host_permissions = [];
    },
    [],
  ],
  ...MANIFEST_POLICY.forbiddenKeys.map((key) => [`key-${key}`, (fx) => (fx.manifest[key] = SAMPLE_KEY_VALUES[key] ?? []), ['manifest-keys']]),
  ['key-empty-host-permissions', (fx) => (fx.manifest.host_permissions = []), ['manifest-keys']],
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
  ['nav-set-uninstall-url', addJs('lib/x.js', 'chrome.runtime.setUninstallURL(chrome.runtime.getManifest().homepage_url);\n'), ['navigation']],
  ['nav-in-comment', addJs('lib/x.js', '// do not call window.open(url) here\n'), ['navigation']],

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
  // Duplicate paths after normalization: a wrong hash listed first and the right one last used
  // to pass, because the last entry silently won.
  ['vendor-sums-duplicate-line', editSums((text, hash) => `${text}${hash}  jsQR.js\n`), ['vendor-sums']],
  ['vendor-sums-duplicate-wrong-last', editSums((text) => `${text}${WRONG_HASH}  ./jsQR.js\n`), ['vendor-sums']],
  ['vendor-sums-duplicate-dot-slash', editSums((text) => `${WRONG_HASH}  ./jsQR.js\n${text}`), ['vendor-sums']],
  ['vendor-sums-duplicate-vendor-prefix', editSums((text) => `${WRONG_HASH} *vendor/jsQR.js\n${text}`), ['vendor-sums']],
  ['vendor-sums-duplicate-dot-segments', editSums((text, hash) => `${text}${hash}  sub/../jsQR.js\n`), ['vendor-sums']],
  ['vendor-sums-outside-vendor', editSums((text) => `${text}${WRONG_HASH}  ../manifest.json\n`), ['vendor-sums']],
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

function buildCase(dir, mutate) {
  const fx = cleanFixture();
  mutate(fx);
  const deferred = fx.sums === 'deferred';
  const comment = fx.sums === 'comment';
  if (deferred || comment) fx.sums = 'auto';
  writeFixture(dir, fx);
  const sumsFile = path.join(dir, SUMS_PATH);
  if (comment) {
    const sums = fs.readFileSync(sumsFile, 'utf8');
    fs.writeFileSync(sumsFile, `# jsQR, pinned upstream build\n${sums}`);
  }
  if (deferred) {
    // Same hashes, written in the other two standard sha256sum forms.
    const lines = fs
      .readFileSync(sumsFile, 'utf8')
      .trim()
      .split('\n')
      .map((l, i) => (i % 2 === 0 ? l.replace('  ', ' *') : l.replace('  ', '  ./')));
    fs.writeFileSync(sumsFile, `${lines.join('\r\n')}\r\n`);
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

    for (const [name, mutate, expected] of CASES) {
      const dir = path.join(root, name);
      buildCase(dir, mutate);
      const results = runChecks(dir);
      const failed = results.filter((r) => !r.ok).map((r) => r.rule);
      const missing = RULES.filter((rule) => !results.some((r) => r.rule === rule));
      const ok = missing.length === 0 && failed.length === expected.length && expected.every((rule) => failed.includes(rule));
      const why = results
        .filter((r) => !r.ok)
        .map((r) => `${r.rule}: ${r.detail}`)
        .join(' | ');
      report(ok, name, `expected FAIL [${expected.join(', ')}] got FAIL [${failed.join(', ')}]${why ? ` (${why})` : ''}`);
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
      const needle = ['allowedPermissions: [', "'storage', 'activeTab'", '],'].join('');
      const count = source.split(needle).length - 1;
      if (count !== 1) {
        report(false, 'cli-policy-edit-fails-self-test', `expected the MANIFEST_POLICY line ${JSON.stringify(needle)} exactly once, found ${count}`);
      } else {
        const widened = path.join(root, 'widened-policy.mjs');
        fs.writeFileSync(widened, source.replace(needle, needle.replace("'activeTab'", "'activeTab', 'tabs'")));
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
