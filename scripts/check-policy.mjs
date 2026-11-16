#!/usr/bin/env node
// Static trust gate for extension/ (npm run check). Rules: .prd/02-architecture.md "Trust gate",
// tightened by MANIFEST_POLICY and the pattern lists below.
//
//   node scripts/check-policy.mjs                 # check ./extension
//   node scripts/check-policy.mjs --ext <dir>     # check another extension dir
//   node scripts/check-policy.mjs --self-test     # prove every rule catches its violation
//
// Prints one `PASS|FAIL <rule> <detail>` line per rule and exits 1 on any FAIL.
// The gate is a tripwire for the repository's own sources; the extension-page CSP
// (connect-src 'none', script-src 'self') is what enforces zero network at runtime.

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

function findAll(text, patterns, label) {
  const hits = [];
  for (const [name, re] of patterns) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const line = text.slice(0, m.index).split('\n').length;
      hits.push(`${label}:${line} ${name}`);
    }
  }
  return hits;
}

function parseCsp(policy) {
  const directives = new Map();
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    if (!directives.has(name)) directives.set(name, tokens.slice(1)); // first occurrence wins (CSP3)
  }
  return directives;
}

function sha256(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function inlineScriptHits(html, label) {
  const hits = [];
  const lineOf = (index) => html.slice(0, index).split('\n').length;
  for (const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)) {
    if (m[1].trim() !== '') hits.push(`${label}:${lineOf(m.index)} inline <script> body`);
  }
  for (const m of html.matchAll(/<[a-zA-Z][^>]*>/g)) {
    const attr = m[0].match(/\s(on[a-z]+)\s*=/i);
    if (attr) hits.push(`${label}:${lineOf(m.index)} ${attr[1]}= attribute`);
  }
  return hits;
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
      const name = m[2].replace(/^\.\//, '').replace(/^vendor\//, '');
      listed.set(`vendor/${name}`, { hash: m[1].toLowerCase(), line: i + 1 });
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
  return [true, `${vendorFiles.length} vendored files match SHA256SUMS`];
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
    if (csp === null || typeof csp !== 'object' || typeof csp.extension_pages !== 'string') {
      cspProblems.push('content_security_policy.extension_pages missing');
    } else {
      const pages = parseCsp(csp.extension_pages);
      const connect = pages.get('connect-src');
      if (!connect || connect.length !== 1 || connect[0] !== "'none'") cspProblems.push(`connect-src is ${connect ? connect.join(' ') : 'missing'} (need 'none')`);
      const script = pages.get('script-src');
      if (!script || !script.includes("'self'")) cspProblems.push(`script-src is ${script ? script.join(' ') : 'missing'} (need 'self')`);
      for (const [key, value] of Object.entries(csp)) {
        if (typeof value !== 'string') continue;
        for (const token of FORBIDDEN_CSP_TOKENS) {
          if (value.toLowerCase().includes(token)) cspProblems.push(`${key} contains ${token}`);
        }
      }
    }
    record('csp', cspProblems.length === 0, cspProblems.length === 0 ? "connect-src 'none'; script-src 'self'; no unsafe-*" : cspProblems.join('; '));
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

  const scanned = files.filter((f) => f.kind === 'file' && !f.rel.startsWith('vendor/') && /\.(js|html)$/.test(f.rel));
  const network = [];
  const dynamic = [];
  const urls = [];
  const inline = [];
  for (const f of scanned) {
    const text = fs.readFileSync(f.abs, 'utf8');
    network.push(...findAll(text, NETWORK_PATTERNS, label(f.rel)));
    dynamic.push(...findAll(text, DYNAMIC_CODE_PATTERNS, label(f.rel)));
    urls.push(...findAll(text, URL_PATTERNS, label(f.rel)));
    if (f.rel.endsWith('.html')) inline.push(...inlineScriptHits(text, label(f.rel)));
  }
  const htmlCount = scanned.filter((f) => f.rel.endsWith('.html')).length;
  const scope = `${scanned.length} .js/.html files outside vendor/`;
  record('network-api', network.length === 0, network.length === 0 ? `none in ${scope}` : network.join('; '));
  record('dynamic-code', dynamic.length === 0, dynamic.length === 0 ? `none in ${scope}` : dynamic.join('; '));
  record('remote-url', urls.length === 0, urls.length === 0 ? `no http(s):// in ${scope}` : urls.join('; '));
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
// Self-test: one clean fixture, negative controls that must stay clean, and one fixture per
// violation that must fail exactly the expected rule(s).

const ONE_PIXEL_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
);

function cleanFixture() {
  return {
    manifest: {
      manifest_version: 3,
      name: 'zauthenticator',
      version: '0.1.0',
      permissions: ['storage', 'activeTab'],
      action: { default_popup: 'popup/popup.html' },
      content_security_policy: {
        extension_pages:
          "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      },
    },
    files: {
      'lib/base32.js': "export function decode(str) { return new Uint8Array(str.length); }\n",
      'lib/totp.js':
        "// RFC 6238 over WebCrypto\nexport async function hotp(key) {\n  return crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);\n}\n",
      'lib/store.js': "export async function load() { return chrome.storage.local.get('vault'); }\n",
      'lib/qr.js': "import jsQR from '../vendor/jsQR.js';\nexport function decode(img) { return jsQR(img.data, img.width, img.height); }\n",
      'popup/popup.html':
        '<!doctype html>\n<html>\n<head><meta charset="utf-8"><link rel="stylesheet" href="popup.css"></head>\n<body data-state="setup">\n<button id="lock-btn" type="button">Lock</button>\n<script type="module" src="popup.js"></script>\n</body>\n</html>\n',
      'popup/popup.css': 'body { font: 13px system-ui; }\n',
      'popup/popup.js': "document.getElementById('lock-btn').addEventListener('click', () => {});\n",
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
const CLEAN_CSP = cleanFixture().manifest.content_security_policy.extension_pages;
const addJs = (rel, code) => (fx) => {
  fx.files[rel] = code;
};

// [name, mutate(fixture), expected failing rules]
const CASES = [
  ['clean', () => {}, []],
  ['ok-homepage-exact', (fx) => (fx.manifest.homepage_url = HOMEPAGE_URL), []],
  ['ok-vendor-exempt-from-scan', addJs('vendor/jsQR.js', "fetch('https://x.test/'); eval('1'); new WebSocket('wss://x');\n"), []],
  ['ok-word-boundaries', addJs('lib/words.js', '// prefetch(x) retrieval(y) refetch(z)\nconst fetched = 1; const evaluate = () => 0;\n'), []],
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
  ['csp-absent', (fx) => delete fx.manifest.content_security_policy, ['csp']],
  ['csp-no-connect-src', setCsp(CLEAN_CSP.replace("connect-src 'none'; ", '')), ['csp']],
  ['csp-connect-self', setCsp(CLEAN_CSP.replace("connect-src 'none'", "connect-src 'self'")), ['csp']],
  ['csp-no-script-self', setCsp(CLEAN_CSP.replace("script-src 'self'; ", '')), ['csp']],
  ['csp-unsafe-eval', setCsp(CLEAN_CSP.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'")), ['csp']],
  ['csp-unsafe-inline', setCsp(CLEAN_CSP.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")), ['csp']],
  ['csp-wasm-unsafe-eval', setCsp(CLEAN_CSP.replace("script-src 'self'", "script-src 'self' 'wasm-unsafe-eval'")), ['csp']],
  [
    'csp-sandbox-unsafe-eval',
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
  [
    'net-fetch-in-html',
    (fx) => (fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('</body>', '<!-- fetch(x) -->\n</body>')),
    ['network-api'],
  ],
  ['dyn-eval', addJs('lib/x.js', "export const v = eval('1 + 1');\n"), ['dynamic-code']],
  ['dyn-new-function', addJs('lib/x.js', "export const v = new Function('return 1');\n"), ['dynamic-code']],
  ['dyn-importscripts', addJs('lib/x.js', "importScripts('a.js');\n"), ['dynamic-code']],
  ['dyn-javascript-url-js', addJs('lib/x.js', "link.href = 'javascript:void 0';\n"), ['dynamic-code']],
  [
    'dyn-javascript-url-html',
    (fx) => (fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('</body>', '<a href="JavaScript:void 0">x</a>\n</body>')),
    ['dynamic-code'],
  ],
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
  [
    'url-http-html',
    (fx) => (fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('</body>', '<img src="http://example.com/a.png">\n</body>')),
    ['remote-url'],
  ],
  [
    'inline-script-body',
    (fx) => (fx.files['popup/popup.html'] = fx.files['popup/popup.html'].replace('</body>', '<script>document.title = 1;</script>\n</body>')),
    ['inline-script'],
  ],
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
  if (comment) {
    const sums = fs.readFileSync(path.join(dir, SUMS_PATH), 'utf8');
    fs.writeFileSync(path.join(dir, SUMS_PATH), `# jsQR, pinned upstream build\n${sums}`);
  }
  if (deferred) {
    // Same hashes, written in the other two standard sha256sum forms.
    const lines = fs
      .readFileSync(path.join(dir, SUMS_PATH), 'utf8')
      .trim()
      .split('\n')
      .map((l, i) => (i % 2 === 0 ? l.replace('  ', ' *') : l.replace('  ', '  ./')));
    fs.writeFileSync(path.join(dir, SUMS_PATH), `${lines.join('\r\n')}\r\n`);
  }
  if (fx.tamper) {
    // Applied after SHA256SUMS was written, so the listed hashes describe the original files.
    const [rel, content] = fx.tamper;
    if (content === null) fs.rmSync(path.join(dir, rel));
    else fs.writeFileSync(path.join(dir, rel), content);
  }
}

function runCli(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });
}

function selfTest() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zauth-policy-selftest-'));
  let failures = 0;
  const report = (ok, name, detail) => {
    if (!ok) failures += 1;
    console.log(`${ok ? 'PASS' : 'FAIL'} self-test:${name} ${detail}`);
  };
  try {
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
    const clean = runCli(['--ext', path.join(root, 'clean')]);
    const cleanLines = clean.stdout.trim().split('\n');
    report(
      clean.status === 0 && cleanLines.length === RULES.length && cleanLines.every((l) => l.startsWith('PASS ')),
      'cli-clean',
      `exit ${clean.status}, ${cleanLines.length} PASS lines`,
    );
    const bad = runCli(['--ext', path.join(root, 'net-fetch')]);
    report(
      bad.status === 1 && bad.stdout.split('\n').some((l) => l.startsWith('FAIL network-api ')),
      'cli-violation',
      `exit ${bad.status}, ${bad.stdout.split('\n').find((l) => l.startsWith('FAIL')) ?? '(no FAIL line)'}`,
    );
    const absent = runCli(['--ext', path.join(root, 'does-not-exist')]);
    report(
      absent.status === 1 && /^FAIL extension-dir /.test(absent.stdout) && absent.stderr.trim() === '',
      'cli-missing-extension',
      `exit ${absent.status}, ${absent.stdout.trim().replace(root, '<tmp>')}, stderr ${JSON.stringify(absent.stderr.trim())}`,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  const total = CASES.length + 3;
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
