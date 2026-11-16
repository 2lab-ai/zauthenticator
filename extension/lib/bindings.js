// Auto-fill bindings: which account's code a web origin gets. They live inside the vault data
// (so they are encrypted with it) as
//   data.bindings = [ { origin, accountId, createdAt } ]
// origin is an exact origin as URL.origin gives it, scheme https only (host lowercased and
// punycoded, the port only when it is not 443); accountId is the id of an entry in data.accounts.
//
// Pure functions; none changes its input. Only a hand-edited vault holds anything else in the
// list: an entry that is not a well-formed binding (or repeats an earlier entry's origin) is
// ignored by every read and kept as stored by every write, like a malformed account entry. A
// bindings value that is not a list reads as no bindings and is replaced only by withBinding().

// → the origin of url ('https:' scheme, host, and port when it is not 443), or null for anything
// else: another scheme, an unparsable or relative URL, an opaque origin. Path, query, fragment
// and user info are dropped. url is a string or a URL.
export function normalizeOrigin(url) {
  if (typeof url !== 'string' && !(url instanceof URL)) return null;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:') return null;
  const origin = parsed.origin;
  return typeof origin === 'string' && origin !== 'null' ? origin : null;
}

// → the well-formed bindings, as copies, the first one for each origin.
export function bindingsOf(data) {
  const out = [];
  const seen = new Set();
  for (const entry of list(data)) {
    if (!isBinding(entry) || seen.has(entry.origin)) continue;
    seen.add(entry.origin);
    out.push(copy(entry));
  }
  return out;
}

// → new data where origin is bound to accountId (any earlier binding of origin is replaced).
// origin must be exactly what normalizeOrigin() returns for it: a URL with a path, another
// scheme or a non-canonical spelling is refused, never widened. Throws TypeError.
export function withBinding(data, origin, accountId, now = Date.now()) {
  if (!isOrigin(origin)) throw new TypeError('withBinding: origin must be an https origin');
  if (!isId(accountId)) throw new TypeError('withBinding: accountId must be a non-empty string');
  const kept = list(data).filter((entry) => !(isBinding(entry) && entry.origin === origin));
  return { ...base(data), bindings: [...kept, { origin, accountId, createdAt: now }] };
}

// → new data without the binding of origin. origin may be any URL of that origin.
export function withoutBinding(data, origin) {
  const key = normalizeOrigin(origin);
  return without(data, (entry) => key !== null && entry.origin === key);
}

// → new data without any binding to accountId.
export function withoutAccountBindings(data, accountId) {
  return without(data, (entry) => entry.accountId === accountId);
}

// → the binding of origin (a copy) or null. origin may be any URL of that origin; only the exact
// origin matches (a subdomain, another port or scheme does not). Does not check that the bound
// account still exists.
export function bindingFor(data, origin) {
  const key = normalizeOrigin(origin);
  if (key === null) return null;
  return bindingsOf(data).find((entry) => entry.origin === key) ?? null;
}

// → the bound origins whose account exists, sorted, each once.
export function boundOrigins(data) {
  const ids = new Set(accountsOf(data).map((entry) => entry.id).filter(isId));
  return bindingsOf(data)
    .filter((entry) => ids.has(entry.accountId))
    .map((entry) => entry.origin)
    .sort();
}

function without(data, match) {
  const next = base(data);
  if (Array.isArray(next.bindings)) {
    next.bindings = next.bindings.filter((entry) => !(isBinding(entry) && match(entry)));
  }
  return next;
}

// A shallow copy of data (an empty object when data is not one).
function base(data) {
  return isObject(data) ? { ...data } : {};
}

function list(data) {
  return isObject(data) && Array.isArray(data.bindings) ? data.bindings : [];
}

function accountsOf(data) {
  return isObject(data) && Array.isArray(data.accounts) ? data.accounts.filter(isObject) : [];
}

function isBinding(entry) {
  return isObject(entry) && isOrigin(entry.origin) && isId(entry.accountId);
}

function copy(entry) {
  return {
    origin: entry.origin,
    accountId: entry.accountId,
    createdAt: Number.isFinite(entry.createdAt) ? entry.createdAt : null,
  };
}

// → true for a string that is exactly an origin normalizeOrigin() returns.
function isOrigin(value) {
  return typeof value === 'string' && normalizeOrigin(value) === value;
}

function isId(value) {
  return typeof value === 'string' && value !== '';
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
