#!/usr/bin/env node
// Submit an already-published Edge Add-ons package for review.
//
// Microsoft Edge Add-ons Update REST API v1.1 (API key + client id):
//   https://learn.microsoft.com/en-us/microsoft-edge/extensions/update/api/using-addons-api
// The API uploads a zip onto the existing product and asks Partner Center to start review.
// It cannot create a product, and it cannot change listing text, screenshots or privacy fields.
// "Succeeded" means the submission was created (In review), not that the store is serving it.
//
//   EDGE_ADDONS_CLIENT_ID / EDGE_ADDONS_API_KEY / EDGE_ADDONS_PRODUCT_ID
//   node scripts/edge-submit.mjs dist/zauthenticator-<version>.zip
//
// A missing credential prints EDGE_SUBMIT=skipped and exits 0, so a tag release still publishes
// the GitHub zip before the one-time Partner Center API setup exists.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ENDPOINT = 'https://api.addons.microsoftedge.microsoft.com';
const NOTES_LIMIT = 2000;

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function certificationNotes(template, version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error(`version must be MAJOR.MINOR.PATCH, got ${version}`);
  }
  const text = String(template).replace(/\r\n/g, '\n');
  const nl = text.indexOf('\n');
  const rest = nl === -1 ? '' : text.slice(nl + 1);
  const notes = `Changed in ${version}: package built from git tag v${version}.\n${rest}`;
  if (notes.length > NOTES_LIMIT) {
    throw new Error(`certification notes are ${notes.length} characters (limit ${NOTES_LIMIT})`);
  }
  return notes;
}

function operationId(location) {
  const value = String(location ?? '').trim();
  if (!value) throw new Error('Edge API response had no Location header');
  const parts = value.split('/').filter(Boolean);
  return decodeURIComponent(parts[parts.length - 1]);
}

function authHeaders(clientId, apiKey) {
  return {
    Authorization: `ApiKey ${apiKey}`,
    'X-ClientID': clientId,
  };
}

async function readJson(res) {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Edge API returned non-JSON (${res.status}): ${text.slice(0, 300)}`);
  }
}

function fail(body, fallback) {
  const err = new Error(body.message || fallback);
  err.code = body.errorCode || 'Failed';
  if (body.errors) err.errors = body.errors;
  return err;
}

async function pollOperation(url, headers, { fetchImpl, pollMs, deadline, sleep }) {
  for (;;) {
    const res = await fetchImpl(url, { method: 'GET', headers });
    const body = await readJson(res);
    if (!res.ok && res.status !== 202) throw fail(body, `Edge API status ${res.status}`);
    if (body.status === 'InProgress') {
      if (Date.now() > deadline) throw new Error(`Edge API operation still InProgress at ${url}`);
      await sleep(pollMs);
      continue;
    }
    if (body.status === 'Succeeded') return body;
    throw fail(body, `Edge API operation ${body.status || res.status}`);
  }
}

export async function submitEdgeUpdate({
  clientId,
  apiKey,
  productId,
  zip,
  notes,
  fetchImpl = globalThis.fetch,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  pollMs = 5000,
  deadlineMs = 12 * 60 * 1000,
  endpoint = ENDPOINT,
}) {
  if (![clientId, apiKey, productId].every((v) => String(v ?? '').trim())) {
    return { skipped: true, outcome: 'skipped' };
  }
  if (typeof notes !== 'string' || notes.length === 0) throw new Error('certification notes are empty');
  if (notes.length > NOTES_LIMIT) {
    throw new Error(`certification notes are ${notes.length} characters (limit ${NOTES_LIMIT})`);
  }

  const auth = authHeaders(clientId.trim(), apiKey.trim());
  const product = productId.trim();
  const deadline = Date.now() + deadlineMs;
  const root = `${endpoint}/v1/products/${product}`;

  const upload = await fetchImpl(`${root}/submissions/draft/package`, {
    method: 'POST',
    headers: { ...auth, 'Content-Type': 'application/zip' },
    body: zip,
  });
  if (upload.status !== 202) {
    throw fail(await readJson(upload), `Edge package upload returned ${upload.status}`);
  }
  const uploadId = operationId(upload.headers.get('location'));
  await pollOperation(`${root}/submissions/draft/package/operations/${uploadId}`, auth, {
    fetchImpl, pollMs, deadline, sleep,
  });

  const form = new URLSearchParams({ notes });
  const publish = await fetchImpl(`${root}/submissions`, {
    method: 'POST',
    headers: { ...auth, 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
    body: form.toString(),
  });
  if (publish.status !== 202) {
    throw fail(await readJson(publish), `Edge publish returned ${publish.status}`);
  }
  const publishId = operationId(publish.headers.get('location'));
  const published = await pollOperation(`${root}/submissions/operations/${publishId}`, auth, {
    fetchImpl, pollMs, deadline, sleep,
  });
  return { skipped: false, outcome: 'submitted', message: published.message || '' };
}

async function main() {
  const zipPath = process.argv[2];
  const clientId = process.env.EDGE_ADDONS_CLIENT_ID;
  const apiKey = process.env.EDGE_ADDONS_API_KEY;
  const productId = process.env.EDGE_ADDONS_PRODUCT_ID;
  if (![clientId, apiKey, productId].every((v) => String(v ?? '').trim())) {
    console.log('EDGE_SUBMIT=skipped missing EDGE_ADDONS_CLIENT_ID, EDGE_ADDONS_API_KEY or EDGE_ADDONS_PRODUCT_ID');
    return;
  }
  if (!zipPath) {
    console.error('usage: node scripts/edge-submit.mjs <zip>');
    process.exitCode = 1;
    return;
  }
  const version = process.env.VERSION
    || JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'extension/manifest.json'), 'utf8')).version;
  const template = fs.readFileSync(path.join(REPO_ROOT, 'store/listing/edge-certification-notes.txt'), 'utf8');
  const notes = certificationNotes(template, version);
  const zip = fs.readFileSync(zipPath);
  const result = await submitEdgeUpdate({ clientId, apiKey, productId, zip, notes });
  console.log(`EDGE_SUBMIT=${result.outcome} ${result.message || ''}`.trim());
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`EDGE_SUBMIT=failed ${err.code || ''} ${err.message}`.trim());
    process.exitCode = 1;
  });
}
