import { test } from 'node:test';
import assert from 'node:assert/strict';
import { submitEdgeUpdate, certificationNotes } from '../scripts/edge-submit.mjs';

const PRODUCT = 'd34f98f5-f9b7-42b1-bebb-98707202b21d';
const ROOT = 'https://api.addons.microsoftedge.microsoft.com';

function response(status, body, headers = {}) {
  const payload = body === undefined ? null : JSON.stringify(body);
  return new Response(payload, { status, headers });
}

test('does not call the network when a credential is missing', async () => {
  let called = false;
  const result = await submitEdgeUpdate({
    clientId: '',
    apiKey: 'key',
    productId: PRODUCT,
    zip: new Uint8Array([1, 2, 3]),
    notes: 'notes',
    fetchImpl: async () => {
      called = true;
      throw new Error('network');
    },
  });
  assert.equal(result.skipped, true);
  assert.equal(called, false);
});

test('uploads the zip, then publishes, polling each operation to Succeeded', async () => {
  const calls = [];
  const script = [
    () => response(202, undefined, { location: `${ROOT}/v1/products/${PRODUCT}/submissions/draft/package/operations/op-upload` }),
    () => response(200, { status: 'InProgress', id: 'op-upload' }),
    () => response(200, { status: 'Succeeded', message: 'Successfully updated package to z.zip', errorCode: '', errors: null }),
    () => response(202, undefined, { location: 'op-publish' }),
    () => response(200, { status: 'Succeeded', message: 'Successfully created submission with ID sub-1', errorCode: '', errors: null }),
  ];
  const result = await submitEdgeUpdate({
    clientId: 'client',
    apiKey: 'secret-key',
    productId: PRODUCT,
    zip: new Uint8Array([9, 8, 7]),
    notes: 'how to test',
    pollMs: 0,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      const next = script.shift();
      assert.ok(next, `unexpected call ${url}`);
      return next();
    },
  });

  assert.equal(result.skipped, false);
  assert.equal(result.outcome, 'submitted');
  assert.equal(script.length, 0);

  const upload = calls[0];
  assert.equal(upload.url, `${ROOT}/v1/products/${PRODUCT}/submissions/draft/package`);
  assert.equal(upload.init.method, 'POST');
  assert.equal(upload.init.headers.Authorization, 'ApiKey secret-key');
  assert.equal(upload.init.headers['X-ClientID'], 'client');
  assert.equal(upload.init.headers['Content-Type'], 'application/zip');
  assert.deepEqual(new Uint8Array(upload.init.body), new Uint8Array([9, 8, 7]));

  assert.equal(calls[1].url, `${ROOT}/v1/products/${PRODUCT}/submissions/draft/package/operations/op-upload`);
  assert.equal(calls[1].init.method, 'GET');

  const publish = calls[3];
  assert.equal(publish.url, `${ROOT}/v1/products/${PRODUCT}/submissions`);
  assert.equal(publish.init.method, 'POST');
  assert.equal(publish.init.headers['Content-Type'], 'application/x-www-form-urlencoded;charset=UTF-8');
  assert.equal(publish.init.body, 'notes=how+to+test');
  assert.equal(calls[4].url, `${ROOT}/v1/products/${PRODUCT}/submissions/operations/op-publish`);
});

test('a Failed publish names the API error code', async () => {
  const script = [
    () => response(202, undefined, { location: 'op-upload' }),
    () => response(200, { status: 'Succeeded', message: 'ok', errorCode: '', errors: null }),
    () => response(202, undefined, { location: 'op-publish' }),
    () => response(200, {
      status: 'Failed',
      message: 'Can\'t publish extension as your extension submission is in progress. Please try again later.',
      errorCode: 'InProgressSubmission',
      errors: null,
    }),
  ];
  await assert.rejects(
    () => submitEdgeUpdate({
      clientId: 'client',
      apiKey: 'key',
      productId: PRODUCT,
      zip: new Uint8Array([1]),
      notes: 'notes',
      pollMs: 0,
      fetchImpl: async () => script.shift()(),
    }),
    (err) => err.code === 'InProgressSubmission' && /in progress/i.test(err.message),
  );
});

test('certification notes keep the tester steps and name this version', () => {
  const template = [
    'Changed in 0.3.0: optional passkey unlock.',
    '',
    'How to test:',
    '1. Click the toolbar icon.',
  ].join('\n');
  const notes = certificationNotes(template, '0.4.0');
  assert.match(notes, /^Changed in 0\.4\.0: /);
  assert.match(notes, /How to test:\n1\. Click the toolbar icon\./);
  assert.doesNotMatch(notes, /0\.3\.0/);
});

test('certification notes refuse a body over 2000 characters', () => {
  const template = `Changed in 0.3.0: x\n${'a'.repeat(1990)}`;
  assert.throws(() => certificationNotes(template, '0.3.0'), /2000/);
});
