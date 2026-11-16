import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse, format, normalize } from '../extension/lib/otpauth.js';

const SECRET = 'JBSWY3DPEHPK3PXP';

test('parse reads a full URI', () => {
  const uri = `otpauth://totp/ACME%20Co:john.doe@email.com?secret=${SECRET}&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60`;
  assert.deepEqual(parse(uri), {
    issuer: 'ACME Co', label: 'john.doe@email.com', secret: SECRET,
    algorithm: 'SHA256', digits: 8, period: 60,
  });
});

test('parse defaults algorithm, digits and period', () => {
  assert.deepEqual(parse(`otpauth://totp/Example:alice?secret=${SECRET}`), {
    issuer: 'Example', label: 'alice', secret: SECRET, algorithm: 'SHA1', digits: 6, period: 30,
  });
});

test('parse handles a label without an issuer prefix', () => {
  const account = parse(`otpauth://totp/alice@example.com?secret=${SECRET}`);
  assert.equal(account.issuer, '');
  assert.equal(account.label, 'alice@example.com');
  assert.equal(parse(`otpauth://totp/alice?secret=${SECRET}&issuer=Example`).issuer, 'Example');
});

test('parse accepts an issuer parameter that matches the label prefix', () => {
  const agree = parse(`otpauth://totp/Example:alice?secret=${SECRET}&issuer=Example`);
  assert.equal(agree.issuer, 'Example');
  assert.equal(agree.label, 'alice');
  const spaced = parse(`otpauth://totp/Big%20Bank%20:%20alice?secret=${SECRET}&issuer=Big+Bank`);
  assert.equal(spaced.issuer, 'Big Bank');
  assert.equal(spaced.label, 'alice');
  // An issuer containing ':' is matched as a whole before the first colon is considered.
  const colon = parse(`otpauth://totp/A%3AB:alice?secret=${SECRET}&issuer=A%3AB`);
  assert.equal(colon.issuer, 'A:B');
  assert.equal(colon.label, 'alice');
  // Either side empty is not a conflict.
  assert.equal(parse(`otpauth://totp/:alice?secret=${SECRET}&issuer=Example`).issuer, 'Example');
  assert.equal(parse(`otpauth://totp/Example:alice?secret=${SECRET}&issuer=`).issuer, 'Example');
  assert.equal(parse(`otpauth://totp/Example:alice?secret=${SECRET}&issuer=%20`).issuer, 'Example');
});

test('parse rejects an issuer parameter that disagrees with the label prefix', () => {
  for (const uri of [
    `otpauth://totp/Old%20Name:alice?secret=${SECRET}&issuer=New%20Name`,
    `otpauth://totp/Example:alice?secret=${SECRET}&issuer=example`,
    `otpauth://totp/Bank:alice?secret=${SECRET}&issuer=Evil`,
    `otpauth://totp/A:B:alice?secret=${SECRET}&issuer=B`,
  ]) {
    assert.throws(() => parse(uri), /Issuer .* does not match the label prefix/, uri);
  }
});

test('parse rejects duplicate secret, issuer, algorithm, digits and period parameters', () => {
  const base = `otpauth://totp/Example:alice?secret=${SECRET}&issuer=Example`;
  for (const extra of [
    `secret=${SECRET}`,
    'secret=GEZDGNBVGY3TQOJQ',
    'issuer=Example',
    'issuer=',
    'algorithm=SHA1&algorithm=SHA1',
    'digits=6&digits=8',
    'period=30&period=30',
    `%73ecret=${SECRET}`,
  ]) {
    assert.throws(() => parse(`${base}&${extra}`), /Duplicate (secret|issuer|algorithm|digits|period) parameter/, extra);
  }
  // Repeated unknown parameters are still ignored.
  assert.equal(parse(`${base}&image=a&image=b&counter=1&counter=2`).secret, SECRET);
});

test('parse rejects malformed percent-encoding in the query', () => {
  const base = `otpauth://totp/Example:alice?secret=${SECRET}`;
  for (const extra of [
    'issuer=Ex%ZZample',
    'issuer=%',
    'issuer=%4',
    'issuer=%E0%A4%A',
    'issuer=%C3',
    'image=%zz',
    'bad%key=1',
  ]) {
    assert.throws(() => parse(`${base}&${extra}`), /Malformed percent-encoding in query/, extra);
  }
  assert.throws(() => parse('otpauth://totp/Example:alice?secret=JBSW%Y3DPEHPK3PXP'), /Malformed percent-encoding in query/);
  // Well-formed escapes and parameters without '=' or empty pairs still parse.
  const account = parse(`${base}&issuer=Ex%61mple&image&&`);
  assert.equal(account.issuer, 'Example');
});

test('parse percent-decodes the label and trims space after the colon', () => {
  const account = parse(`otpauth://totp/Caf%C3%A9%3A%20bob%2Fwork?secret=${SECRET}`);
  assert.equal(account.issuer, 'Café');
  assert.equal(account.label, 'bob/work');
  assert.equal(parse(`otpauth://totp/Example:+alice?secret=${SECRET}`).label, '+alice');
  assert.equal(parse(`otpauth://totp/x?secret=${SECRET}&issuer=Big+Bank`).issuer, 'Big Bank');
});

test('parse normalizes the secret and is case-insensitive on scheme, type and algorithm', () => {
  const account = parse('OTPAUTH://TOTP/Example:alice?secret=jbsw%20y3dp+ehpk+3pxp%3D%3D&algorithm=sha512');
  assert.equal(account.secret, SECRET);
  assert.equal(account.algorithm, 'SHA512');
  assert.equal(parse(`otpauth://totp/a?secret=${SECRET}&algorithm=sha-256`).algorithm, 'SHA256');
  assert.equal(parse(`otpauth://totp/a?secret=${SECRET}&algorithm=Sha1`).algorithm, 'SHA1');
});

test('parse ignores unknown parameters, fragments and surrounding whitespace', () => {
  const account = parse(`  otpauth://totp/Example:alice?image=x.png&secret=${SECRET}&counter=5#frag \n`);
  assert.equal(account.secret, SECRET);
  assert.equal(account.label, 'alice');
});

test('parse accepts a URI with no label', () => {
  const account = parse(`otpauth://totp/?secret=${SECRET}&issuer=Example`);
  assert.equal(account.issuer, 'Example');
  assert.equal(account.label, '');
});

test('parse rejects HOTP URIs', () => {
  assert.throws(() => parse(`otpauth://hotp/Example:alice?secret=${SECRET}&counter=0`), /HOTP is not supported/);
  assert.throws(() => parse(`otpauth://HOTP/alice?secret=${SECRET}`), /HOTP is not supported/);
});

test('parse rejects other schemes and types', () => {
  for (const uri of [
    `otpauths://totp/a?secret=${SECRET}`,
    `steam://totp/a?secret=${SECRET}`,
    `otpauth:/totp/a?secret=${SECRET}`,
    SECRET,
    '',
  ]) {
    assert.throws(() => parse(uri), /Not an otpauth:\/\/ URI/, uri);
  }
  assert.throws(() => parse('otpauth-migration://offline?data=CjEKCkhlbGxv'), /otpauth-migration/);
  assert.throws(() => parse(`otpauth://yubi/a?secret=${SECRET}`), /Unsupported OTP type: yubi/);
  assert.throws(() => parse(`otpauth:///a?secret=${SECRET}`), /Unsupported OTP type/);
  assert.throws(() => parse(42), TypeError);
});

test('parse rejects a missing or invalid secret', () => {
  assert.throws(() => parse('otpauth://totp/Example:alice?issuer=Example'), /Missing secret/);
  assert.throws(() => parse('otpauth://totp/Example:alice?secret='), /Missing secret/);
  assert.throws(() => parse('otpauth://totp/Example:alice?secret=JBSW1Y3DP'), /Invalid secret/);
  assert.throws(() => parse('otpauth://totp/Example:alice?secret=JBSWY3'), /Invalid secret/);
});

test('parse rejects bad algorithm, digits and period', () => {
  const base = `otpauth://totp/a?secret=${SECRET}`;
  assert.throws(() => parse(`${base}&algorithm=MD5`), /Unsupported algorithm: MD5/);
  for (const digits of ['5', '9', '6.5', 'six', '-6']) {
    assert.throws(() => parse(`${base}&digits=${digits}`), /Invalid digits/, digits);
  }
  for (const period of ['0', '301', '30s', '1e2']) {
    assert.throws(() => parse(`${base}&period=${period}`), /Invalid period/, period);
  }
});

test('parse rejects malformed percent-encoding in the label', () => {
  assert.throws(() => parse(`otpauth://totp/bad%E0%A4%A?secret=${SECRET}`), /Malformed percent-encoding/);
});

test('format writes every parameter', () => {
  const uri = format({ issuer: 'ACME Co', label: 'john@example.com', secret: 'jbsw y3dp ehpk 3pxp' });
  assert.equal(
    uri,
    `otpauth://totp/ACME%20Co:john%40example.com?secret=${SECRET}&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30`,
  );
  assert.equal(
    format({ label: 'solo', secret: SECRET, algorithm: 'SHA512', digits: 8, period: 60 }),
    `otpauth://totp/solo?secret=${SECRET}&algorithm=SHA512&digits=8&period=60`,
  );
});

test('format round-trips through parse', () => {
  const awkward = ['', 'plain', 'a:b', ':lead', 'trail:', 'x/y?z#w&v=u', 'p+q%r', 'two  spaces', 'Café 東京 🔐', 'A:B:C'];
  for (const issuer of awkward) {
    for (const label of awkward) {
      const account = { issuer, label, secret: SECRET, algorithm: 'SHA256', digits: 7, period: 45 };
      const uri = format(account);
      assert.deepEqual(parse(uri), normalize(account), uri);
      assert.equal(format(parse(uri)), uri, uri);
    }
  }
});

test('format drops extra properties such as id and createdAt', () => {
  const uri = format({ id: 'x1', createdAt: 1, issuer: 'Example', label: 'alice', secret: SECRET });
  assert.ok(!uri.includes('x1') && !uri.includes('createdAt'), uri);
});

test('normalize applies defaults and canonical forms for manual entry', () => {
  assert.deepEqual(normalize({ issuer: '  Example ', label: ' alice ', secret: 'jbsw-y3dp ehpk-3pxp==' }), {
    issuer: 'Example', label: 'alice', secret: SECRET, algorithm: 'SHA1', digits: 6, period: 30,
  });
  assert.deepEqual(
    normalize({ secret: SECRET, algorithm: 'sha256', digits: '8', period: ' 60 ' }),
    { issuer: '', label: '', secret: SECRET, algorithm: 'SHA256', digits: 8, period: 60 },
  );
  assert.deepEqual(
    normalize({ secret: SECRET, algorithm: '', digits: '', period: null }),
    { issuer: '', label: '', secret: SECRET, algorithm: 'SHA1', digits: 6, period: 30 },
  );
});

test('normalize rejects bad input', () => {
  assert.throws(() => normalize({ label: 'alice' }), /Missing secret/);
  assert.throws(() => normalize({ secret: '   ' }), /Missing secret/);
  assert.throws(() => normalize({ secret: 'JBSW1' }), /Invalid secret/);
  assert.throws(() => normalize({ secret: SECRET, algorithm: 'SHA384' }), /Unsupported algorithm/);
  assert.throws(() => normalize({ secret: SECRET, digits: 10 }), /Invalid digits/);
  assert.throws(() => normalize({ secret: SECRET, digits: 6.5 }), /Invalid digits/);
  assert.throws(() => normalize({ secret: SECRET, period: 0 }), /Invalid period/);
  assert.throws(() => normalize(null), TypeError);
});
