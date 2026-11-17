// WebAuthn is confined to this module. No ceremony result is persisted here.
export class PasskeyError extends Error {
  constructor(code, orphan = false) {
    super(code);
    this.code = code;
    this.orphan = orphan;
  }
}

export async function support() {
  try {
    if (typeof PublicKeyCredential === 'undefined') return 'no';
    if (typeof PublicKeyCredential.getClientCapabilities !== 'function') return 'unknown';
    return (await PublicKeyCredential.getClientCapabilities())['extension:prf'] === true ? 'yes' : 'no';
  } catch {
    return 'unknown';
  }
}

function validBytes(value, min, max) {
  return value instanceof Uint8Array && value.length >= min && value.length <= max;
}

function bytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return null;
}

function equal(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function output(credential) {
  const value = bytes(credential?.getClientExtensionResults?.()?.prf?.results?.first);
  if (!value || value.length !== 32) throw new PasskeyError('no-prf');
  return new Uint8Array(value);
}

function assertion(credential, expected) {
  const id = bytes(credential?.rawId);
  const data = bytes(credential?.response?.authenticatorData);
  if (!id || !equal(id, expected) || !data || data.length < 37 || !(data[32] & 4)) {
    throw new PasskeyError('failed');
  }
  return output(credential);
}

function mapped(error, orphan = false) {
  const code = error instanceof PasskeyError ? error.code :
    error?.name === 'NotAllowedError' || error?.name === 'TimeoutError' ? 'cancelled' : 'failed';
  return new PasskeyError(code, orphan);
}

export async function enrollCeremony({ prfSalt } = {}) {
  if (!validBytes(prfSalt, 32, 32)) throw new PasskeyError('failed');
  let orphan = false;
  try {
    let platform = true;
    try {
      if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
        platform = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      }
    } catch { platform = false; }
    const selection = { residentKey: 'required', userVerification: 'required' };
    if (!platform) selection.authenticatorAttachment = 'cross-platform';
    const created = await navigator.credentials.create({ publicKey: {
      rp: { name: 'zauthenticator' },
      user: { id: crypto.getRandomValues(new Uint8Array(32)), name: 'vault', displayName: 'Vault' },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [-8, -7, -257].map((alg) => ({ type: 'public-key', alg })),
      authenticatorSelection: selection,
      hints: ['hybrid', 'security-key'],
      extensions: { prf: { eval: { first: prfSalt } } },
      timeout: 120000,
    } });
    orphan = Boolean(created);
    const id = bytes(created?.rawId);
    if (!id || !validBytes(id, 1, 1023)) throw new PasskeyError('failed');
    const cred = new Uint8Array(id);
    const createdOutput = bytes(created.getClientExtensionResults?.()?.prf?.results?.first);
    if (createdOutput && createdOutput.length !== 32) throw new PasskeyError('no-prf');
    const prf = await unlockCeremony({ credBytes: cred, prfSalt });
    if (createdOutput && !equal(createdOutput, prf)) throw new PasskeyError('mismatch');
    return { cred, prf };
  } catch (error) {
    throw mapped(error, orphan);
  }
}

export async function unlockCeremony({ credBytes, prfSalt } = {}) {
  if (!validBytes(credBytes, 1, 1023) || !validBytes(prfSalt, 32, 32)) throw new PasskeyError('failed');
  try {
    const credential = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credBytes }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: prfSalt } } },
      timeout: 120000,
    } });
    return assertion(credential, credBytes);
  } catch (error) {
    throw mapped(error);
  }
}
