/**
 * AEAD Encrypted Disclosures (draft-ietf-spice-sd-cwt-08, Section 13)
 *
 * A Holder MAY encrypt some of the Salted Disclosed Claims it presents, moving
 * them from `sd_claims` (17) to `sd_aead_encrypted_claims` (171). Each entry is
 *
 *   [ nonce, ciphertext, tag, ? aead-key-context ]
 *
 * The plaintext is the CBOR encoding of `bstr .cbor salted-entry` -- the byte
 * string header included -- which is exactly what the Redacted Claim Hash is
 * computed over. The associated data is zero-length. The algorithm is the
 * `sd_aead` (172) protected header of the SD-CWT if present, otherwise
 * AEAD_AES_128_GCM.
 *
 * AES-GCM runs on Web Crypto, so it works in Node and in the browser bundle.
 * ChaCha20-Poly1305 has no Web Crypto binding and is only available in Node.
 */

import * as cbor from 'cbor2';
import crypto from 'node:crypto';
import { cborDecodeOptions } from './sd-cwt.js';

/**
 * AEAD algorithm identifiers from the IANA "AEAD Algorithms" registry.
 */
export const AeadAlgorithm = {
  AES_128_GCM: 1,
  AES_256_GCM: 2,
  CHACHA20_POLY1305: 29,
};

/**
 * Parameters per supported algorithm. Section 15.2: implementations MUST NOT
 * use an AEAD algorithm with a tag shorter than 16 octets, so anything not
 * listed here is refused rather than guessed at.
 */
const PARAMS = {
  [AeadAlgorithm.AES_128_GCM]: { keyLength: 16, nonceLength: 12, tagLength: 16, kind: 'aes-gcm' },
  [AeadAlgorithm.AES_256_GCM]: { keyLength: 32, nonceLength: 12, tagLength: 16, kind: 'aes-gcm' },
  [AeadAlgorithm.CHACHA20_POLY1305]: { keyLength: 32, nonceLength: 12, tagLength: 16, kind: 'chacha20-poly1305' },
};

/** The default when `sd_aead` (172) is absent. */
export const DEFAULT_AEAD_ALGORITHM = AeadAlgorithm.AES_128_GCM;

const EMPTY = new Uint8Array(0);

function toBytes(data) {
  if (data instanceof Uint8Array) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  throw new Error('Expected bytes');
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Returns the parameters for an AEAD algorithm, or throws if unsupported.
 *
 * @param {number} algorithm - IANA AEAD algorithm identifier
 * @returns {{keyLength: number, nonceLength: number, tagLength: number, kind: string}}
 */
export function getAeadParams(algorithm) {
  const params = PARAMS[algorithm];
  if (!params) {
    throw new Error(
      `Unsupported AEAD algorithm ${JSON.stringify(algorithm)}; supported: ` +
      `${Object.keys(PARAMS).join(', ')} (Section 15.2 forbids tags shorter than 16 octets)`
    );
  }
  return params;
}

/**
 * Resolves the AEAD algorithm from an SD-CWT's protected headers.
 *
 * @param {Map} protectedHeaders - SD-CWT protected headers
 * @returns {number} The `sd_aead` (172) value, or AEAD_AES_128_GCM if absent
 */
export function aeadAlgorithmFromHeaders(protectedHeaders) {
  const value = protectedHeaders instanceof Map ? protectedHeaders.get(172) : undefined;
  return value === undefined ? DEFAULT_AEAD_ALGORITHM : value;
}

function checkKey(key, params) {
  const keyBytes = toBytes(key);
  if (keyBytes.length !== params.keyLength) {
    throw new Error(`AEAD key must be ${params.keyLength} octets, got ${keyBytes.length}`);
  }
  return keyBytes;
}

function getSubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error('Web Crypto (crypto.subtle) is required for AES-GCM');
  }
  return subtle;
}

async function seal(params, key, nonce, plaintext) {
  if (params.kind === 'aes-gcm') {
    const subtle = getSubtle();
    const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    const sealed = new Uint8Array(await subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: EMPTY, tagLength: params.tagLength * 8 },
      cryptoKey,
      plaintext
    ));
    const split = sealed.length - params.tagLength;
    return { ciphertext: sealed.slice(0, split), tag: sealed.slice(split) };
  }
  if (typeof crypto.createCipheriv !== 'function') {
    throw new Error('ChaCha20-Poly1305 is not available in this environment (Node.js only)');
  }
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: params.tagLength });
  cipher.setAAD(EMPTY, { plaintextLength: plaintext.length });
  const ciphertext = new Uint8Array(Buffer.concat([cipher.update(plaintext), cipher.final()]));
  return { ciphertext, tag: new Uint8Array(cipher.getAuthTag()) };
}

async function open(params, key, nonce, ciphertext, tag) {
  if (params.kind === 'aes-gcm') {
    const subtle = getSubtle();
    const cryptoKey = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    try {
      return new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: EMPTY, tagLength: params.tagLength * 8 },
        cryptoKey,
        concat(ciphertext, tag)
      ));
    } catch {
      throw new Error('AEAD decryption failed: authentication tag did not verify');
    }
  }
  if (typeof crypto.createDecipheriv !== 'function') {
    throw new Error('ChaCha20-Poly1305 is not available in this environment (Node.js only)');
  }
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: params.tagLength });
  decipher.setAAD(EMPTY, { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  try {
    return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  } catch {
    throw new Error('AEAD decryption failed: authentication tag did not verify');
  }
}

/**
 * Checks the shape of one `sd_aead_encrypted_claims` entry against aead.cddl
 * and the algorithm's nonce and tag lengths.
 *
 * @param {Array} entry - [nonce, ciphertext, tag, ?keyContext]
 * @param {number} [algorithm] - IANA AEAD algorithm identifier
 * @returns {{nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, keyContext?: number|string|Uint8Array}}
 */
export function parseEncryptedDisclosure(entry, algorithm = DEFAULT_AEAD_ALGORITHM) {
  const params = getAeadParams(algorithm);
  if (!Array.isArray(entry) || entry.length < 3 || entry.length > 4) {
    throw new Error('Invalid AEAD encrypted disclosure: expected [nonce, ciphertext, tag, ?key-context]');
  }
  const [nonce, ciphertext, tag, keyContext] = entry;
  for (const [name, value] of [['nonce', nonce], ['ciphertext', ciphertext], ['tag', tag]]) {
    if (!(value instanceof Uint8Array)) {
      throw new Error(`Invalid AEAD encrypted disclosure: ${name} must be a bstr`);
    }
  }
  if (nonce.length !== params.nonceLength) {
    throw new Error(`Invalid AEAD encrypted disclosure: nonce must be ${params.nonceLength} octets, got ${nonce.length}`);
  }
  if (tag.length !== params.tagLength) {
    throw new Error(`Invalid AEAD encrypted disclosure: tag must be ${params.tagLength} octets, got ${tag.length}`);
  }
  const result = { nonce, ciphertext, tag };
  if (entry.length === 4) {
    const validContext =
      (typeof keyContext === 'number' && Number.isInteger(keyContext) && keyContext >= 0) ||
      (typeof keyContext === 'bigint' && keyContext >= 0n) ||
      typeof keyContext === 'string' ||
      keyContext instanceof Uint8Array;
    if (!validContext) {
      throw new Error('Invalid AEAD encrypted disclosure: key context must be a uint, tstr, or bstr thumbprint');
    }
    result.keyContext = keyContext;
  }
  return result;
}

/**
 * Encrypts one Salted Disclosed Claim for `sd_aead_encrypted_claims` (171).
 *
 * @param {Uint8Array} disclosure - The salted-entry encoding (an `sd_claims` element)
 * @param {Uint8Array} key - The AEAD key
 * @param {Object} [options]
 * @param {number} [options.algorithm=1] - IANA AEAD algorithm identifier
 * @param {Uint8Array} [options.nonce] - Nonce; a fresh random one is generated if omitted.
 *   Never reuse a nonce under the same key; this exists for test vectors.
 * @param {number|string|Uint8Array} [options.keyContext] - Optional aead-key-context
 * @returns {Promise<Array>} [nonce, ciphertext, tag, ?keyContext]
 */
export async function encryptDisclosure(disclosure, key, { algorithm = DEFAULT_AEAD_ALGORITHM, nonce, keyContext } = {}) {
  const params = getAeadParams(algorithm);
  const keyBytes = checkKey(key, params);
  const nonceBytes = nonce === undefined
    ? new Uint8Array(globalThis.crypto.getRandomValues(new Uint8Array(params.nonceLength)))
    : toBytes(nonce);
  if (nonceBytes.length !== params.nonceLength) {
    throw new Error(`AEAD nonce must be ${params.nonceLength} octets, got ${nonceBytes.length}`);
  }

  // The plaintext is the bstr, header included: the same bytes the Redacted
  // Claim Hash covers.
  const plaintext = new Uint8Array(cbor.encode(toBytes(disclosure)));
  const { ciphertext, tag } = await seal(params, keyBytes, nonceBytes, plaintext);

  const entry = [new Uint8Array(nonceBytes), ciphertext, tag];
  if (keyContext !== undefined) {
    entry.push(keyContext instanceof Uint8Array || ArrayBuffer.isView(keyContext) ? new Uint8Array(toBytes(keyContext)) : keyContext);
  }
  parseEncryptedDisclosure(entry, algorithm);
  return entry;
}

/**
 * Decrypts one `sd_aead_encrypted_claims` entry back to a Salted Disclosed Claim.
 *
 * @param {Array} entry - [nonce, ciphertext, tag, ?keyContext]
 * @param {Uint8Array} key - The AEAD key
 * @param {Object} [options]
 * @param {number} [options.algorithm=1] - IANA AEAD algorithm identifier
 * @returns {Promise<Uint8Array>} The salted-entry encoding, usable as an `sd_claims` element
 * @throws {Error} If authentication fails or the plaintext is not exactly one bstr
 */
export async function decryptDisclosure(entry, key, { algorithm = DEFAULT_AEAD_ALGORITHM } = {}) {
  const params = getAeadParams(algorithm);
  const { nonce, ciphertext, tag } = parseEncryptedDisclosure(entry, algorithm);
  const plaintext = await open(params, checkKey(key, params), nonce, ciphertext, tag);

  let inner;
  try {
    inner = cbor.decode(plaintext, cborDecodeOptions);
  } catch (e) {
    throw new Error(`Invalid AEAD plaintext: not a single CBOR item (${e.message})`);
  }
  if (!(inner instanceof Uint8Array)) {
    throw new Error('Invalid AEAD plaintext: expected bstr .cbor salted-entry');
  }
  // Byte-exact round trip rules out non-preferred length encodings, which
  // would otherwise hash differently from what the Issuer committed to.
  if (!bytesEqual(new Uint8Array(cbor.encode(inner)), plaintext)) {
    throw new Error('Invalid AEAD plaintext: bstr is not in preferred serialization');
  }
  return new Uint8Array(inner);
}
