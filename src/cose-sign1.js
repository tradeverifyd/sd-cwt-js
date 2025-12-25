/**
 * COSE Sign1 - High-level API
 * 
 * This module provides a user-friendly API for COSE_Sign1 operations,
 * built on top of our minimal COSE Sign1 implementation.
 */

import * as sign1 from './cose/sign1.js';

// Re-export core types and constants
export { HeaderParam, Alg, COSE_Sign1_Tag } from './cose/sign1.js';

/**
 * COSE Sign1 algorithms supported (string aliases)
 */
export const Algorithm = {
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
};

/**
 * Map string algorithm names to COSE algorithm identifiers
 */
const AlgNameToId = {
  'ES256': sign1.Alg.ES256,
  'ES384': sign1.Alg.ES384,
  'ES512': sign1.Alg.ES512,
};

/**
 * Creates a COSE Sign1 signed message
 * 
 * @param {Buffer|Uint8Array|string} payload - The payload to sign
 * @param {Object} signerKey - The signer's private key
 * @param {Buffer|Uint8Array} signerKey.d - The private key 'd' component
 * @param {Buffer|Uint8Array} signerKey.x - The public key 'x' coordinate
 * @param {Buffer|Uint8Array} signerKey.y - The public key 'y' coordinate
 * @param {Object} [options] - Optional parameters
 * @param {string} [options.algorithm='ES256'] - The signing algorithm
 * @param {string|Buffer} [options.kid] - Key identifier
 * @param {Object} [options.protectedHeaders] - Additional protected headers (string keys)
 * @param {Object} [options.unprotectedHeaders] - Additional unprotected headers (string keys)
 * @param {Map|Object} [options.customProtectedHeaders] - Custom headers with integer keys
 * @param {Map|Object} [options.customUnprotectedHeaders] - Custom headers with integer keys
 * @returns {Promise<Buffer>} The COSE Sign1 message
 */
export async function sign(payload, signerKey, options = {}) {
  const {
    algorithm = Algorithm.ES256,
    kid,
    protectedHeaders = {},
    unprotectedHeaders = {},
    customProtectedHeaders,
    customUnprotectedHeaders,
  } = options;

  if (!payload) {
    throw new Error('Payload is required');
  }

  if (!signerKey || !signerKey.d || !signerKey.x || !signerKey.y) {
    throw new Error('Signer key must include d, x, and y components');
  }

  // Convert algorithm string to COSE algorithm identifier
  const algId = AlgNameToId[algorithm];
  if (algId === undefined) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  // Build protected header Map
  const protectedMap = new Map();
  protectedMap.set(sign1.HeaderParam.Algorithm, algId);

  // Add standard protected headers
  for (const [key, value] of Object.entries(protectedHeaders)) {
    const label = HeaderLabels[key];
    if (label !== undefined) {
      protectedMap.set(label, value);
    }
  }

  // Add custom protected headers
  if (customProtectedHeaders) {
    const entries = customProtectedHeaders instanceof Map
      ? customProtectedHeaders.entries()
      : Object.entries(customProtectedHeaders);
    for (const [key, value] of entries) {
      protectedMap.set(Number(key), convertBufferValues(value));
    }
  }

  // Build unprotected header Map
  const unprotectedMap = new Map();
  
  if (kid) {
    // Ensure kid is Uint8Array for proper CBOR encoding
    const kidBuffer = typeof kid === 'string' ? Buffer.from(kid) : kid;
    const kidValue = toUint8Array(kidBuffer);
    unprotectedMap.set(sign1.HeaderParam.KeyId, kidValue);
  }

  // Add standard unprotected headers
  for (const [key, value] of Object.entries(unprotectedHeaders)) {
    const label = HeaderLabels[key];
    if (label !== undefined) {
      unprotectedMap.set(label, value);
    }
  }

  // Add custom unprotected headers
  if (customUnprotectedHeaders) {
    const entries = customUnprotectedHeaders instanceof Map
      ? customUnprotectedHeaders.entries()
      : Object.entries(customUnprotectedHeaders);
    for (const [key, value] of entries) {
      unprotectedMap.set(Number(key), convertBufferValues(value));
    }
  }

  // Ensure payload is Uint8Array
  let payloadBytes;
  if (payload instanceof Uint8Array) {
    payloadBytes = payload;
  } else if (Buffer.isBuffer(payload)) {
    payloadBytes = new Uint8Array(payload);
  } else {
    payloadBytes = new Uint8Array(Buffer.from(payload));
  }

  // Ensure key components are Uint8Array
  const key = {
    d: toUint8Array(signerKey.d),
    x: toUint8Array(signerKey.x),
    y: toUint8Array(signerKey.y),
  };

  const signed = await sign1.sign({
    protectedHeader: protectedMap,
    unprotectedHeader: unprotectedMap,
    payload: payloadBytes,
    key,
  });

  return Buffer.from(signed);
}

/**
 * Verifies a COSE Sign1 message and returns the payload
 * 
 * @param {Buffer|Uint8Array} coseSign1 - The COSE Sign1 message to verify
 * @param {Object} verifierKey - The verifier's public key
 * @param {Buffer|Uint8Array} verifierKey.x - The public key 'x' coordinate
 * @param {Buffer|Uint8Array} verifierKey.y - The public key 'y' coordinate
 * @returns {Promise<Buffer>} The verified payload
 * @throws {Error} If verification fails
 */
export async function verify(coseSign1, verifierKey) {
  if (!coseSign1) {
    throw new Error('COSE Sign1 message is required');
  }

  if (!verifierKey || !verifierKey.x || !verifierKey.y) {
    throw new Error('Verifier key must include x and y components');
  }

  const key = {
    x: toUint8Array(verifierKey.x),
    y: toUint8Array(verifierKey.y),
  };

  const messageBytes = toUint8Array(coseSign1);

  const payload = await sign1.verify(messageBytes, key);
  return Buffer.from(payload);
}

/**
 * Extracts headers from a COSE Sign1 message without verification
 * 
 * @param {Buffer|Uint8Array} coseSign1 - The COSE Sign1 message
 * @returns {Object} Object containing protectedHeaders and unprotectedHeaders as Maps
 */
export function getHeaders(coseSign1) {
  if (!coseSign1) {
    throw new Error('COSE Sign1 message is required');
  }

  const messageBytes = toUint8Array(coseSign1);

  const decoded = sign1.decode(messageBytes);
  
  return {
    protectedHeaders: decoded.protectedHeader,
    unprotectedHeaders: decoded.unprotectedHeader,
  };
}

/**
 * Generates a key pair for COSE Sign1 operations
 * 
 * @param {string} [algorithm='ES256'] - The algorithm to generate keys for
 * @returns {Object} An object containing privateKey and publicKey with Buffer components
 */
export function generateKeyPair(algorithm = Algorithm.ES256) {
  const algId = AlgNameToId[algorithm];
  if (algId === undefined) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  const { privateKey, publicKey } = sign1.generateKeyPair(algId);

  return {
    privateKey: {
      d: Buffer.from(privateKey.d),
      x: Buffer.from(privateKey.x),
      y: Buffer.from(privateKey.y),
    },
    publicKey: {
      x: Buffer.from(publicKey.x),
      y: Buffer.from(publicKey.y),
    },
  };
}

/**
 * Standard COSE header labels for string key conversion
 */
const HeaderLabels = {
  alg: sign1.HeaderParam.Algorithm,
  crit: sign1.HeaderParam.Critical,
  content_type: sign1.HeaderParam.ContentType,
  ctyp: sign1.HeaderParam.ContentType,
  kid: sign1.HeaderParam.KeyId,
  IV: sign1.HeaderParam.IV,
  Partial_IV: sign1.HeaderParam.PartialIV,
  counter_signature: sign1.HeaderParam.CounterSignature,
  x5chain: sign1.HeaderParam.X5Chain,
};

/**
 * Helper to convert Buffer or Uint8Array to pure Uint8Array
 * (Buffer extends Uint8Array but we need pure Uint8Array for crypto operations)
 * Always creates a copy to avoid issues with views over shared buffers.
 */
function toUint8Array(value) {
  if (Buffer.isBuffer(value)) {
    // Create a copy to avoid issues with views over shared buffers
    const copy = new Uint8Array(value.length);
    copy.set(value);
    return copy;
  }
  if (value instanceof Uint8Array) {
    // Create a copy to avoid issues with views
    const copy = new Uint8Array(value.length);
    copy.set(value);
    return copy;
  }
  return new Uint8Array(Buffer.from(value));
}

/**
 * Recursively converts Buffer values to Uint8Array in a value
 * (cbor2 encodes Buffer differently than Uint8Array)
 * Always creates copies to avoid issues with views over shared buffers.
 */
function convertBufferValues(value) {
  if (Buffer.isBuffer(value)) {
    // Create a copy to avoid issues with views over shared buffers
    const copy = new Uint8Array(value.length);
    copy.set(value);
    return copy;
  }
  if (value instanceof Uint8Array) {
    // Create a copy to avoid issues with views
    const copy = new Uint8Array(value.length);
    copy.set(value);
    return copy;
  }
  if (Array.isArray(value)) {
    return value.map(convertBufferValues);
  }
  if (value instanceof Map) {
    const result = new Map();
    for (const [k, v] of value) {
      result.set(k, convertBufferValues(v));
    }
    return result;
  }
  if (value !== null && typeof value === 'object') {
    const result = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = convertBufferValues(v);
    }
    return result;
  }
  return value;
}
