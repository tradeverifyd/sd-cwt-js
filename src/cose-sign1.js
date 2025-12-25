/**
 * COSE Sign1 - High-level API
 * 
 * This module provides a user-friendly API for COSE_Sign1 operations,
 * built on top of our minimal COSE Sign1 implementation.
 */

import * as sign1 from './cose/sign1.js';
import * as cbor from 'cbor2';

// Re-export core types and constants
export { HeaderParam, Alg, COSE_Sign1_Tag, getCrypto } from './cose/sign1.js';

/**
 * COSE Sign1 algorithms supported (string aliases)
 */
export const Algorithm = {
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
};

/**
 * COSE Key parameter labels (RFC 8152 Section 7)
 */
export const CoseKeyParam = {
  Kty: 1,      // Key Type
  Kid: 2,      // Key ID
  Alg: 3,      // Key Algorithm
  KeyOps: 4,   // Key Operations
  BaseIV: 5,   // Base IV
  // EC2 specific parameters
  Crv: -1,     // Curve (EC2)
  X: -2,       // x coordinate
  Y: -3,       // y coordinate
  D: -4,       // Private key d
};

/**
 * COSE Key Types (RFC 8152 Section 13)
 */
export const CoseKeyType = {
  OKP: 1,   // Octet Key Pair (EdDSA)
  EC2: 2,   // Elliptic Curve with x, y coordinates
};

/**
 * COSE Elliptic Curves (RFC 8152 Section 13.1)
 */
export const CoseCurve = {
  P256: 1,   // NIST P-256 (secp256r1)
  P384: 2,   // NIST P-384 (secp384r1)
  P521: 3,   // NIST P-521 (secp521r1)
};

/**
 * Map algorithm names to COSE curves
 */
const AlgToCurve = {
  'ES256': CoseCurve.P256,
  'ES384': CoseCurve.P384,
  'ES512': CoseCurve.P521,
};

/**
 * Map COSE curves to algorithm names
 */
const CurveToAlg = {
  [CoseCurve.P256]: 'ES256',
  [CoseCurve.P384]: 'ES384',
  [CoseCurve.P521]: 'ES512',
};

/**
 * Check if a key is in COSE Key format (Map with integer keys)
 * @param {any} key - The key to check
 * @returns {boolean}
 */
export function isCoseKey(key) {
  if (key instanceof Map) {
    return key.has(CoseKeyParam.Kty) || key.has(CoseKeyParam.X);
  }
  if (typeof key === 'object' && key !== null) {
    // Check for integer keys (COSE format) vs string keys (legacy format)
    const keys = Object.keys(key);
    return keys.some(k => k === '1' || k === '-2' || k === '-3');
  }
  return false;
}

/**
 * Convert a COSE Key (Map or object) to internal key format { d, x, y }
 * @param {Map|Object} coseKey - COSE Key
 * @returns {Object} Internal key format with d, x, y as Uint8Array
 */
export function coseKeyToInternal(coseKey) {
  let x, y, d;
  
  if (coseKey instanceof Map) {
    x = coseKey.get(CoseKeyParam.X);
    y = coseKey.get(CoseKeyParam.Y);
    d = coseKey.get(CoseKeyParam.D);
  } else if (typeof coseKey === 'object') {
    x = coseKey[CoseKeyParam.X] || coseKey['-2'];
    y = coseKey[CoseKeyParam.Y] || coseKey['-3'];
    d = coseKey[CoseKeyParam.D] || coseKey['-4'];
  }
  
  const result = {};
  if (x) result.x = toUint8Array(x);
  if (y) result.y = toUint8Array(y);
  if (d) result.d = toUint8Array(d);
  
  return result;
}

/**
 * Convert internal key format { d, x, y } to COSE Key Map
 * @param {Object} key - Internal key with d, x, y components
 * @param {string} [algorithm='ES256'] - Algorithm to determine curve
 * @returns {Map} COSE Key as Map
 */
export function internalToCoseKey(key, algorithm = 'ES256') {
  const coseKey = new Map();
  coseKey.set(CoseKeyParam.Kty, CoseKeyType.EC2);
  coseKey.set(CoseKeyParam.Crv, AlgToCurve[algorithm] || CoseCurve.P256);
  
  if (key.x) coseKey.set(CoseKeyParam.X, toUint8Array(key.x));
  if (key.y) coseKey.set(CoseKeyParam.Y, toUint8Array(key.y));
  if (key.d) coseKey.set(CoseKeyParam.D, toUint8Array(key.d));
  
  return coseKey;
}

/**
 * Get algorithm from COSE Key based on curve
 * @param {Map|Object} coseKey - COSE Key
 * @returns {string} Algorithm name (e.g., 'ES256')
 */
export function getAlgorithmFromCoseKey(coseKey) {
  let crv;
  if (coseKey instanceof Map) {
    crv = coseKey.get(CoseKeyParam.Crv);
  } else if (typeof coseKey === 'object') {
    crv = coseKey[CoseKeyParam.Crv] || coseKey['-1'];
  }
  return CurveToAlg[crv] || 'ES256';
}

/**
 * Serialize a COSE Key to CBOR bytes
 * @param {Map} coseKey - COSE Key Map
 * @returns {Uint8Array} CBOR-encoded COSE Key
 */
export function serializeCoseKey(coseKey) {
  if (!(coseKey instanceof Map)) {
    throw new Error('COSE Key must be a Map');
  }
  return new Uint8Array(cbor.encode(coseKey));
}

/**
 * Deserialize CBOR bytes to a COSE Key Map
 * @param {Uint8Array|Buffer} bytes - CBOR-encoded COSE Key
 * @returns {Map} COSE Key Map
 */
export function deserializeCoseKey(bytes) {
  if (!bytes || bytes.length === 0) {
    throw new Error('COSE Key bytes are required');
  }
  
  const decoded = cbor.decode(bytes, { preferMap: true });
  
  if (!(decoded instanceof Map)) {
    throw new Error('Invalid COSE Key: expected a CBOR map');
  }
  
  // Validate it has minimum COSE Key structure
  if (!decoded.has(CoseKeyParam.Kty)) {
    throw new Error('Invalid COSE Key: missing kty (key type)');
  }
  
  return decoded;
}

/**
 * Serialize a COSE Key to hex string (base16 encoding of CBOR bytes)
 * @param {Map} coseKey - COSE Key Map
 * @returns {string} Base16 (hex) encoded CBOR representation of the COSE Key
 */
export function coseKeyToHex(coseKey) {
  const bytes = serializeCoseKey(coseKey);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Deserialize hex string to COSE Key Map
 * @param {string} hex - Base16 (hex) encoded CBOR representation of a COSE Key
 * @returns {Map} COSE Key Map
 */
export function coseKeyFromHex(hex) {
  if (!hex || typeof hex !== 'string') {
    throw new Error('Hex string is required');
  }
  const clean = hex.replace(/\s/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return deserializeCoseKey(bytes);
}

/**
 * Compute COSE Key Thumbprint per RFC 9679
 * 
 * The thumbprint is computed by:
 * 1. Extracting only the required public key parameters
 * 2. Encoding them in deterministic CBOR (sorted by integer key)
 * 3. Hashing with the specified algorithm (default SHA-256)
 * 
 * For EC2 keys (kty=2), required parameters are: kty, crv, x, y
 * 
 * @param {Map|Object} coseKey - COSE Key (public or private)
 * @param {string} [hashAlgorithm='SHA-256'] - Hash algorithm ('SHA-256', 'SHA-384', 'SHA-512')
 * @returns {Uint8Array} The thumbprint bytes
 */
export function computeCoseKeyThumbprint(coseKey, hashAlgorithm = 'SHA-256') {
  // Extract key parameters
  let kty, crv, x, y;
  
  if (coseKey instanceof Map) {
    kty = coseKey.get(CoseKeyParam.Kty);
    crv = coseKey.get(CoseKeyParam.Crv);
    x = coseKey.get(CoseKeyParam.X);
    y = coseKey.get(CoseKeyParam.Y);
  } else if (typeof coseKey === 'object') {
    kty = coseKey[CoseKeyParam.Kty] || coseKey['1'];
    crv = coseKey[CoseKeyParam.Crv] || coseKey['-1'];
    x = coseKey[CoseKeyParam.X] || coseKey['-2'];
    y = coseKey[CoseKeyParam.Y] || coseKey['-3'];
  } else {
    throw new Error('COSE Key must be a Map or Object');
  }
  
  // Validate required parameters for EC2 keys
  if (kty !== CoseKeyType.EC2) {
    throw new Error(`Unsupported key type for thumbprint: ${kty}. Only EC2 (2) is supported.`);
  }
  
  if (crv === undefined || !x || !y) {
    throw new Error('COSE Key must have crv, x, and y parameters for thumbprint');
  }
  
  // Build the thumbprint input Map with only required public key parameters
  // RFC 9679: Parameters must be in deterministic order
  // For EC2: kty (1), crv (-1), x (-2), y (-3)
  // CBOR deterministic encoding sorts integer keys by:
  // 1. Positive integers before negative integers
  // 2. Within each group, by absolute value
  // So the order is: 1, -1, -2, -3
  
  // Use an array of [key, value] pairs in the correct order for deterministic encoding
  const thumbprintParams = new Map();
  thumbprintParams.set(CoseKeyParam.Kty, kty);        // 1
  thumbprintParams.set(CoseKeyParam.Crv, crv);        // -1
  thumbprintParams.set(CoseKeyParam.X, toUint8Array(x)); // -2
  thumbprintParams.set(CoseKeyParam.Y, toUint8Array(y)); // -3
  
  // Encode with deterministic/canonical CBOR
  // cbor2 uses canonical encoding by default when encoding Maps
  const encoded = cbor.encode(thumbprintParams);
  
  // Hash the encoded bytes
  const crypto = sign1.getCrypto();
  const hash = crypto.createHash(hashAlgorithm.toLowerCase().replace('-', ''));
  hash.update(new Uint8Array(encoded));
  const digest = hash.digest();
  
  return new Uint8Array(digest);
}

/**
 * Compute COSE Key Thumbprint and return as hex string
 * @param {Map|Object} coseKey - COSE Key (public or private)
 * @param {string} [hashAlgorithm='SHA-256'] - Hash algorithm
 * @returns {string} Hex-encoded thumbprint
 */
export function coseKeyThumbprint(coseKey, hashAlgorithm = 'SHA-256') {
  const bytes = computeCoseKeyThumbprint(coseKey, hashAlgorithm);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute COSE Key Thumbprint URI per RFC 9679
 * Format: urn:ietf:params:oauth:ckt:<hash-name>:<base64url-thumbprint>
 * @param {Map|Object} coseKey - COSE Key (public or private)
 * @param {string} [hashAlgorithm='SHA-256'] - Hash algorithm
 * @returns {string} CKT URI
 */
export function coseKeyThumbprintUri(coseKey, hashAlgorithm = 'SHA-256') {
  const bytes = computeCoseKeyThumbprint(coseKey, hashAlgorithm);
  
  // Convert to base64url
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  
  // Hash name for URI (lowercase, no hyphen for SHA-256 -> sha-256)
  const hashName = hashAlgorithm.toLowerCase();
  
  return `urn:ietf:params:oauth:ckt:${hashName}:${base64url}`;
}

/**
 * Normalize a key to internal format, accepting both COSE Key and legacy format
 * @param {Map|Object} key - COSE Key or legacy { d, x, y } format
 * @returns {{ key: Object, algorithm: string }} Normalized key and detected algorithm
 */
function normalizeKey(key) {
  if (isCoseKey(key)) {
    return {
      key: coseKeyToInternal(key),
      algorithm: getAlgorithmFromCoseKey(key),
    };
  }
  // Legacy format - assume { d, x, y }
  return {
    key: {
      d: key.d ? toUint8Array(key.d) : undefined,
      x: key.x ? toUint8Array(key.x) : undefined,
      y: key.y ? toUint8Array(key.y) : undefined,
    },
    algorithm: 'ES256', // Default for legacy format
  };
}

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
 * @param {Map|Object} signerKey - The signer's private key (COSE Key format or legacy { d, x, y })
 * @param {Object} [options] - Optional parameters
 * @param {string} [options.algorithm='ES256'] - The signing algorithm (auto-detected from COSE Key)
 * @param {string|Buffer} [options.kid] - Key identifier
 * @param {Object} [options.protectedHeaders] - Additional protected headers (string keys)
 * @param {Object} [options.unprotectedHeaders] - Additional unprotected headers (string keys)
 * @param {Map|Object} [options.customProtectedHeaders] - Custom headers with integer keys
 * @param {Map|Object} [options.customUnprotectedHeaders] - Custom headers with integer keys
 * @returns {Promise<Buffer>} The COSE Sign1 message
 */
export async function sign(payload, signerKey, options = {}) {
  const {
    algorithm: explicitAlgorithm,
    kid,
    protectedHeaders = {},
    unprotectedHeaders = {},
    customProtectedHeaders,
    customUnprotectedHeaders,
  } = options;

  if (!payload) {
    throw new Error('Payload is required');
  }

  // Normalize key to internal format
  const { key: internalKey, algorithm: detectedAlgorithm } = normalizeKey(signerKey);
  const algorithm = explicitAlgorithm || detectedAlgorithm;

  if (!internalKey || !internalKey.d || !internalKey.x || !internalKey.y) {
    throw new Error('Signer key must include d, x, and y components (COSE Key params -4, -2, -3)');
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

  // Key is already normalized to internal format with Uint8Array components
  const key = internalKey;

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
 * @param {Map|Object} verifierKey - The verifier's public key (COSE Key format or legacy { x, y })
 * @returns {Promise<Buffer>} The verified payload
 * @throws {Error} If verification fails
 */
export async function verify(coseSign1, verifierKey) {
  if (!coseSign1) {
    throw new Error('COSE Sign1 message is required');
  }

  // Normalize key to internal format
  const { key: internalKey } = normalizeKey(verifierKey);

  if (!internalKey || !internalKey.x || !internalKey.y) {
    throw new Error('Verifier key must include x and y components (COSE Key params -2, -3)');
  }

  const messageBytes = toUint8Array(coseSign1);

  const payload = await sign1.verify(messageBytes, internalKey);
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
 * @returns {{ privateKey: Map, publicKey: Map }} COSE Key Maps for private and public keys
 */
export function generateKeyPair(algorithm = Algorithm.ES256) {
  const algId = AlgNameToId[algorithm];
  if (algId === undefined) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  const { privateKey, publicKey } = sign1.generateKeyPair(algId);
  const curve = AlgToCurve[algorithm];

  // Create COSE Key Maps with algorithm
  const privateKeyMap = new Map();
  privateKeyMap.set(CoseKeyParam.Kty, CoseKeyType.EC2);
  privateKeyMap.set(CoseKeyParam.Alg, algId);  // Store algorithm in key
  privateKeyMap.set(CoseKeyParam.Crv, curve);
  privateKeyMap.set(CoseKeyParam.X, new Uint8Array(privateKey.x));
  privateKeyMap.set(CoseKeyParam.Y, new Uint8Array(privateKey.y));
  privateKeyMap.set(CoseKeyParam.D, new Uint8Array(privateKey.d));

  const publicKeyMap = new Map();
  publicKeyMap.set(CoseKeyParam.Kty, CoseKeyType.EC2);
  publicKeyMap.set(CoseKeyParam.Alg, algId);  // Store algorithm in key
  publicKeyMap.set(CoseKeyParam.Crv, curve);
  publicKeyMap.set(CoseKeyParam.X, new Uint8Array(publicKey.x));
  publicKeyMap.set(CoseKeyParam.Y, new Uint8Array(publicKey.y));

  // Compute and store thumbprint as kid (key ID)
  const thumbprint = computeCoseKeyThumbprint(publicKeyMap);
  privateKeyMap.set(CoseKeyParam.Kid, thumbprint);
  publicKeyMap.set(CoseKeyParam.Kid, thumbprint);

  return {
    privateKey: privateKeyMap,
    publicKey: publicKeyMap,
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
