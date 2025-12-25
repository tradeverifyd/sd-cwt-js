import cose from 'cose-js';
import crypto from 'node:crypto';
import * as cbor from 'cbor2';

/**
 * COSE Sign1 algorithms supported
 */
export const Algorithm = {
  ES256: 'ES256',   // ECDSA w/ SHA-256, P-256 curve
  ES384: 'ES384',   // ECDSA w/ SHA-384, P-384 curve
  ES512: 'ES512',   // ECDSA w/ SHA-512, P-521 curve
};

/**
 * COSE_Sign1 tag value
 */
const COSE_Sign1_TAG = 18;

/**
 * Algorithm to COSE algorithm identifier mapping
 */
const AlgToId = {
  'ES256': -7,
  'ES384': -35,
  'ES512': -36,
};

/**
 * COSE algorithm identifier to algorithm name mapping
 */
const IdToAlg = {
  '-7': 'ES256',
  '-35': 'ES384',
  '-36': 'ES512',
};

/**
 * Creates a COSE Sign1 signed message
 * 
 * @param {Buffer} payload - The payload to sign
 * @param {Object} signerKey - The signer's private key
 * @param {Buffer} signerKey.d - The private key 'd' component
 * @param {Buffer} signerKey.x - The public key 'x' coordinate
 * @param {Buffer} signerKey.y - The public key 'y' coordinate
 * @param {Object} [options] - Optional parameters
 * @param {string} [options.algorithm='ES256'] - The signing algorithm
 * @param {string} [options.kid] - Key identifier
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

  // Check if we have custom headers - if so, we need to handle manually
  const hasCustomHeaders = customProtectedHeaders || customUnprotectedHeaders;

  // Ensure payload is a Buffer
  const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);

  if (!hasCustomHeaders) {
    // Use the standard cose-js path for known headers
    const headers = {
      p: { 
        alg: algorithm,
        ...protectedHeaders,
      },
      u: {
        ...(kid && { kid }),
        ...unprotectedHeaders,
      },
    };

    const signer = {
      key: {
        d: Buffer.isBuffer(signerKey.d) ? signerKey.d : Buffer.from(signerKey.d),
        x: Buffer.isBuffer(signerKey.x) ? signerKey.x : Buffer.from(signerKey.x),
        y: Buffer.isBuffer(signerKey.y) ? signerKey.y : Buffer.from(signerKey.y),
      },
    };

    return await cose.sign.create(headers, payloadBuffer, signer);
  }

  // Handle custom headers manually
  // Build protected header map
  const protectedMap = new Map();
  protectedMap.set(1, AlgToId[algorithm]); // alg
  
  // Add standard protected headers
  for (const [key, value] of Object.entries(protectedHeaders)) {
    const label = HeaderLabels[key];
    if (label !== undefined) {
      protectedMap.set(label, value);
    }
  }
  
  // Add custom protected headers (integer keys)
  if (customProtectedHeaders) {
    const customEntries = customProtectedHeaders instanceof Map 
      ? customProtectedHeaders.entries() 
      : Object.entries(customProtectedHeaders);
    for (const [key, value] of customEntries) {
      protectedMap.set(Number(key), value);
    }
  }

  // Build unprotected header map
  const unprotectedMap = new Map();
  if (kid) {
    unprotectedMap.set(4, kid); // kid label
  }
  
  // Add standard unprotected headers
  for (const [key, value] of Object.entries(unprotectedHeaders)) {
    const label = HeaderLabels[key];
    if (label !== undefined) {
      unprotectedMap.set(label, value);
    }
  }
  
  // Add custom unprotected headers (integer keys)
  if (customUnprotectedHeaders) {
    const customEntries = customUnprotectedHeaders instanceof Map 
      ? customUnprotectedHeaders.entries() 
      : Object.entries(customUnprotectedHeaders);
    for (const [key, value] of customEntries) {
      unprotectedMap.set(Number(key), value);
    }
  }

  // Encode protected headers
  const protectedBytes = cbor.encode(protectedMap);

  // Create Sig_structure for signing
  // Sig_structure = ["Signature1", protectedBytes, externalAAD, payload]
  const sigStructure = [
    'Signature1',
    protectedBytes,
    Buffer.alloc(0), // external_aad
    payloadBuffer,
  ];
  const toBeSigned = cbor.encode(sigStructure);

  // Sign using Node's crypto
  const curveMap = {
    'ES256': 'P-256',
    'ES384': 'P-384', 
    'ES512': 'P-521',
  };
  
  const hashMap = {
    'ES256': 'sha256',
    'ES384': 'sha384',
    'ES512': 'sha512',
  };

  const curve = curveMap[algorithm];
  const hash = hashMap[algorithm];
  
  // Build JWK for signing
  const jwk = {
    kty: 'EC',
    crv: curve,
    d: Buffer.isBuffer(signerKey.d) ? signerKey.d.toString('base64url') : Buffer.from(signerKey.d).toString('base64url'),
    x: Buffer.isBuffer(signerKey.x) ? signerKey.x.toString('base64url') : Buffer.from(signerKey.x).toString('base64url'),
    y: Buffer.isBuffer(signerKey.y) ? signerKey.y.toString('base64url') : Buffer.from(signerKey.y).toString('base64url'),
  };

  const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const signatureRaw = crypto.sign(null, toBeSigned, { key: privateKey, dsaEncoding: 'ieee-p1363' });

  // Build COSE_Sign1 structure: [protectedBytes, unprotectedMap, payload, signature]
  const coseSign1 = [protectedBytes, unprotectedMap, payloadBuffer, signatureRaw];
  
  // Encode with COSE_Sign1 tag (18)
  return cbor.encode(new cbor.Tag(COSE_Sign1_TAG, coseSign1));
}

/**
 * Standard COSE header labels
 */
const HeaderLabels = {
  alg: 1,
  crit: 2,
  content_type: 3,
  ctyp: 3,
  kid: 4,
  IV: 5,
  Partial_IV: 6,
  counter_signature: 7,
  x5chain: 33,
};

/**
 * Verifies a COSE Sign1 message and returns the payload
 * 
 * @param {Buffer} coseSign1 - The COSE Sign1 message to verify
 * @param {Object} verifierKey - The verifier's public key
 * @param {Buffer} verifierKey.x - The public key 'x' coordinate
 * @param {Buffer} verifierKey.y - The public key 'y' coordinate
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

  // Try cose-js first, fall back to manual verification if it fails
  try {
    const verifier = {
      key: {
        x: Buffer.isBuffer(verifierKey.x) ? verifierKey.x : Buffer.from(verifierKey.x),
        y: Buffer.isBuffer(verifierKey.y) ? verifierKey.y : Buffer.from(verifierKey.y),
      },
    };
    return await cose.sign.verify(coseSign1, verifier);
  } catch (e) {
    // Fall back to manual verification for custom header support
    return await verifyManual(coseSign1, verifierKey);
  }
}

/**
 * Manual verification for COSE Sign1 messages with custom headers
 */
async function verifyManual(coseSign1, verifierKey) {
  const decoded = cbor.decode(coseSign1);
  
  // Handle tagged or untagged COSE_Sign1
  const structure = decoded instanceof cbor.Tag ? decoded.contents : decoded;
  
  if (!Array.isArray(structure) || structure.length !== 4) {
    throw new Error('Invalid COSE Sign1 structure');
  }

  const [protectedBytes, , payload, signature] = structure;
  
  // Decode protected headers to get algorithm
  const protectedHeaders = cbor.decode(protectedBytes);
  const algId = protectedHeaders instanceof Map ? protectedHeaders.get(1) : protectedHeaders[1];
  const algorithm = IdToAlg[String(algId)];
  
  if (!algorithm) {
    throw new Error(`Unknown algorithm: ${algId}`);
  }

  // Build Sig_structure for verification
  const sigStructure = [
    'Signature1',
    protectedBytes,
    Buffer.alloc(0), // external_aad
    payload,
  ];
  const toBeVerified = cbor.encode(sigStructure);

  // Verify using Node's crypto
  const curveMap = {
    'ES256': 'P-256',
    'ES384': 'P-384',
    'ES512': 'P-521',
  };

  const curve = curveMap[algorithm];
  
  // Build JWK for verification
  const jwk = {
    kty: 'EC',
    crv: curve,
    x: Buffer.isBuffer(verifierKey.x) ? verifierKey.x.toString('base64url') : Buffer.from(verifierKey.x).toString('base64url'),
    y: Buffer.isBuffer(verifierKey.y) ? verifierKey.y.toString('base64url') : Buffer.from(verifierKey.y).toString('base64url'),
  };

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  
  // Ensure signature is a Buffer
  const signatureBuffer = Buffer.isBuffer(signature) ? signature : Buffer.from(signature);
  
  const isValid = crypto.verify(null, toBeVerified, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signatureBuffer);
  
  if (!isValid) {
    throw new Error('Signature verification failed');
  }

  return payload;
}

/**
 * Extracts headers from a COSE Sign1 message without verification
 * 
 * @param {Buffer} coseSign1 - The COSE Sign1 message
 * @returns {Object} Object containing protectedHeaders and unprotectedHeaders as Maps
 */
export function getHeaders(coseSign1) {
  if (!coseSign1) {
    throw new Error('COSE Sign1 message is required');
  }

  const decoded = cbor.decode(coseSign1);
  
  // Handle tagged or untagged COSE_Sign1
  const structure = decoded instanceof cbor.Tag ? decoded.contents : decoded;
  
  if (!Array.isArray(structure) || structure.length !== 4) {
    throw new Error('Invalid COSE Sign1 structure');
  }

  const [protectedBytes, unprotectedMap, , ] = structure;
  
  // Decode protected headers
  let protectedHeaders = new Map();
  if (protectedBytes && protectedBytes.length > 0) {
    protectedHeaders = cbor.decode(protectedBytes);
    if (!(protectedHeaders instanceof Map)) {
      // Convert object to Map if needed
      protectedHeaders = new Map(Object.entries(protectedHeaders).map(([k, v]) => [Number(k), v]));
    }
  }

  // Ensure unprotected headers is a Map
  let unprotected = unprotectedMap;
  if (!(unprotected instanceof Map)) {
    unprotected = new Map(Object.entries(unprotected || {}).map(([k, v]) => [Number(k), v]));
  }

  return {
    protectedHeaders,
    unprotectedHeaders: unprotected,
  };
}

/**
 * Generates a key pair for COSE Sign1 operations
 * 
 * @param {string} [algorithm='ES256'] - The algorithm to generate keys for
 * @returns {Object} An object containing privateKey and publicKey
 */
export function generateKeyPair(algorithm = Algorithm.ES256) {
  const curveMap = {
    [Algorithm.ES256]: 'P-256',
    [Algorithm.ES384]: 'P-384',
    [Algorithm.ES512]: 'P-521',
  };

  const curve = curveMap[algorithm];
  if (!curve) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: curve,
  });

  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicJwk = publicKey.export({ format: 'jwk' });

  return {
    privateKey: {
      d: Buffer.from(privateJwk.d, 'base64url'),
      x: Buffer.from(privateJwk.x, 'base64url'),
      y: Buffer.from(privateJwk.y, 'base64url'),
    },
    publicKey: {
      x: Buffer.from(publicJwk.x, 'base64url'),
      y: Buffer.from(publicJwk.y, 'base64url'),
    },
  };
}

