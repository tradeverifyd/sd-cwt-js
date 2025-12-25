/**
 * Minimal COSE Sign1 Implementation
 * 
 * This module provides COSE_Sign1 signing and verification using
 * native Maps for headers (no object API weirdness).
 * 
 * References:
 * - RFC 9052: COSE Structures and Process
 * - RFC 9053: COSE Algorithms
 */

import * as cbor from 'cbor2';
import crypto from 'node:crypto';

/**
 * COSE_Sign1 tag value (RFC 9052)
 */
export const COSE_Sign1_Tag = 18;

/**
 * COSE Header Parameters (RFC 9052 Section 3.1)
 */
export const HeaderParam = {
  Algorithm: 1,
  Critical: 2,
  ContentType: 3,
  KeyId: 4,
  IV: 5,
  PartialIV: 6,
  CounterSignature: 7,
  CounterSignature0: 9,
  X5Bag: 32,
  X5Chain: 33,
  X5T: 34,
  X5U: 35,
};

/**
 * COSE Algorithms (RFC 9053)
 */
export const Alg = {
  ES256: -7,   // ECDSA w/ SHA-256
  ES384: -35,  // ECDSA w/ SHA-384
  ES512: -36,  // ECDSA w/ SHA-512
};

/**
 * Default CBOR decode options.
 * Uses preferMap: true to ensure CBOR maps decode as JavaScript Maps.
 */
const cborDecodeOptions = {
  preferMap: true,
};

/**
 * Algorithm metadata
 */
const AlgInfo = {
  [Alg.ES256]: { name: 'ES256', curve: 'P-256', hash: 'sha256', sigSize: 64 },
  [Alg.ES384]: { name: 'ES384', curve: 'P-384', hash: 'sha384', sigSize: 96 },
  [Alg.ES512]: { name: 'ES512', curve: 'P-521', hash: 'sha512', sigSize: 132 },
};

/**
 * Creates a copy of byte data to avoid issues with views over shared buffers
 */
function copyBytes(data) {
  if (!data || data.length === 0) {
    return data;
  }
  if (data instanceof Uint8Array) {
    const copy = new Uint8Array(data.length);
    copy.set(data);
    return copy;
  }
  if (ArrayBuffer.isView(data)) {
    const view = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    const copy = new Uint8Array(view.length);
    copy.set(view);
    return copy;
  }
  return data;
}

/**
 * Creates the Sig_structure for signing/verification
 * 
 * Sig_structure = [
 *   context : "Signature1",
 *   body_protected : bstr,
 *   external_aad : bstr,
 *   payload : bstr
 * ]
 * 
 * @param {Uint8Array} protectedHeader - Encoded protected header
 * @param {Uint8Array} payload - The payload
 * @param {Uint8Array} [externalAad] - External additional authenticated data
 * @returns {Uint8Array} - CBOR-encoded Sig_structure
 */
function createSigStructure(protectedHeader, payload, externalAad = new Uint8Array(0)) {
  const structure = [
    'Signature1',
    protectedHeader,
    externalAad,
    payload,
  ];
  return cbor.encode(structure);
}

/**
 * Signs a payload and creates a COSE_Sign1 message
 * 
 * @param {Object} options - Signing options
 * @param {Map} options.protectedHeader - Protected header parameters (must include Algorithm)
 * @param {Map} [options.unprotectedHeader] - Unprotected header parameters
 * @param {Uint8Array} options.payload - The payload to sign
 * @param {Object} options.key - The signing key
 * @param {Uint8Array} options.key.d - Private key 'd' component
 * @param {Uint8Array} options.key.x - Public key 'x' coordinate
 * @param {Uint8Array} options.key.y - Public key 'y' coordinate
 * @param {Uint8Array} [options.externalAad] - External additional authenticated data
 * @returns {Promise<Uint8Array>} - COSE_Sign1 message (tagged)
 */
export async function sign(options) {
  const {
    protectedHeader,
    unprotectedHeader = new Map(),
    payload,
    key,
    externalAad = new Uint8Array(0),
  } = options;

  // Validate inputs
  if (!(protectedHeader instanceof Map)) {
    throw new TypeError('protectedHeader must be a Map');
  }
  if (!(unprotectedHeader instanceof Map)) {
    throw new TypeError('unprotectedHeader must be a Map');
  }
  if (!payload) {
    throw new Error('payload is required');
  }
  if (!key || !key.d || !key.x || !key.y) {
    throw new Error('key must include d, x, and y components');
  }

  // Get algorithm from protected header
  const alg = protectedHeader.get(HeaderParam.Algorithm);
  if (alg === undefined) {
    throw new Error('Algorithm (1) must be in protected header');
  }

  const algInfo = AlgInfo[alg];
  if (!algInfo) {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  // Encode protected header
  const protectedBytes = protectedHeader.size > 0 
    ? cbor.encode(protectedHeader) 
    : new Uint8Array(0);

  // Ensure payload is Uint8Array (not Buffer, which cbor2 encodes differently)
  let payloadBytes;
  if (Buffer.isBuffer(payload)) {
    payloadBytes = new Uint8Array(payload.buffer, payload.byteOffset, payload.length);
  } else if (payload instanceof Uint8Array) {
    payloadBytes = payload;
  } else {
    payloadBytes = new Uint8Array(Buffer.from(payload));
  }

  // Create Sig_structure
  const sigStructure = createSigStructure(protectedBytes, payloadBytes, externalAad);

  // Sign
  const signature = await signECDSA(sigStructure, key, algInfo);

  // Build COSE_Sign1: [protected, unprotected, payload, signature]
  const coseSign1 = [
    protectedBytes,
    unprotectedHeader,
    payloadBytes,
    signature,
  ];

  // Return tagged COSE_Sign1
  return cbor.encode(new cbor.Tag(COSE_Sign1_Tag, coseSign1));
}

/**
 * Verifies a COSE_Sign1 message
 * 
 * @param {Uint8Array} coseSign1 - The COSE_Sign1 message
 * @param {Object} key - The verification key
 * @param {Uint8Array} key.x - Public key 'x' coordinate
 * @param {Uint8Array} key.y - Public key 'y' coordinate
 * @param {Uint8Array} [externalAad] - External additional authenticated data
 * @returns {Promise<Uint8Array>} - The verified payload
 * @throws {Error} If verification fails
 */
export async function verify(coseSign1, key, externalAad = new Uint8Array(0)) {
  if (!coseSign1) {
    throw new Error('COSE_Sign1 message is required');
  }
  if (!key || !key.x || !key.y) {
    throw new Error('key must include x and y components');
  }

  // Decode COSE_Sign1
  const decoded = cbor.decode(coseSign1, cborDecodeOptions);
  
  // Handle tagged or untagged
  const structure = decoded instanceof cbor.Tag ? decoded.contents : decoded;
  
  if (!Array.isArray(structure) || structure.length !== 4) {
    throw new Error('Invalid COSE_Sign1 structure');
  }

  const [protectedBytesRaw, , payloadRaw, signatureRaw] = structure;

  // Create copies of byte arrays to avoid issues with views over shared buffers
  const protectedBytes = copyBytes(protectedBytesRaw);
  const payload = copyBytes(payloadRaw);
  const signature = copyBytes(signatureRaw);

  // Decode protected header to get algorithm
  let protectedHeader = new Map();
  if (protectedBytes && protectedBytes.length > 0) {
    const decodedProtected = cbor.decode(protectedBytes, cborDecodeOptions);
    protectedHeader = decodedProtected instanceof Map ? decodedProtected : new Map(Object.entries(decodedProtected));
  }

  const alg = protectedHeader.get(HeaderParam.Algorithm);
  if (alg === undefined) {
    throw new Error('Algorithm not found in protected header');
  }

  const algInfo = AlgInfo[alg];
  if (!algInfo) {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  // Create Sig_structure
  const sigStructure = createSigStructure(protectedBytes, payload, externalAad);

  // Verify signature
  const isValid = await verifyECDSA(sigStructure, signature, key, algInfo);
  
  if (!isValid) {
    throw new Error('Signature verification failed');
  }

  return payload;
}

/**
 * Decodes a COSE_Sign1 message and extracts its components
 * 
 * @param {Uint8Array} coseSign1 - The COSE_Sign1 message
 * @returns {Object} - Decoded components
 */
export function decode(coseSign1) {
  if (!coseSign1) {
    throw new Error('COSE_Sign1 message is required');
  }

  const decoded = cbor.decode(coseSign1, cborDecodeOptions);
  const structure = decoded instanceof cbor.Tag ? decoded.contents : decoded;
  
  if (!Array.isArray(structure) || structure.length !== 4) {
    throw new Error('Invalid COSE_Sign1 structure');
  }

  const [protectedBytesRaw, unprotectedHeader, payloadRaw, signatureRaw] = structure;
  
  // Create copies of byte arrays to avoid issues with views over shared buffers
  const protectedBytes = copyBytes(protectedBytesRaw);
  const payload = copyBytes(payloadRaw);
  const signature = copyBytes(signatureRaw);

  // Decode protected header
  let protectedHeader = new Map();
  if (protectedBytes && protectedBytes.length > 0) {
    const decodedHeader = cbor.decode(protectedBytes, cborDecodeOptions);
    protectedHeader = decodedHeader instanceof Map 
      ? decodedHeader 
      : new Map(Object.entries(decodedHeader).map(([k, v]) => [Number(k), v]));
  }

  // Ensure unprotected header is a Map
  let unprotected = unprotectedHeader;
  if (!(unprotected instanceof Map)) {
    unprotected = new Map(Object.entries(unprotected || {}).map(([k, v]) => [Number(k), v]));
  }

  return {
    protectedHeader,
    unprotectedHeader: unprotected,
    payload,
    signature,
  };
}

/**
 * ECDSA signing using Node.js crypto
 */
async function signECDSA(data, key, algInfo) {
  const jwk = {
    kty: 'EC',
    crv: algInfo.curve,
    d: Buffer.from(key.d).toString('base64url'),
    x: Buffer.from(key.x).toString('base64url'),
    y: Buffer.from(key.y).toString('base64url'),
  };

  const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const signature = crypto.sign(null, data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  
  return new Uint8Array(signature);
}

/**
 * ECDSA verification using Node.js crypto
 */
async function verifyECDSA(data, signature, key, algInfo) {
  // Ensure we have a copy of the signature to avoid view issues
  let sigBytes;
  if (signature instanceof Uint8Array) {
    sigBytes = new Uint8Array(signature.length);
    sigBytes.set(signature);
  } else if (ArrayBuffer.isView(signature)) {
    sigBytes = new Uint8Array(signature.buffer, signature.byteOffset, signature.byteLength);
    const copy = new Uint8Array(sigBytes.length);
    copy.set(sigBytes);
    sigBytes = copy;
  } else {
    sigBytes = new Uint8Array(Buffer.from(signature));
  }
  
  const jwk = {
    kty: 'EC',
    crv: algInfo.curve,
    x: Buffer.from(key.x).toString('base64url'),
    y: Buffer.from(key.y).toString('base64url'),
  };

  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const sigBuffer = Buffer.from(sigBytes);
  
  return crypto.verify(null, data, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sigBuffer);
}

/**
 * Generates an EC key pair for COSE signing
 * 
 * @param {number} [alg=Alg.ES256] - The algorithm identifier
 * @returns {Object} - { privateKey, publicKey }
 */
export function generateKeyPair(alg = Alg.ES256) {
  const algInfo = AlgInfo[alg];
  if (!algInfo) {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: algInfo.curve,
  });

  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicJwk = publicKey.export({ format: 'jwk' });

  return {
    privateKey: {
      d: new Uint8Array(Buffer.from(privateJwk.d, 'base64url')),
      x: new Uint8Array(Buffer.from(privateJwk.x, 'base64url')),
      y: new Uint8Array(Buffer.from(privateJwk.y, 'base64url')),
    },
    publicKey: {
      x: new Uint8Array(Buffer.from(publicJwk.x, 'base64url')),
      y: new Uint8Array(Buffer.from(publicJwk.y, 'base64url')),
    },
  };
}

