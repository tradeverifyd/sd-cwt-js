import cose from 'cose-js';
import crypto from 'node:crypto';

/**
 * COSE Sign1 algorithms supported
 */
export const Algorithm = {
  ES256: 'ES256',   // ECDSA w/ SHA-256, P-256 curve
  ES384: 'ES384',   // ECDSA w/ SHA-384, P-384 curve
  ES512: 'ES512',   // ECDSA w/ SHA-512, P-521 curve
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
 * @param {Object} [options.protectedHeaders] - Additional protected headers
 * @param {Object} [options.unprotectedHeaders] - Additional unprotected headers
 * @returns {Promise<Buffer>} The COSE Sign1 message
 */
export async function sign(payload, signerKey, options = {}) {
  const {
    algorithm = Algorithm.ES256,
    kid,
    protectedHeaders = {},
    unprotectedHeaders = {},
  } = options;

  if (!payload) {
    throw new Error('Payload is required');
  }

  if (!signerKey || !signerKey.d || !signerKey.x || !signerKey.y) {
    throw new Error('Signer key must include d, x, and y components');
  }

  // Ensure payload is a Buffer
  const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);

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

  const verifier = {
    key: {
      x: Buffer.isBuffer(verifierKey.x) ? verifierKey.x : Buffer.from(verifierKey.x),
      y: Buffer.isBuffer(verifierKey.y) ? verifierKey.y : Buffer.from(verifierKey.y),
    },
  };

  return await cose.sign.verify(coseSign1, verifier);
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

