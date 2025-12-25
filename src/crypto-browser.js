/**
 * Browser-compatible crypto shim using Web Crypto API
 * 
 * This provides the crypto functions needed by sd-cwt in the browser.
 * Includes pure JavaScript SHA-256 for synchronous hashing.
 */

// Use the global crypto object in the browser
const webcrypto = typeof globalThis.crypto !== 'undefined' ? globalThis.crypto : null;

if (!webcrypto) {
  throw new Error('Web Crypto API not available. Are you running in a secure context (HTTPS)?');
}

/**
 * Pure JavaScript SHA-256 implementation for synchronous hashing in browser
 * Based on the FIPS 180-4 specification
 */
const SHA256 = (() => {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  const H_INIT = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);

  function rotr(x, n) {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
  }

  function ch(x, y, z) {
    return ((x & y) ^ (~x & z)) >>> 0;
  }

  function maj(x, y, z) {
    return ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
  }

  function sigma0(x) {
    return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0;
  }

  function sigma1(x) {
    return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0;
  }

  function gamma0(x) {
    return (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) >>> 0;
  }

  function gamma1(x) {
    return (rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10)) >>> 0;
  }

  function hash(message) {
    // Pre-processing: adding padding bits
    const msgLen = message.length;
    const bitLen = msgLen * 8;
    
    // Calculate padded length: message + 1 byte (0x80) + padding + 8 bytes (length)
    const padLen = ((msgLen + 9 + 63) & ~63);
    const padded = new Uint8Array(padLen);
    padded.set(message);
    padded[msgLen] = 0x80;
    
    // Append length in bits as 64-bit big-endian
    const view = new DataView(padded.buffer);
    view.setUint32(padLen - 4, bitLen, false);
    
    // Initialize hash values
    const H = new Uint32Array(H_INIT);
    const W = new Uint32Array(64);
    
    // Process each 512-bit block
    for (let i = 0; i < padLen; i += 64) {
      // Prepare message schedule
      for (let t = 0; t < 16; t++) {
        W[t] = view.getUint32(i + t * 4, false);
      }
      for (let t = 16; t < 64; t++) {
        W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
      }
      
      // Initialize working variables
      let a = H[0], b = H[1], c = H[2], d = H[3];
      let e = H[4], f = H[5], g = H[6], h = H[7];
      
      // Main loop
      for (let t = 0; t < 64; t++) {
        const T1 = (h + sigma1(e) + ch(e, f, g) + K[t] + W[t]) >>> 0;
        const T2 = (sigma0(a) + maj(a, b, c)) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + T1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (T1 + T2) >>> 0;
      }
      
      // Update hash values
      H[0] = (H[0] + a) >>> 0;
      H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0;
      H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0;
      H[7] = (H[7] + h) >>> 0;
    }
    
    // Produce final hash
    const result = new Uint8Array(32);
    const resultView = new DataView(result.buffer);
    for (let i = 0; i < 8; i++) {
      resultView.setUint32(i * 4, H[i], false);
    }
    return result;
  }

  return { hash };
})();

/**
 * Create a hash using Web Crypto API
 * @param {string} algorithm - 'sha256', 'sha384', or 'sha512'
 * @param {Uint8Array} data - Data to hash
 * @returns {Promise<Uint8Array>}
 */
async function hashAsync(algorithm, data) {
  const algoMap = {
    'sha256': 'SHA-256',
    'sha384': 'SHA-384',
    'sha512': 'SHA-512',
  };
  const algoName = algoMap[algorithm.toLowerCase()];
  if (!algoName) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
  const hashBuffer = await webcrypto.subtle.digest(algoName, data);
  return new Uint8Array(hashBuffer);
}

/**
 * Synchronous hash implementation for browser using pure JavaScript
 * Compatible with Node.js crypto.createHash interface
 */
function createHash(algorithm) {
  const normalizedAlg = algorithm.toLowerCase().replace('-', '');
  if (normalizedAlg !== 'sha256') {
    throw new Error(`Synchronous hashing only supports sha256 in browser, got: ${algorithm}`);
  }
  
  let data = new Uint8Array(0);
  
  return {
    update(input) {
      // Concatenate input to data
      const inputBytes = input instanceof Uint8Array ? input : 
        (ArrayBuffer.isView(input) ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) :
        (typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input)));
      const newData = new Uint8Array(data.length + inputBytes.length);
      newData.set(data);
      newData.set(inputBytes, data.length);
      data = newData;
      return this;
    },
    digest() {
      return SHA256.hash(data);
    },
  };
}

/**
 * Generate random bytes
 * @param {number} size 
 * @returns {Uint8Array}
 */
function randomBytes(size) {
  const bytes = new Uint8Array(size);
  webcrypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Create ECDSA key pair
 */
async function generateKeyPairAsync(namedCurve) {
  const keyPair = await webcrypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve,
    },
    true,
    ['sign', 'verify']
  );

  // Export to JWK format
  const privateJwk = await webcrypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);

  // Convert base64url to Uint8Array
  const base64urlDecode = (str) => {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  };

  return {
    privateKey: {
      d: base64urlDecode(privateJwk.d),
      x: base64urlDecode(privateJwk.x),
      y: base64urlDecode(privateJwk.y),
    },
    publicKey: {
      x: base64urlDecode(publicJwk.x),
      y: base64urlDecode(publicJwk.y),
    },
  };
}

/**
 * Sign data with ECDSA
 */
async function signAsync(algorithm, privateKey, data) {
  const curveMap = {
    'ES256': 'P-256',
    'ES384': 'P-384',
    'ES512': 'P-521',
  };
  const hashMap = {
    'ES256': 'SHA-256',
    'ES384': 'SHA-384',
    'ES512': 'SHA-512',
  };
  
  const namedCurve = curveMap[algorithm];
  const hashName = hashMap[algorithm];
  
  if (!namedCurve) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  // Convert key to JWK format
  const base64urlEncode = (bytes) => {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const jwk = {
    kty: 'EC',
    crv: namedCurve,
    x: base64urlEncode(privateKey.x),
    y: base64urlEncode(privateKey.y),
    d: base64urlEncode(privateKey.d),
  };

  const key = await webcrypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve },
    false,
    ['sign']
  );

  const signature = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: hashName },
    key,
    data
  );

  return new Uint8Array(signature);
}

/**
 * Verify ECDSA signature
 */
async function verifyAsync(algorithm, publicKey, signature, data) {
  const curveMap = {
    'ES256': 'P-256',
    'ES384': 'P-384',
    'ES512': 'P-521',
  };
  const hashMap = {
    'ES256': 'SHA-256',
    'ES384': 'SHA-384',
    'ES512': 'SHA-512',
  };
  
  const namedCurve = curveMap[algorithm];
  const hashName = hashMap[algorithm];
  
  if (!namedCurve) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  // Convert key to JWK format
  const base64urlEncode = (bytes) => {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const jwk = {
    kty: 'EC',
    crv: namedCurve,
    x: base64urlEncode(publicKey.x),
    y: base64urlEncode(publicKey.y),
  };

  const key = await webcrypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve },
    false,
    ['verify']
  );

  return webcrypto.subtle.verify(
    { name: 'ECDSA', hash: hashName },
    key,
    signature,
    data
  );
}

/**
 * Create private key from JWK (browser-compatible)
 * @param {Object} options - Key options
 * @param {Object} options.key - JWK key object
 * @returns {Object} - CryptoKey wrapper
 */
function createPrivateKey(options) {
  // Return a wrapper that will be used with the WebCrypto-based sign function
  return {
    _jwk: options.key,
    _type: 'private',
  };
}

/**
 * Create public key from JWK (browser-compatible)
 * @param {Object} options - Key options
 * @param {Object} options.key - JWK key object
 * @returns {Object} - CryptoKey wrapper
 */
function createPublicKey(options) {
  return {
    _jwk: options.key,
    _type: 'public',
  };
}

/**
 * Convert any buffer-like to Uint8Array
 * Always creates a copy to avoid issues with views over shared buffers.
 */
function toBytes(data) {
  if (!data) {
    return new Uint8Array(0);
  }
  
  // For Uint8Array, create a copy to avoid view issues
  if (data instanceof Uint8Array) {
    const copy = new Uint8Array(data.length);
    copy.set(data);
    return copy;
  }
  
  // For other ArrayBufferViews, copy the data
  if (ArrayBuffer.isView(data)) {
    const view = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    const copy = new Uint8Array(view.length);
    copy.set(view);
    return copy;
  }
  
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  
  if (Array.isArray(data)) {
    return new Uint8Array(data);
  }
  
  // Handle Buffer-like objects with buffer property
  if (data && typeof data === 'object' && 'buffer' in data && data.buffer instanceof ArrayBuffer) {
    const view = new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength || data.length);
    const copy = new Uint8Array(view.length);
    copy.set(view);
    return copy;
  }
  
  return new Uint8Array(data);
}

/**
 * Sign data with a private key (browser-compatible)
 * @param {null} algorithm - Unused, algorithm is inferred from key
 * @param {Uint8Array} data - Data to sign
 * @param {Object} options - Signing options
 * @param {Object} options.key - Key wrapper from createPrivateKey
 * @param {string} options.dsaEncoding - Signature encoding
 * @returns {Promise<Uint8Array>} - Signature
 */
async function sign(algorithm, data, options) {
  if (!options || !options.key) {
    throw new Error('sign: options.key is required');
  }
  if (!options.key._jwk) {
    throw new Error('sign: options.key._jwk is missing. Did you use createPrivateKey?');
  }
  
  const jwk = options.key._jwk;
  const namedCurve = jwk.crv;
  
  if (!namedCurve) {
    throw new Error(`sign: JWK missing crv property. Got: ${JSON.stringify(Object.keys(jwk))}`);
  }
  
  const hashMap = {
    'P-256': 'SHA-256',
    'P-384': 'SHA-384',
    'P-521': 'SHA-512',
  };
  const hashName = hashMap[namedCurve];
  
  if (!hashName) {
    throw new Error(`sign: Unsupported curve: ${namedCurve}`);
  }
  
  // Ensure data is Uint8Array
  const dataBytes = toBytes(data);
  
  const cryptoKey = await webcrypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve },
    false,
    ['sign']
  );
  
  const signature = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: hashName },
    cryptoKey,
    dataBytes
  );
  
  return new Uint8Array(signature);
}

/**
 * Verify signature with a public key (browser-compatible)
 * @param {null} algorithm - Unused, algorithm is inferred from key
 * @param {Uint8Array} data - Data that was signed
 * @param {Object} options - Verification options
 * @param {Object} options.key - Key wrapper from createPublicKey
 * @param {string} options.dsaEncoding - Signature encoding
 * @param {Uint8Array} signature - Signature to verify
 * @returns {Promise<boolean>} - True if valid
 */
async function verify(algorithm, data, options, signature) {
  if (!options || !options.key) {
    throw new Error('verify: options.key is required');
  }
  if (!options.key._jwk) {
    throw new Error('verify: options.key._jwk is missing. Did you use createPublicKey?');
  }
  
  const jwk = options.key._jwk;
  const namedCurve = jwk.crv;
  
  if (!namedCurve) {
    throw new Error(`verify: JWK missing crv property. Got: ${JSON.stringify(Object.keys(jwk))}`);
  }
  
  const hashMap = {
    'P-256': 'SHA-256',
    'P-384': 'SHA-384',
    'P-521': 'SHA-512',
  };
  const hashName = hashMap[namedCurve];
  
  if (!hashName) {
    throw new Error(`verify: Unsupported curve: ${namedCurve}`);
  }
  
  // Ensure data and signature are Uint8Arrays
  const dataBytes = toBytes(data);
  const sigBytes = toBytes(signature);
  
  const cryptoKey = await webcrypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve },
    false,
    ['verify']
  );
  
  const result = await webcrypto.subtle.verify(
    { name: 'ECDSA', hash: hashName },
    cryptoKey,
    sigBytes,
    dataBytes
  );
  
  return result;
}

/**
 * Generate key pair synchronously (browser-compatible wrapper)
 * Note: This is async in browser but returns a promise
 */
function generateKeyPairSync(type, options) {
  throw new Error('generateKeyPairSync not available in browser. Use generateKeyPair() async version.');
}

// Export browser-compatible crypto module
export default {
  randomBytes,
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  generateKeyPair: generateKeyPairAsync,
  generateKeyPairSync,
  hashAsync,
  subtle: webcrypto?.subtle,
};

export { 
  randomBytes, 
  createHash, 
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  hashAsync, 
  generateKeyPairAsync, 
  signAsync, 
  verifyAsync,
  generateKeyPairSync,
};

