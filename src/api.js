/**
 * SD-CWT High-Level API
 * 
 * This module provides a complete API for SD-CWT operations including:
 * - Key generation
 * - Issuer: Create SD-CWTs from claims with "to be redacted" structures
 * - Holder: Select which claims to disclose
 * - Verifier: Verify and reconstruct disclosed claims
 * 
 * References:
 * - draft-ietf-spice-sd-cwt (SD-CWT specification)
 */

import * as cbor from 'cbor2';
import * as coseSign1 from './cose-sign1.js';
import * as sdCwt from './sd-cwt.js';

// Re-export key utilities
export { toBeRedacted, toBeDecoy, MAX_DEPTH, validateClaimsClean, assertClaimsClean, ClaimKey, MediaType, HeaderParam } from './sd-cwt.js';
export { 
  generateKeyPair, 
  Algorithm, 
  CoseKeyParam, 
  CoseKeyType, 
  CoseCurve, 
  isCoseKey, 
  coseKeyToInternal, 
  internalToCoseKey, 
  getAlgorithmFromCoseKey,
  serializeCoseKey,
  deserializeCoseKey,
  coseKeyToHex,
  coseKeyFromHex,
} from './cose-sign1.js';

/**
 * SD-CWT Issuer API
 * 
 * Creates signed SD-CWT tokens from claims that may contain
 * "to be redacted" tagged values.
 */
export const Issuer = {
  /**
   * Creates a signed SD-CWT from claims with optional redactable values.
   * 
   * Per spec Section 7: The payload MUST include a key confirmation element (cnf)
   * for the Holder's public key. Either sub or redacted sub MUST be present.
   * 
   * Claims can include:
   * - Regular claims: included directly in the token
   * - Redactable claims: wrapped with toBeRedacted(), stored as hashes with disclosures
   * - Decoys: wrapped with toBeDecoy(count), adds fake redacted entries
   * 
   * @param {Object} options - Issuance options
   * @param {Map} options.claims - Claims map, MUST contain cnf (8) claim with holder's public key
   * @param {Object} options.privateKey - Issuer's private key {d, x, y}
   * @param {string} [options.algorithm='ES256'] - Signing algorithm
   * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm for redactions
   * @param {string|Buffer} [options.kid] - Key identifier
   * @param {boolean} [options.strict=false] - If true, enforce max depth of 16 (per spec section 6.5)
   * @returns {Promise<{token: Buffer, disclosures: Uint8Array[]}>} The signed SD-CWT and disclosures
   * 
   * @example
   * const claims = new Map([
   *   [1, 'issuer.example'],                    // iss - public
   *   [8, { 1: { 1: 2, -1: 1, -2: holderKey.x, -3: holderKey.y } }], // cnf - REQUIRED
   *   [toBeRedacted(500), 'sensitive-value'],   // redactable claim
   * ]);
   * 
   * const { token, disclosures } = await Issuer.issue({
   *   claims,
   *   privateKey: issuerKey.privateKey,
   * });
   */
  async issue({ claims, privateKey, algorithm = 'ES256', hashAlgorithm = 'sha256', kid, strict = false }) {
    if (!(claims instanceof Map)) {
      throw new Error('Claims must be a Map');
    }

    // Per spec Section 7: cnf (8) claim is REQUIRED and MUST NOT be redacted
    // Check for cnf key (either plain or wrapped in toBeRedacted)
    let hasCnf = false;
    let cnfIsRedacted = false;
    
    for (const key of claims.keys()) {
      if (key === sdCwt.ClaimKey.Cnf) {
        hasCnf = true;
        break;
      }
      if (sdCwt.isToBeRedacted(key) && sdCwt.getTagContents(key) === sdCwt.ClaimKey.Cnf) {
        hasCnf = true;
        cnfIsRedacted = true;
        break;
      }
    }

    if (!hasCnf) {
      throw new Error('Claims MUST include cnf (8) claim with Holder\'s public key (per spec Section 7)');
    }

    if (cnfIsRedacted) {
      throw new Error('cnf (8) claim MUST NOT be redacted (per spec Section 7)');
    }

    // Process claims to handle toBeRedacted and toBeDecoy tags
    const { claims: processedClaims, disclosures } = sdCwt.processToBeRedacted(claims, { hashAlg: hashAlgorithm, strict });

    // Encode claims as CBOR payload
    const payload = cbor.encode(processedClaims);

    // Build custom protected headers for SD-CWT
    const customProtectedHeaders = new Map();
    
    // Add typ header for SD-CWT
    customProtectedHeaders.set(sdCwt.HeaderParam.Typ, sdCwt.MediaType.SdCwt);
    
    // Add sd_alg header if there are disclosures
    if (disclosures.length > 0) {
      customProtectedHeaders.set(sdCwt.HeaderParam.SdAlg, sdCwt.SdAlg.SHA256);
    }

    // Sign the token
    const token = await coseSign1.sign(payload, privateKey, {
      algorithm,
      kid,
      customProtectedHeaders: customProtectedHeaders.size > 0 ? customProtectedHeaders : undefined,
    });

    return { token, disclosures };
  },
};

/**
 * SD-CWT Holder API
 * 
 * Allows holders to select which disclosures to present,
 * enabling selective disclosure of claims.
 * Per spec Section 8.1: Holder MUST create a Key Binding Token (SD-KBT) for every presentation.
 */
export const Holder = {
  /**
   * Parses an SD-CWT token to extract the redacted claims structure.
   * Does not verify the signature.
   * 
   * @param {Buffer|Uint8Array} token - The SD-CWT token
   * @returns {{claims: Map, protectedHeaders: Map, unprotectedHeaders: Map}} Parsed token data
   */
  parse(token) {
    const { protectedHeaders, unprotectedHeaders } = coseSign1.getHeaders(token);
    
    // Decode the token to get the payload
    const decoded = cbor.decode(token, sdCwt.cborDecodeOptions);
    
    // COSE_Sign1 structure: [protected, unprotected, payload, signature]
    // But it's wrapped in a tag, so we need the contents
    const coseArray = decoded.contents || decoded;
    const payloadBytes = coseArray[2];
    
    const claims = cbor.decode(payloadBytes, sdCwt.cborDecodeOptions);

    return { claims, protectedHeaders, unprotectedHeaders };
  },

  /**
   * Selects which disclosures to present based on claim names/keys.
   * 
   * @param {Uint8Array[]} allDisclosures - All disclosures from the issuer
   * @param {Array<string|number>} claimNames - Claim names/keys to disclose
   * @returns {Uint8Array[]} Selected disclosures for presentation
   */
  selectDisclosures(allDisclosures, claimNames) {
    const selectedDisclosures = [];
    const claimNameSet = new Set(claimNames);

    for (const disclosure of allDisclosures) {
      const decoded = sdCwt.decodeDisclosure(disclosure);
      
      // Check if this is a claim-key disclosure (has claimName)
      if (decoded.claimName !== undefined && claimNameSet.has(decoded.claimName)) {
        selectedDisclosures.push(disclosure);
      }
      
      // For array element disclosures (no claimName), include if value matches
      // This allows selecting array elements by their value
      if (decoded.claimName === undefined && !decoded.isDecoy) {
        if (claimNames.includes(decoded.value)) {
          selectedDisclosures.push(disclosure);
        }
      }
    }

    return selectedDisclosures;
  },

  /**
   * Creates a Key Binding Token (SD-KBT) presentation per spec Section 8.1.
   * 
   * The SD-KBT is a COSE_Sign1 signed by the Holder's private key that:
   * - Contains the SD-CWT (with disclosures) in the kcwt protected header
   * - Has aud (audience) claim REQUIRED per spec
   * - Has iat (issued at) claim REQUIRED per spec
   * - Optionally includes cnonce (client nonce)
   * 
   * @param {Object} options - Presentation options
   * @param {Buffer|Uint8Array} options.token - The original SD-CWT token
   * @param {Uint8Array[]} options.selectedDisclosures - Disclosures to include
   * @param {Object} options.holderPrivateKey - Holder's private key (matching cnf in SD-CWT)
   * @param {string} options.audience - The intended verifier (aud claim) - REQUIRED
   * @param {Uint8Array|Buffer} [options.nonce] - Optional nonce from verifier (cnonce claim)
   * @param {string} [options.algorithm='ES256'] - Signing algorithm
   * @returns {Promise<Buffer>} The signed SD-KBT presentation
   */
  async present({ token, selectedDisclosures, holderPrivateKey, audience, nonce, algorithm = 'ES256' }) {
    if (!audience) {
      throw new Error('audience (aud) is REQUIRED in SD-KBT per spec Section 8.1');
    }
    if (!holderPrivateKey) {
      throw new Error('holderPrivateKey is REQUIRED to sign the SD-KBT');
    }

    // Debug: Log token info at start
    console.log('[Holder.present] token type:', token?.constructor?.name);
    console.log('[Holder.present] token length:', token?.length);
    console.log('[Holder.present] token instanceof Uint8Array:', token instanceof Uint8Array);

    // Ensure token is Uint8Array
    const tokenBytes = Buffer.isBuffer(token) 
      ? new Uint8Array(token.buffer, token.byteOffset, token.length)
      : (token instanceof Uint8Array ? token : new Uint8Array(token));
    
    console.log('[Holder.present] tokenBytes length:', tokenBytes?.length);
    
    // Ensure disclosures are Uint8Arrays
    const disclosureBytes = selectedDisclosures.map(d => 
      Buffer.isBuffer(d) 
        ? new Uint8Array(d.buffer, d.byteOffset, d.length)
        : (d instanceof Uint8Array ? d : new Uint8Array(d))
    );

    // Build the SD-CWT with disclosures in unprotected header
    // We need to re-encode the SD-CWT with disclosures in the unprotected header
    const sdCwtWithDisclosures = embedDisclosuresInToken(tokenBytes, disclosureBytes);

    // Build SD-KBT payload per spec Section 8.1
    // REQUIRED: aud (3), iat (6)
    // OPTIONAL: cnonce (39), exp, nbf
    const kbtPayload = new Map([
      [sdCwt.ClaimKey.Aud, audience],
      [sdCwt.ClaimKey.Iat, Math.floor(Date.now() / 1000)],
    ]);

    if (nonce) {
      const nonceBytes = Buffer.isBuffer(nonce)
        ? new Uint8Array(nonce.buffer, nonce.byteOffset, nonce.length)
        : (nonce instanceof Uint8Array ? nonce : new Uint8Array(nonce));
      kbtPayload.set(sdCwt.ClaimKey.Cnonce, nonceBytes);
    }

    // Build SD-KBT protected headers
    // REQUIRED: typ, alg, kcwt (containing SD-CWT)
    const kbtProtectedHeaders = new Map([
      [sdCwt.HeaderParam.Typ, sdCwt.MediaType.KbCwt],
      [sdCwt.HeaderParam.Kcwt, sdCwtWithDisclosures],
    ]);

    // Encode the payload
    const payloadEncoded = cbor.encode(kbtPayload);

    // Sign the SD-KBT with Holder's private key
    const kbt = await coseSign1.sign(payloadEncoded, holderPrivateKey, {
      algorithm,
      customProtectedHeaders: kbtProtectedHeaders,
    });

    return kbt;
  },

  /**
   * Filters disclosures by matching against redacted hashes in the claims.
   * Only returns disclosures that match actual redacted entries.
   * 
   * @param {Map} claims - The redacted claims from the token
   * @param {Uint8Array[]} disclosures - Disclosures to filter
   * @param {string} [hashAlgorithm='sha256'] - Hash algorithm used
   * @returns {Uint8Array[]} Valid disclosures that match redacted entries
   */
  filterValidDisclosures(claims, disclosures, hashAlgorithm = 'sha256') {
    // Build set of all redacted hashes in the claims
    const redactedHashes = new Set();
    collectRedactedHashes(claims, redactedHashes);

    // Filter disclosures that match
    const validDisclosures = [];
    for (const disclosure of disclosures) {
      const hash = sdCwt.hashDisclosure(disclosure, hashAlgorithm);
      const hexHash = Buffer.from(hash).toString('hex');
      if (redactedHashes.has(hexHash)) {
        validDisclosures.push(disclosure);
      }
    }

    return validDisclosures;
  },
};

/**
 * Embeds disclosures into the SD-CWT's unprotected header
 * Per RFC 9528 Section 4.4.1: kcwt contains a CWT but without the CBOR tag.
 * So we return the COSE_Sign1 array wrapped in Tag 18 (as raw bytes).
 * 
 * @param {Uint8Array} token - The original SD-CWT
 * @param {Uint8Array[]} disclosures - The disclosures to embed
 * @returns {Uint8Array} The SD-CWT with disclosures in unprotected header
 */
function embedDisclosuresInToken(token, disclosures) {
  // Decode the COSE_Sign1 structure
  const decoded = cbor.decode(token, sdCwt.cborDecodeOptions);
  const coseArray = decoded.contents || decoded;
  
  // COSE_Sign1: [protected, unprotected, payload, signature]
  const [protectedBytes, unprotectedMap, payload, signature] = coseArray;
  
  // Debug: Log signature info
  console.log('[embedDisclosuresInToken] signature type:', signature?.constructor?.name);
  console.log('[embedDisclosuresInToken] signature length:', signature?.length);
  console.log('[embedDisclosuresInToken] signature instanceof Uint8Array:', signature instanceof Uint8Array);
  if (signature && signature.length > 0) {
    console.log('[embedDisclosuresInToken] first 5 bytes:', Array.from(signature.slice(0, 5)).map(b => b.toString(16).padStart(2, '0')).join(''));
  }
  
  // Add disclosures to unprotected header
  const newUnprotected = unprotectedMap instanceof Map ? new Map(unprotectedMap) : new Map();
  newUnprotected.set(sdCwt.HeaderParam.SdClaims, disclosures);
  
  // Re-encode as COSE_Sign1 (tag 18) and return as Uint8Array
  // The kcwt header expects raw CBOR bytes of the CWT
  const newCoseArray = [protectedBytes, newUnprotected, payload, signature];
  const encoded = cbor.encode(new cbor.Tag(18, newCoseArray));
  // Ensure it's a Uint8Array (not Buffer) for proper handling
  return Buffer.isBuffer(encoded) 
    ? new Uint8Array(encoded.buffer, encoded.byteOffset, encoded.length)
    : new Uint8Array(encoded);
}

/**
 * Recursively collects all redacted hashes from claims
 */
function collectRedactedHashes(claims, hashSet) {
  if (claims instanceof Map) {
    for (const [key, value] of claims) {
      if (sdCwt.isRedactedKeysKey(key)) {
        // This is the array of redacted key hashes
        for (const hash of value) {
          const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);
          hashSet.add(Buffer.from(hashBytes).toString('hex'));
        }
      } else if (value instanceof Map) {
        collectRedactedHashes(value, hashSet);
      } else if (Array.isArray(value)) {
        collectRedactedHashesFromArray(value, hashSet);
      }
    }
  }
}

function collectRedactedHashesFromArray(array, hashSet) {
  for (const element of array) {
    if (sdCwt.isRedactedClaimElement(element)) {
      const hashBytes = element.contents instanceof Uint8Array 
        ? element.contents 
        : new Uint8Array(element.contents);
      hashSet.add(Buffer.from(hashBytes).toString('hex'));
    } else if (element instanceof Map) {
      collectRedactedHashes(element, hashSet);
    } else if (Array.isArray(element)) {
      collectRedactedHashesFromArray(element, hashSet);
    }
  }
}

/**
 * SD-CWT Verifier API
 * 
 * Verifies SD-CWT presentations (SD-KBT) and reconstructs disclosed claims.
 * Per spec Section 9: Verifier MUST validate both the SD-KBT and the embedded SD-CWT.
 */
export const Verifier = {
  /**
   * Verifies an SD-KBT (Key Binding Token) presentation per spec Section 9.
   * 
   * This function:
   * 1. Extracts the SD-CWT from the kcwt header in the SD-KBT
   * 2. Verifies the SD-CWT signature using the Issuer's public key
   * 3. Extracts the confirmation key (cnf) from the SD-CWT
   * 4. Verifies the SD-KBT signature using the confirmation key
   * 5. Validates audience matches the expected value
   * 6. Validates nonce if provided
   * 7. Reconstructs claims from disclosures
   * 
   * @param {Object} options - Verification options
   * @param {Buffer|Uint8Array} options.presentation - The SD-KBT presentation
   * @param {Object} options.issuerPublicKey - Issuer's public key {x, y}
   * @param {string} options.expectedAudience - The expected audience value (REQUIRED per spec Section 9)
   * @param {Uint8Array|Buffer} [options.expectedNonce] - Expected nonce if one was sent to Holder
   * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm used
   * @param {boolean} [options.strict=false] - If true, enforce max depth of 16 (per spec section 6.5)
   * @param {boolean} [options.requireClean=false] - If true, verify claims have no remaining SD-CWT artifacts
   * @returns {Promise<{claims: Map, redactedKeys: Uint8Array[], sdCwtClaims: Map, kbtPayload: Map, headers: Object}>} Verified result
   * @throws {Error} If verification fails
   * 
   * @example
   * const result = await Verifier.verify({
   *   presentation: kbt,
   *   issuerPublicKey: issuerKey.publicKey,
   *   expectedAudience: 'https://verifier.example/app',
   * });
   */
  async verify({ presentation, issuerPublicKey, expectedAudience, expectedNonce, hashAlgorithm = 'sha256', strict = false, requireClean = false }) {
    if (!expectedAudience) {
      throw new Error('expectedAudience is REQUIRED per spec Section 9 Step 6');
    }

    // Step 1: Parse the SD-KBT and extract the SD-CWT from kcwt header
    const kbtHeaders = coseSign1.getHeaders(presentation);
    let sdCwtBytes = kbtHeaders.protectedHeaders.get(sdCwt.HeaderParam.Kcwt);
    
    if (!sdCwtBytes) {
      throw new Error('Invalid SD-KBT: missing kcwt header parameter containing SD-CWT');
    }

    // Handle case where kcwt was decoded as a CBOR Tag or Array instead of bytes
    // The CBOR library may decode embedded CBOR structures
    if (sdCwtBytes instanceof cbor.Tag) {
      // It's a decoded CBOR Tag, re-encode to bytes
      sdCwtBytes = cbor.encode(sdCwtBytes);
    } else if (Array.isArray(sdCwtBytes) && sdCwtBytes.length === 4) {
      // It's a decoded COSE_Sign1 array, wrap in Tag and encode
      sdCwtBytes = cbor.encode(new cbor.Tag(18, sdCwtBytes));
    }

    // Ensure sdCwtBytes is Uint8Array
    if (Buffer.isBuffer(sdCwtBytes)) {
      sdCwtBytes = new Uint8Array(sdCwtBytes.buffer, sdCwtBytes.byteOffset, sdCwtBytes.length);
    }

    // Validate SD-KBT typ header
    const kbtTyp = kbtHeaders.protectedHeaders.get(sdCwt.HeaderParam.Typ);
    if (kbtTyp !== sdCwt.MediaType.KbCwt) {
      throw new Error(`Invalid SD-KBT: typ must be "${sdCwt.MediaType.KbCwt}", got "${kbtTyp}"`);
    }

    // Step 2: Verify the SD-CWT signature using Issuer's public key
    const sdCwtPayloadBytes = await coseSign1.verify(sdCwtBytes, issuerPublicKey);
    const sdCwtClaims = cbor.decode(sdCwtPayloadBytes, sdCwt.cborDecodeOptions);

    // Step 3: Extract the confirmation key from cnf claim
    const cnfClaim = sdCwtClaims.get(sdCwt.ClaimKey.Cnf);
    if (!cnfClaim) {
      throw new Error('Invalid SD-CWT: missing cnf (8) claim with Holder confirmation key');
    }

    // Extract the public key from cnf claim
    // cnf structure: { 1: { 1: kty, -1: crv, -2: x, -3: y } } (COSE_Key in map)
    const holderPublicKey = extractPublicKeyFromCnf(cnfClaim);

    // Step 4: Verify the SD-KBT signature using the confirmation key
    const kbtPayloadBytes = await coseSign1.verify(presentation, holderPublicKey);
    const kbtPayload = cbor.decode(kbtPayloadBytes, sdCwt.cborDecodeOptions);

    // Step 5: Validate SD-KBT has required claims (aud, iat)
    const kbtAud = kbtPayload.get(sdCwt.ClaimKey.Aud);
    if (!kbtAud) {
      throw new Error('Invalid SD-KBT: missing aud (3) claim');
    }
    const kbtIat = kbtPayload.get(sdCwt.ClaimKey.Iat);
    if (kbtIat === undefined) {
      throw new Error('Invalid SD-KBT: missing iat (6) claim');
    }

    // Step 6: Validate audience matches
    if (kbtAud !== expectedAudience) {
      throw new Error(`Audience mismatch: expected "${expectedAudience}", got "${kbtAud}"`);
    }

    // Validate SD-CWT audience if present
    const sdCwtAud = sdCwtClaims.get(sdCwt.ClaimKey.Aud);
    if (sdCwtAud && sdCwtAud !== expectedAudience) {
      throw new Error(`SD-CWT audience mismatch: expected "${expectedAudience}", got "${sdCwtAud}"`);
    }

    // Validate nonce if expected
    if (expectedNonce) {
      const kbtNonce = kbtPayload.get(sdCwt.ClaimKey.Cnonce);
      if (!kbtNonce) {
        throw new Error('Expected nonce (cnonce) but none present in SD-KBT');
      }
      const expectedBytes = Buffer.isBuffer(expectedNonce) 
        ? expectedNonce 
        : Buffer.from(expectedNonce);
      const actualBytes = Buffer.isBuffer(kbtNonce) 
        ? kbtNonce 
        : Buffer.from(kbtNonce);
      if (!expectedBytes.equals(actualBytes)) {
        throw new Error('Nonce mismatch');
      }
    }

    // Step 7: Extract disclosures from SD-CWT unprotected header
    const sdCwtHeaders = coseSign1.getHeaders(sdCwtBytes);
    const disclosures = sdCwtHeaders.unprotectedHeaders.get(sdCwt.HeaderParam.SdClaims) || [];

    // Validate disclosures match redacted entries
    const validatedDisclosures = validateDisclosures(sdCwtClaims, disclosures, hashAlgorithm);

    // Reconstruct claims with the provided disclosures
    const { claims, redactedKeys } = sdCwt.reconstructClaims(
      sdCwtClaims, 
      validatedDisclosures, 
      { hashAlg: hashAlgorithm, strict }
    );

    // Optionally verify that claims are clean
    if (requireClean) {
      sdCwt.assertClaimsClean(claims, { strict });
      if (redactedKeys.length > 0) {
        throw new Error(`Claims contain SD-CWT artifacts:\n${redactedKeys.length} undisclosed redacted key(s) remain`);
      }
    }

    return {
      claims,
      redactedKeys,
      sdCwtClaims, // Original SD-CWT claims (for inspection)
      kbtPayload,  // SD-KBT payload (aud, iat, cnonce)
      headers: {
        sdCwt: {
          protected: sdCwtHeaders.protectedHeaders,
          unprotected: sdCwtHeaders.unprotectedHeaders,
        },
        kbt: {
          protected: kbtHeaders.protectedHeaders,
          unprotected: kbtHeaders.unprotectedHeaders,
        },
      },
    };
  },

  /**
   * Verifies a raw SD-CWT token with separate disclosures (no key binding).
   * 
   * WARNING: This method does NOT verify key binding. Per spec, SD-CWT requires
   * key binding (SD-KBT). Use verify() for spec-compliant verification.
   * 
   * This method is provided for testing and backwards compatibility only.
   * 
   * @param {Object} options - Verification options
   * @param {Buffer|Uint8Array} options.token - The SD-CWT token
   * @param {Uint8Array[]} options.disclosures - Disclosures to apply
   * @param {Object} options.publicKey - Issuer's public key {x, y}
   * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm used
   * @param {boolean} [options.strict=false] - If true, enforce max depth of 16
   * @param {boolean} [options.requireClean=false] - If true, verify claims have no remaining SD-CWT artifacts
   * @returns {Promise<{claims: Map, redactedKeys: Uint8Array[], headers: Object}>} Verified result
   * @deprecated Use verify() with proper SD-KBT presentation for spec compliance
   */
  async verifyWithoutKeyBinding({ token, disclosures, publicKey, hashAlgorithm = 'sha256', strict = false, requireClean = false }) {
    // Verify the COSE signature
    const payloadBytes = await coseSign1.verify(token, publicKey);

    // Decode the verified payload as claims
    const redactedClaims = cbor.decode(payloadBytes, sdCwt.cborDecodeOptions);

    // Validate disclosures match redacted entries
    const validatedDisclosures = validateDisclosures(redactedClaims, disclosures, hashAlgorithm);

    // Reconstruct claims with the provided disclosures
    const { claims, redactedKeys } = sdCwt.reconstructClaims(
      redactedClaims, 
      validatedDisclosures, 
      { hashAlg: hashAlgorithm, strict }
    );

    // Optionally verify that claims are clean
    if (requireClean) {
      sdCwt.assertClaimsClean(claims, { strict });
      if (redactedKeys.length > 0) {
        throw new Error(`Claims contain SD-CWT artifacts:\n${redactedKeys.length} undisclosed redacted key(s) remain`);
      }
    }

    // Get headers for metadata
    const { protectedHeaders, unprotectedHeaders } = coseSign1.getHeaders(token);

    return {
      claims,
      redactedKeys,
      headers: {
        protected: protectedHeaders,
        unprotected: unprotectedHeaders,
      },
    };
  },
};

/**
 * Extracts a public key from a cnf claim structure
 * @param {Map|Object} cnfClaim - The cnf claim value
 * @returns {Object} The public key {x, y}
 */
function extractPublicKeyFromCnf(cnfClaim) {
  // cnf can be a Map or object with key 1 (COSE_Key)
  let coseKey;
  if (cnfClaim instanceof Map) {
    coseKey = cnfClaim.get(1); // COSE_Key
  } else if (typeof cnfClaim === 'object') {
    coseKey = cnfClaim[1];
  }

  if (!coseKey) {
    throw new Error('Invalid cnf claim: missing COSE_Key (key 1)');
  }

  // Extract x and y coordinates from COSE_Key
  let x, y;
  if (coseKey instanceof Map) {
    x = coseKey.get(-2);
    y = coseKey.get(-3);
  } else if (typeof coseKey === 'object') {
    x = coseKey[-2] || coseKey['-2'];
    y = coseKey[-3] || coseKey['-3'];
  }

  if (!x || !y) {
    throw new Error('Invalid COSE_Key in cnf: missing x (-2) or y (-3) coordinates');
  }

  return { x, y };
}

/**
 * Validates that disclosures match actual redacted entries in the claims.
 * Returns only the valid disclosures (filters out any that don't match).
 * 
 * @param {Map} redactedClaims - The redacted claims from the token
 * @param {Uint8Array[]} disclosures - Disclosures to validate
 * @param {string} hashAlgorithm - Hash algorithm used
 * @returns {Uint8Array[]} Valid disclosures
 */
function validateDisclosures(redactedClaims, disclosures, hashAlgorithm) {
  // Build set of all redacted hashes
  const redactedHashes = new Set();
  collectRedactedHashes(redactedClaims, redactedHashes);

  // Validate and filter disclosures
  const validDisclosures = [];
  
  for (const disclosure of disclosures) {
    const hash = sdCwt.hashDisclosure(disclosure, hashAlgorithm);
    const hexHash = Buffer.from(hash).toString('hex');
    
    if (!redactedHashes.has(hexHash)) {
      // Disclosure doesn't match any redacted entry - this is suspicious
      // but we'll just filter it out rather than fail completely
      console.warn('Warning: Disclosure does not match any redacted entry');
      continue;
    }

    validDisclosures.push(disclosure);
  }

  return validDisclosures;
}

/**
 * Utility functions for working with SD-CWT
 */
export const Utils = {
  /**
   * Decodes a disclosure to inspect its contents.
   * 
   * @param {Uint8Array} disclosure - The disclosure to decode
   * @returns {{salt: Uint8Array, value: any, claimName?: string|number, isDecoy?: boolean}}
   */
  decodeDisclosure: sdCwt.decodeDisclosure,

  /**
   * Computes the hash of a disclosure.
   * 
   * @param {Uint8Array} disclosure - The disclosure
   * @param {string} [algorithm='sha256'] - Hash algorithm
   * @returns {Uint8Array} The hash
   */
  hashDisclosure: sdCwt.hashDisclosure,

  /**
   * Checks if a claims map has any redacted entries.
   * 
   * @param {Map} claims - The claims to check
   * @returns {boolean} True if there are redacted entries
   */
  hasRedactions(claims) {
    for (const [key, value] of claims) {
      if (sdCwt.isRedactedKeysKey(key)) {
        return true;
      }
      if (value instanceof Map && this.hasRedactions(value)) {
        return true;
      }
      if (Array.isArray(value)) {
        for (const element of value) {
          if (sdCwt.isRedactedClaimElement(element)) {
            return true;
          }
          if (element instanceof Map && this.hasRedactions(element)) {
            return true;
          }
        }
      }
    }
    return false;
  },

  /**
   * Counts the number of redacted entries in claims.
   * 
   * @param {Map} claims - The claims to analyze
   * @returns {{mapKeys: number, arrayElements: number, total: number}} Redaction counts
   */
  countRedactions(claims) {
    let mapKeys = 0;
    let arrayElements = 0;

    function countInMap(map) {
      for (const [key, value] of map) {
        if (sdCwt.isRedactedKeysKey(key)) {
          mapKeys += value.length;
        } else if (value instanceof Map) {
          countInMap(value);
        } else if (Array.isArray(value)) {
          countInArray(value);
        }
      }
    }

    function countInArray(array) {
      for (const element of array) {
        if (sdCwt.isRedactedClaimElement(element)) {
          arrayElements++;
        } else if (element instanceof Map) {
          countInMap(element);
        } else if (Array.isArray(element)) {
          countInArray(element);
        }
      }
    }

    countInMap(claims);
    return { mapKeys, arrayElements, total: mapKeys + arrayElements };
  },

  /**
   * Lists all claim names/keys that are currently redacted.
   * Only works for map key redactions, not array elements.
   * Requires disclosures to determine the original claim names.
   * 
   * @param {Uint8Array[]} disclosures - All available disclosures
   * @returns {Array<string|number>} List of redacted claim names
   */
  getDisclosableClaimNames(disclosures) {
    const names = [];
    for (const disclosure of disclosures) {
      const decoded = sdCwt.decodeDisclosure(disclosure);
      if (decoded.claimName !== undefined) {
        names.push(decoded.claimName);
      }
    }
    return names;
  },

  /**
   * CBOR decode options that ensure Maps are decoded properly.
   */
  cborDecodeOptions: sdCwt.cborDecodeOptions,
};

