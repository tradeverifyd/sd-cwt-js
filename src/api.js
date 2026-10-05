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
import * as aead from './aead.js';

// Re-export key utilities
export { toBeRedacted, toBeDecoy, MAX_DEPTH, validateClaimsClean, assertClaimsClean, assertPreIssuanceValid, ClaimKey, MediaType, ContentFormat, isSdCwtTyp, isKbCwtTyp, HeaderParam } from './sd-cwt.js';
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
export {
  AeadAlgorithm,
  encryptDisclosure,
  decryptDisclosure,
  parseEncryptedDisclosure,
} from './aead.js';

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
   * @param {boolean} [options.claimsInProtectedHeader=false] - If true, place claims in CWT Claims header (15) instead of payload (per RFC 9597)
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
  async issue({ claims, privateKey, algorithm = 'ES256', hashAlgorithm = 'sha256', kid, strict = false, claimsInProtectedHeader = false }) {
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

    // Section 6.4 and 6.5: reject nested tags in map keys, a key present both
    // plain and To Be Redacted, duplicate Preferred Encodings, and non-finite
    // exp/nbf/iat, before anything is signed.
    sdCwt.assertPreIssuanceValid(claims);

    // Process claims to handle toBeRedacted and toBeDecoy tags
    const { claims: processedClaims, disclosures } = sdCwt.processToBeRedacted(claims, { hashAlg: hashAlgorithm, strict });

    // Build custom protected headers for SD-CWT
    const customProtectedHeaders = new Map();
    
    // Add typ header for SD-CWT
    customProtectedHeaders.set(sdCwt.HeaderParam.Typ, sdCwt.ContentFormat.SdCwt);
    
    // Add sd_alg header if there are disclosures
    if (disclosures.length > 0) {
      customProtectedHeaders.set(sdCwt.HeaderParam.SdAlg, sdCwt.SdAlg.SHA256);
    }

    // Encode claims - either in payload or in CWT Claims header (15) per RFC 9597
    let payload;
    if (claimsInProtectedHeader) {
      // Place claims in CWT Claims header parameter (15)
      customProtectedHeaders.set(sdCwt.HeaderParam.CwtClaims, processedClaims);
      // Per RFC 9597, payload should be nil (empty bstr) when claims are in header
      payload = new Uint8Array(0);
    } else {
      // Standard: claims in payload
      payload = cbor.encode(processedClaims);
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
    
    // Check for claims in CWT Claims header (15) per RFC 9597
    // If payload is empty/nil, use claims from header 15
    let claims;
    const cwtClaimsHeader = protectedHeaders.get(sdCwt.HeaderParam.CwtClaims);
    
    if (cwtClaimsHeader instanceof Map) {
      // Claims are in protected header (RFC 9597)
      // Payload should be empty/nil in this case
      claims = cwtClaimsHeader;
    } else if (payloadBytes && payloadBytes.length > 0) {
      // Standard: claims in payload
      claims = cbor.decode(payloadBytes, sdCwt.cborDecodeOptions);
    } else {
      // Empty payload and no claims header - return empty map
      claims = new Map();
    }

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
   * @param {Array<{disclosure: Uint8Array, key: Uint8Array, keyContext?: number|string|Uint8Array, nonce?: Uint8Array}>} [options.encryptedDisclosures]
   *   Disclosures to present encrypted, in `sd_aead_encrypted_claims` (171), per spec Section 13.
   *   Any of these that also appear in selectedDisclosures are sent only in encrypted form.
   *   The AEAD algorithm is the SD-CWT's `sd_aead` (172) protected header, or AES-128-GCM.
   * @returns {Promise<Buffer>} The signed SD-KBT presentation
   */
  async present({ token, selectedDisclosures = [], holderPrivateKey, audience, nonce, algorithm = 'ES256', encryptedDisclosures = [] }) {
    if (!audience) {
      throw new Error('audience (aud) is REQUIRED in SD-KBT per spec Section 8.1');
    }
    if (!holderPrivateKey) {
      throw new Error('holderPrivateKey is REQUIRED to sign the SD-KBT');
    }

    // Ensure token is Uint8Array
    const tokenBytes = Buffer.isBuffer(token) 
      ? new Uint8Array(token.buffer, token.byteOffset, token.length)
      : (token instanceof Uint8Array ? token : new Uint8Array(token));
    
    // Ensure disclosures are Uint8Arrays
    const disclosureBytes = selectedDisclosures.map(d => 
      Buffer.isBuffer(d) 
        ? new Uint8Array(d.buffer, d.byteOffset, d.length)
        : (d instanceof Uint8Array ? d : new Uint8Array(d))
    );

    // Build the SD-CWT with disclosures in unprotected header
    // We need to re-encode the SD-CWT with disclosures in the unprotected header
    // Section 13: the Holder MAY encrypt some disclosures, omitting their
    // plaintext from sd_claims and adding them to sd_aead_encrypted_claims.
    const aeadAlgorithm = aead.aeadAlgorithmFromHeaders(coseSign1.getHeaders(tokenBytes).protectedHeaders);
    const encryptedEntries = [];
    const encryptedHex = new Set();
    for (const { disclosure, key, keyContext, nonce: aeadNonce } of encryptedDisclosures) {
      const bytes = copyBytes(disclosure);
      encryptedHex.add(Buffer.from(bytes).toString('hex'));
      encryptedEntries.push(await aead.encryptDisclosure(bytes, key, { algorithm: aeadAlgorithm, nonce: aeadNonce, keyContext }));
    }
    const plaintextDisclosures = disclosureBytes.filter(d => !encryptedHex.has(Buffer.from(d).toString('hex')));

    const sdCwtWithDisclosures = embedDisclosuresInToken(tokenBytes, plaintextDisclosures, encryptedEntries);

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
    // The CDDL declares `&(kcwt: 13) ^ => sd-cwt-issued`, and sd-cwt-issued is
    // `#6.18([...])`, so kcwt holds the embedded COSE_Sign1 structure itself.
    // Passing the encoded bytes would nest the SD-CWT inside a bstr instead.
    const kbtProtectedHeaders = new Map([
      [sdCwt.HeaderParam.Typ, sdCwt.ContentFormat.KbCwt],
      [sdCwt.HeaderParam.Kcwt, cbor.decode(sdCwtWithDisclosures, sdCwt.cborDecodeOptions)],
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
/**
 * Copy bytes from a potentially shared buffer to ensure independence
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

function embedDisclosuresInToken(token, disclosures, encryptedEntries = []) {
  // Decode the COSE_Sign1 structure
  const decoded = cbor.decode(token, sdCwt.cborDecodeOptions);
  const coseArray = decoded.contents || decoded;
  
  // COSE_Sign1: [protected, unprotected, payload, signature]
  const [protectedBytesRaw, unprotectedMap, payloadRaw, signatureRaw] = coseArray;
  
  // Create copies of byte arrays to avoid issues with views over shared buffers
  const protectedBytes = copyBytes(protectedBytesRaw);
  const payload = copyBytes(payloadRaw);
  const signature = copyBytes(signatureRaw);
  
  // Add disclosures to unprotected header.
  // Section 4: "If the Holder does not disclose any claims, it MUST omit the
  // `sd_claims` header parameter." An empty array is not the same thing -- a
  // Verifier is required to treat that as invalid.
  const newUnprotected = unprotectedMap instanceof Map ? new Map(unprotectedMap) : new Map();
  if (disclosures.length > 0) {
    newUnprotected.set(sdCwt.HeaderParam.SdClaims, disclosures);
  } else {
    newUnprotected.delete(sdCwt.HeaderParam.SdClaims);
  }
  // The same rule applies to sd_aead_encrypted_claims (Section 9 step 2).
  if (encryptedEntries.length > 0) {
    newUnprotected.set(sdCwt.HeaderParam.SdAeadEncryptedClaims, encryptedEntries);
  } else {
    newUnprotected.delete(sdCwt.HeaderParam.SdAeadEncryptedClaims);
  }
  
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
      const rawContents = sdCwt.getRedactedElementContents(element);
      const hashBytes = rawContents instanceof Uint8Array 
        ? rawContents 
        : new Uint8Array(rawContents);
      hashSet.add(Buffer.from(hashBytes).toString('hex'));
    } else if (element instanceof Map && !element.has('tag')) {
      // Regular Map, not a tag representation
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
   * @param {function({keyContext?: number|string|Uint8Array, entry: Array, algorithm: number}): (Uint8Array|Uint8Array[]|undefined|Promise<Uint8Array|Uint8Array[]|undefined>)} [options.aeadKeyResolver]
   *   Resolves the AEAD key (or candidate keys) for an `sd_aead_encrypted_claims` (171) entry,
   *   per spec Section 13. Decrypted disclosures are processed exactly as if they were in
   *   `sd_claims`. Entries for which no key is returned are left encrypted and reported in
   *   `undecryptedDisclosures`, so an initial Verifier can forward them. If keys are returned
   *   and none of them decrypts the entry, verification fails.
   * @returns {Promise<{claims: Map, redactedKeys: Uint8Array[], sdCwtClaims: Map, kbtPayload: Map, headers: Object, decryptedDisclosures: Uint8Array[], undecryptedDisclosures: Array[]}>} Verified result
   * @throws {Error} If verification fails
   * 
   * @example
   * const result = await Verifier.verify({
   *   presentation: kbt,
   *   issuerPublicKey: issuerKey.publicKey,
   *   expectedAudience: 'https://verifier.example/app',
   * });
   */
  async verify({ presentation, issuerPublicKey, expectedAudience, expectedNonce, hashAlgorithm = 'sha256', strict = false, requireClean = false, aeadKeyResolver }) {
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
    if (!sdCwt.isKbCwtTyp(kbtTyp)) {
      throw new Error(`Invalid SD-KBT: typ must be ${sdCwt.ContentFormat.KbCwt} or "${sdCwt.MediaType.KbCwt}", got ${JSON.stringify(kbtTyp)}`);
    }

    // Step 2: Verify the SD-CWT signature using Issuer's public key
    const sdCwtPayloadBytes = await coseSign1.verify(sdCwtBytes, issuerPublicKey);
    
    // Get SD-CWT headers to check for claims in protected header (RFC 9597)
    const sdCwtHeaders = coseSign1.getHeaders(sdCwtBytes);
    const cwtClaimsHeader = sdCwtHeaders.protectedHeaders.get(sdCwt.HeaderParam.CwtClaims);
    
    // Claims can be in payload OR in CWT Claims header (15) per RFC 9597
    let sdCwtClaims;
    if (cwtClaimsHeader instanceof Map) {
      // Claims are in protected header
      sdCwtClaims = cwtClaimsHeader;
    } else if (sdCwtPayloadBytes && sdCwtPayloadBytes.length > 0) {
      // Claims are in payload
      sdCwtClaims = cbor.decode(sdCwtPayloadBytes, sdCwt.cborDecodeOptions);
    } else {
      throw new Error('Invalid SD-CWT: no claims in payload or CWT Claims header (15)');
    }

    // Section 9 step 2: "Verifiers MUST treat an `sd_claims` or
    // `sd_aead_encrypted_claims` unprotected Header Parameter with an empty
    // array as invalid." Section 4 requires the parameter be omitted instead.
    for (const label of [sdCwt.HeaderParam.SdClaims, sdCwt.HeaderParam.SdAeadEncryptedClaims]) {
      if (sdCwtHeaders.unprotectedHeaders.has(label)) {
        const value = sdCwtHeaders.unprotectedHeaders.get(label);
        if (Array.isArray(value) && value.length === 0) {
          throw new Error(
            `Invalid SD-CWT: header parameter ${label} is an empty array; it MUST be omitted ` +
            'when nothing is disclosed (per spec Section 4 and Section 9 step 2)'
          );
        }
      }
    }

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

    // Step 5: Validate SD-KBT has required claims (aud, and iat or cti)
    // Section 8.1: iss and sub are implied by the cnf claim of the embedded
    // SD-CWT, so repeating them here is superfluous and MUST NOT be done.
    for (const label of [sdCwt.ClaimKey.Iss, sdCwt.ClaimKey.Sub]) {
      if (kbtPayload.has(label)) {
        throw new Error(
          `Invalid SD-KBT: claim ${label} (iss and sub) MUST NOT be present; both are implied ` +
          'by the cnf claim of the embedded SD-CWT (per spec Section 8.1)'
        );
      }
    }

    const kbtAud = kbtPayload.get(sdCwt.ClaimKey.Aud);
    if (!kbtAud) {
      throw new Error('Invalid SD-KBT: missing aud (3) claim');
    }
    // Section 8.1: "The KBT payload MUST contain either the `iat` (issued at)
    // claim, or the `cti` (CWT ID) claim."
    const kbtIat = kbtPayload.get(sdCwt.ClaimKey.Iat);
    const kbtCti = kbtPayload.get(sdCwt.ClaimKey.Cti);
    if (kbtIat === undefined && kbtCti === undefined) {
      throw new Error('Invalid SD-KBT: MUST contain either the iat (6) or the cti (7) claim');
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
    // (sdCwtHeaders was already retrieved above for CWT Claims check)
    const plaintextDisclosures = sdCwtHeaders.unprotectedHeaders.get(sdCwt.HeaderParam.SdClaims) || [];

    // Section 13: decrypt what we can of sd_aead_encrypted_claims and process
    // it as if it had been in sd_claims.
    const { decryptedDisclosures, undecryptedDisclosures } = await decryptAeadDisclosures(
      sdCwtHeaders, aeadKeyResolver
    );
    const plaintextHex = new Set(plaintextDisclosures.map(d => Buffer.from(d).toString('hex')));
    for (const d of decryptedDisclosures) {
      if (plaintextHex.has(Buffer.from(d).toString('hex'))) {
        throw new Error('Invalid SD-CWT: a disclosure is present both in sd_claims and in sd_aead_encrypted_claims');
      }
    }
    const disclosures = [...plaintextDisclosures, ...decryptedDisclosures];

    // Reconstruct claims with the provided disclosures. Every disclosure is
    // handed to the reconstruction, including ones whose Redacted Claim Hash is
    // nested inside another redacted claim and so is not yet visible.
    const { claims, redactedKeys, unusedDisclosures } = sdCwt.reconstructClaims(
      sdCwtClaims,
      disclosures,
      { hashAlg: hashAlgorithm, strict }
    );

    // Appendix A step 6: "If there remain unused claims in the Digest To
    // Disclosed Claim Map at the end of this procedure the SD-CWT MUST be
    // considered invalid." Checking here rather than before reconstruction is
    // what makes nested disclosures work.
    if (unusedDisclosures.length > 0) {
      const shown = unusedDisclosures.map(u => u.hexKey.slice(0, 16) + '…').join(', ');
      throw new Error(
        `Invalid SD-CWT: ${unusedDisclosures.length} disclosure(s) match no Redacted Claim Hash ` +
        `(${shown}); every disclosure MUST be used (per spec Appendix A step 6)`
      );
    }

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
      decryptedDisclosures,   // Disclosures recovered from sd_aead_encrypted_claims (171)
      undecryptedDisclosures, // 171 entries with no available key, still encrypted
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
 * Decrypts the `sd_aead_encrypted_claims` (171) entries of an SD-CWT.
 *
 * Every entry is shape-checked whether or not a key is available, so a
 * malformed header is rejected even by a Verifier that cannot decrypt it.
 *
 * @param {{protectedHeaders: Map, unprotectedHeaders: Map}} sdCwtHeaders
 * @param {Function} [aeadKeyResolver]
 * @returns {Promise<{decryptedDisclosures: Uint8Array[], undecryptedDisclosures: Array[]}>}
 */
async function decryptAeadDisclosures(sdCwtHeaders, aeadKeyResolver) {
  const entries = sdCwtHeaders.unprotectedHeaders.get(sdCwt.HeaderParam.SdAeadEncryptedClaims);
  const decryptedDisclosures = [];
  const undecryptedDisclosures = [];
  if (entries === undefined) {
    return { decryptedDisclosures, undecryptedDisclosures };
  }
  if (!Array.isArray(entries)) {
    throw new Error('Invalid SD-CWT: sd_aead_encrypted_claims (171) must be an array');
  }

  const algorithm = aead.aeadAlgorithmFromHeaders(sdCwtHeaders.protectedHeaders);
  for (const entry of entries) {
    const { keyContext } = aead.parseEncryptedDisclosure(entry, algorithm);
    const resolved = aeadKeyResolver ? await aeadKeyResolver({ keyContext, entry, algorithm }) : undefined;
    const keys = resolved === undefined || resolved === null ? [] : (Array.isArray(resolved) ? resolved : [resolved]);
    if (keys.length === 0) {
      undecryptedDisclosures.push(entry);
      continue;
    }

    let disclosure;
    let lastError;
    for (const key of keys) {
      try {
        disclosure = await aead.decryptDisclosure(entry, key, { algorithm });
        break;
      } catch (e) {
        lastError = e;
      }
    }
    if (!disclosure) {
      throw new Error(`Invalid SD-CWT: AEAD encrypted disclosure could not be decrypted (${lastError.message})`);
    }
    decryptedDisclosures.push(disclosure);
  }
  return { decryptedDisclosures, undecryptedDisclosures };
}

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

  // Extract key type and coordinates from COSE_Key
  let kty, x, y;
  if (coseKey instanceof Map) {
    kty = coseKey.get(1);  // kty
    x = coseKey.get(-2);
    y = coseKey.get(-3);
  } else if (typeof coseKey === 'object') {
    kty = coseKey[1] || coseKey['1'];
    x = coseKey[-2] || coseKey['-2'];
    y = coseKey[-3] || coseKey['-3'];
  }

  if (!x) {
    throw new Error('Invalid COSE_Key in cnf: missing x (-2) coordinate');
  }

  // For EC2 keys (kty=2), y is required
  // For OKP keys (kty=1), y is not used
  if (kty === 2 && !y) {
    throw new Error('Invalid EC2 COSE_Key in cnf: missing y (-3) coordinate');
  }

  const result = { x };
  if (y) result.y = y;
  return result;
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
      // Only the hashes visible at this level are known here, so a disclosure
      // nested under a still-redacted parent legitimately misses. This helper
      // is a best-effort filter for Holders choosing what to send; the
      // authoritative "every disclosure MUST be used" check runs after
      // reconstruction, in Verifier.verify.
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

