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
export { toBeRedacted, toBeDecoy } from './sd-cwt.js';
export { generateKeyPair, Algorithm } from './cose-sign1.js';

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
   * Claims can include:
   * - Regular claims: included directly in the token
   * - Redactable claims: wrapped with toBeRedacted(), stored as hashes with disclosures
   * - Decoys: wrapped with toBeDecoy(count), adds fake redacted entries
   * 
   * @param {Object} options - Issuance options
   * @param {Map} options.claims - Claims map, may contain toBeRedacted() tagged keys/values
   * @param {Object} options.privateKey - Issuer's private key {d, x, y}
   * @param {string} [options.algorithm='ES256'] - Signing algorithm
   * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm for redactions
   * @param {string|Buffer} [options.kid] - Key identifier
   * @returns {Promise<{token: Buffer, disclosures: Uint8Array[]}>} The signed SD-CWT and disclosures
   * 
   * @example
   * const claims = new Map([
   *   [1, 'issuer.example'],                    // iss - public
   *   [toBeRedacted(500), 'sensitive-value'],   // redactable claim
   *   [toBeDecoy(2), null],                     // add 2 decoys
   * ]);
   * 
   * const { token, disclosures } = await Issuer.issue({
   *   claims,
   *   privateKey: issuerKey.privateKey,
   * });
   */
  async issue({ claims, privateKey, algorithm = 'ES256', hashAlgorithm = 'sha256', kid }) {
    if (!(claims instanceof Map)) {
      throw new Error('Claims must be a Map');
    }

    // Process claims to handle toBeRedacted and toBeDecoy tags
    const { claims: processedClaims, disclosures } = sdCwt.processToBeRedacted(claims, hashAlgorithm);

    // Encode claims as CBOR payload
    const payload = cbor.encode(processedClaims);

    // Build custom protected headers for SD-CWT
    const customProtectedHeaders = new Map();
    
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
   * Creates a presentation with selected disclosures.
   * 
   * The presentation format is a CBOR array: [token, disclosures]
   * where disclosures is an array of the selected disclosure byte strings.
   * 
   * @param {Buffer|Uint8Array} token - The original SD-CWT token
   * @param {Uint8Array[]} selectedDisclosures - Disclosures to include
   * @returns {Buffer} The presentation (CBOR-encoded)
   */
  present(token, selectedDisclosures) {
    // Ensure token is Uint8Array (not Buffer) for proper CBOR byte string encoding
    // cbor2 encodes Buffer differently than Uint8Array
    const tokenBytes = Buffer.isBuffer(token) 
      ? new Uint8Array(token.buffer, token.byteOffset, token.length)
      : (token instanceof Uint8Array ? token : new Uint8Array(token));
    
    // Also ensure disclosures are Uint8Arrays
    const disclosureBytes = selectedDisclosures.map(d => 
      Buffer.isBuffer(d) 
        ? new Uint8Array(d.buffer, d.byteOffset, d.length)
        : (d instanceof Uint8Array ? d : new Uint8Array(d))
    );
    
    const presentation = [tokenBytes, disclosureBytes];
    return Buffer.from(cbor.encode(presentation));
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
 * Verifies SD-CWT presentations and reconstructs disclosed claims.
 */
export const Verifier = {
  /**
   * Verifies an SD-CWT presentation and returns the disclosed claims.
   * 
   * This function:
   * 1. Verifies the COSE signature
   * 2. Validates disclosure hashes match redacted entries
   * 3. Reconstructs claims from disclosures
   * 4. Returns both the verified claims and metadata about redactions
   * 
   * @param {Object} options - Verification options
   * @param {Buffer|Uint8Array} options.presentation - The presentation (CBOR: [token, disclosures])
   * @param {Object} options.publicKey - Issuer's public key {x, y}
   * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm used
   * @returns {Promise<{claims: Map, redactedKeys: Uint8Array[], headers: Object}>} Verified result
   * @throws {Error} If signature verification fails or disclosures are invalid
   * 
   * @example
   * const result = await Verifier.verify({
   *   presentation,
   *   publicKey: issuerKey.publicKey,
   * });
   * console.log(result.claims); // Reconstructed claims Map
   */
  async verify({ presentation, publicKey, hashAlgorithm = 'sha256' }) {
    // Decode the presentation
    const decoded = cbor.decode(presentation, sdCwt.cborDecodeOptions);
    
    if (!Array.isArray(decoded) || decoded.length !== 2) {
      throw new Error('Invalid presentation format: expected [token, disclosures]');
    }

    const [tokenBytes, disclosures] = decoded;
    
    if (!Array.isArray(disclosures)) {
      throw new Error('Invalid presentation format: disclosures must be an array');
    }

    // Ensure token is Uint8Array
    const token = tokenBytes instanceof Uint8Array ? tokenBytes : new Uint8Array(tokenBytes);

    // Verify the token and get the payload
    return this.verifyToken({ token, disclosures, publicKey, hashAlgorithm });
  },

  /**
   * Verifies a raw SD-CWT token with separate disclosures.
   * 
   * @param {Object} options - Verification options
   * @param {Buffer|Uint8Array} options.token - The SD-CWT token
   * @param {Uint8Array[]} options.disclosures - Disclosures to apply
   * @param {Object} options.publicKey - Issuer's public key {x, y}
   * @param {string} [options.hashAlgorithm='sha256'] - Hash algorithm used
   * @returns {Promise<{claims: Map, redactedKeys: Uint8Array[], headers: Object}>} Verified result
   */
  async verifyToken({ token, disclosures, publicKey, hashAlgorithm = 'sha256' }) {
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
      hashAlgorithm
    );

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

  /**
   * Verifies a token without any disclosures (full redaction).
   * Returns only the non-redacted claims.
   * 
   * @param {Object} options - Verification options
   * @param {Buffer|Uint8Array} options.token - The SD-CWT token
   * @param {Object} options.publicKey - Issuer's public key {x, y}
   * @returns {Promise<{claims: Map, redactedKeys: Uint8Array[], headers: Object}>} Verified result
   */
  async verifyWithoutDisclosures({ token, publicKey }) {
    return this.verifyToken({ token, disclosures: [], publicKey });
  },
};

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

