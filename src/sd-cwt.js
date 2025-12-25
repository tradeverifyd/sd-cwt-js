/**
 * SD-CWT (Selective Disclosure CBOR Web Token) Utilities
 * 
 * This module provides convenience APIs for working with SD-CWT structures,
 * including "To Be Redacted" tagging as defined in draft-ietf-spice-sd-cwt.
 * 
 * References:
 * - draft-ietf-spice-sd-cwt (SD-CWT specification)
 * - RFC 8949 (CBOR)
 */

import * as cbor from 'cbor2';
import crypto from 'node:crypto';

/**
 * Maximum recommended depth for nested structures (per spec section 6.5)
 */
export const MAX_DEPTH = 16;

/**
 * CBOR Tags defined for SD-CWT
 */
export const Tag = {
  /** Tag 58: Wraps claims intended to be redacted (used in pre-issuance) */
  ToBeRedacted: 58,
  /** Tag 60: Wraps a redacted array element (contains hash) */
  RedactedClaimElement: 60,
  /** Tag 61: Wraps a decoy value to be inserted */
  ToBeDecoy: 61,
};

/**
 * CBOR Simple Values defined for SD-CWT
 */
export const SimpleValue = {
  /** Simple value 59: Map key for array of redacted claim key hashes */
  RedactedKeys: 59,
};

/**
 * SD-CWT Header Parameters
 */
export const HeaderParam = {
  /** sd_claims: Array of selectively disclosed claims */
  SdClaims: 17,
  /** sd_alg: Hash algorithm used for redaction */
  SdAlg: 18,
  /** sd_aead_encrypted_claims */
  SdAeadEncryptedClaims: 19,
  /** sd_aead */
  SdAead: 20,
};

/**
 * Hash algorithms for SD-CWT
 */
export const SdAlg = {
  SHA256: -16,
};

/**
 * Default CBOR decode options for SD-CWT.
 * Uses preferMap: true to ensure CBOR maps decode as JavaScript Maps.
 */
export const cborDecodeOptions = {
  preferMap: true,
};

/**
 * Creates a "To Be Redacted" tagged value.
 * 
 * This tag indicates to the Issuer that the wrapped value should be
 * converted to a redacted claim during issuance.
 * 
 * @param {any} value - The value to wrap (can be a map key, map value, or array element)
 * @returns {cbor.Tag} A CBOR Tag with tag number 58 containing the value
 * 
 * @example
 * // Mark a claim to be redactable
 * const claims = new Map([
 *   [toBeRedacted(1), "sensitive-value"],  // key 1 will be redactable
 *   [2, "public-value"]
 * ]);
 */
export function toBeRedacted(value) {
  return new cbor.Tag(Tag.ToBeRedacted, value);
}

/**
 * Creates a "To Be Decoy" tagged value.
 * 
 * This tag indicates to the Issuer that a decoy should be inserted
 * at this position. The value is a positive integer indicating
 * how many decoys to insert.
 * 
 * @param {number} count - Number of decoys to insert (positive integer)
 * @returns {cbor.Tag} A CBOR Tag with tag number 61 containing the count
 */
export function toBeDecoy(count) {
  if (!Number.isInteger(count) || count < 1) {
    throw new Error('Decoy count must be a positive integer');
  }
  return new cbor.Tag(Tag.ToBeDecoy, count);
}

/**
 * Creates a Redacted Claim Element tag.
 * 
 * This wraps a hash that represents a redacted element in an array.
 * Used in issued SD-CWTs to represent array elements that have been redacted.
 * 
 * @param {Uint8Array|Buffer} hash - The hash of the salted disclosure
 * @returns {cbor.Tag} A CBOR Tag with tag number 60 containing the hash
 */
export function redactedClaimElement(hash) {
  const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);
  return new cbor.Tag(Tag.RedactedClaimElement, hashBytes);
}

/**
 * Creates a CBOR simple value for use as a map key.
 * 
 * @param {number} value - The simple value number
 * @returns {cbor.Simple} A CBOR simple value
 */
export function simple(value) {
  return new cbor.Simple(value);
}

/**
 * Returns the CBOR simple value used as map key for redacted claim keys array
 * 
 * @returns {cbor.Simple} Simple value 59
 */
export function redactedKeysKey() {
  return new cbor.Simple(SimpleValue.RedactedKeys);
}

/**
 * Checks if a value is a "To Be Redacted" tagged value
 * 
 * @param {any} value - The value to check
 * @returns {boolean} True if the value is tagged with tag 58
 */
export function isToBeRedacted(value) {
  return value instanceof cbor.Tag && value.tag === Tag.ToBeRedacted;
}

/**
 * Checks if a value is a "Redacted Claim Element" tagged value
 * 
 * @param {any} value - The value to check
 * @returns {boolean} True if the value is tagged with tag 60
 */
export function isRedactedClaimElement(value) {
  return value instanceof cbor.Tag && value.tag === Tag.RedactedClaimElement;
}

/**
 * Checks if a value is a "To Be Decoy" tagged value
 * 
 * @param {any} value - The value to check
 * @returns {boolean} True if the value is tagged with tag 61
 */
export function isToBeDecoy(value) {
  return value instanceof cbor.Tag && value.tag === Tag.ToBeDecoy;
}

/**
 * Checks if a value is the redacted keys simple value (59)
 * 
 * @param {any} value - The value to check
 * @returns {boolean} True if the value is simple(59)
 */
export function isRedactedKeysKey(value) {
  return value instanceof cbor.Simple && value.value === SimpleValue.RedactedKeys;
}

/**
 * Extracts the contents from a CBOR tag
 * 
 * @param {cbor.Tag} tag - The CBOR tag
 * @returns {any} The contents of the tag
 */
export function getTagContents(tag) {
  if (!(tag instanceof cbor.Tag)) {
    throw new Error('Value is not a CBOR tag');
  }
  return tag.contents;
}

/**
 * Generates a random 128-bit salt for disclosures
 * 
 * @returns {Uint8Array} A 16-byte random salt
 */
export function generateSalt() {
  return new Uint8Array(crypto.randomBytes(16));
}

/**
 * Creates a salted disclosure for a claim key
 * 
 * Format: [salt, value, claimName]
 * 
 * @param {Uint8Array} salt - 128-bit salt
 * @param {any} value - The claim value
 * @param {string|number} claimName - The claim name/key
 * @returns {Uint8Array} CBOR-encoded salted disclosure
 */
export function createSaltedDisclosure(salt, value, claimName) {
  const disclosure = [salt, value, claimName];
  return cbor.encode(disclosure);
}

/**
 * Creates a salted disclosure for an array element
 * 
 * Format: [salt, value] (no claim name for array elements)
 * 
 * @param {Uint8Array} salt - 128-bit salt
 * @param {any} value - The element value
 * @returns {Uint8Array} CBOR-encoded salted disclosure
 */
export function createArrayElementDisclosure(salt, value) {
  const disclosure = [salt, value];
  return cbor.encode(disclosure);
}

/**
 * Computes the hash of a disclosure
 * 
 * @param {Uint8Array} disclosure - The CBOR-encoded disclosure
 * @param {string} [algorithm='sha256'] - Hash algorithm to use
 * @returns {Uint8Array} The hash digest
 */
export function hashDisclosure(disclosure, algorithm = 'sha256') {
  const hash = crypto.createHash(algorithm);
  hash.update(disclosure);
  return new Uint8Array(hash.digest());
}

/**
 * Options for processing redacted claims
 * @typedef {Object} ProcessOptions
 * @property {boolean} [strict=false] - If true, throw error if depth exceeds MAX_DEPTH (16)
 * @property {string} [hashAlg='sha256'] - Hash algorithm to use
 */

/**
 * Checks and enforces depth limit
 * @param {number} depth - Current depth
 * @param {boolean} strict - Whether to enforce strict depth limit
 */
function checkDepth(depth, strict) {
  if (strict && depth > MAX_DEPTH) {
    throw new Error(`Depth ${depth} exceeds maximum allowed depth of ${MAX_DEPTH}`);
  }
}

/**
 * Processes a value recursively, handling maps, arrays, and CBOR tags
 * @param {any} value - The value to process
 * @param {string} hashAlg - Hash algorithm
 * @param {boolean} strict - Enforce depth limit
 * @param {number} depth - Current depth
 * @returns {{value: any, disclosures: Uint8Array[]}} Processed value and disclosures
 */
function processValueRecursive(value, hashAlg, strict, depth) {
  checkDepth(depth, strict);
  
  if (value instanceof Map) {
    return processMapInternal(value, hashAlg, strict, depth);
  } else if (Array.isArray(value)) {
    return processArrayInternal(value, hashAlg, strict, depth);
  } else if (value instanceof cbor.Tag) {
    // Handle non-SD-CWT CBOR tags - process their contents recursively
    if (!isToBeRedacted(value) && !isToBeDecoy(value) && !isRedactedClaimElement(value)) {
      const { value: processedContents, disclosures } = processValueRecursive(
        value.contents, hashAlg, strict, depth + 1
      );
      return { value: new cbor.Tag(value.tag, processedContents), disclosures };
    }
  }
  return { value, disclosures: [] };
}

/**
 * Internal implementation for processing maps with depth tracking
 */
function processMapInternal(claims, hashAlg, strict, depth) {
  checkDepth(depth, strict);
  
  const resultClaims = new Map();
  const disclosures = [];
  const redactedKeyHashes = [];

  for (const [key, value] of claims) {
    if (isToBeRedacted(key)) {
      // This is a claim marked for redaction
      const actualKey = getTagContents(key);
      const salt = generateSalt();
      
      // Process the value before creating disclosure (to handle nested structures)
      const { value: processedValue, disclosures: nestedDisclosures } = processValueRecursive(
        value, hashAlg, strict, depth + 1
      );
      disclosures.push(...nestedDisclosures);
      
      const disclosure = createSaltedDisclosure(salt, processedValue, actualKey);
      const hash = hashDisclosure(disclosure, hashAlg);
      
      disclosures.push(disclosure);
      redactedKeyHashes.push(hash);
    } else if (isToBeDecoy(key)) {
      // Insert decoy hashes
      const count = getTagContents(key);
      for (let i = 0; i < count; i++) {
        const salt = generateSalt();
        const decoyDisclosure = cbor.encode([salt]); // Decoy is just a salt
        const hash = hashDisclosure(decoyDisclosure, hashAlg);
        redactedKeyHashes.push(hash);
      }
    } else {
      // Regular claim, pass through with recursive processing
      const { value: processedValue, disclosures: nestedDisclosures } = processValueRecursive(
        value, hashAlg, strict, depth + 1
      );
      resultClaims.set(key, processedValue);
      disclosures.push(...nestedDisclosures);
    }
  }

  // Add redacted keys array if there are any
  if (redactedKeyHashes.length > 0) {
    resultClaims.set(redactedKeysKey(), redactedKeyHashes);
  }

  return { value: resultClaims, claims: resultClaims, disclosures };
}

/**
 * Internal implementation for processing arrays with depth tracking
 */
function processArrayInternal(array, hashAlg, strict, depth) {
  checkDepth(depth, strict);
  
  const resultArray = [];
  const disclosures = [];

  for (const element of array) {
    if (isToBeRedacted(element)) {
      // This element should be redacted
      const actualValue = getTagContents(element);
      const salt = generateSalt();
      
      // Process the value before creating disclosure (to handle nested structures)
      const { value: processedValue, disclosures: nestedDisclosures } = processValueRecursive(
        actualValue, hashAlg, strict, depth + 1
      );
      disclosures.push(...nestedDisclosures);
      
      const disclosure = createArrayElementDisclosure(salt, processedValue);
      const hash = hashDisclosure(disclosure, hashAlg);
      
      disclosures.push(disclosure);
      resultArray.push(redactedClaimElement(hash));
    } else if (isToBeDecoy(element)) {
      // Insert decoy elements
      const count = getTagContents(element);
      for (let i = 0; i < count; i++) {
        const salt = generateSalt();
        const decoyDisclosure = cbor.encode([salt]);
        const hash = hashDisclosure(decoyDisclosure, hashAlg);
        resultArray.push(redactedClaimElement(hash));
      }
    } else {
      // Regular element - process recursively
      const { value: processedValue, disclosures: nestedDisclosures } = processValueRecursive(
        element, hashAlg, strict, depth + 1
      );
      resultArray.push(processedValue);
      disclosures.push(...nestedDisclosures);
    }
  }

  return { value: resultArray, array: resultArray, disclosures };
}

/**
 * Processes a claims map and converts "To Be Redacted" tagged keys
 * into redacted claims structure.
 * 
 * This transforms:
 * {
 *   58(500): "secret",
 *   501: "public"
 * }
 * 
 * Into:
 * {
 *   501: "public",
 *   simple(59): [<hash-of-disclosure-for-500>]
 * }
 * 
 * Plus returns the disclosures for the redacted claims.
 * 
 * @param {Map} claims - Map with potentially tagged keys
 * @param {string|ProcessOptions} [hashAlgOrOptions='sha256'] - Hash algorithm or options object
 * @returns {{claims: Map, disclosures: Uint8Array[]}} Processed claims and disclosures
 */
export function processToBeRedacted(claims, hashAlgOrOptions = 'sha256') {
  const { hashAlg, strict } = normalizeOptions(hashAlgOrOptions);
  const result = processMapInternal(claims, hashAlg, strict, 1);
  return { claims: result.claims, disclosures: result.disclosures };
}

/**
 * Normalizes options parameter to extract hashAlg and strict
 */
function normalizeOptions(hashAlgOrOptions) {
  if (typeof hashAlgOrOptions === 'string') {
    return { hashAlg: hashAlgOrOptions, strict: false };
  }
  return {
    hashAlg: hashAlgOrOptions.hashAlg || 'sha256',
    strict: hashAlgOrOptions.strict || false,
  };
}

/**
 * Processes an array and converts "To Be Redacted" tagged elements
 * into redacted claim elements.
 * 
 * @param {Array} array - Array with potentially tagged elements
 * @param {string|ProcessOptions} [hashAlgOrOptions='sha256'] - Hash algorithm or options object
 * @returns {{array: Array, disclosures: Uint8Array[]}} Processed array and disclosures
 */
export function processArrayToBeRedacted(array, hashAlgOrOptions = 'sha256') {
  const { hashAlg, strict } = normalizeOptions(hashAlgOrOptions);
  const result = processArrayInternal(array, hashAlg, strict, 1);
  return { array: result.array, disclosures: result.disclosures };
}

/**
 * Decodes a disclosure and returns its components.
 * Uses preferMap: true to ensure any CBOR maps in the disclosure
 * are decoded as JavaScript Maps.
 * 
 * @param {Uint8Array} disclosure - CBOR-encoded disclosure
 * @returns {{salt: Uint8Array, value: any, claimName?: string|number}} Decoded components
 */
export function decodeDisclosure(disclosure) {
  const decoded = cbor.decode(disclosure, cborDecodeOptions);
  
  if (!Array.isArray(decoded)) {
    throw new Error('Invalid disclosure format: expected array');
  }

  if (decoded.length === 2) {
    // Array element disclosure: [salt, value]
    return {
      salt: decoded[0],
      value: decoded[1],
    };
  } else if (decoded.length === 3) {
    // Claim key disclosure: [salt, value, claimName]
    return {
      salt: decoded[0],
      value: decoded[1],
      claimName: decoded[2],
    };
  } else if (decoded.length === 1) {
    // Decoy: [salt]
    return {
      salt: decoded[0],
      value: undefined,
      isDecoy: true,
    };
  }

  throw new Error(`Invalid disclosure format: unexpected length ${decoded.length}`);
}

/**
 * Compares two Uint8Arrays for equality
 * 
 * @param {Uint8Array} a - First array
 * @param {Uint8Array} b - Second array
 * @returns {boolean} True if arrays are equal
 */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Builds a lookup map from disclosure hash to decoded disclosure
 * 
 * @param {Uint8Array[]} disclosures - Array of CBOR-encoded disclosures
 * @param {string} [hashAlg='sha256'] - Hash algorithm used
 * @returns {Map<string, {hash: Uint8Array, decoded: object}>} Lookup map keyed by hex hash
 */
function buildDisclosureLookup(disclosures, hashAlg = 'sha256') {
  const lookup = new Map();
  for (const disclosure of disclosures) {
    const hash = hashDisclosure(disclosure, hashAlg);
    const decoded = decodeDisclosure(disclosure);
    // Use hex string as key for easy Map lookup
    const hexKey = Buffer.from(hash).toString('hex');
    lookup.set(hexKey, { hash, decoded, disclosure });
  }
  return lookup;
}

/**
 * Options for reconstructing claims
 * @typedef {Object} ReconstructOptions
 * @property {boolean} [strict=false] - If true, throw error if depth exceeds MAX_DEPTH (16)
 * @property {string} [hashAlg='sha256'] - Hash algorithm to use
 */

/**
 * Reconstructs a value recursively, handling maps, arrays, and CBOR tags
 * @param {any} value - The value to reconstruct
 * @param {Map} lookup - Disclosure lookup map
 * @param {boolean} strict - Enforce depth limit
 * @param {number} depth - Current depth
 * @returns {{value: any, redactedHashes: Uint8Array[]}} Reconstructed value and remaining redacted hashes
 */
function reconstructValueRecursive(value, lookup, strict, depth) {
  checkDepth(depth, strict);
  
  if (value instanceof Map) {
    const result = reconstructMapInternal(value, lookup, strict, depth);
    return { value: result.claims, redactedHashes: result.redactedKeys };
  } else if (Array.isArray(value)) {
    const result = reconstructArrayRecursive(value, lookup, strict, depth);
    return { value: result.array, redactedHashes: result.redactedElements };
  } else if (value instanceof cbor.Tag) {
    // Handle non-SD-CWT CBOR tags - reconstruct their contents recursively
    if (!isRedactedClaimElement(value)) {
      const { value: reconstructedContents, redactedHashes } = reconstructValueRecursive(
        value.contents, lookup, strict, depth + 1
      );
      return { value: new cbor.Tag(value.tag, reconstructedContents), redactedHashes };
    }
  }
  return { value, redactedHashes: [] };
}

/**
 * Reconstructs claims from a redacted map and disclosures.
 * 
 * This is the inverse of processToBeRedacted. It takes a redacted claims map
 * (with simple(59) keys containing hashes) and the disclosures, then
 * reconstructs the original claims by matching disclosure hashes.
 * 
 * @param {Map} redactedClaims - The redacted claims map
 * @param {Uint8Array[]} disclosures - Array of CBOR-encoded disclosures to apply
 * @param {string|ReconstructOptions} [hashAlgOrOptions='sha256'] - Hash algorithm or options object
 * @returns {{claims: Map, redactedKeys: Uint8Array[]}} Reconstructed claims and remaining redacted key hashes
 */
export function reconstructClaims(redactedClaims, disclosures, hashAlgOrOptions = 'sha256') {
  const { hashAlg, strict } = normalizeOptions(hashAlgOrOptions);
  const lookup = buildDisclosureLookup(disclosures, hashAlg);
  return reconstructMapInternal(redactedClaims, lookup, strict, 1);
}

/**
 * Internal recursive implementation for reconstructClaims with depth tracking
 */
function reconstructMapInternal(redactedClaims, lookup, strict, depth) {
  checkDepth(depth, strict);
  
  const resultClaims = new Map();
  const remainingRedactedHashes = [];

  // First, find and process the redacted keys array (simple(59) key)
  let redactedKeyHashes = null;
  for (const [key, value] of redactedClaims) {
    if (isRedactedKeysKey(key)) {
      redactedKeyHashes = value;
    } else {
      // Copy non-redacted-keys entries, recursively processing nested structures
      const { value: processedValue, redactedHashes } = reconstructValueRecursive(
        value, lookup, strict, depth + 1
      );
      resultClaims.set(key, processedValue);
      remainingRedactedHashes.push(...redactedHashes);
    }
  }

  // Process redacted key hashes - match against disclosures
  if (redactedKeyHashes) {
    for (const hash of redactedKeyHashes) {
      const hashBytes = hash instanceof Uint8Array ? hash : new Uint8Array(hash);
      const hexKey = Buffer.from(hashBytes).toString('hex');
      const entry = lookup.get(hexKey);
      
      if (entry && entry.decoded.claimName !== undefined) {
        // Found matching disclosure - restore the claim
        const { value: restoredValue, redactedHashes } = reconstructValueRecursive(
          entry.decoded.value, lookup, strict, depth + 1
        );
        remainingRedactedHashes.push(...redactedHashes);
        resultClaims.set(entry.decoded.claimName, restoredValue);
      } else {
        // No matching disclosure - keep as redacted
        remainingRedactedHashes.push(hashBytes);
      }
    }
  }

  return { claims: resultClaims, redactedKeys: remainingRedactedHashes };
}

/**
 * Reconstructs an array from redacted elements and disclosures.
 * 
 * @param {Array} redactedArray - Array containing redacted claim elements (tag 60)
 * @param {Uint8Array[]} disclosures - Array of CBOR-encoded disclosures
 * @param {string|ReconstructOptions} [hashAlgOrOptions='sha256'] - Hash algorithm or options object
 * @returns {{array: Array, redactedElements: Uint8Array[]}} Reconstructed array and remaining redacted hashes
 */
export function reconstructArray(redactedArray, disclosures, hashAlgOrOptions = 'sha256') {
  const { hashAlg, strict } = normalizeOptions(hashAlgOrOptions);
  const lookup = buildDisclosureLookup(disclosures, hashAlg);
  return reconstructArrayRecursive(redactedArray, lookup, strict, 1);
}

/**
 * Internal recursive implementation for reconstructArray with depth tracking
 */
function reconstructArrayRecursive(redactedArray, lookup, strict, depth) {
  checkDepth(depth, strict);
  
  const resultArray = [];
  const remainingRedactedHashes = [];

  for (const element of redactedArray) {
    if (isRedactedClaimElement(element)) {
      // This is a redacted element - try to find matching disclosure
      const hashBytes = element.contents instanceof Uint8Array 
        ? element.contents 
        : new Uint8Array(element.contents);
      const hexKey = Buffer.from(hashBytes).toString('hex');
      const entry = lookup.get(hexKey);
      
      if (entry && entry.decoded.claimName === undefined && !entry.decoded.isDecoy) {
        // Found matching array element disclosure - restore the value
        const { value: restoredValue, redactedHashes } = reconstructValueRecursive(
          entry.decoded.value, lookup, strict, depth + 1
        );
        remainingRedactedHashes.push(...redactedHashes);
        resultArray.push(restoredValue);
      } else {
        // No matching disclosure (or is decoy) - keep as redacted
        resultArray.push(element);
        remainingRedactedHashes.push(hashBytes);
      }
    } else {
      // Regular element - reconstruct recursively
      const { value: processedValue, redactedHashes } = reconstructValueRecursive(
        element, lookup, strict, depth + 1
      );
      resultArray.push(processedValue);
      remainingRedactedHashes.push(...redactedHashes);
    }
  }

  return { array: resultArray, redactedElements: remainingRedactedHashes };
}

/**
 * Result of validating claims for cleanliness
 * @typedef {Object} ValidationResult
 * @property {boolean} isClean - True if claims contain no SD-CWT artifacts
 * @property {string[]} issues - List of issues found
 */

/**
 * Validates that claims are clean - containing no SD-CWT artifacts.
 * 
 * A clean claims object should not contain:
 * - ToBeRedacted tags (tag 58) - should have been processed during issuance
 * - ToBeDecoy tags (tag 61) - should have been processed during issuance
 * - RedactedClaimElement tags (tag 60) - means some disclosures are missing
 * - Redacted keys (simple 59) - means some disclosures are missing
 * 
 * @param {Map|Array|any} claims - The claims to validate
 * @param {Object} [options] - Validation options
 * @param {boolean} [options.strict=false] - If true, enforce depth limit
 * @param {boolean} [options.allowRedacted=false] - If true, allow redacted elements (tag 60 and simple 59)
 * @returns {ValidationResult} Validation result
 */
export function validateClaimsClean(claims, options = {}) {
  const { strict = false, allowRedacted = false } = options;
  const issues = [];
  validateValueClean(claims, issues, strict, 1, allowRedacted, '');
  return { isClean: issues.length === 0, issues };
}

/**
 * Internal recursive validation function
 */
function validateValueClean(value, issues, strict, depth, allowRedacted, path) {
  if (strict && depth > MAX_DEPTH) {
    issues.push(`Depth ${depth} exceeds maximum at ${path || 'root'}`);
    return;
  }

  if (value instanceof Map) {
    for (const [key, val] of value) {
      const keyPath = path ? `${path}.${String(key)}` : String(key);
      
      // Check for SD-CWT artifact keys
      if (isToBeRedacted(key)) {
        issues.push(`ToBeRedacted tag (58) found as key at ${keyPath}`);
      }
      if (isToBeDecoy(key)) {
        issues.push(`ToBeDecoy tag (61) found as key at ${keyPath}`);
      }
      if (!allowRedacted && isRedactedKeysKey(key)) {
        issues.push(`Redacted keys (simple 59) found at ${keyPath}`);
      }
      
      // Check the value recursively
      validateValueClean(val, issues, strict, depth + 1, allowRedacted, keyPath);
    }
  } else if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const elemPath = `${path}[${i}]`;
      const elem = value[i];
      
      // Check for SD-CWT artifact elements
      if (isToBeRedacted(elem)) {
        issues.push(`ToBeRedacted tag (58) found at ${elemPath}`);
      }
      if (isToBeDecoy(elem)) {
        issues.push(`ToBeDecoy tag (61) found at ${elemPath}`);
      }
      if (!allowRedacted && isRedactedClaimElement(elem)) {
        issues.push(`RedactedClaimElement tag (60) found at ${elemPath}`);
      }
      
      // Recursively check element (if not already a tag we reported)
      if (!isToBeRedacted(elem) && !isToBeDecoy(elem) && !(isRedactedClaimElement(elem) && !allowRedacted)) {
        validateValueClean(elem, issues, strict, depth + 1, allowRedacted, elemPath);
      }
    }
  } else if (value instanceof cbor.Tag) {
    const tagPath = path ? `${path}.<tag ${value.tag}>` : `<tag ${value.tag}>`;
    
    // Check for SD-CWT tags in unexpected places
    if (isToBeRedacted(value)) {
      issues.push(`ToBeRedacted tag (58) found at ${tagPath}`);
    } else if (isToBeDecoy(value)) {
      issues.push(`ToBeDecoy tag (61) found at ${tagPath}`);
    } else if (!allowRedacted && isRedactedClaimElement(value)) {
      issues.push(`RedactedClaimElement tag (60) found at ${tagPath}`);
    } else {
      // For other tags, check contents recursively
      validateValueClean(value.contents, issues, strict, depth + 1, allowRedacted, tagPath);
    }
  }
}

/**
 * Asserts that claims are clean, throwing an error if not.
 * 
 * @param {Map|Array|any} claims - The claims to validate
 * @param {Object} [options] - Validation options
 * @param {boolean} [options.strict=false] - If true, enforce depth limit
 * @param {boolean} [options.allowRedacted=false] - If true, allow redacted elements
 * @throws {Error} If claims contain SD-CWT artifacts
 */
export function assertClaimsClean(claims, options = {}) {
  const result = validateClaimsClean(claims, options);
  if (!result.isClean) {
    throw new Error(`Claims contain SD-CWT artifacts:\n${result.issues.join('\n')}`);
  }
}

