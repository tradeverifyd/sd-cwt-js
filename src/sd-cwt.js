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
 * @param {string} [hashAlg='sha256'] - Hash algorithm
 * @returns {{claims: Map, disclosures: Uint8Array[]}} Processed claims and disclosures
 */
export function processToBeRedacted(claims, hashAlg = 'sha256') {
  const resultClaims = new Map();
  const disclosures = [];
  const redactedKeyHashes = [];

  for (const [key, value] of claims) {
    if (isToBeRedacted(key)) {
      // This is a claim marked for redaction
      const actualKey = getTagContents(key);
      const salt = generateSalt();
      const disclosure = createSaltedDisclosure(salt, value, actualKey);
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
      // Regular claim, pass through
      // But recursively process if value is a Map
      if (value instanceof Map) {
        const processed = processToBeRedacted(value, hashAlg);
        resultClaims.set(key, processed.claims);
        disclosures.push(...processed.disclosures);
      } else if (Array.isArray(value)) {
        const processed = processArrayToBeRedacted(value, hashAlg);
        resultClaims.set(key, processed.array);
        disclosures.push(...processed.disclosures);
      } else {
        resultClaims.set(key, value);
      }
    }
  }

  // Add redacted keys array if there are any
  if (redactedKeyHashes.length > 0) {
    resultClaims.set(redactedKeysKey(), redactedKeyHashes);
  }

  return { claims: resultClaims, disclosures };
}

/**
 * Processes an array and converts "To Be Redacted" tagged elements
 * into redacted claim elements.
 * 
 * @param {Array} array - Array with potentially tagged elements
 * @param {string} [hashAlg='sha256'] - Hash algorithm
 * @returns {{array: Array, disclosures: Uint8Array[]}} Processed array and disclosures
 */
export function processArrayToBeRedacted(array, hashAlg = 'sha256') {
  const resultArray = [];
  const disclosures = [];

  for (const element of array) {
    if (isToBeRedacted(element)) {
      // This element should be redacted
      const actualValue = getTagContents(element);
      const salt = generateSalt();
      const disclosure = createArrayElementDisclosure(salt, actualValue);
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
    } else if (element instanceof Map) {
      // Recursively process nested maps
      const processed = processToBeRedacted(element, hashAlg);
      resultArray.push(processed.claims);
      disclosures.push(...processed.disclosures);
    } else if (Array.isArray(element)) {
      // Recursively process nested arrays
      const processed = processArrayToBeRedacted(element, hashAlg);
      resultArray.push(processed.array);
      disclosures.push(...processed.disclosures);
    } else {
      resultArray.push(element);
    }
  }

  return { array: resultArray, disclosures };
}

/**
 * Decodes a disclosure and returns its components
 * 
 * @param {Uint8Array} disclosure - CBOR-encoded disclosure
 * @returns {{salt: Uint8Array, value: any, claimName?: string|number}} Decoded components
 */
export function decodeDisclosure(disclosure) {
  const decoded = cbor.decode(disclosure);
  
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

