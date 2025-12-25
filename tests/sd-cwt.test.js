import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as cbor from 'cbor2';

import {
  // Tags and simple values
  Tag,
  SimpleValue,
  
  // Tag creators
  toBeRedacted,
  toBeDecoy,
  redactedClaimElement,
  redactedKeysKey,
  simple,
  
  // Type checkers
  isToBeRedacted,
  isRedactedClaimElement,
  isToBeDecoy,
  isRedactedKeysKey,
  getTagContents,
  
  // Disclosure utilities
  generateSalt,
  createSaltedDisclosure,
  createArrayElementDisclosure,
  hashDisclosure,
  decodeDisclosure,
  
  // Processing utilities
  processToBeRedacted,
  processArrayToBeRedacted,
  
  // Reconstruction utilities
  reconstructClaims,
  reconstructArray,
  
  // CBOR options
  cborDecodeOptions,
} from '../src/sd-cwt.js';

describe('SD-CWT Tags and Simple Values', () => {
  
  describe('Tag constants', () => {
    it('should have correct tag numbers', () => {
      assert.strictEqual(Tag.ToBeRedacted, 58);
      assert.strictEqual(Tag.RedactedClaimElement, 60);
      assert.strictEqual(Tag.ToBeDecoy, 61);
    });
  });

  describe('SimpleValue constants', () => {
    it('should have correct simple value numbers', () => {
      assert.strictEqual(SimpleValue.RedactedKeys, 59);
    });
  });

});

describe('To Be Redacted Tag', () => {

  describe('toBeRedacted()', () => {
    it('should create a tag with number 58', () => {
      const tagged = toBeRedacted(500);
      assert.ok(tagged instanceof cbor.Tag);
      assert.strictEqual(tagged.tag, 58);
      assert.strictEqual(tagged.contents, 500);
    });

    it('should wrap integer claim keys', () => {
      const tagged = toBeRedacted(1);
      assert.strictEqual(tagged.tag, Tag.ToBeRedacted);
      assert.strictEqual(tagged.contents, 1);
    });

    it('should wrap string claim keys', () => {
      const tagged = toBeRedacted('name');
      assert.strictEqual(tagged.tag, Tag.ToBeRedacted);
      assert.strictEqual(tagged.contents, 'name');
    });

    it('should wrap negative integer claim keys', () => {
      const tagged = toBeRedacted(-7);
      assert.strictEqual(tagged.tag, Tag.ToBeRedacted);
      assert.strictEqual(tagged.contents, -7);
    });
  });

  describe('isToBeRedacted()', () => {
    it('should return true for toBeRedacted tagged values', () => {
      const tagged = toBeRedacted(500);
      assert.strictEqual(isToBeRedacted(tagged), true);
    });

    it('should return false for other tags', () => {
      const otherTag = new cbor.Tag(60, 'value');
      assert.strictEqual(isToBeRedacted(otherTag), false);
    });

    it('should return false for non-tag values', () => {
      assert.strictEqual(isToBeRedacted(500), false);
      assert.strictEqual(isToBeRedacted('text'), false);
      assert.strictEqual(isToBeRedacted(null), false);
    });
  });

  describe('CBOR encoding roundtrip', () => {
    it('should encode and decode tag 58 with integer', () => {
      const tagged = toBeRedacted(500);
      const encoded = cbor.encode(tagged);
      const decoded = cbor.decode(encoded);
      
      assert.ok(decoded instanceof cbor.Tag);
      assert.strictEqual(decoded.tag, 58);
      assert.strictEqual(decoded.contents, 500);
    });

    it('should encode and decode tag 58 with string', () => {
      const tagged = toBeRedacted('inspector_license_number');
      const encoded = cbor.encode(tagged);
      const decoded = cbor.decode(encoded);
      
      assert.strictEqual(decoded.tag, 58);
      assert.strictEqual(decoded.contents, 'inspector_license_number');
    });

    it('should encode tag 58 as map key in a Map', () => {
      const claims = new Map([
        [toBeRedacted(500), 'ABCD-123456'],
        [501, true],
      ]);
      
      const encoded = cbor.encode(claims);
      const decoded = cbor.decode(encoded);
      
      assert.ok(decoded instanceof Map);
      
      // Find the tagged key
      let foundTaggedKey = false;
      for (const [key, value] of decoded) {
        if (key instanceof cbor.Tag && key.tag === 58) {
          foundTaggedKey = true;
          assert.strictEqual(key.contents, 500);
          assert.strictEqual(value, 'ABCD-123456');
        }
      }
      assert.ok(foundTaggedKey, 'Should find a tagged key');
    });
  });

});

describe('Redacted Claim Element Tag', () => {

  describe('redactedClaimElement()', () => {
    it('should create a tag with number 60', () => {
      const hash = new Uint8Array(32).fill(0xAB);
      const tagged = redactedClaimElement(hash);
      
      assert.ok(tagged instanceof cbor.Tag);
      assert.strictEqual(tagged.tag, 60);
      assert.deepStrictEqual(tagged.contents, hash);
    });
  });

  describe('isRedactedClaimElement()', () => {
    it('should return true for redacted claim element tags', () => {
      const hash = new Uint8Array(32);
      const tagged = redactedClaimElement(hash);
      assert.strictEqual(isRedactedClaimElement(tagged), true);
    });

    it('should return false for other values', () => {
      const otherTag = toBeRedacted(500);
      assert.strictEqual(isRedactedClaimElement(otherTag), false);
      assert.strictEqual(isRedactedClaimElement('hash'), false);
    });
  });

  describe('CBOR encoding roundtrip', () => {
    it('should encode and decode tag 60 with byte string', () => {
      const hash = new Uint8Array([0x1b, 0x7f, 0xc8, 0xec, 0xf4, 0xb1, 0x29, 0x07]);
      const tagged = redactedClaimElement(hash);
      
      const encoded = cbor.encode(tagged);
      const decoded = cbor.decode(encoded);
      
      assert.strictEqual(decoded.tag, 60);
      assert.deepStrictEqual(new Uint8Array(decoded.contents), hash);
    });

    it('should encode redacted elements in an array', () => {
      const hash1 = new Uint8Array(32).fill(0x11);
      const hash2 = new Uint8Array(32).fill(0x22);
      
      const array = [
        redactedClaimElement(hash1),
        redactedClaimElement(hash2),
        1674004740, // non-redacted timestamp
      ];
      
      const encoded = cbor.encode(array);
      const decoded = cbor.decode(encoded);
      
      assert.ok(Array.isArray(decoded));
      assert.strictEqual(decoded.length, 3);
      
      assert.strictEqual(decoded[0].tag, 60);
      assert.strictEqual(decoded[1].tag, 60);
      assert.strictEqual(decoded[2], 1674004740);
    });
  });

});

describe('Redacted Keys Simple Value', () => {

  describe('redactedKeysKey()', () => {
    it('should create simple value 59', () => {
      const key = redactedKeysKey();
      assert.ok(key instanceof cbor.Simple);
      assert.strictEqual(key.value, 59);
    });
  });

  describe('simple()', () => {
    it('should create arbitrary simple values', () => {
      const s = simple(59);
      assert.ok(s instanceof cbor.Simple);
      assert.strictEqual(s.value, 59);
    });
  });

  describe('isRedactedKeysKey()', () => {
    it('should return true for simple(59)', () => {
      const key = redactedKeysKey();
      assert.strictEqual(isRedactedKeysKey(key), true);
    });

    it('should return false for other simple values', () => {
      const other = simple(60);
      assert.strictEqual(isRedactedKeysKey(other), false);
    });

    it('should return false for non-simple values', () => {
      assert.strictEqual(isRedactedKeysKey(59), false);
      assert.strictEqual(isRedactedKeysKey('simple'), false);
    });
  });

  describe('CBOR encoding roundtrip', () => {
    it('should encode and decode simple(59) as map key', () => {
      const hashes = [
        new Uint8Array(32).fill(0xAA),
        new Uint8Array(32).fill(0xBB),
      ];
      
      const claims = new Map([
        [500, true],
        [redactedKeysKey(), hashes],
      ]);
      
      const encoded = cbor.encode(claims);
      const decoded = cbor.decode(encoded);
      
      assert.ok(decoded instanceof Map);
      
      // Find the simple(59) key
      let foundSimpleKey = false;
      for (const [key, value] of decoded) {
        if (key instanceof cbor.Simple && key.value === 59) {
          foundSimpleKey = true;
          assert.ok(Array.isArray(value));
          assert.strictEqual(value.length, 2);
        }
      }
      assert.ok(foundSimpleKey, 'Should find simple(59) key');
    });
  });

});

describe('To Be Decoy Tag', () => {

  describe('toBeDecoy()', () => {
    it('should create a tag with number 61', () => {
      const tagged = toBeDecoy(3);
      assert.ok(tagged instanceof cbor.Tag);
      assert.strictEqual(tagged.tag, 61);
      assert.strictEqual(tagged.contents, 3);
    });

    it('should throw for non-positive integers', () => {
      assert.throws(() => toBeDecoy(0), /positive integer/);
      assert.throws(() => toBeDecoy(-1), /positive integer/);
      assert.throws(() => toBeDecoy(1.5), /positive integer/);
    });
  });

  describe('isToBeDecoy()', () => {
    it('should return true for toBeDecoy tagged values', () => {
      const tagged = toBeDecoy(2);
      assert.strictEqual(isToBeDecoy(tagged), true);
    });

    it('should return false for other values', () => {
      assert.strictEqual(isToBeDecoy(toBeRedacted(500)), false);
      assert.strictEqual(isToBeDecoy(61), false);
    });
  });

});

describe('Disclosure Utilities', () => {

  describe('generateSalt()', () => {
    it('should generate 16-byte salt', () => {
      const salt = generateSalt();
      assert.ok(salt instanceof Uint8Array);
      assert.strictEqual(salt.length, 16);
    });

    it('should generate different salts each time', () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      assert.notDeepStrictEqual(salt1, salt2);
    });
  });

  describe('createSaltedDisclosure()', () => {
    it('should create disclosure for claim key', () => {
      const salt = new Uint8Array(16).fill(0x12);
      const value = 'ABCD-123456';
      const claimName = 500;
      
      const disclosure = createSaltedDisclosure(salt, value, claimName);
      
      assert.ok(disclosure instanceof Uint8Array);
      
      // Decode and verify structure
      const decoded = cbor.decode(disclosure);
      assert.ok(Array.isArray(decoded));
      assert.strictEqual(decoded.length, 3);
      assert.deepStrictEqual(new Uint8Array(decoded[0]), salt);
      assert.strictEqual(decoded[1], value);
      assert.strictEqual(decoded[2], claimName);
    });

    it('should work with string claim names', () => {
      const salt = generateSalt();
      const disclosure = createSaltedDisclosure(salt, 'value', 'claimName');
      const decoded = cbor.decode(disclosure);
      
      assert.strictEqual(decoded[2], 'claimName');
    });
  });

  describe('createArrayElementDisclosure()', () => {
    it('should create disclosure for array element (no claim name)', () => {
      const salt = new Uint8Array(16).fill(0x34);
      const value = 1549560720; // timestamp
      
      const disclosure = createArrayElementDisclosure(salt, value);
      const decoded = cbor.decode(disclosure);
      
      assert.ok(Array.isArray(decoded));
      assert.strictEqual(decoded.length, 2);
      assert.deepStrictEqual(new Uint8Array(decoded[0]), salt);
      assert.strictEqual(decoded[1], value);
    });
  });

  describe('hashDisclosure()', () => {
    it('should compute SHA-256 hash of disclosure', () => {
      const disclosure = new Uint8Array([0x01, 0x02, 0x03]);
      const hash = hashDisclosure(disclosure, 'sha256');
      
      assert.ok(hash instanceof Uint8Array);
      assert.strictEqual(hash.length, 32); // SHA-256 produces 32 bytes
    });

    it('should produce consistent hashes', () => {
      const disclosure = createSaltedDisclosure(
        new Uint8Array(16).fill(0xFF),
        'test-value',
        500
      );
      
      const hash1 = hashDisclosure(disclosure);
      const hash2 = hashDisclosure(disclosure);
      
      assert.deepStrictEqual(hash1, hash2);
    });
  });

  describe('decodeDisclosure()', () => {
    it('should decode claim key disclosure', () => {
      const salt = new Uint8Array(16).fill(0xAB);
      const value = 'secret-value';
      const claimName = 500;
      
      const disclosure = createSaltedDisclosure(salt, value, claimName);
      const decoded = decodeDisclosure(disclosure);
      
      assert.deepStrictEqual(new Uint8Array(decoded.salt), salt);
      assert.strictEqual(decoded.value, value);
      assert.strictEqual(decoded.claimName, claimName);
    });

    it('should decode array element disclosure', () => {
      const salt = new Uint8Array(16).fill(0xCD);
      const value = 1674004740;
      
      const disclosure = createArrayElementDisclosure(salt, value);
      const decoded = decodeDisclosure(disclosure);
      
      assert.deepStrictEqual(new Uint8Array(decoded.salt), salt);
      assert.strictEqual(decoded.value, value);
      assert.strictEqual(decoded.claimName, undefined);
    });

    it('should decode decoy disclosure', () => {
      const salt = new Uint8Array(16).fill(0xEF);
      const disclosure = cbor.encode([salt]);
      const decoded = decodeDisclosure(disclosure);
      
      assert.deepStrictEqual(new Uint8Array(decoded.salt), salt);
      assert.strictEqual(decoded.isDecoy, true);
    });
  });

});

describe('processToBeRedacted()', () => {

  it('should process a map with tagged keys', () => {
    const claims = new Map([
      [toBeRedacted(500), 'ABCD-123456'],
      [501, true],
    ]);
    
    const result = processToBeRedacted(claims);
    
    // Check that the tagged key was removed
    assert.strictEqual(result.claims.has(500), false);
    
    // Check that the non-tagged key remains
    assert.strictEqual(result.claims.get(501), true);
    
    // Check that redacted keys array was added
    let hasRedactedKeysKey = false;
    for (const key of result.claims.keys()) {
      if (isRedactedKeysKey(key)) {
        hasRedactedKeysKey = true;
        const hashes = result.claims.get(key);
        assert.ok(Array.isArray(hashes));
        assert.strictEqual(hashes.length, 1);
        assert.strictEqual(hashes[0].length, 32); // SHA-256 hash
      }
    }
    assert.ok(hasRedactedKeysKey);
    
    // Check that disclosure was created
    assert.strictEqual(result.disclosures.length, 1);
    
    // Verify disclosure contents
    const decoded = decodeDisclosure(result.disclosures[0]);
    assert.strictEqual(decoded.value, 'ABCD-123456');
    assert.strictEqual(decoded.claimName, 500);
  });

  it('should process multiple tagged keys', () => {
    const claims = new Map([
      [toBeRedacted(500), 'value1'],
      [toBeRedacted(501), 'value2'],
      [502, 'public'],
    ]);
    
    const result = processToBeRedacted(claims);
    
    assert.strictEqual(result.disclosures.length, 2);
    
    let redactedKeysArray = null;
    for (const [key, value] of result.claims) {
      if (isRedactedKeysKey(key)) {
        redactedKeysArray = value;
      }
    }
    assert.ok(redactedKeysArray);
    assert.strictEqual(redactedKeysArray.length, 2);
  });

  it('should handle nested maps', () => {
    const innerMap = new Map([
      [toBeRedacted('region'), 'ca'],
      ['country', 'us'],
    ]);
    
    const claims = new Map([
      [503, innerMap],
    ]);
    
    const result = processToBeRedacted(claims);
    
    // Check nested map was processed
    const processedInner = result.claims.get(503);
    assert.ok(processedInner instanceof Map);
    assert.strictEqual(processedInner.get('country'), 'us');
    
    // Disclosure should be created for nested redacted claim
    assert.strictEqual(result.disclosures.length, 1);
  });

  it('should process decoys', () => {
    const claims = new Map([
      [toBeDecoy(2), null], // Insert 2 decoys
      [500, 'public'],
    ]);
    
    const result = processToBeRedacted(claims);
    
    // Should have redacted keys array with 2 decoy hashes
    let redactedKeysArray = null;
    for (const [key, value] of result.claims) {
      if (isRedactedKeysKey(key)) {
        redactedKeysArray = value;
      }
    }
    assert.ok(redactedKeysArray);
    assert.strictEqual(redactedKeysArray.length, 2);
    
    // Decoys don't create disclosures
    assert.strictEqual(result.disclosures.length, 0);
  });

});

describe('processArrayToBeRedacted()', () => {

  it('should process array with tagged elements', () => {
    const array = [
      toBeRedacted(1549560720),
      toBeRedacted(1612345678),
      1674004740, // non-redacted
    ];
    
    const result = processArrayToBeRedacted(array);
    
    assert.strictEqual(result.array.length, 3);
    
    // First two should be redacted claim elements (tag 60)
    assert.ok(isRedactedClaimElement(result.array[0]));
    assert.ok(isRedactedClaimElement(result.array[1]));
    
    // Third should be unchanged
    assert.strictEqual(result.array[2], 1674004740);
    
    // Two disclosures created
    assert.strictEqual(result.disclosures.length, 2);
  });

  it('should handle mixed redacted and regular elements', () => {
    const array = [
      'public1',
      toBeRedacted('secret'),
      'public2',
    ];
    
    const result = processArrayToBeRedacted(array);
    
    assert.strictEqual(result.array[0], 'public1');
    assert.ok(isRedactedClaimElement(result.array[1]));
    assert.strictEqual(result.array[2], 'public2');
  });

  it('should handle decoys in arrays', () => {
    const array = [
      toBeDecoy(3),
      'public',
    ];
    
    const result = processArrayToBeRedacted(array);
    
    // Should have 4 elements (3 decoys + 1 public)
    assert.strictEqual(result.array.length, 4);
    
    // First 3 should be redacted claim elements
    assert.ok(isRedactedClaimElement(result.array[0]));
    assert.ok(isRedactedClaimElement(result.array[1]));
    assert.ok(isRedactedClaimElement(result.array[2]));
    
    // Last should be unchanged
    assert.strictEqual(result.array[3], 'public');
  });

});

describe('Example from SD-CWT spec', () => {

  it('should create structure similar to spec example', () => {
    // Create a pre-issuance claims structure with To Be Redacted tags
    const inspectionDates = [
      toBeRedacted(1549560720), // 7-Feb-2019
      toBeRedacted(1612445940), // 4-Feb-2021  
      1674004740,               // 2023-01-17 (not redacted)
    ];
    
    const inspectionLocation = new Map([
      ['country', 'us'],
      [toBeRedacted('region'), 'ca'],
      [toBeRedacted('postal_code'), '90210'],
    ]);
    
    const claims = new Map([
      [500, true], // most_recent_inspection_passed
      [502, inspectionDates],
      [503, inspectionLocation],
      [toBeRedacted(504), 'ABCD-123456'], // inspector_license_number
    ]);
    
    const result = processToBeRedacted(claims);
    
    // Verify structure
    assert.strictEqual(result.claims.get(500), true);
    
    // Check that inspection_dates array was processed
    const dates = result.claims.get(502);
    assert.ok(isRedactedClaimElement(dates[0]));
    assert.ok(isRedactedClaimElement(dates[1]));
    assert.strictEqual(dates[2], 1674004740);
    
    // Check that inspection_location was processed
    const location = result.claims.get(503);
    assert.strictEqual(location.get('country'), 'us');
    
    // Check disclosures were created
    // 2 from dates + 2 from location + 1 from inspector_license_number = 5
    assert.strictEqual(result.disclosures.length, 5);
    
    // Verify the structure can be CBOR encoded
    const encoded = cbor.encode(result.claims);
    assert.ok(encoded.length > 0);
    
    // And decoded back
    const decoded = cbor.decode(encoded);
    assert.ok(decoded instanceof Map);
  });

});

describe('reconstructClaims()', () => {

  it('should reconstruct a simple redacted map claim', () => {
    const claims = new Map([
      [toBeRedacted(500), 'ABCD-123456'],
      [501, true],
    ]);
    
    const { claims: redactedClaims, disclosures } = processToBeRedacted(claims);
    const { claims: reconstructed } = reconstructClaims(redactedClaims, disclosures);
    
    // Should have reconstructed the redacted claim
    assert.strictEqual(reconstructed.get(500), 'ABCD-123456');
    assert.strictEqual(reconstructed.get(501), true);
    
    // Should not have the redacted keys array anymore
    let hasRedactedKeysKey = false;
    for (const key of reconstructed.keys()) {
      if (isRedactedKeysKey(key)) {
        hasRedactedKeysKey = true;
      }
    }
    assert.strictEqual(hasRedactedKeysKey, false);
  });

  it('should reconstruct multiple redacted claims', () => {
    const claims = new Map([
      [toBeRedacted(500), 'value1'],
      [toBeRedacted(501), 'value2'],
      [502, 'public'],
    ]);
    
    const { claims: redactedClaims, disclosures } = processToBeRedacted(claims);
    const { claims: reconstructed } = reconstructClaims(redactedClaims, disclosures);
    
    assert.strictEqual(reconstructed.get(500), 'value1');
    assert.strictEqual(reconstructed.get(501), 'value2');
    assert.strictEqual(reconstructed.get(502), 'public');
  });

  it('should handle partial disclosure (selective disclosure)', () => {
    const claims = new Map([
      [toBeRedacted(500), 'secret1'],
      [toBeRedacted(501), 'secret2'],
      [502, 'public'],
    ]);
    
    const { claims: redactedClaims, disclosures } = processToBeRedacted(claims);
    
    // Only provide the first disclosure (partial selective disclosure)
    const partialDisclosures = [disclosures[0]];
    const { claims: reconstructed, redactedKeys } = reconstructClaims(redactedClaims, partialDisclosures);
    
    // One claim should be reconstructed, one should remain redacted
    assert.strictEqual(reconstructed.get(502), 'public');
    
    // Should have one remaining redacted key hash
    assert.strictEqual(redactedKeys.length, 1);
  });

  it('should reconstruct nested maps', () => {
    const innerMap = new Map([
      [toBeRedacted('region'), 'ca'],
      ['country', 'us'],
    ]);
    
    const claims = new Map([
      [503, innerMap],
    ]);
    
    const { claims: redactedClaims, disclosures } = processToBeRedacted(claims);
    const { claims: reconstructed } = reconstructClaims(redactedClaims, disclosures);
    
    const location = reconstructed.get(503);
    assert.ok(location instanceof Map);
    assert.strictEqual(location.get('region'), 'ca');
    assert.strictEqual(location.get('country'), 'us');
  });

  it('should handle claims with no redacted keys', () => {
    const claims = new Map([
      [500, 'public1'],
      [501, 'public2'],
    ]);
    
    const { claims: redactedClaims, disclosures } = processToBeRedacted(claims);
    const { claims: reconstructed } = reconstructClaims(redactedClaims, disclosures);
    
    assert.strictEqual(reconstructed.get(500), 'public1');
    assert.strictEqual(reconstructed.get(501), 'public2');
    assert.strictEqual(disclosures.length, 0);
  });

  it('should handle decoys (no reconstruction possible)', () => {
    const claims = new Map([
      [toBeDecoy(2), null],
      [500, 'public'],
    ]);
    
    const { claims: redactedClaims, disclosures } = processToBeRedacted(claims);
    const { claims: reconstructed, redactedKeys } = reconstructClaims(redactedClaims, disclosures);
    
    assert.strictEqual(reconstructed.get(500), 'public');
    // Decoys should remain as redacted (no disclosure to match)
    assert.strictEqual(redactedKeys.length, 2);
  });

});

describe('reconstructArray()', () => {

  it('should reconstruct a simple redacted array', () => {
    const array = [
      toBeRedacted(1549560720),
      toBeRedacted(1612345678),
      1674004740, // non-redacted
    ];
    
    const { array: redactedArray, disclosures } = processArrayToBeRedacted(array);
    const { array: reconstructed } = reconstructArray(redactedArray, disclosures);
    
    assert.strictEqual(reconstructed.length, 3);
    assert.strictEqual(reconstructed[0], 1549560720);
    assert.strictEqual(reconstructed[1], 1612345678);
    assert.strictEqual(reconstructed[2], 1674004740);
  });

  it('should handle partial array disclosure', () => {
    const array = [
      toBeRedacted('secret1'),
      toBeRedacted('secret2'),
      'public',
    ];
    
    const { array: redactedArray, disclosures } = processArrayToBeRedacted(array);
    
    // Only provide first disclosure
    const partialDisclosures = [disclosures[0]];
    const { array: reconstructed, redactedElements } = reconstructArray(redactedArray, partialDisclosures);
    
    assert.strictEqual(reconstructed.length, 3);
    assert.strictEqual(reconstructed[0], 'secret1');
    assert.ok(isRedactedClaimElement(reconstructed[1])); // Still redacted
    assert.strictEqual(reconstructed[2], 'public');
    assert.strictEqual(redactedElements.length, 1);
  });

  it('should handle array decoys', () => {
    const array = [
      toBeDecoy(2),
      'public',
    ];
    
    const { array: redactedArray, disclosures } = processArrayToBeRedacted(array);
    const { array: reconstructed, redactedElements } = reconstructArray(redactedArray, disclosures);
    
    assert.strictEqual(reconstructed.length, 3); // 2 decoys + 1 public
    // Decoys remain as redacted elements
    assert.ok(isRedactedClaimElement(reconstructed[0]));
    assert.ok(isRedactedClaimElement(reconstructed[1]));
    assert.strictEqual(reconstructed[2], 'public');
    assert.strictEqual(redactedElements.length, 2);
  });

  it('should reconstruct nested arrays', () => {
    const innerArray = [toBeRedacted('inner-secret'), 'inner-public'];
    const outerArray = ['outer-public', innerArray];
    
    const { array: redactedArray, disclosures } = processArrayToBeRedacted(outerArray);
    const { array: reconstructed } = reconstructArray(redactedArray, disclosures);
    
    assert.strictEqual(reconstructed[0], 'outer-public');
    assert.ok(Array.isArray(reconstructed[1]));
    assert.strictEqual(reconstructed[1][0], 'inner-secret');
    assert.strictEqual(reconstructed[1][1], 'inner-public');
  });

});

describe('Roundtrip: Redaction → Reconstruction', () => {

  it('should roundtrip simple map claims', () => {
    const original = new Map([
      [toBeRedacted(500), 'secret-license'],
      [501, true],
      [502, 42],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(original);
    const { claims: reconstructed } = reconstructClaims(redacted, disclosures);
    
    // Verify roundtrip
    assert.strictEqual(reconstructed.get(500), 'secret-license');
    assert.strictEqual(reconstructed.get(501), true);
    assert.strictEqual(reconstructed.get(502), 42);
  });

  it('should roundtrip array elements', () => {
    const original = [
      toBeRedacted('secret1'),
      'public',
      toBeRedacted('secret2'),
    ];
    
    const { array: redacted, disclosures } = processArrayToBeRedacted(original);
    const { array: reconstructed } = reconstructArray(redacted, disclosures);
    
    assert.strictEqual(reconstructed[0], 'secret1');
    assert.strictEqual(reconstructed[1], 'public');
    assert.strictEqual(reconstructed[2], 'secret2');
  });

  it('should roundtrip complex nested structures', () => {
    const inspectionDates = [
      toBeRedacted(1549560720),
      toBeRedacted(1612445940),
      1674004740,
    ];
    
    const inspectionLocation = new Map([
      ['country', 'us'],
      [toBeRedacted('region'), 'ca'],
      [toBeRedacted('postal_code'), '90210'],
    ]);
    
    const original = new Map([
      [500, true],
      [502, inspectionDates],
      [503, inspectionLocation],
      [toBeRedacted(504), 'ABCD-123456'],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(original);
    
    // Verify redacted structure has correct shape
    assert.strictEqual(disclosures.length, 5);
    
    // Reconstruct with all disclosures
    const { claims: reconstructed } = reconstructClaims(redacted, disclosures);
    
    // Verify reconstructed values
    assert.strictEqual(reconstructed.get(500), true);
    assert.strictEqual(reconstructed.get(504), 'ABCD-123456');
    
    const dates = reconstructed.get(502);
    assert.strictEqual(dates[0], 1549560720);
    assert.strictEqual(dates[1], 1612445940);
    assert.strictEqual(dates[2], 1674004740);
    
    const location = reconstructed.get(503);
    assert.strictEqual(location.get('country'), 'us');
    assert.strictEqual(location.get('region'), 'ca');
    assert.strictEqual(location.get('postal_code'), '90210');
  });

  it('should handle selective disclosure in complex structures', () => {
    const inspectionDates = [
      toBeRedacted(1549560720),
      toBeRedacted(1612445940),
      1674004740,
    ];
    
    const original = new Map([
      [500, true],
      [502, inspectionDates],
      [toBeRedacted(504), 'ABCD-123456'],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(original);
    
    // Only disclose the license number, not the dates
    // Find the disclosure for claim 504
    const licenseDisclosure = disclosures.find(d => {
      const decoded = decodeDisclosure(d);
      return decoded.claimName === 504;
    });
    
    assert.ok(licenseDisclosure, 'Should find license disclosure');
    
    const { claims: reconstructed, redactedKeys } = reconstructClaims(redacted, [licenseDisclosure]);
    
    // License should be disclosed
    assert.strictEqual(reconstructed.get(504), 'ABCD-123456');
    assert.strictEqual(reconstructed.get(500), true);
    
    // Dates should remain redacted
    const dates = reconstructed.get(502);
    assert.ok(isRedactedClaimElement(dates[0]));
    assert.ok(isRedactedClaimElement(dates[1]));
    assert.strictEqual(dates[2], 1674004740);
  });

  it('should survive CBOR encode/decode cycle', () => {
    const original = new Map([
      [toBeRedacted(500), 'secret-value'],
      [501, 'public-value'],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(original);
    
    // Encode/decode the redacted claims (simulating transmission)
    const encoded = cbor.encode(redacted);
    const decoded = cbor.decode(encoded);
    
    // Reconstruct from decoded claims
    const { claims: reconstructed } = reconstructClaims(decoded, disclosures);
    
    assert.strictEqual(reconstructed.get(500), 'secret-value');
    assert.strictEqual(reconstructed.get(501), 'public-value');
  });

  it('should handle string claim keys', () => {
    const original = new Map([
      [toBeRedacted('secret_key'), 'secret-value'],
      ['public_key', 'public-value'],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(original);
    const { claims: reconstructed } = reconstructClaims(redacted, disclosures);
    
    assert.strictEqual(reconstructed.get('secret_key'), 'secret-value');
    assert.strictEqual(reconstructed.get('public_key'), 'public-value');
  });

  it('should handle mixed integer and string keys', () => {
    const original = new Map([
      [toBeRedacted(1), 'int-secret'],
      [toBeRedacted('str'), 'str-secret'],
      [2, 'int-public'],
      ['pub', 'str-public'],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(original);
    const { claims: reconstructed } = reconstructClaims(redacted, disclosures);
    
    assert.strictEqual(reconstructed.get(1), 'int-secret');
    assert.strictEqual(reconstructed.get('str'), 'str-secret');
    assert.strictEqual(reconstructed.get(2), 'int-public');
    assert.strictEqual(reconstructed.get('pub'), 'str-public');
  });

  it('should handle deeply nested structures', () => {
    const level3 = new Map([
      [toBeRedacted('deep'), 'deep-secret'],
      ['visible', 'deep-public'],
    ]);
    
    const level2 = new Map([
      ['nested', level3],
      [toBeRedacted('mid'), 'mid-secret'],
    ]);
    
    const original = new Map([
      ['outer', level2],
      [toBeRedacted('top'), 'top-secret'],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(original);
    const { claims: reconstructed } = reconstructClaims(redacted, disclosures);
    
    assert.strictEqual(reconstructed.get('top'), 'top-secret');
    
    const l2 = reconstructed.get('outer');
    assert.strictEqual(l2.get('mid'), 'mid-secret');
    
    const l3 = l2.get('nested');
    assert.strictEqual(l3.get('deep'), 'deep-secret');
    assert.strictEqual(l3.get('visible'), 'deep-public');
  });

});

describe('CBOR Map Preservation', () => {

  it('should decode CBOR maps as JavaScript Maps with cborDecodeOptions', () => {
    const original = new Map([
      ['key1', 'value1'],
      ['key2', 42],
      [1, 'numeric-key'],
    ]);
    
    const encoded = cbor.encode(original);
    const decoded = cbor.decode(encoded, cborDecodeOptions);
    
    assert.ok(decoded instanceof Map, 'Decoded value should be a Map');
    assert.strictEqual(decoded.get('key1'), 'value1');
    assert.strictEqual(decoded.get('key2'), 42);
    assert.strictEqual(decoded.get(1), 'numeric-key');
  });

  it('should preserve nested Maps through CBOR roundtrip', () => {
    const innerMap = new Map([['nested', 'value']]);
    const original = new Map([
      ['outer', innerMap],
    ]);
    
    const encoded = cbor.encode(original);
    const decoded = cbor.decode(encoded, cborDecodeOptions);
    
    assert.ok(decoded instanceof Map);
    const inner = decoded.get('outer');
    assert.ok(inner instanceof Map, 'Nested value should be a Map');
    assert.strictEqual(inner.get('nested'), 'value');
  });

  it('should preserve Maps inside arrays through CBOR roundtrip', () => {
    const mapInArray = new Map([['key', 'value']]);
    const original = ['before', mapInArray, 'after'];
    
    const encoded = cbor.encode(original);
    const decoded = cbor.decode(encoded, cborDecodeOptions);
    
    assert.ok(Array.isArray(decoded));
    assert.strictEqual(decoded[0], 'before');
    assert.ok(decoded[1] instanceof Map, 'Map in array should be a Map');
    assert.strictEqual(decoded[1].get('key'), 'value');
    assert.strictEqual(decoded[2], 'after');
  });

  it('should preserve Maps in disclosure values', () => {
    const nestedMap = new Map([
      ['field1', 'sensitive1'],
      ['field2', 'sensitive2'],
    ]);
    
    const salt = generateSalt();
    const disclosure = createSaltedDisclosure(salt, nestedMap, 'complexClaim');
    const decoded = decodeDisclosure(disclosure);
    
    assert.ok(decoded.value instanceof Map, 'Disclosure value should be a Map');
    assert.strictEqual(decoded.value.get('field1'), 'sensitive1');
    assert.strictEqual(decoded.value.get('field2'), 'sensitive2');
  });

});

describe('Isolation Tests: Redaction and Reconstruction without Signing', () => {

  it('should verify that disclosure hash matches redacted key hash', () => {
    const claims = new Map([
      [toBeRedacted(500), 'test-value'],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(claims);
    
    // Get the hash from the redacted keys array
    let redactedHash = null;
    for (const [key, value] of redacted) {
      if (isRedactedKeysKey(key)) {
        redactedHash = value[0];
      }
    }
    assert.ok(redactedHash, 'Should have redacted hash');
    
    // Compute hash of the disclosure
    const disclosureHash = hashDisclosure(disclosures[0]);
    
    // They should match
    assert.deepStrictEqual(new Uint8Array(redactedHash), disclosureHash);
  });

  it('should verify that array element disclosure hash matches tag contents', () => {
    const array = [toBeRedacted('secret-element')];
    
    const { array: redacted, disclosures } = processArrayToBeRedacted(array);
    
    // Get the hash from the redacted element tag
    const redactedElement = redacted[0];
    assert.ok(isRedactedClaimElement(redactedElement));
    const redactedHash = redactedElement.contents;
    
    // Compute hash of the disclosure
    const disclosureHash = hashDisclosure(disclosures[0]);
    
    // They should match
    assert.deepStrictEqual(new Uint8Array(redactedHash), disclosureHash);
  });

  it('should fail reconstruction with wrong disclosure', () => {
    const claims = new Map([
      [toBeRedacted(500), 'correct-value'],
    ]);
    
    const { claims: redacted } = processToBeRedacted(claims);
    
    // Create a wrong disclosure with different salt
    const wrongSalt = new Uint8Array(16).fill(0xFF);
    const wrongDisclosure = createSaltedDisclosure(wrongSalt, 'wrong-value', 500);
    
    const { claims: reconstructed, redactedKeys } = reconstructClaims(redacted, [wrongDisclosure]);
    
    // Should not have reconstructed the claim (hash mismatch)
    assert.strictEqual(reconstructed.has(500), false);
    assert.strictEqual(redactedKeys.length, 1);
  });

  it('should handle empty claims map', () => {
    const claims = new Map();
    
    const { claims: redacted, disclosures } = processToBeRedacted(claims);
    const { claims: reconstructed } = reconstructClaims(redacted, disclosures);
    
    assert.strictEqual(redacted.size, 0);
    assert.strictEqual(disclosures.length, 0);
    assert.strictEqual(reconstructed.size, 0);
  });

  it('should handle empty array', () => {
    const array = [];
    
    const { array: redacted, disclosures } = processArrayToBeRedacted(array);
    const { array: reconstructed } = reconstructArray(redacted, disclosures);
    
    assert.strictEqual(redacted.length, 0);
    assert.strictEqual(disclosures.length, 0);
    assert.strictEqual(reconstructed.length, 0);
  });

  it('should reconstruct complex values (maps as claim values)', () => {
    const nestedValue = new Map([
      ['inner1', 'value1'],
      ['inner2', 42],
    ]);
    
    const claims = new Map([
      [toBeRedacted(500), nestedValue],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(claims);
    const { claims: reconstructed } = reconstructClaims(redacted, disclosures);
    
    const restored = reconstructed.get(500);
    // With preferMap: true, CBOR maps are decoded as JavaScript Maps
    assert.ok(restored instanceof Map, 'Should be a Map instance');
    assert.strictEqual(restored.get('inner1'), 'value1');
    assert.strictEqual(restored.get('inner2'), 42);
  });

  it('should reconstruct complex values (arrays as claim values)', () => {
    const arrayValue = [1, 2, 3, 'four'];
    
    const claims = new Map([
      [toBeRedacted(500), arrayValue],
    ]);
    
    const { claims: redacted, disclosures } = processToBeRedacted(claims);
    const { claims: reconstructed } = reconstructClaims(redacted, disclosures);
    
    const restored = reconstructed.get(500);
    assert.ok(Array.isArray(restored));
    assert.deepStrictEqual(restored, [1, 2, 3, 'four']);
  });

});

