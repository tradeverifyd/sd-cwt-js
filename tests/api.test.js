import { describe, it } from 'node:test';
import assert from 'node:assert';

import {
  // High-level API
  Issuer,
  Holder,
  Verifier,
  Utils,
  
  // Utilities
  toBeRedacted,
  toBeDecoy,
  generateKeyPair,
  Algorithm,
  MAX_DEPTH,
  validateClaimsClean,
  assertClaimsClean,
} from '../src/api.js';

describe('SD-CWT High-Level API', () => {

  describe('Key Generation', () => {
    it('should generate ES256 key pair', () => {
      const keyPair = generateKeyPair(Algorithm.ES256);
      
      assert.ok(keyPair.privateKey);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.privateKey.d);
      assert.ok(keyPair.privateKey.x);
      assert.ok(keyPair.privateKey.y);
      assert.ok(keyPair.publicKey.x);
      assert.ok(keyPair.publicKey.y);
    });

    it('should generate ES384 key pair', () => {
      const keyPair = generateKeyPair(Algorithm.ES384);
      assert.ok(keyPair.privateKey.d);
      assert.ok(keyPair.publicKey.x);
    });

    it('should generate ES512 key pair', () => {
      const keyPair = generateKeyPair(Algorithm.ES512);
      assert.ok(keyPair.privateKey.d);
      assert.ok(keyPair.publicKey.x);
    });
  });

  describe('Issuer API', () => {
    const keyPair = generateKeyPair();

    it('should issue an SD-CWT with no redactable claims', async () => {
      const claims = new Map([
        [1, 'issuer.example'],
        [2, 'subject-123'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      assert.ok(token.length > 0);
      assert.strictEqual(disclosures.length, 0);
    });

    it('should issue an SD-CWT with redactable claims', async () => {
      const claims = new Map([
        [1, 'issuer.example'],
        [toBeRedacted(500), 'sensitive-license-number'],
        [501, true],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      assert.ok(token.length > 0);
      assert.strictEqual(disclosures.length, 1);
      
      // Verify disclosure content
      const decoded = Utils.decodeDisclosure(disclosures[0]);
      assert.strictEqual(decoded.value, 'sensitive-license-number');
      assert.strictEqual(decoded.claimName, 500);
    });

    it('should issue an SD-CWT with multiple redactable claims', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'value1'],
        [toBeRedacted(501), 'value2'],
        [toBeRedacted(502), 'value3'],
        [503, 'public'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      assert.ok(token.length > 0);
      assert.strictEqual(disclosures.length, 3);
    });

    it('should issue an SD-CWT with decoys', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [toBeDecoy(3), null],
        [501, 'public'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      // Only 1 real disclosure (decoys don't create disclosures)
      assert.strictEqual(disclosures.length, 1);
      
      // But the token should have 4 hashes (1 real + 3 decoys)
      const parsed = Holder.parse(token);
      const redactionInfo = Utils.countRedactions(parsed.claims);
      assert.strictEqual(redactionInfo.mapKeys, 4);
    });

    it('should issue an SD-CWT with nested redactable claims', async () => {
      const innerMap = new Map([
        [toBeRedacted('region'), 'ca'],
        ['country', 'us'],
      ]);

      const claims = new Map([
        [1, 'issuer.example'],
        [503, innerMap],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      assert.strictEqual(disclosures.length, 1);
      
      const decoded = Utils.decodeDisclosure(disclosures[0]);
      assert.strictEqual(decoded.claimName, 'region');
      assert.strictEqual(decoded.value, 'ca');
    });

    it('should issue an SD-CWT with redactable array elements', async () => {
      const dates = [
        toBeRedacted(1549560720),
        toBeRedacted(1612445940),
        1674004740, // not redacted
      ];

      const claims = new Map([
        [502, dates],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      assert.strictEqual(disclosures.length, 2);
    });

    it('should include kid in the token when provided', async () => {
      const claims = new Map([[1, 'issuer.example']]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
        kid: 'issuer-key-1',
      });

      const parsed = Holder.parse(token);
      // kid is in unprotected headers
      assert.ok(parsed.unprotectedHeaders.has(4)); // Header 4 is kid
    });

    it('should throw if claims is not a Map', async () => {
      await assert.rejects(
        () => Issuer.issue({
          claims: { not: 'a-map' },
          privateKey: keyPair.privateKey,
        }),
        /Claims must be a Map/
      );
    });
  });

  describe('Holder API', () => {
    const keyPair = generateKeyPair();

    it('should parse an SD-CWT token', async () => {
      const claims = new Map([
        [1, 'issuer.example'],
        [toBeRedacted(500), 'secret'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const parsed = Holder.parse(token);
      
      assert.ok(parsed.claims instanceof Map);
      assert.strictEqual(parsed.claims.get(1), 'issuer.example');
      assert.ok(parsed.protectedHeaders instanceof Map);
    });

    it('should select disclosures by claim name', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'value500'],
        [toBeRedacted(501), 'value501'],
        [toBeRedacted(502), 'value502'],
      ]);

      const { disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      // Select only claim 500 and 502
      const selected = Holder.selectDisclosures(disclosures, [500, 502]);
      
      assert.strictEqual(selected.length, 2);
      
      // Verify the selected ones
      const selectedNames = selected.map(d => Utils.decodeDisclosure(d).claimName);
      assert.ok(selectedNames.includes(500));
      assert.ok(selectedNames.includes(502));
      assert.ok(!selectedNames.includes(501));
    });

    it('should create a presentation with selected disclosures', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [501, 'public'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const presentation = Holder.present(token, disclosures);
      
      assert.ok(presentation.length > token.length);
    });

    it('should create a presentation with no disclosures (full redaction)', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [501, 'public'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      // Present with no disclosures
      const presentation = Holder.present(token, []);
      
      assert.ok(presentation.length > 0);
    });

    it('should filter valid disclosures', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [501, 'public'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const parsed = Holder.parse(token);
      const valid = Holder.filterValidDisclosures(parsed.claims, disclosures);
      
      assert.strictEqual(valid.length, 1);
    });
  });

  describe('Verifier API', () => {
    const keyPair = generateKeyPair();

    it('should verify a presentation with full disclosure', async () => {
      const claims = new Map([
        [1, 'issuer.example'],
        [toBeRedacted(500), 'sensitive-value'],
        [501, 'public-value'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const presentation = Holder.present(token, disclosures);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
      });

      assert.ok(result.claims instanceof Map);
      assert.strictEqual(result.claims.get(1), 'issuer.example');
      assert.strictEqual(result.claims.get(500), 'sensitive-value');
      assert.strictEqual(result.claims.get(501), 'public-value');
      assert.strictEqual(result.redactedKeys.length, 0);
    });

    it('should verify a presentation with partial disclosure', async () => {
      const claims = new Map([
        [1, 'issuer.example'],
        [toBeRedacted(500), 'disclosed'],
        [toBeRedacted(501), 'redacted'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      // Only disclose claim 500
      const selectedDisclosures = Holder.selectDisclosures(disclosures, [500]);
      const presentation = Holder.present(token, selectedDisclosures);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
      });

      assert.strictEqual(result.claims.get(500), 'disclosed');
      assert.strictEqual(result.claims.has(501), false); // Still redacted
      assert.strictEqual(result.redactedKeys.length, 1);
    });

    it('should verify a presentation with no disclosures', async () => {
      const claims = new Map([
        [1, 'issuer.example'],
        [toBeRedacted(500), 'secret'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const presentation = Holder.present(token, []);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
      });

      assert.strictEqual(result.claims.get(1), 'issuer.example');
      assert.strictEqual(result.claims.has(500), false);
      assert.strictEqual(result.redactedKeys.length, 1);
    });

    it('should verify a token directly without presentation wrapper', async () => {
      const claims = new Map([
        [1, 'issuer.example'],
        [toBeRedacted(500), 'secret'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const result = await Verifier.verifyToken({
        token,
        disclosures,
        publicKey: keyPair.publicKey,
      });

      assert.strictEqual(result.claims.get(500), 'secret');
    });

    it('should verify a token without disclosures', async () => {
      const claims = new Map([
        [1, 'issuer.example'],
        [toBeRedacted(500), 'secret'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const result = await Verifier.verifyWithoutDisclosures({
        token,
        publicKey: keyPair.publicKey,
      });

      assert.strictEqual(result.claims.get(1), 'issuer.example');
      assert.strictEqual(result.claims.has(500), false);
    });

    it('should fail verification with wrong key', async () => {
      const claims = new Map([[1, 'issuer.example']]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const wrongKey = generateKeyPair();
      const presentation = Holder.present(token, []);

      await assert.rejects(
        () => Verifier.verify({
          presentation,
          publicKey: wrongKey.publicKey,
        }),
        /Signature verification failed/
      );
    });

    it('should return header information', async () => {
      const claims = new Map([[1, 'issuer.example']]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
        kid: 'test-key',
      });

      const presentation = Holder.present(token, []);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
      });

      assert.ok(result.headers.protected instanceof Map);
      assert.ok(result.headers.unprotected instanceof Map);
    });

    it('should handle nested map reconstructions', async () => {
      const innerMap = new Map([
        [toBeRedacted('region'), 'ca'],
        ['country', 'us'],
      ]);

      const claims = new Map([
        [503, innerMap],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const presentation = Holder.present(token, disclosures);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
      });

      const location = result.claims.get(503);
      assert.ok(location instanceof Map);
      assert.strictEqual(location.get('region'), 'ca');
      assert.strictEqual(location.get('country'), 'us');
    });

    it('should handle array element disclosures', async () => {
      const dates = [
        toBeRedacted(1549560720),
        1674004740,
      ];

      const claims = new Map([
        [502, dates],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const presentation = Holder.present(token, disclosures);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
      });

      const reconstructedDates = result.claims.get(502);
      assert.strictEqual(reconstructedDates[0], 1549560720);
      assert.strictEqual(reconstructedDates[1], 1674004740);
    });
  });

  describe('Utils', () => {
    const keyPair = generateKeyPair();

    it('should check if claims have redactions', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [501, 'public'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const parsed = Holder.parse(token);
      assert.strictEqual(Utils.hasRedactions(parsed.claims), true);
    });

    it('should return false if no redactions', async () => {
      const claims = new Map([
        [500, 'public1'],
        [501, 'public2'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const parsed = Holder.parse(token);
      assert.strictEqual(Utils.hasRedactions(parsed.claims), false);
    });

    it('should count redactions correctly', async () => {
      const dates = [
        toBeRedacted(1),
        toBeRedacted(2),
        3,
      ];

      const claims = new Map([
        [toBeRedacted(500), 'secret1'],
        [toBeRedacted(501), 'secret2'],
        [502, dates],
        [503, 'public'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const parsed = Holder.parse(token);
      const counts = Utils.countRedactions(parsed.claims);
      
      assert.strictEqual(counts.mapKeys, 2);
      assert.strictEqual(counts.arrayElements, 2);
      assert.strictEqual(counts.total, 4);
    });

    it('should get disclosable claim names', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'val1'],
        [toBeRedacted('myString'), 'val2'],
        [toBeRedacted(-7), 'val3'],
        [501, 'public'],
      ]);

      const { disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const names = Utils.getDisclosableClaimNames(disclosures);
      
      assert.strictEqual(names.length, 3);
      assert.ok(names.includes(500));
      assert.ok(names.includes('myString'));
      assert.ok(names.includes(-7));
    });
  });

  describe('End-to-End Scenarios', () => {
    it('should complete full SD-CWT workflow', async () => {
      // 1. Issuer generates keys
      const issuerKey = generateKeyPair();

      // 2. Issuer creates SD-CWT with redactable claims
      const claims = new Map([
        [1, 'issuer.example'],           // iss
        [2, 'user-12345'],               // sub
        [6, Math.floor(Date.now() / 1000)], // iat
        [toBeRedacted(500), 'DL-123456'], // license number - redactable
        [toBeRedacted(501), '1990-01-15'], // birthdate - redactable
        [502, true],                      // over_21 - public
        [toBeDecoy(2), null],            // add decoys
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKey.privateKey,
        kid: 'issuer-key-001',
      });

      // 3. Holder receives token and disclosures
      // Holder inspects what can be disclosed
      const availableClaims = Utils.getDisclosableClaimNames(disclosures);
      assert.ok(availableClaims.includes(500));
      assert.ok(availableClaims.includes(501));

      // 4. Holder creates presentation, disclosing only birthdate
      const selectedDisclosures = Holder.selectDisclosures(disclosures, [501]);
      const presentation = Holder.present(token, selectedDisclosures);

      // 5. Verifier verifies the presentation
      const result = await Verifier.verify({
        presentation,
        publicKey: issuerKey.publicKey,
      });

      // 6. Verify results
      assert.strictEqual(result.claims.get(1), 'issuer.example');
      assert.strictEqual(result.claims.get(2), 'user-12345');
      assert.strictEqual(result.claims.get(501), '1990-01-15'); // disclosed
      assert.strictEqual(result.claims.has(500), false);        // still redacted
      assert.strictEqual(result.claims.get(502), true);         // public claim
      
      // Should have 1 remaining redacted key (claim 500) + 2 decoys = 3
      assert.strictEqual(result.redactedKeys.length, 3);
    });

    it('should handle complex nested structures', async () => {
      const issuerKey = generateKeyPair();

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

      const claims = new Map([
        [500, true],
        [502, inspectionDates],
        [503, inspectionLocation],
        [toBeRedacted(504), 'ABCD-123456'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKey.privateKey,
      });

      // Full disclosure
      const presentation = Holder.present(token, disclosures);

      const result = await Verifier.verify({
        presentation,
        publicKey: issuerKey.publicKey,
      });

      assert.strictEqual(result.claims.get(500), true);
      assert.strictEqual(result.claims.get(504), 'ABCD-123456');
      
      const dates = result.claims.get(502);
      assert.strictEqual(dates[0], 1549560720);
      assert.strictEqual(dates[1], 1612445940);
      assert.strictEqual(dates[2], 1674004740);

      const location = result.claims.get(503);
      assert.strictEqual(location.get('country'), 'us');
      assert.strictEqual(location.get('region'), 'ca');
      assert.strictEqual(location.get('postal_code'), '90210');
    });

    it('should work with different algorithms', async () => {
      for (const algorithm of [Algorithm.ES256, Algorithm.ES384, Algorithm.ES512]) {
        const keyPair = generateKeyPair(algorithm);

        const claims = new Map([
          [toBeRedacted(500), 'secret'],
          [501, 'public'],
        ]);

        const { token, disclosures } = await Issuer.issue({
          claims,
          privateKey: keyPair.privateKey,
          algorithm,
        });

        const presentation = Holder.present(token, disclosures);

        const result = await Verifier.verify({
          presentation,
          publicKey: keyPair.publicKey,
        });

        assert.strictEqual(result.claims.get(500), 'secret');
        assert.strictEqual(result.claims.get(501), 'public');
      }
    });
  });

});

describe('API: Strict Depth and Validation', () => {
  // Per spec Section 6.5: "Selective disclosure of deeply nested structures 
  // (exceeding a depth of 16 levels), is NOT RECOMMENDED"
  //
  // Per spec Section 14: ToBeRedacted tag is for pre-issuance only
  //
  // Per spec Section 9, Step 7: "Validated Disclosed Claims Set is now a 
  // CWT Claims Set with no claims marked for redaction"
  //
  // Note: The spec allows partial disclosure (Holder chooses what to reveal).
  // The `requireClean` option is an extension for use cases that need
  // all claims disclosed (no redacted elements remaining).

  const keyPair = generateKeyPair();

  describe('MAX_DEPTH constant export', () => {
    it('should export MAX_DEPTH as 16 per spec Section 6.5', () => {
      assert.strictEqual(MAX_DEPTH, 16);
    });
  });

  describe('Issuer with strict mode', () => {
    it('should issue with strict mode enabled', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [501, 'public'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
        strict: true,
      });

      assert.ok(token.length > 0);
      assert.strictEqual(disclosures.length, 1);
    });

    it('should reject deeply nested structures in strict mode', async () => {
      // Build structure exceeding depth 16
      let current = new Map([['val', 'deep']]);
      for (let i = 0; i < 17; i++) {
        current = new Map([['nested', current]]);
      }

      await assert.rejects(
        Issuer.issue({
          claims: current,
          privateKey: keyPair.privateKey,
          strict: true,
        }),
        /exceeds maximum/
      );
    });
  });

  describe('Verifier with strict mode', () => {
    it('should verify with strict mode enabled', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [501, 'public'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const presentation = Holder.present(token, disclosures);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
        strict: true,
      });

      assert.strictEqual(result.claims.get(500), 'secret');
    });
  });

  describe('Verifier with requireClean option', () => {
    it('should pass requireClean when all disclosures provided', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [501, 'public'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      const presentation = Holder.present(token, disclosures);

      // Should not throw with requireClean when fully disclosed
      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
        requireClean: true,
      });

      assert.strictEqual(result.claims.get(500), 'secret');
    });

    it('should fail requireClean when disclosures are missing', async () => {
      const claims = new Map([
        [toBeRedacted(500), 'secret'],
        [501, 'public'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      // Present with no disclosures
      const presentation = Holder.present(token, []);

      // Should throw because claims still have redacted entries
      await assert.rejects(
        Verifier.verify({
          presentation,
          publicKey: keyPair.publicKey,
          requireClean: true,
        }),
        /SD-CWT artifacts/
      );
    });
  });

  describe('validateClaimsClean and assertClaimsClean exports', () => {
    it('should export validateClaimsClean function', () => {
      const claims = new Map([['name', 'Alice']]);
      const result = validateClaimsClean(claims);
      assert.ok(result.isClean);
      assert.deepStrictEqual(result.issues, []);
    });

    it('should export assertClaimsClean function', () => {
      const claims = new Map([['name', 'Alice']]);
      assert.doesNotThrow(() => assertClaimsClean(claims));
    });

    it('should detect unprocessed toBeRedacted tags', () => {
      const claims = new Map([
        [toBeRedacted('secret'), 'value'],
      ]);
      const result = validateClaimsClean(claims);
      assert.strictEqual(result.isClean, false);
      assert.ok(result.issues.length > 0);
    });
  });

  describe('Full API flow with nested structures and decoys', () => {
    it('should handle deeply nested structures with decoys', async () => {
      const nested = new Map([
        [toBeRedacted('inner'), 'inner-secret'],
        ['visible', 'inner-public'],
      ]);

      const claims = new Map([
        ['nested', nested],
        [toBeRedacted('outer'), 'outer-secret'],
        [toBeDecoy(2), null],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      // 2 real disclosures (inner + outer)
      assert.strictEqual(disclosures.length, 2);

      const presentation = Holder.present(token, disclosures);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
      });

      // Verify reconstructed values
      assert.strictEqual(result.claims.get('outer'), 'outer-secret');
      const nestedResult = result.claims.get('nested');
      assert.ok(nestedResult instanceof Map);
      assert.strictEqual(nestedResult.get('inner'), 'inner-secret');
      assert.strictEqual(nestedResult.get('visible'), 'inner-public');

      // Should be clean (no artifacts left after full disclosure)
      const cleanResult = validateClaimsClean(result.claims);
      assert.ok(cleanResult.isClean, `Issues: ${cleanResult.issues.join(', ')}`);
    });

    it('should handle arrays with redactable elements and decoys', async () => {
      const claims = new Map([
        ['items', [
          toBeRedacted('secret-item'),
          'public-item',
          toBeDecoy(1),
        ]],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: keyPair.privateKey,
      });

      // 1 real disclosure for array element
      assert.strictEqual(disclosures.length, 1);

      const presentation = Holder.present(token, disclosures);

      const result = await Verifier.verify({
        presentation,
        publicKey: keyPair.publicKey,
      });

      const items = result.claims.get('items');
      assert.strictEqual(items[0], 'secret-item');
      assert.strictEqual(items[1], 'public-item');
      // items[2] is decoy - remains as RedactedClaimElement

      // Should NOT be clean with default validation (decoy remains)
      const strictResult = validateClaimsClean(result.claims);
      assert.strictEqual(strictResult.isClean, false);

      // Should be clean with allowRedacted
      const lenientResult = validateClaimsClean(result.claims, { allowRedacted: true });
      assert.ok(lenientResult.isClean);
    });
  });

});

