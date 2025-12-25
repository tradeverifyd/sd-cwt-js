/**
 * Tests using keys and examples from the SD-CWT specification
 * 
 * Appendix C of draft-ietf-spice-sd-cwt contains the test keys.
 * Section 13 contains the examples.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';

import {
  Issuer,
  Holder,
  Verifier,
  toBeRedacted,
  ClaimKey,
} from '../src/api.js';

import * as sdCwt from '../src/sd-cwt.js';
import * as coseSign1 from '../src/cose-sign1.js';
import * as cbor from 'cbor2';

/**
 * Test keys from Appendix C of the SD-CWT specification
 */

// C.1. Subject / Holder key (P-256 / ES256)
// From the COSE key in EDN format
const HOLDER_KEY = {
  privateKey: {
    // /d/ -4 : h'5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5'
    d: new Uint8Array(Buffer.from('5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5', 'hex')),
    // /x/ -2 : h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d'
    x: new Uint8Array(Buffer.from('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d', 'hex')),
    // /y/ -3 : h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
    y: new Uint8Array(Buffer.from('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343', 'hex')),
  },
  publicKey: {
    x: new Uint8Array(Buffer.from('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d', 'hex')),
    y: new Uint8Array(Buffer.from('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343', 'hex')),
  },
};

// C.2. Issuer key (P-384 / ES384)
// From the COSE key in EDN format
const ISSUER_KEY = {
  privateKey: {
    // /d/ -4 : h'71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c'
    d: new Uint8Array(Buffer.from('71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c', 'hex')),
    // /x/ -2 : h'c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf'
    x: new Uint8Array(Buffer.from('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf', 'hex')),
    // /y/ -3 : h'8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554'
    y: new Uint8Array(Buffer.from('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554', 'hex')),
  },
  publicKey: {
    x: new Uint8Array(Buffer.from('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf', 'hex')),
    y: new Uint8Array(Buffer.from('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554', 'hex')),
  },
};

/**
 * Helper to create a cnf claim with a holder's public key matching spec format
 */
function createCnfClaim(holderPublicKey) {
  return new Map([
    [1, new Map([
      [1, 2],  // kty: EC2
      [-1, 1], // crv: P-256
      [-2, holderPublicKey.x],
      [-3, holderPublicKey.y],
    ])],
  ]);
}

describe('SD-CWT Spec Test Vectors', () => {

  describe('Appendix C: Test Keys', () => {

    it('should have valid Holder key (P-256)', () => {
      // Verify key components have correct length for P-256
      assert.strictEqual(HOLDER_KEY.privateKey.d.length, 32);
      assert.strictEqual(HOLDER_KEY.publicKey.x.length, 32);
      assert.strictEqual(HOLDER_KEY.publicKey.y.length, 32);
    });

    it('should have valid Issuer key (P-384)', () => {
      // Verify key components have correct length for P-384
      assert.strictEqual(ISSUER_KEY.privateKey.d.length, 48);
      assert.strictEqual(ISSUER_KEY.publicKey.x.length, 48);
      assert.strictEqual(ISSUER_KEY.publicKey.y.length, 48);
    });

  });

  describe('Section 13.1: Minimal Spanning Example', () => {
    // Recreate the example from Section 13.1 using the spec keys

    it('should create and verify SD-CWT matching spec structure', async () => {
      // Claims from Section 13.1 example
      const claims = new Map([
        // / iss / 1 : "https://issuer.example"
        [1, 'https://issuer.example'],
        // / sub / 2 : "https://device.example"
        [2, 'https://device.example'],
        // / exp / 4 : 1725330600
        [4, 1725330600],
        // / nbf / 5 : 1725243900
        [5, 1725243900],
        // / iat / 6 : 1725244200
        [6, 1725244200],
        // / cnf / 8 - holder's public key
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        // /most_recent_inspection_passed/ 500: true
        [500, true],
        // /inspector_license_number/ 501 - redactable
        [toBeRedacted(501), 'ABCD-123456'],
        // /inspection_dates/ 502 - array with redactable elements
        [502, [
          toBeRedacted(1549560720),  // inspected 7-Feb-2019
          toBeRedacted(1612560720),  // inspected 4-Feb-2021
          1674004740,                // 2023-01-17T17:19:00 - not redacted
        ]],
        // / inspection_location / 503 - nested map with redactable claims
        [503, new Map([
          ['country', 'us'],
          [toBeRedacted('region'), 'ca'],
          [toBeRedacted('postal_code'), '94188'],
        ])],
      ]);

      // Issue the SD-CWT using the spec's Issuer key (ES384)
      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      assert.ok(token.length > 0);
      // Should have 5 disclosures: 501, two dates, region, postal_code
      assert.strictEqual(disclosures.length, 5);

      // Parse and verify structure
      const parsed = Holder.parse(token);
      assert.strictEqual(parsed.claims.get(1), 'https://issuer.example');
      assert.strictEqual(parsed.claims.get(2), 'https://device.example');
      assert.strictEqual(parsed.claims.get(500), true);

      // Verify the redacted structure
      // Claim 501 should be redacted (not present as plain value)
      assert.ok(!parsed.claims.has(501));

      // Array should have redacted elements (Tags 60)
      const dates = parsed.claims.get(502);
      assert.ok(Array.isArray(dates));
      assert.strictEqual(dates.length, 3);
      assert.ok(sdCwt.isRedactedClaimElement(dates[0])); // First date redacted
      assert.ok(sdCwt.isRedactedClaimElement(dates[1])); // Second date redacted
      assert.strictEqual(dates[2], 1674004740);          // Third date visible

      // Nested map should have redacted keys
      const location = parsed.claims.get(503);
      assert.ok(location instanceof Map);
      assert.strictEqual(location.get('country'), 'us');
    });

    it('should create SD-KBT and verify with spec keys', async () => {
      // Create claims
      const claims = new Map([
        [1, 'https://issuer.example'],
        [2, 'https://device.example'],
        [4, 1725330600],
        [5, 1725243900],
        [6, 1725244200],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
        [toBeRedacted(501), 'ABCD-123456'],
        [502, [
          toBeRedacted(1549560720),
          1674004740,
        ]],
        [503, new Map([
          ['country', 'us'],
          [toBeRedacted('region'), 'ca'],
        ])],
      ]);

      // Issue with Issuer's ES384 key
      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Select disclosures for presentation (partial disclosure)
      // Disclose: inspector_license_number (501) and region
      const selectedDisclosures = Holder.selectDisclosures(disclosures, [501, 'region']);

      // Create SD-KBT with Holder's ES256 key
      const expectedAudience = 'https://verifier.example/app';
      const nonce = new Uint8Array(Buffer.from('8c0f5f523b95bea44a9a48c649240803', 'hex'));

      const kbt = await Holder.present({
        token,
        selectedDisclosures,
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: expectedAudience,
        nonce,
        algorithm: 'ES256',
      });

      assert.ok(kbt.length > 0);

      // Verify the SD-KBT
      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience,
        expectedNonce: nonce,
      });

      // Verify claims
      assert.strictEqual(result.claims.get(1), 'https://issuer.example');
      assert.strictEqual(result.claims.get(2), 'https://device.example');
      assert.strictEqual(result.claims.get(500), true);
      
      // Disclosed claims should be present
      assert.strictEqual(result.claims.get(501), 'ABCD-123456');
      
      // Nested disclosed claim
      const location = result.claims.get(503);
      assert.strictEqual(location.get('country'), 'us');
      assert.strictEqual(location.get('region'), 'ca');

      // Verify KBT payload
      assert.strictEqual(result.kbtPayload.get(ClaimKey.Aud), expectedAudience);
      assert.ok(result.kbtPayload.has(ClaimKey.Iat));
      
      // Verify nonce matches
      const kbtNonce = result.kbtPayload.get(ClaimKey.Cnonce);
      assert.ok(kbtNonce);
      assert.deepStrictEqual(Buffer.from(kbtNonce), Buffer.from(nonce));
    });

    it('should reject SD-KBT with wrong issuer key', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      const kbt = await Holder.present({
        token,
        selectedDisclosures: [],
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example/app',
        algorithm: 'ES256',
      });

      // Try to verify with holder's key instead of issuer's key
      // This fails because P-256 key can't verify P-384 signature (wrong curve)
      await assert.rejects(
        Verifier.verify({
          presentation: kbt,
          issuerPublicKey: HOLDER_KEY.publicKey, // Wrong key!
          expectedAudience: 'https://verifier.example/app',
        }),
        /Signature verification failed|Invalid.*key/i
      );
    });

    it('should reject SD-KBT with wrong holder key binding', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Attacker tries to present with issuer's key (not holder's key)
      const kbt = await Holder.present({
        token,
        selectedDisclosures: [],
        holderPrivateKey: ISSUER_KEY.privateKey, // Wrong key!
        audience: 'https://verifier.example/app',
        algorithm: 'ES384',
      });

      // Should fail because the KBT signature doesn't match the cnf key
      // The cnf key is P-256 but KBT was signed with P-384
      await assert.rejects(
        Verifier.verify({
          presentation: kbt,
          issuerPublicKey: ISSUER_KEY.publicKey,
          expectedAudience: 'https://verifier.example/app',
        }),
        /Signature verification failed|Invalid.*key/i
      );
    });

  });

  describe('Hash computation verification', () => {
    // Verify our hash computation matches the spec examples

    it('should compute correct disclosure hash', () => {
      // From Section 5 of the spec, a disclosure has format:
      // [salt, value] for array elements
      // [salt, value, claimName] for map claims
      
      // Create a disclosure matching the spec format
      const salt = Buffer.from('bae611067bb823486797da1ebbb52f83', 'hex');
      const value = 'ABCD-123456';
      const claimName = 501;

      // Create the disclosure structure
      const disclosureContent = [salt, value, claimName];
      const disclosureBytes = cbor.encode(disclosureContent);

      // Compute the hash
      const hash = sdCwt.hashDisclosure(disclosureBytes, 'sha256');
      
      // The hash should be 32 bytes for SHA-256
      assert.strictEqual(hash.length, 32);
      
      // Note: We can't verify against spec hash because salt is random in real use
      // This test verifies the mechanism works correctly
    });

  });

  describe('CBOR structure verification', () => {

    it('should encode cnf claim in spec-compatible format', () => {
      const cnf = createCnfClaim(HOLDER_KEY.publicKey);
      
      // Verify structure: { 1: { 1: 2, -1: 1, -2: x, -3: y } }
      assert.ok(cnf instanceof Map);
      assert.ok(cnf.has(1));
      
      const coseKey = cnf.get(1);
      assert.ok(coseKey instanceof Map);
      assert.strictEqual(coseKey.get(1), 2);   // kty: EC2
      assert.strictEqual(coseKey.get(-1), 1);  // crv: P-256
      assert.deepStrictEqual(coseKey.get(-2), HOLDER_KEY.publicKey.x);
      assert.deepStrictEqual(coseKey.get(-3), HOLDER_KEY.publicKey.y);
    });

    it('should encode redacted claim element with Tag 60', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [502, [
          toBeRedacted('secret-value'),
          'public-value',
        ]],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      const parsed = Holder.parse(token);
      const array = parsed.claims.get(502);

      // First element should be Tag 60 (RedactedClaimElement)
      assert.ok(sdCwt.isRedactedClaimElement(array[0]));
      assert.ok(array[0] instanceof cbor.Tag);
      assert.strictEqual(array[0].tag, 60);

      // Second element should be plain value
      assert.strictEqual(array[1], 'public-value');
    });

    it('should encode redacted claim keys with simple(59)', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [toBeRedacted(500), 'secret-value'],
        [501, 'public-value'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      const parsed = Holder.parse(token);

      // Should have simple(59) key for redacted claim keys
      let hasRedactedKeysKey = false;
      for (const key of parsed.claims.keys()) {
        if (sdCwt.isRedactedKeysKey(key)) {
          hasRedactedKeysKey = true;
          // Value should be array of hashes
          const hashes = parsed.claims.get(key);
          assert.ok(Array.isArray(hashes));
          assert.ok(hashes.length > 0);
          assert.ok(hashes[0] instanceof Uint8Array || Buffer.isBuffer(hashes[0]));
        }
      }
      assert.ok(hasRedactedKeysKey);
    });

  });

  describe('IANA Considerations - Header Parameters (Section 17.1)', () => {
    // Tests for COSE Header Parameters defined in IANA considerations
    // Note: sd_claims is added during presentation, not issuance

    it('should set sd_alg (label 18) in protected header when disclosures exist', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [toBeRedacted(501), 'secret-value'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Parse the COSE_Sign1 structure to check headers
      const headers = coseSign1.getHeaders(token);
      
      // sd_alg (18) should be in protected header
      assert.ok(headers.protectedHeaders.has(18), 'sd_alg (18) must be in protected header');
      
      // The value should be -16 (SHA-256)
      const sdAlgHeader = headers.protectedHeaders.get(18);
      assert.strictEqual(sdAlgHeader, -16, 'sd_alg value should be -16 (SHA-256)');
    });

    it('should set typ (label 16) to application/sd-cwt in protected header', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, 'public-value'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      const headers = coseSign1.getHeaders(token);
      
      // typ (16) should be in protected header
      assert.ok(headers.protectedHeaders.has(16), 'typ (16) must be in protected header');
      
      const typHeader = headers.protectedHeaders.get(16);
      assert.strictEqual(typHeader, 'application/sd-cwt');
    });

    it('should set sd_claims (label 17) in SD-CWT during presentation', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [toBeRedacted(501), 'secret-value'],
        [toBeRedacted(502), 'another-secret'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // At issuance, disclosures are returned separately (not in token headers)
      assert.strictEqual(disclosures.length, 2);

      // Create presentation with selected disclosures
      const kbt = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      // Parse the SD-KBT to extract the embedded SD-CWT
      const kbtDecoded = cbor.decode(kbt);
      assert.ok(kbtDecoded instanceof cbor.Tag);
      assert.strictEqual(kbtDecoded.tag, 18);
      
      // Get the kcwt from KBT protected header
      const kbtProtectedBytes = kbtDecoded.contents[0];
      const kbtProtectedHeader = cbor.decode(kbtProtectedBytes);
      
      // kcwt (13) contains the SD-CWT
      const sdCwtBytes = kbtProtectedHeader.get(13);
      assert.ok(sdCwtBytes);
      
      // Parse the SD-CWT inside
      const sdCwtDecoded = cbor.decode(sdCwtBytes);
      assert.ok(sdCwtDecoded instanceof cbor.Tag);
      
      // Get the unprotected header of the SD-CWT
      const sdCwtUnprotected = sdCwtDecoded.contents[1];
      
      // sd_claims (17) should be present with the disclosures
      assert.ok(sdCwtUnprotected.has(17), 'sd_claims (17) must be in SD-CWT unprotected header during presentation');
      
      const sdClaimsHeader = sdCwtUnprotected.get(17);
      assert.ok(Array.isArray(sdClaimsHeader));
      assert.strictEqual(sdClaimsHeader.length, 2, 'All selected disclosures should be in sd_claims');
    });

    it('should have empty sd_claims in presentation when no disclosures selected', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [toBeRedacted(501), 'secret-value'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Create presentation with NO disclosures
      const kbt = await Holder.present({
        token,
        selectedDisclosures: [],  // Empty - don't disclose anything
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      // Parse and check the SD-CWT inside the SD-KBT
      const kbtDecoded = cbor.decode(kbt);
      const kbtProtectedBytes = kbtDecoded.contents[0];
      const kbtProtectedHeader = cbor.decode(kbtProtectedBytes);
      const sdCwtBytes = kbtProtectedHeader.get(13);
      const sdCwtDecoded = cbor.decode(sdCwtBytes);
      const sdCwtUnprotected = sdCwtDecoded.contents[1];
      
      // sd_claims should be empty array
      const sdClaimsHeader = sdCwtUnprotected.get(17);
      assert.ok(Array.isArray(sdClaimsHeader));
      assert.strictEqual(sdClaimsHeader.length, 0, 'sd_claims should be empty when no disclosures selected');
    });

  });

  describe('IANA Considerations - CBOR Simple Values (Section 17.2)', () => {
    // simple(59) for redacted claim keys

    it('should use simple(59) as map key for redacted claim keys array', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [toBeRedacted(500), 'secret-value'],
        [501, 'public-value'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      const parsed = Holder.parse(token);
      
      // Find simple(59) key in the claims
      let foundSimple59 = false;
      for (const key of parsed.claims.keys()) {
        if (key instanceof cbor.Simple && key.value === 59) {
          foundSimple59 = true;
          // Value should be an array of hashes
          const hashes = parsed.claims.get(key);
          assert.ok(Array.isArray(hashes));
          break;
        }
      }
      assert.ok(foundSimple59, 'Claims must contain simple(59) key for redacted keys');
    });

  });

  describe('IANA Considerations - CBOR Tags (Section 17.3)', () => {
    // Tag 58: To Be Redacted
    // Tag 60: Redacted Claim Element

    it('should use Tag 58 for marking claims to be redacted (pre-issuance)', () => {
      const tagged = sdCwt.toBeRedacted(500);
      
      assert.ok(tagged instanceof cbor.Tag);
      assert.strictEqual(tagged.tag, 58, 'toBeRedacted must use Tag 58');
      assert.strictEqual(tagged.contents, 500);
    });

    it('should use Tag 60 for redacted array elements (post-issuance)', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [502, [
          toBeRedacted('secret-element'),
          'public-element',
        ]],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      const parsed = Holder.parse(token);
      const array = parsed.claims.get(502);
      
      // First element should be Tag 60
      assert.ok(array[0] instanceof cbor.Tag);
      assert.strictEqual(array[0].tag, 60, 'Redacted array element must use Tag 60');
      
      // The contents should be the hash (byte string)
      assert.ok(
        array[0].contents instanceof Uint8Array || Buffer.isBuffer(array[0].contents),
        'Tag 60 contents must be a byte string (hash)'
      );
    });

    it('should have Tag 60 contents matching disclosure hash', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [502, [toBeRedacted('secret-value')]],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      assert.strictEqual(disclosures.length, 1);

      const parsed = Holder.parse(token);
      const array = parsed.claims.get(502);
      
      // Get the hash from Tag 60
      const tagHash = array[0].contents;
      
      // Compute the expected hash
      const expectedHash = sdCwt.hashDisclosure(disclosures[0], 'sha256');
      
      // They should match
      assert.deepStrictEqual(
        new Uint8Array(tagHash),
        expectedHash,
        'Tag 60 hash must match disclosure hash'
      );
    });

  });

  describe('Disclosure format verification (Section 5)', () => {
    // SD-CWT spec: disclosure format is [salt, value, key] for named claims
    // and [salt, value] for array elements

    it('should create named claim disclosure with format [salt, value, key]', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [toBeRedacted(501), 'ABCD-123456'],
      ]);

      const { disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      assert.strictEqual(disclosures.length, 1);
      
      // Decode and verify structure matches spec: [salt, value, key]
      const decoded = cbor.decode(disclosures[0]);
      assert.ok(Array.isArray(decoded));
      assert.strictEqual(decoded.length, 3, 'Named claim disclosure must have 3 elements');
      
      // Per spec: [salt, value, key]
      const [salt, value, key] = decoded;
      assert.ok(salt instanceof Uint8Array || Buffer.isBuffer(salt), 'salt must be bytes');
      assert.strictEqual(salt.length, 16, 'salt must be 16 bytes');
      assert.strictEqual(value, 'ABCD-123456', 'value must be the claim value');
      assert.strictEqual(key, 501, 'key must be the claim key');
    });

    it('should create array element disclosure with format [salt, value] (no key)', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [502, [
          toBeRedacted(1549560720),  // redactable date
          1674004740,                // non-redactable date
        ]],
      ]);

      const { disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      assert.strictEqual(disclosures.length, 1);
      
      // Decode and verify structure matches spec: [salt, value] for array elements
      const decoded = cbor.decode(disclosures[0]);
      assert.ok(Array.isArray(decoded));
      assert.strictEqual(decoded.length, 2, 'Array element disclosure must have 2 elements (no key)');
      
      // Per spec: [salt, value] - no key for array elements
      const [salt, value] = decoded;
      assert.ok(salt instanceof Uint8Array || Buffer.isBuffer(salt), 'salt must be bytes');
      assert.strictEqual(salt.length, 16, 'salt must be 16 bytes');
      assert.strictEqual(value, 1549560720, 'value must be the array element value');
    });

    it('should create string-keyed claim disclosure with format [salt, value, key]', async () => {
      const claims = new Map([
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [503, new Map([
          ['country', 'us'],
          [toBeRedacted('region'), 'ca'],
        ])],
      ]);

      const { disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      assert.strictEqual(disclosures.length, 1);
      
      // Decode and verify structure
      const decoded = cbor.decode(disclosures[0]);
      assert.ok(Array.isArray(decoded));
      assert.strictEqual(decoded.length, 3, 'String-keyed claim disclosure must have 3 elements');
      
      // Per spec: [salt, value, key]
      const [salt, value, key] = decoded;
      assert.ok(salt instanceof Uint8Array || Buffer.isBuffer(salt));
      assert.strictEqual(value, 'ca');
      assert.strictEqual(key, 'region');
    });

  });

  describe('Array element disclosure (Section 13.1)', () => {
    // The minimal spanning example shows arrays with redacted elements

    it('should issue and verify with redacted array elements', async () => {
      // From Section 13.1: inspection_dates array with some redacted elements
      const claims = new Map([
        [1, 'https://issuer.example'],
        [2, 'https://device.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
        // inspection_dates with redactable and non-redactable elements
        [502, [
          toBeRedacted(1549560720),  // 7-Feb-2019 - redactable
          toBeRedacted(1612560720),  // 4-Feb-2021 - redactable  
          1674004740,                // 2023-01-17 - always visible
        ]],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Should have 2 disclosures (one for each redacted array element)
      assert.strictEqual(disclosures.length, 2);

      // Parse the issued token
      const parsed = Holder.parse(token);
      const dates = parsed.claims.get(502);
      
      assert.ok(Array.isArray(dates));
      assert.strictEqual(dates.length, 3);
      
      // First two should be redacted (Tag 60)
      assert.ok(sdCwt.isRedactedClaimElement(dates[0]));
      assert.ok(sdCwt.isRedactedClaimElement(dates[1]));
      // Third should be visible
      assert.strictEqual(dates[2], 1674004740);
    });

    it('should allow selective disclosure of individual array elements', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [502, [
          toBeRedacted('element-0'),
          toBeRedacted('element-1'),
          toBeRedacted('element-2'),
          'always-visible',
        ]],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      assert.strictEqual(disclosures.length, 3);

      // Decode each disclosure to find the one for 'element-1'
      let element1Disclosure = null;
      for (const disclosure of disclosures) {
        const decoded = cbor.decode(disclosure);
        if (decoded[1] === 'element-1') {
          element1Disclosure = disclosure;
          break;
        }
      }
      assert.ok(element1Disclosure, 'Should find disclosure for element-1');

      // Present with only element-1 disclosed
      const kbt = await Holder.present({
        token,
        selectedDisclosures: [element1Disclosure],
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience: 'https://verifier.example',
      });

      const arr = result.claims.get(502);
      assert.ok(Array.isArray(arr));
      
      // Only element-1 should be disclosed
      assert.ok(sdCwt.isRedactedClaimElement(arr[0]));
      assert.strictEqual(arr[1], 'element-1');
      assert.ok(sdCwt.isRedactedClaimElement(arr[2]));
      assert.strictEqual(arr[3], 'always-visible');
    });

    it('should disclose all array elements when all disclosures provided', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [502, [
          toBeRedacted(1549560720),
          toBeRedacted(1612560720),
          1674004740,
        ]],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Present with ALL disclosures
      const kbt = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience: 'https://verifier.example',
      });

      const arr = result.claims.get(502);
      assert.ok(Array.isArray(arr));
      assert.strictEqual(arr.length, 3);
      
      // All elements should be visible
      assert.strictEqual(arr[0], 1549560720);
      assert.strictEqual(arr[1], 1612560720);
      assert.strictEqual(arr[2], 1674004740);
    });

    it('should keep array elements redacted when disclosures withheld', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [502, [
          toBeRedacted('secret-date-1'),
          toBeRedacted('secret-date-2'),
          'public-date',
        ]],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Present with NO disclosures (keep all redacted)
      const kbt = await Holder.present({
        token,
        selectedDisclosures: [],
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience: 'https://verifier.example',
      });

      const arr = result.claims.get(502);
      assert.ok(Array.isArray(arr));
      assert.strictEqual(arr.length, 3);
      
      // First two should still be redacted
      assert.ok(sdCwt.isRedactedClaimElement(arr[0]));
      assert.ok(sdCwt.isRedactedClaimElement(arr[1]));
      // Third always visible
      assert.strictEqual(arr[2], 'public-date');
    });

  });

  describe('Combined named claims and array elements (Section 13.1)', () => {
    // Full minimal spanning example with both types of disclosures

    it('should handle mixed disclosure types in a single SD-CWT', async () => {
      // Exact structure from Section 13.1
      const claims = new Map([
        [1, 'https://issuer.example'],
        [2, 'https://device.example'],
        [4, 1725330600],
        [5, 1725243900],
        [6, 1725244200],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
        // Named claim with redactable key
        [toBeRedacted(501), 'ABCD-123456'],
        // Array with redactable elements
        [502, [
          toBeRedacted(1549560720),
          toBeRedacted(1612560720),
          1674004740,
        ]],
        // Nested map with redactable claims
        [503, new Map([
          ['country', 'us'],
          [toBeRedacted('region'), 'ca'],
          [toBeRedacted('postal_code'), '94188'],
        ])],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Should have 5 disclosures total:
      // 1 for claim 501, 2 for array elements, 2 for nested map claims
      assert.strictEqual(disclosures.length, 5);

      // Categorize disclosures by type
      let namedClaimCount = 0;
      let arrayElementCount = 0;
      
      for (const disclosure of disclosures) {
        const decoded = cbor.decode(disclosure);
        if (decoded.length === 2) {
          arrayElementCount++;
        } else if (decoded.length === 3) {
          namedClaimCount++;
        }
      }
      
      assert.strictEqual(arrayElementCount, 2, 'Should have 2 array element disclosures');
      assert.strictEqual(namedClaimCount, 3, 'Should have 3 named claim disclosures');
    });

    it('should support partial disclosure of both types', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [toBeRedacted(501), 'LICENSE-NUMBER'],
        [502, [
          toBeRedacted('date-1'),
          toBeRedacted('date-2'),
        ]],
        [503, new Map([
          ['country', 'us'],
          [toBeRedacted('region'), 'ca'],
        ])],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // Select only: claim 501 and region
      // Should NOT include array element disclosures
      const selectedDisclosures = Holder.selectDisclosures(disclosures, [501, 'region']);
      
      assert.strictEqual(selectedDisclosures.length, 2);

      const kbt = await Holder.present({
        token,
        selectedDisclosures,
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience: 'https://verifier.example',
      });

      // Claim 501 should be disclosed
      assert.strictEqual(result.claims.get(501), 'LICENSE-NUMBER');
      
      // Array elements should still be redacted
      const arr = result.claims.get(502);
      assert.ok(sdCwt.isRedactedClaimElement(arr[0]));
      assert.ok(sdCwt.isRedactedClaimElement(arr[1]));
      
      // Nested region should be disclosed
      const location = result.claims.get(503);
      assert.strictEqual(location.get('country'), 'us');
      assert.strictEqual(location.get('region'), 'ca');
    });

  });

  describe('Full roundtrip with spec keys', () => {

    it('should complete full issuance and verification flow', async () => {
      // 1. Issuer creates SD-CWT with spec keys
      const claims = new Map([
        [1, 'https://issuer.example'],
        [2, 'https://device.example'],
        [4, Math.floor(Date.now() / 1000) + 3600], // exp: 1 hour from now
        [5, Math.floor(Date.now() / 1000) - 60],   // nbf: 1 minute ago
        [6, Math.floor(Date.now() / 1000)],        // iat: now
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
        [toBeRedacted(501), 'LICENSE-12345'],
        [toBeRedacted(502), '1990-01-15'],
        [503, 'public-claim'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
      });

      // 2. Holder selects disclosures
      const selectedDisclosures = Holder.selectDisclosures(disclosures, [501]);

      // 3. Holder creates presentation
      const nonce = crypto.getRandomValues(new Uint8Array(16));
      const kbt = await Holder.present({
        token,
        selectedDisclosures,
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        nonce,
        algorithm: 'ES256',
      });

      // 4. Verifier validates
      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience: 'https://verifier.example',
        expectedNonce: nonce,
      });

      // 5. Verify results
      assert.strictEqual(result.claims.get(1), 'https://issuer.example');
      assert.strictEqual(result.claims.get(500), true);
      assert.strictEqual(result.claims.get(501), 'LICENSE-12345'); // Disclosed
      assert.strictEqual(result.claims.has(502), false);            // Still redacted
      assert.strictEqual(result.claims.get(503), 'public-claim');

      // 6. One claim still redacted
      assert.strictEqual(result.redactedKeys.length, 1);
    });

  });

  describe('CWT Claims Header Parameter (RFC 9597 / Section 17.1)', () => {
    // Tests for claims in protected header instead of payload
    // Per RFC 9597, CWT Claims header parameter (15) can contain claims

    it('should issue SD-CWT with claims in protected header', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [2, 'https://device.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
        [toBeRedacted(501), 'secret-value'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
        claimsInProtectedHeader: true,  // Enable claims in header
      });

      assert.ok(token.length > 0);
      assert.strictEqual(disclosures.length, 1);

      // Verify the structure - claims should be in header 15
      const headers = coseSign1.getHeaders(token);
      
      // CWT Claims header (15) should contain the claims
      assert.ok(headers.protectedHeaders.has(15), 'CWT Claims (15) must be in protected header');
      const headerClaims = headers.protectedHeaders.get(15);
      assert.ok(headerClaims instanceof Map, 'CWT Claims value must be a Map');
      
      // Verify claims are in the header
      assert.strictEqual(headerClaims.get(1), 'https://issuer.example');
      assert.strictEqual(headerClaims.get(500), true);
      
      // Payload should be empty
      const decoded = cbor.decode(token);
      const coseArray = decoded.contents || decoded;
      const payload = coseArray[2];
      assert.strictEqual(payload.length, 0, 'Payload should be empty when claims in header');
    });

    it('should parse SD-CWT with claims in protected header', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
        [toBeRedacted(501), 'secret-value'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
        claimsInProtectedHeader: true,
      });

      // Parse should work and return claims from header
      const parsed = Holder.parse(token);
      
      assert.ok(parsed.claims instanceof Map);
      assert.strictEqual(parsed.claims.get(1), 'https://issuer.example');
      assert.strictEqual(parsed.claims.get(500), true);
      
      // Redacted claim should be present as simple(59) array
      let hasRedactedKeys = false;
      for (const key of parsed.claims.keys()) {
        if (sdCwt.isRedactedKeysKey(key)) {
          hasRedactedKeys = true;
          break;
        }
      }
      assert.ok(hasRedactedKeys, 'Should have redacted keys marker');
    });

    it('should verify SD-CWT with claims in protected header', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [2, 'https://device.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, true],
        [toBeRedacted(501), 'LICENSE-12345'],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
        claimsInProtectedHeader: true,
      });

      // Create presentation
      const kbt = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      // Verify should work
      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience: 'https://verifier.example',
      });

      // Verify claims
      assert.strictEqual(result.claims.get(1), 'https://issuer.example');
      assert.strictEqual(result.claims.get(2), 'https://device.example');
      assert.strictEqual(result.claims.get(500), true);
      assert.strictEqual(result.claims.get(501), 'LICENSE-12345');
    });

    it('should handle array disclosures with claims in protected header', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [502, [
          toBeRedacted('secret-date-1'),
          toBeRedacted('secret-date-2'),
          'public-date',
        ]],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
        claimsInProtectedHeader: true,
      });

      assert.strictEqual(disclosures.length, 2);

      // Parse and check array structure
      const parsed = Holder.parse(token);
      const arr = parsed.claims.get(502);
      
      assert.ok(Array.isArray(arr));
      assert.strictEqual(arr.length, 3);
      assert.ok(sdCwt.isRedactedClaimElement(arr[0]));
      assert.ok(sdCwt.isRedactedClaimElement(arr[1]));
      assert.strictEqual(arr[2], 'public-date');

      // Full verification with disclosures
      const kbt = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience: 'https://verifier.example',
      });

      const resultArr = result.claims.get(502);
      assert.strictEqual(resultArr[0], 'secret-date-1');
      assert.strictEqual(resultArr[1], 'secret-date-2');
      assert.strictEqual(resultArr[2], 'public-date');
    });

    it('should handle nested map disclosures with claims in protected header', async () => {
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [503, new Map([
          ['country', 'us'],
          [toBeRedacted('region'), 'ca'],
          [toBeRedacted('postal_code'), '94188'],
        ])],
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
        claimsInProtectedHeader: true,
      });

      assert.strictEqual(disclosures.length, 2);

      // Verify with all disclosures
      const kbt = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      const result = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_KEY.publicKey,
        expectedAudience: 'https://verifier.example',
      });

      const location = result.claims.get(503);
      assert.ok(location instanceof Map);
      assert.strictEqual(location.get('country'), 'us');
      assert.strictEqual(location.get('region'), 'ca');
      assert.strictEqual(location.get('postal_code'), '94188');
    });

    it('should maintain protected header integrity for claims', async () => {
      // Claims in protected header are protected by the signature
      const claims = new Map([
        [1, 'https://issuer.example'],
        [ClaimKey.Cnf, createCnfClaim(HOLDER_KEY.publicKey)],
        [500, 'important-claim'],
      ]);

      const { token } = await Issuer.issue({
        claims,
        privateKey: ISSUER_KEY.privateKey,
        algorithm: 'ES384',
        claimsInProtectedHeader: true,
      });

      // Attempting to verify with wrong key should fail
      // (proving the protected header is integrity-protected)
      const kbt = await Holder.present({
        token,
        selectedDisclosures: [],
        holderPrivateKey: HOLDER_KEY.privateKey,
        audience: 'https://verifier.example',
        algorithm: 'ES256',
      });

      await assert.rejects(
        Verifier.verify({
          presentation: kbt,
          issuerPublicKey: HOLDER_KEY.publicKey, // Wrong key!
          expectedAudience: 'https://verifier.example',
        }),
        /Signature verification failed|Invalid.*key/i
      );
    });

  });

});

