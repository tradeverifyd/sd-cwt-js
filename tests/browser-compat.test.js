/**
 * Browser Compatibility Tests
 * 
 * Tests that verify Node.js and browser implementations produce
 * compatible results for the SD-CWT workflow.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';

import * as coseSign1 from '../src/cose-sign1.js';
import * as sdCwt from '../src/sd-cwt.js';
import { Issuer, Holder, Verifier, toBeRedacted, ClaimKey } from '../src/api.js';

// Spec test keys from Appendix C
const SPEC_HOLDER_KEY = {
  d: Buffer.from('5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5', 'hex'),
  x: Buffer.from('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d', 'hex'),
  y: Buffer.from('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343', 'hex'),
};

const SPEC_ISSUER_KEY = {
  d: Buffer.from('71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c', 'hex'),
  x: Buffer.from('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf', 'hex'),
  y: Buffer.from('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554', 'hex'),
};

function createCoseKey(key, algorithm, includePrivate = true) {
  const kty = 2; // EC2
  const crv = algorithm === 'ES384' ? 2 : 1; // P-384 = 2, P-256 = 1
  
  const coseKey = new Map();
  coseKey.set(1, kty);
  coseKey.set(-1, crv);
  coseKey.set(-2, new Uint8Array(key.x));
  coseKey.set(-3, new Uint8Array(key.y));
  if (includePrivate && key.d) {
    coseKey.set(-4, new Uint8Array(key.d));
  }
  return coseKey;
}

function createCnfClaim(holderPublicKey) {
  return new Map([
    [1, holderPublicKey],
  ]);
}

describe('Browser Compatibility - Spec Keys', () => {
  
  it('should create matching COSE Key hex representations', () => {
    const holderPrivateCoseKey = createCoseKey(SPEC_HOLDER_KEY, 'ES256', true);
    const holderPublicCoseKey = createCoseKey(SPEC_HOLDER_KEY, 'ES256', false);
    const issuerPrivateCoseKey = createCoseKey(SPEC_ISSUER_KEY, 'ES384', true);
    const issuerPublicCoseKey = createCoseKey(SPEC_ISSUER_KEY, 'ES384', false);
    
    // Serialize to hex
    const holderPrivateHex = coseSign1.coseKeyToHex(holderPrivateCoseKey);
    const holderPublicHex = coseSign1.coseKeyToHex(holderPublicCoseKey);
    const issuerPrivateHex = coseSign1.coseKeyToHex(issuerPrivateCoseKey);
    const issuerPublicHex = coseSign1.coseKeyToHex(issuerPublicCoseKey);
    
    console.log('Holder Public Key Hex:', holderPublicHex);
    console.log('Issuer Public Key Hex:', issuerPublicHex);
    
    // Verify they can be deserialized
    const holderPublicRestored = coseSign1.coseKeyFromHex(holderPublicHex);
    const issuerPublicRestored = coseSign1.coseKeyFromHex(issuerPublicHex);
    
    assert.ok(holderPublicRestored instanceof Map);
    assert.ok(issuerPublicRestored instanceof Map);
    
    // Verify key type
    assert.strictEqual(holderPublicRestored.get(1), 2); // EC2
    assert.strictEqual(issuerPublicRestored.get(1), 2); // EC2
    
    // Verify curve
    assert.strictEqual(holderPublicRestored.get(-1), 1); // P-256
    assert.strictEqual(issuerPublicRestored.get(-1), 2); // P-384
  });

  it('should complete full SD-CWT workflow with spec keys', async () => {
    // Create COSE Keys
    const issuerPrivateKey = createCoseKey(SPEC_ISSUER_KEY, 'ES384', true);
    const issuerPublicKey = createCoseKey(SPEC_ISSUER_KEY, 'ES384', false);
    const holderPrivateKey = createCoseKey(SPEC_HOLDER_KEY, 'ES256', true);
    const holderPublicKey = createCoseKey(SPEC_HOLDER_KEY, 'ES256', false);
    
    // Claims matching Section 13.1
    const claims = new Map([
      [1, 'https://issuer.example'],
      [2, 'https://device.example'],
      [4, 1725330600],
      [5, 1725243900],
      [6, 1725244200],
      [ClaimKey.Cnf, createCnfClaim(holderPublicKey)],
      [500, true],
      [toBeRedacted(501), 'ABCD-123456'],
      [503, new Map([
        ['country', 'us'],
        [toBeRedacted('region'), 'ca'],
        [toBeRedacted('postal_code'), '94188'],
      ])],
    ]);
    
    // Step 1: Issue SD-CWT
    console.log('\n=== Step 1: Issue SD-CWT ===');
    const { token, disclosures } = await Issuer.issue({
      claims,
      privateKey: issuerPrivateKey,
      algorithm: 'ES384',
    });
    
    console.log('Token length:', token.length);
    console.log('Number of disclosures:', disclosures.length);
    assert.ok(token.length > 0);
    assert.strictEqual(disclosures.length, 3); // 501, region, postal_code
    
    // Serialize for comparison
    const tokenHex = Buffer.from(token).toString('hex');
    console.log('Token hex (first 100 chars):', tokenHex.slice(0, 100) + '...');
    
    // Step 2: Parse token (Holder)
    console.log('\n=== Step 2: Parse Token ===');
    const parsed = Holder.parse(token);
    assert.strictEqual(parsed.claims.get(1), 'https://issuer.example');
    assert.strictEqual(parsed.claims.get(500), true);
    console.log('Parsed issuer:', parsed.claims.get(1));
    
    // Step 3: Create presentation (without nonce for simplicity)
    console.log('\n=== Step 3: Create Presentation ===');
    const presentation = await Holder.present({
      token,
      selectedDisclosures: disclosures, // Disclose all
      holderPrivateKey,
      audience: 'https://verifier.example',
      algorithm: 'ES256',
    });
    
    console.log('Presentation length:', presentation.length);
    const presentationHex = Buffer.from(presentation).toString('hex');
    console.log('Presentation hex (first 100 chars):', presentationHex.slice(0, 100) + '...');
    
    // Step 4: Verify presentation
    console.log('\n=== Step 4: Verify Presentation ===');
    const result = await Verifier.verify({
      presentation,
      issuerPublicKey,
      expectedAudience: 'https://verifier.example',
      hashAlgorithm: 'sha-256',
    });
    
    console.log('Verification successful!');
    console.log('Verified claims:');
    for (const [key, value] of result.claims) {
      if (typeof value !== 'object') {
        console.log(`  ${key}: ${value}`);
      }
    }
    
    // Verify claims
    assert.strictEqual(result.claims.get(1), 'https://issuer.example');
    assert.strictEqual(result.claims.get(2), 'https://device.example');
    assert.strictEqual(result.claims.get(500), true);
    assert.strictEqual(result.claims.get(501), 'ABCD-123456');
    
    const location = result.claims.get(503);
    assert.ok(location instanceof Map);
    assert.strictEqual(location.get('country'), 'us');
    assert.strictEqual(location.get('region'), 'ca');
    assert.strictEqual(location.get('postal_code'), '94188');
    
    console.log('\n=== All assertions passed! ===');
  });

  it('should generate deterministic hex output for COSE Keys', () => {
    // Test that the same key always produces the same hex
    const key1 = createCoseKey(SPEC_HOLDER_KEY, 'ES256', false);
    const key2 = createCoseKey(SPEC_HOLDER_KEY, 'ES256', false);
    
    const hex1 = coseSign1.coseKeyToHex(key1);
    const hex2 = coseSign1.coseKeyToHex(key2);
    
    assert.strictEqual(hex1, hex2, 'Same key should produce same hex');
    console.log('Deterministic hex:', hex1);
  });

  it('should serialize disclosures consistently', async () => {
    const issuerPrivateKey = createCoseKey(SPEC_ISSUER_KEY, 'ES384', true);
    const holderPublicKey = createCoseKey(SPEC_HOLDER_KEY, 'ES256', false);
    
    const claims = new Map([
      [1, 'https://issuer.example'],
      [ClaimKey.Cnf, createCnfClaim(holderPublicKey)],
      [toBeRedacted(100), 'secret-value'],
    ]);
    
    const { disclosures } = await Issuer.issue({
      claims,
      privateKey: issuerPrivateKey,
      algorithm: 'ES384',
    });
    
    assert.strictEqual(disclosures.length, 1);
    
    // Check disclosure structure
    const disclosure = disclosures[0];
    assert.ok(disclosure instanceof Uint8Array);
    console.log('Disclosure length:', disclosure.length);
    console.log('Disclosure hex:', Buffer.from(disclosure).toString('hex'));
  });

  it('should handle audience mismatch correctly', async () => {
    const issuerPrivateKey = createCoseKey(SPEC_ISSUER_KEY, 'ES384', true);
    const issuerPublicKey = createCoseKey(SPEC_ISSUER_KEY, 'ES384', false);
    const holderPrivateKey = createCoseKey(SPEC_HOLDER_KEY, 'ES256', true);
    const holderPublicKey = createCoseKey(SPEC_HOLDER_KEY, 'ES256', false);
    
    const claims = new Map([
      [1, 'https://issuer.example'],
      [ClaimKey.Cnf, createCnfClaim(holderPublicKey)],
    ]);
    
    const { token, disclosures } = await Issuer.issue({
      claims,
      privateKey: issuerPrivateKey,
      algorithm: 'ES384',
    });
    
    const presentation = await Holder.present({
      token,
      selectedDisclosures: disclosures,
      holderPrivateKey,
      audience: 'https://verifier.example',
      algorithm: 'ES256',
    });
    
    // Verification should fail with wrong audience
    await assert.rejects(
      async () => {
        await Verifier.verify({
          presentation,
          issuerPublicKey,
          expectedAudience: 'https://wrong-verifier.example',
          hashAlgorithm: 'sha-256',
        });
      },
      /audience/i,
      'Should reject wrong audience'
    );
    
    console.log('Correctly rejected wrong audience');
  });

});

describe('Browser Compatibility - Generated Keys', () => {
  
  it('should work with dynamically generated ES256 keys', async () => {
    // Generate keys using the library
    const issuerKeyPair = coseSign1.generateKeyPair('ES256');
    const holderKeyPair = coseSign1.generateKeyPair('ES256');
    
    // Verify keys are COSE Key Maps
    assert.ok(issuerKeyPair.privateKey instanceof Map);
    assert.ok(issuerKeyPair.publicKey instanceof Map);
    assert.ok(holderKeyPair.privateKey instanceof Map);
    assert.ok(holderKeyPair.publicKey instanceof Map);
    
    // Create claims
    const claims = new Map([
      [1, 'https://issuer.example'],
      [ClaimKey.Cnf, createCnfClaim(holderKeyPair.publicKey)],
      [toBeRedacted('name'), 'Alice'],
    ]);
    
    // Issue
    const { token, disclosures } = await Issuer.issue({
      claims,
      privateKey: issuerKeyPair.privateKey,
      algorithm: 'ES256',
    });
    
    // Present
    const presentation = await Holder.present({
      token,
      selectedDisclosures: disclosures,
      holderPrivateKey: holderKeyPair.privateKey,
      audience: 'https://verifier.example',
      algorithm: 'ES256',
    });
    
    // Verify
    const result = await Verifier.verify({
      presentation,
      issuerPublicKey: issuerKeyPair.publicKey,
      expectedAudience: 'https://verifier.example',
      hashAlgorithm: 'sha-256',
    });
    
    assert.strictEqual(result.claims.get(1), 'https://issuer.example');
    assert.strictEqual(result.claims.get('name'), 'Alice');
    
    console.log('Generated ES256 keys workflow passed!');
  });

  it('should serialize and deserialize generated keys correctly', () => {
    const keyPair = coseSign1.generateKeyPair('ES256');
    
    // Serialize public key
    const publicKeyHex = coseSign1.coseKeyToHex(keyPair.publicKey);
    console.log('Generated public key hex:', publicKeyHex);
    
    // Deserialize
    const restored = coseSign1.coseKeyFromHex(publicKeyHex);
    
    // Verify structure
    assert.strictEqual(restored.get(1), keyPair.publicKey.get(1)); // kty
    assert.strictEqual(restored.get(-1), keyPair.publicKey.get(-1)); // crv
    
    // Verify x and y match
    const originalX = keyPair.publicKey.get(-2);
    const restoredX = restored.get(-2);
    assert.strictEqual(
      Buffer.from(originalX).toString('hex'),
      Buffer.from(restoredX).toString('hex'),
      'X coordinates should match'
    );
  });

});

