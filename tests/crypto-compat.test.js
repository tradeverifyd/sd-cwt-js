import { test, describe } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';

// Import COSE Sign1 with COSE Key support
import * as coseSign1 from '../src/cose-sign1.js';

// Import browser crypto shim for cross-platform testing
import * as browserCrypto from '../src/crypto-browser.js';

describe('Cross-platform Crypto Compatibility', () => {
  
  const testMessage = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  
  describe('COSE Key Format', () => {
    test('generateKeyPair returns COSE Key Maps', () => {
      const keyPair = coseSign1.generateKeyPair('ES256');
      
      // Verify keys are Maps
      assert.ok(keyPair.privateKey instanceof Map, 'Private key should be a Map');
      assert.ok(keyPair.publicKey instanceof Map, 'Public key should be a Map');
      
      // Verify COSE Key structure
      assert.strictEqual(keyPair.privateKey.get(coseSign1.CoseKeyParam.Kty), coseSign1.CoseKeyType.EC2);
      assert.strictEqual(keyPair.privateKey.get(coseSign1.CoseKeyParam.Crv), coseSign1.CoseCurve.P256);
      assert.ok(keyPair.privateKey.has(coseSign1.CoseKeyParam.X), 'Private key should have X');
      assert.ok(keyPair.privateKey.has(coseSign1.CoseKeyParam.Y), 'Private key should have Y');
      assert.ok(keyPair.privateKey.has(coseSign1.CoseKeyParam.D), 'Private key should have D');
      
      assert.strictEqual(keyPair.publicKey.get(coseSign1.CoseKeyParam.Kty), coseSign1.CoseKeyType.EC2);
      assert.strictEqual(keyPair.publicKey.get(coseSign1.CoseKeyParam.Crv), coseSign1.CoseCurve.P256);
      assert.ok(keyPair.publicKey.has(coseSign1.CoseKeyParam.X), 'Public key should have X');
      assert.ok(keyPair.publicKey.has(coseSign1.CoseKeyParam.Y), 'Public key should have Y');
      assert.ok(!keyPair.publicKey.has(coseSign1.CoseKeyParam.D), 'Public key should not have D');
      
      // Verify coordinate sizes (32 bytes for P-256)
      assert.strictEqual(keyPair.privateKey.get(coseSign1.CoseKeyParam.X).length, 32);
      assert.strictEqual(keyPair.privateKey.get(coseSign1.CoseKeyParam.Y).length, 32);
      assert.strictEqual(keyPair.privateKey.get(coseSign1.CoseKeyParam.D).length, 32);
    });

    test('isCoseKey correctly identifies COSE Keys', () => {
      const keyPair = coseSign1.generateKeyPair('ES256');
      
      assert.strictEqual(coseSign1.isCoseKey(keyPair.privateKey), true, 'Map COSE Key should be identified');
      assert.strictEqual(coseSign1.isCoseKey(keyPair.publicKey), true, 'Map public key should be identified');
      
      // Legacy format should not be identified as COSE Key
      const legacyKey = { x: new Uint8Array(32), y: new Uint8Array(32) };
      assert.strictEqual(coseSign1.isCoseKey(legacyKey), false, 'Legacy key should not be COSE Key');
    });

    test('coseKeyToInternal converts COSE Key to internal format', () => {
      const keyPair = coseSign1.generateKeyPair('ES256');
      
      const internal = coseSign1.coseKeyToInternal(keyPair.privateKey);
      
      assert.ok(internal.x instanceof Uint8Array, 'x should be Uint8Array');
      assert.ok(internal.y instanceof Uint8Array, 'y should be Uint8Array');
      assert.ok(internal.d instanceof Uint8Array, 'd should be Uint8Array');
      
      // Values should match
      assert.deepStrictEqual(internal.x, keyPair.privateKey.get(coseSign1.CoseKeyParam.X));
      assert.deepStrictEqual(internal.y, keyPair.privateKey.get(coseSign1.CoseKeyParam.Y));
      assert.deepStrictEqual(internal.d, keyPair.privateKey.get(coseSign1.CoseKeyParam.D));
    });

    test('getAlgorithmFromCoseKey detects algorithm from curve', () => {
      const es256Key = coseSign1.generateKeyPair('ES256').publicKey;
      const es384Key = coseSign1.generateKeyPair('ES384').publicKey;
      
      assert.strictEqual(coseSign1.getAlgorithmFromCoseKey(es256Key), 'ES256');
      assert.strictEqual(coseSign1.getAlgorithmFromCoseKey(es384Key), 'ES384');
    });
  });

  describe('Sign and Verify with COSE Keys', () => {
    test('sign and verify with COSE Key format', async () => {
      const keyPair = coseSign1.generateKeyPair('ES256');
      
      // Sign with COSE Key
      const signed = await coseSign1.sign(testMessage, keyPair.privateKey);
      
      assert.ok(signed instanceof Uint8Array || Buffer.isBuffer(signed), 'Signed message should be buffer');
      assert.ok(signed.length > testMessage.length, 'Signed message should be larger than payload');
      
      // Verify with COSE Key
      const payload = await coseSign1.verify(signed, keyPair.publicKey);
      
      assert.deepStrictEqual(new Uint8Array(payload), testMessage);
    });

    test('sign with algorithm auto-detection from COSE Key', async () => {
      // Generate ES384 key
      const keyPair = coseSign1.generateKeyPair('ES384');
      
      // Sign without explicit algorithm - should auto-detect from key
      const signed = await coseSign1.sign(testMessage, keyPair.privateKey);
      
      // Verify
      const payload = await coseSign1.verify(signed, keyPair.publicKey);
      assert.deepStrictEqual(new Uint8Array(payload), testMessage);
      
      // Check that ES384 was used by examining headers
      const headers = coseSign1.getHeaders(signed);
      // protectedHeaders is a Map
      const alg = headers.protectedHeaders instanceof Map 
        ? headers.protectedHeaders.get(1) 
        : headers.protectedHeaders[1];
      assert.strictEqual(alg, -35); // -35 is ES384
    });
  });

  describe('Node-Browser Cross-Platform Signing', () => {
    test('Node crypto self-roundtrip', async () => {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      });
      
      const signature = crypto.sign(null, testMessage, { 
        key: privateKey, 
        dsaEncoding: 'ieee-p1363' 
      });
      
      assert.strictEqual(signature.length, 64, 'ES256 signature should be 64 bytes');
      
      const isValid = crypto.verify(null, testMessage, { 
        key: publicKey, 
        dsaEncoding: 'ieee-p1363' 
      }, signature);
      
      assert.strictEqual(isValid, true);
    });

    test('Browser crypto self-roundtrip', async () => {
      const keyPair = await browserCrypto.generateKeyPairAsync('ES256');
      
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: Buffer.from(keyPair.publicKey.x).toString('base64url'),
        y: Buffer.from(keyPair.publicKey.y).toString('base64url'),
        d: Buffer.from(keyPair.privateKey.d).toString('base64url'),
      };
      
      const privateKeyWrapper = browserCrypto.createPrivateKey({ key: jwk, format: 'jwk' });
      const signature = await browserCrypto.sign(null, testMessage, { 
        key: privateKeyWrapper, 
        dsaEncoding: 'ieee-p1363' 
      });
      
      assert.strictEqual(signature.length, 64, 'ES256 signature should be 64 bytes');
      
      const publicKeyWrapper = browserCrypto.createPublicKey({ key: jwk, format: 'jwk' });
      const isValid = await browserCrypto.verify(null, testMessage, { 
        key: publicKeyWrapper, 
        dsaEncoding: 'ieee-p1363' 
      }, signature);
      
      assert.strictEqual(isValid, true);
    });

    test('Node sign -> Browser verify (cross-platform)', async () => {
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256',
      });
      
      const jwk = publicKey.export({ format: 'jwk' });
      
      const nodeSignature = crypto.sign(null, testMessage, { 
        key: privateKey, 
        dsaEncoding: 'ieee-p1363' 
      });
      
      const publicKeyWrapper = browserCrypto.createPublicKey({ key: jwk, format: 'jwk' });
      const isValid = await browserCrypto.verify(null, testMessage, { 
        key: publicKeyWrapper, 
        dsaEncoding: 'ieee-p1363' 
      }, nodeSignature);
      
      assert.strictEqual(isValid, true, 'Browser should verify Node signature');
    });

    test('Browser sign -> Node verify (cross-platform)', async () => {
      const keyPair = await browserCrypto.generateKeyPairAsync('ES256');
      
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: Buffer.from(keyPair.publicKey.x).toString('base64url'),
        y: Buffer.from(keyPair.publicKey.y).toString('base64url'),
        d: Buffer.from(keyPair.privateKey.d).toString('base64url'),
      };
      
      const privateKeyWrapper = browserCrypto.createPrivateKey({ key: jwk, format: 'jwk' });
      const browserSignature = await browserCrypto.sign(null, testMessage, { 
        key: privateKeyWrapper, 
        dsaEncoding: 'ieee-p1363' 
      });
      
      const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
      const nodePublicKey = crypto.createPublicKey({ key: publicJwk, format: 'jwk' });
      
      const isValid = crypto.verify(null, testMessage, { 
        key: nodePublicKey, 
        dsaEncoding: 'ieee-p1363' 
      }, Buffer.from(browserSignature));
      
      assert.strictEqual(isValid, true, 'Node should verify Browser signature');
    });
  });

  describe('COSE Sign1 with COSE Keys End-to-End', () => {
    test('COSE Sign1 roundtrip with COSE Key format', async () => {
      const keyPair = coseSign1.generateKeyPair('ES256');
      
      console.log('COSE Key private key type:', keyPair.privateKey.constructor.name);
      console.log('COSE Key has kty:', keyPair.privateKey.has(1));
      console.log('COSE Key has crv:', keyPair.privateKey.has(-1));
      
      const payload = new Uint8Array([1, 2, 3, 4, 5]);
      
      const signed = await coseSign1.sign(payload, keyPair.privateKey);
      console.log('Signed message length:', signed.length);
      
      const verified = await coseSign1.verify(signed, keyPair.publicKey);
      console.log('Verified payload length:', verified.length);
      
      assert.deepStrictEqual(new Uint8Array(verified), payload);
    });

    test('COSE Sign1 with custom headers and COSE Key', async () => {
      const keyPair = coseSign1.generateKeyPair('ES256');
      
      const payload = { iss: 'test-issuer', sub: 'test-subject' };
      const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
      
      const signed = await coseSign1.sign(payloadBytes, keyPair.privateKey, {
        protectedHeaders: { typ: 'application/test' },
      });
      
      const verified = await coseSign1.verify(signed, keyPair.publicKey);
      const decoded = JSON.parse(new TextDecoder().decode(verified));
      
      assert.deepStrictEqual(decoded, payload);
    });

    test('Verification fails with wrong COSE Key', async () => {
      const keyPair1 = coseSign1.generateKeyPair('ES256');
      const keyPair2 = coseSign1.generateKeyPair('ES256');
      
      const signed = await coseSign1.sign(testMessage, keyPair1.privateKey);
      
      await assert.rejects(
        async () => coseSign1.verify(signed, keyPair2.publicKey),
        /verification failed/i
      );
    });
  });
});

describe('COSE Key Serialization', () => {
  
  test('serializeCoseKey serializes a COSE Key to CBOR bytes', () => {
    const keyPair = coseSign1.generateKeyPair('ES256');
    
    const bytes = coseSign1.serializeCoseKey(keyPair.publicKey);
    
    assert.ok(bytes instanceof Uint8Array, 'Should return Uint8Array');
    assert.ok(bytes.length > 0, 'Should have content');
    
    // CBOR map starts with 0xa (map) or 0xb (map with length > 23)
    const firstByte = bytes[0];
    assert.ok(
      (firstByte >= 0xa0 && firstByte <= 0xbf) || firstByte === 0xbf,
      `Should start with CBOR map byte, got 0x${firstByte.toString(16)}`
    );
  });

  test('deserializeCoseKey parses CBOR bytes back to COSE Key', () => {
    const keyPair = coseSign1.generateKeyPair('ES256');
    
    const bytes = coseSign1.serializeCoseKey(keyPair.publicKey);
    const restored = coseSign1.deserializeCoseKey(bytes);
    
    assert.ok(restored instanceof Map, 'Should return a Map');
    assert.strictEqual(restored.get(coseSign1.CoseKeyParam.Kty), coseSign1.CoseKeyType.EC2);
    assert.strictEqual(restored.get(coseSign1.CoseKeyParam.Crv), coseSign1.CoseCurve.P256);
    
    // Compare x and y coordinates
    assert.deepStrictEqual(
      restored.get(coseSign1.CoseKeyParam.X),
      keyPair.publicKey.get(coseSign1.CoseKeyParam.X)
    );
    assert.deepStrictEqual(
      restored.get(coseSign1.CoseKeyParam.Y),
      keyPair.publicKey.get(coseSign1.CoseKeyParam.Y)
    );
  });

  test('roundtrip: serialize and deserialize private key', () => {
    const keyPair = coseSign1.generateKeyPair('ES384');
    
    const bytes = coseSign1.serializeCoseKey(keyPair.privateKey);
    const restored = coseSign1.deserializeCoseKey(bytes);
    
    // Verify all components match
    assert.strictEqual(restored.get(coseSign1.CoseKeyParam.Kty), coseSign1.CoseKeyType.EC2);
    assert.strictEqual(restored.get(coseSign1.CoseKeyParam.Crv), coseSign1.CoseCurve.P384);
    assert.deepStrictEqual(
      restored.get(coseSign1.CoseKeyParam.D),
      keyPair.privateKey.get(coseSign1.CoseKeyParam.D)
    );
  });

  test('coseKeyToHex returns base16 of CBOR-serialized COSE Key', () => {
    const keyPair = coseSign1.generateKeyPair('ES256');
    
    // Get hex representation
    const hex = coseSign1.coseKeyToHex(keyPair.publicKey);
    
    // Get CBOR bytes directly
    const cborBytes = coseSign1.serializeCoseKey(keyPair.publicKey);
    
    // Manually convert CBOR bytes to hex
    const expectedHex = Array.from(cborBytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    // They should be identical
    assert.strictEqual(hex, expectedHex, 'Hex should be base16 of CBOR bytes');
    
    // Hex length should be 2x the byte length
    assert.strictEqual(hex.length, cborBytes.length * 2, 'Hex length should be 2x byte length');
    
    console.log('CBOR bytes length:', cborBytes.length);
    console.log('Hex string length:', hex.length);
    console.log('Hex:', hex.slice(0, 40) + '...');
  });

  test('coseKeyFromHex parses hex string back to COSE Key', () => {
    const keyPair = coseSign1.generateKeyPair('ES256');
    
    const hex = coseSign1.coseKeyToHex(keyPair.publicKey);
    const restored = coseSign1.coseKeyFromHex(hex);
    
    assert.ok(restored instanceof Map, 'Should return a Map');
    assert.deepStrictEqual(
      restored.get(coseSign1.CoseKeyParam.X),
      keyPair.publicKey.get(coseSign1.CoseKeyParam.X)
    );
  });

  test('serialized key can be used for verification', async () => {
    const keyPair = coseSign1.generateKeyPair('ES256');
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    
    // Sign with original key
    const signed = await coseSign1.sign(payload, keyPair.privateKey);
    
    // Serialize and deserialize public key
    const bytes = coseSign1.serializeCoseKey(keyPair.publicKey);
    const restoredKey = coseSign1.deserializeCoseKey(bytes);
    
    // Verify with restored key
    const verified = await coseSign1.verify(signed, restoredKey);
    
    assert.deepStrictEqual(new Uint8Array(verified), payload);
  });

  test('serialized key can be used for signing', async () => {
    const keyPair = coseSign1.generateKeyPair('ES256');
    const payload = new Uint8Array([1, 2, 3, 4, 5]);
    
    // Serialize and deserialize private key
    const bytes = coseSign1.serializeCoseKey(keyPair.privateKey);
    const restoredKey = coseSign1.deserializeCoseKey(bytes);
    
    // Sign with restored key
    const signed = await coseSign1.sign(payload, restoredKey);
    
    // Verify with original public key
    const verified = await coseSign1.verify(signed, keyPair.publicKey);
    
    assert.deepStrictEqual(new Uint8Array(verified), payload);
  });

  test('deserializeCoseKey throws on invalid input', () => {
    assert.throws(
      () => coseSign1.deserializeCoseKey(null),
      /bytes are required/
    );
    
    assert.throws(
      () => coseSign1.deserializeCoseKey(new Uint8Array(0)),
      /bytes are required/
    );
  });

  test('serializeCoseKey throws on non-Map input', () => {
    assert.throws(
      () => coseSign1.serializeCoseKey({ x: new Uint8Array(32) }),
      /must be a Map/
    );
  });
});
