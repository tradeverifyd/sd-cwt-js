import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { sign, verify, generateKeyPair, getHeaders, Algorithm, CoseKeyParam } from '../src/cose-sign1.js';

describe('COSE Sign1 Module', () => {

  describe('generateKeyPair', () => {
    it('should generate an ES256 key pair as COSE Keys by default', () => {
      const { privateKey, publicKey } = generateKeyPair();
      
      // Keys should be Maps (COSE Key format)
      assert.ok(privateKey instanceof Map, 'Private key should be a Map');
      assert.ok(publicKey instanceof Map, 'Public key should be a Map');
      
      // Check COSE Key params using COSE Key labels
      assert.ok(privateKey.has(CoseKeyParam.D), 'Private key should have d component');
      assert.ok(privateKey.has(CoseKeyParam.X), 'Private key should have x component');
      assert.ok(privateKey.has(CoseKeyParam.Y), 'Private key should have y component');
      assert.ok(publicKey.has(CoseKeyParam.X), 'Public key should have x component');
      assert.ok(publicKey.has(CoseKeyParam.Y), 'Public key should have y component');
      
      // P-256 keys should be 32 bytes
      assert.strictEqual(privateKey.get(CoseKeyParam.D).length, 32);
      assert.strictEqual(privateKey.get(CoseKeyParam.X).length, 32);
      assert.strictEqual(privateKey.get(CoseKeyParam.Y).length, 32);
    });

    it('should generate an ES384 key pair as COSE Keys', () => {
      const { privateKey, publicKey } = generateKeyPair(Algorithm.ES384);
      
      // P-384 keys should be 48 bytes
      assert.strictEqual(privateKey.get(CoseKeyParam.D).length, 48);
      assert.strictEqual(publicKey.get(CoseKeyParam.X).length, 48);
      assert.strictEqual(publicKey.get(CoseKeyParam.Y).length, 48);
    });

    it('should generate an ES512 key pair as COSE Keys', () => {
      const { privateKey, publicKey } = generateKeyPair(Algorithm.ES512);
      
      // P-521 keys should be 66 bytes
      assert.strictEqual(privateKey.get(CoseKeyParam.D).length, 66);
      assert.strictEqual(publicKey.get(CoseKeyParam.X).length, 66);
      assert.strictEqual(publicKey.get(CoseKeyParam.Y).length, 66);
    });

    it('should throw for unsupported algorithm', () => {
      assert.throws(
        () => generateKeyPair('UNSUPPORTED'),
        /Unsupported algorithm/
      );
    });
  });

  describe('sign', () => {
    const { privateKey } = generateKeyPair();

    it('should sign a buffer payload', async () => {
      const payload = Buffer.from('Hello, COSE!');
      const signed = await sign(payload, privateKey);
      
      assert.ok(Buffer.isBuffer(signed) || signed instanceof Uint8Array);
      assert.ok(signed.length > payload.length);
    });

    it('should sign a string payload', async () => {
      const payload = 'Hello, COSE!';
      const signed = await sign(payload, privateKey);
      
      assert.ok(signed.length > 0);
    });

    it('should sign with custom kid', async () => {
      const payload = Buffer.from('test');
      const signed = await sign(payload, privateKey, { kid: 'my-key-id' });
      
      assert.ok(signed.length > 0);
    });

    it('should throw if payload is missing', async () => {
      await assert.rejects(
        async () => await sign(null, privateKey),
        /Payload is required/
      );
    });

    it('should throw if signer key is incomplete', async () => {
      await assert.rejects(
        async () => await sign(Buffer.from('test'), { x: Buffer.alloc(32), y: Buffer.alloc(32) }),
        /Signer key must include d, x, and y components/
      );
    });

    it('should sign with different algorithms', async () => {
      const payload = Buffer.from('test payload');
      
      // ES256
      const { privateKey: es256Key } = generateKeyPair(Algorithm.ES256);
      const signedES256 = await sign(payload, es256Key, { algorithm: Algorithm.ES256 });
      assert.ok(signedES256.length > 0);
      
      // ES384
      const { privateKey: es384Key } = generateKeyPair(Algorithm.ES384);
      const signedES384 = await sign(payload, es384Key, { algorithm: Algorithm.ES384 });
      assert.ok(signedES384.length > 0);
      
      // ES512
      const { privateKey: es512Key } = generateKeyPair(Algorithm.ES512);
      const signedES512 = await sign(payload, es512Key, { algorithm: Algorithm.ES512 });
      assert.ok(signedES512.length > 0);
    });
  });

  describe('verify', () => {
    it('should verify a signed message', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('Hello, COSE Sign1!');
      
      const signed = await sign(payload, privateKey);
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should verify with ES384', async () => {
      const { privateKey, publicKey } = generateKeyPair(Algorithm.ES384);
      const payload = Buffer.from('ES384 test');
      
      const signed = await sign(payload, privateKey, { algorithm: Algorithm.ES384 });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should verify with ES512', async () => {
      const { privateKey, publicKey } = generateKeyPair(Algorithm.ES512);
      const payload = Buffer.from('ES512 test');
      
      const signed = await sign(payload, privateKey, { algorithm: Algorithm.ES512 });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should fail verification with wrong key', async () => {
      const { privateKey } = generateKeyPair();
      const { publicKey: wrongPublicKey } = generateKeyPair();
      const payload = Buffer.from('test');
      
      const signed = await sign(payload, privateKey);
      
      await assert.rejects(
        async () => await verify(signed, wrongPublicKey),
        'Verification should fail with wrong key'
      );
    });

    it('should throw if COSE Sign1 message is missing', async () => {
      const { publicKey } = generateKeyPair();
      
      await assert.rejects(
        async () => await verify(null, publicKey),
        /COSE Sign1 message is required/
      );
    });

    it('should throw if verifier key is incomplete', async () => {
      const { privateKey } = generateKeyPair();
      const payload = Buffer.from('test');
      const signed = await sign(payload, privateKey);
      
      await assert.rejects(
        async () => await verify(signed, { x: Buffer.alloc(32) }),
        /Verifier key must include x and y components/
      );
    });
  });

  describe('sign and verify integration', () => {
    it('should handle empty payload', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('');
      
      const signed = await sign(payload, privateKey);
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should handle large payload', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.alloc(10000, 'x');
      
      const signed = await sign(payload, privateKey);
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should handle binary payload', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
      
      const signed = await sign(payload, privateKey);
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should handle JSON payload', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const data = { 
        iss: 'issuer', 
        sub: 'subject', 
        claims: { name: 'John', age: 30 } 
      };
      const payload = Buffer.from(JSON.stringify(data));
      
      const signed = await sign(payload, privateKey);
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(JSON.parse(verified.toString()), data);
    });

    it('should use custom kid option', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with kid');
      
      const signed = await sign(payload, privateKey, {
        kid: 'custom-key-identifier'
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should work with externally generated keys', async () => {
      // Generate keys using Node's crypto directly
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      
      const privateJwk = privateKey.export({ format: 'jwk' });
      const publicJwk = publicKey.export({ format: 'jwk' });
      
      const signerKey = {
        d: Buffer.from(privateJwk.d, 'base64url'),
        x: Buffer.from(privateJwk.x, 'base64url'),
        y: Buffer.from(privateJwk.y, 'base64url'),
      };
      
      const verifierKey = {
        x: Buffer.from(publicJwk.x, 'base64url'),
        y: Buffer.from(publicJwk.y, 'base64url'),
      };
      
      const payload = Buffer.from('External key test');
      const signed = await sign(payload, signerKey);
      const verified = await verify(signed, verifierKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });
  });

  describe('custom header parameters', () => {
    it('should sign with content_type in protected headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from(JSON.stringify({ data: 'test' }));
      
      const signed = await sign(payload, privateKey, {
        protectedHeaders: { content_type: 'application/json' }
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should sign with kid in protected headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test payload');
      
      const signed = await sign(payload, privateKey, {
        protectedHeaders: { kid: 'protected-key-id' }
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should sign with kid in unprotected headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test payload');
      
      const signed = await sign(payload, privateKey, {
        unprotectedHeaders: { kid: 'unprotected-key-id' }
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should sign with x5chain (X.509 certificate chain)', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with x5chain');
      
      // Simulated certificate chain (just example bytes for testing)
      const mockCertChain = Buffer.from('mock-certificate-data');
      
      const signed = await sign(payload, privateKey, {
        unprotectedHeaders: { x5chain: mockCertChain }
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should sign with crit (critical) header', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with critical header');
      
      const signed = await sign(payload, privateKey, {
        protectedHeaders: { crit: [1] } // alg is critical
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should sign with numeric content_type', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with numeric content type');
      
      // Content type can be a numeric value (CoAP content format)
      const signed = await sign(payload, privateKey, {
        protectedHeaders: { content_type: 60 } // application/cbor
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should sign with combined protected and unprotected headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with multiple headers');
      
      const signed = await sign(payload, privateKey, {
        kid: 'main-key-id',
        protectedHeaders: { 
          content_type: 'application/cwt'
        },
        unprotectedHeaders: { 
          x5chain: Buffer.from('cert-chain')
        }
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should override kid option with unprotectedHeaders kid', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test kid override');
      
      // When both kid option and unprotectedHeaders.kid are provided,
      // unprotectedHeaders.kid should be used (spread after)
      const signed = await sign(payload, privateKey, {
        kid: 'option-kid',
        unprotectedHeaders: { kid: 'header-kid' }
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should handle IV in unprotected headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with IV');
      
      // IV is typically for encryption but can be included
      const iv = crypto.randomBytes(12);
      
      const signed = await sign(payload, privateKey, {
        unprotectedHeaders: { IV: iv }
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should handle Partial_IV in unprotected headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with Partial IV');
      
      const partialIv = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      
      const signed = await sign(payload, privateKey, {
        unprotectedHeaders: { Partial_IV: partialIv }
      });
      const verified = await verify(signed, publicKey);
      
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    it('should preserve payload integrity with various header combinations', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const testCases = [
        { protectedHeaders: { content_type: 'text/plain' } },
        { unprotectedHeaders: { kid: 'test-1' } },
        { protectedHeaders: { crit: [1] }, unprotectedHeaders: { kid: 'test-2' } },
        { kid: 'simple-kid' },
        { protectedHeaders: { content_type: 50 }, kid: 'numeric-ct' },
      ];

      for (const options of testCases) {
        const payload = Buffer.from(`payload for ${JSON.stringify(options)}`);
        const signed = await sign(payload, privateKey, options);
        const verified = await verify(signed, publicKey);
        
        assert.deepStrictEqual(
          Buffer.from(verified), 
          payload,
          `Failed for options: ${JSON.stringify(options)}`
        );
      }
    });
  });

  describe('private/custom header parameters (integer keys)', () => {
    it('should sign with custom protected header using negative integer key', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with private header');
      
      // Use negative integer key for private use (per COSE spec)
      const signed = await sign(payload, privateKey, {
        customProtectedHeaders: { [-65537]: 'private-value' }
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      // Verify the custom header is present
      const { protectedHeaders } = getHeaders(signed);
      assert.strictEqual(protectedHeaders.get(-65537), 'private-value');
    });

    it('should sign with custom unprotected header using negative integer key', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with unprotected private header');
      
      const signed = await sign(payload, privateKey, {
        customUnprotectedHeaders: { [-65538]: 'unprotected-private' }
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      // Verify the custom header is present
      const { unprotectedHeaders } = getHeaders(signed);
      assert.strictEqual(unprotectedHeaders.get(-65538), 'unprotected-private');
    });

    it('should sign with custom header using Map', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('test with Map header');
      
      const customHeaders = new Map();
      customHeaders.set(-100, 'value-100');
      customHeaders.set(-200, Buffer.from('binary-value'));
      
      const signed = await sign(payload, privateKey, {
        customProtectedHeaders: customHeaders
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      const { protectedHeaders } = getHeaders(signed);
      assert.strictEqual(protectedHeaders.get(-100), 'value-100');
      assert.deepStrictEqual(Buffer.from(protectedHeaders.get(-200)), Buffer.from('binary-value'));
    });

    it('should sign with multiple custom headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('multiple custom headers');
      
      const signed = await sign(payload, privateKey, {
        customProtectedHeaders: {
          [-1000]: 'header-1000',
          [-1001]: 12345,
          [-1002]: true,
        },
        customUnprotectedHeaders: {
          [-2000]: 'unprotected-2000',
          [-2001]: ['array', 'value'],
        }
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      const { protectedHeaders, unprotectedHeaders } = getHeaders(signed);
      assert.strictEqual(protectedHeaders.get(-1000), 'header-1000');
      assert.strictEqual(protectedHeaders.get(-1001), 12345);
      assert.strictEqual(protectedHeaders.get(-1002), true);
      assert.strictEqual(unprotectedHeaders.get(-2000), 'unprotected-2000');
      assert.deepStrictEqual(unprotectedHeaders.get(-2001), ['array', 'value']);
    });

    it('should combine standard and custom headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('combined headers');
      
      const signed = await sign(payload, privateKey, {
        kid: 'my-key-id',
        protectedHeaders: { content_type: 'application/cbor' },
        customProtectedHeaders: { [-9999]: 'custom-protected' },
        customUnprotectedHeaders: { [-8888]: 'custom-unprotected' }
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      const { protectedHeaders, unprotectedHeaders } = getHeaders(signed);
      
      // Check algorithm is present (label 1)
      assert.ok(protectedHeaders.has(1), 'Should have alg header');
      
      // Check content_type (label 3)
      assert.strictEqual(protectedHeaders.get(3), 'application/cbor');
      
      // Check custom protected header
      assert.strictEqual(protectedHeaders.get(-9999), 'custom-protected');
      
      // Check kid (label 4) - must be a Uint8Array (bstr in COSE)
      const kidValue = unprotectedHeaders.get(4);
      assert.ok(kidValue instanceof Uint8Array, 'kid must be a Uint8Array');
      assert.deepStrictEqual(Buffer.from(kidValue), Buffer.from('my-key-id'));
      
      // Check custom unprotected header
      assert.strictEqual(unprotectedHeaders.get(-8888), 'custom-unprotected');
    });

    it('should handle binary data in custom headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('binary custom header test');
      
      const binaryValue = crypto.randomBytes(32);
      
      const signed = await sign(payload, privateKey, {
        customProtectedHeaders: { [-12345]: binaryValue }
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      const { protectedHeaders } = getHeaders(signed);
      assert.deepStrictEqual(Buffer.from(protectedHeaders.get(-12345)), binaryValue);
    });

    it('should handle nested structures in custom headers', async () => {
      const { privateKey, publicKey } = generateKeyPair();
      const payload = Buffer.from('nested custom header');
      
      const nestedValue = {
        issuer: 'test-issuer',
        claims: ['read', 'write'],
        metadata: { version: 1 }
      };
      
      const signed = await sign(payload, privateKey, {
        customUnprotectedHeaders: { [-77777]: nestedValue }
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      const { unprotectedHeaders } = getHeaders(signed);
      // With preferMap: true, CBOR maps decode as JavaScript Maps
      const decoded = unprotectedHeaders.get(-77777);
      assert.ok(decoded instanceof Map, 'Nested structure should be a Map');
      assert.strictEqual(decoded.get('issuer'), 'test-issuer');
      assert.deepStrictEqual(decoded.get('claims'), ['read', 'write']);
      const metadata = decoded.get('metadata');
      assert.ok(metadata instanceof Map);
      assert.strictEqual(metadata.get('version'), 1);
    });

    it('should work with ES384 and custom headers', async () => {
      const { privateKey, publicKey } = generateKeyPair(Algorithm.ES384);
      const payload = Buffer.from('ES384 with custom headers');
      
      const signed = await sign(payload, privateKey, {
        algorithm: Algorithm.ES384,
        customProtectedHeaders: { [-555]: 'es384-custom' }
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      const { protectedHeaders } = getHeaders(signed);
      assert.strictEqual(protectedHeaders.get(-555), 'es384-custom');
      assert.strictEqual(protectedHeaders.get(1), -35); // ES384 alg id
    });

    it('should work with ES512 and custom headers', async () => {
      const { privateKey, publicKey } = generateKeyPair(Algorithm.ES512);
      const payload = Buffer.from('ES512 with custom headers');
      
      const signed = await sign(payload, privateKey, {
        algorithm: Algorithm.ES512,
        customProtectedHeaders: { [-666]: 'es512-custom' }
      });
      
      const verified = await verify(signed, publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
      
      const { protectedHeaders } = getHeaders(signed);
      assert.strictEqual(protectedHeaders.get(-666), 'es512-custom');
      assert.strictEqual(protectedHeaders.get(1), -36); // ES512 alg id
    });
  });

  describe('getHeaders', () => {
    it('should extract protected headers from a signed message', async () => {
      const { privateKey } = generateKeyPair();
      const payload = Buffer.from('test');
      
      const signed = await sign(payload, privateKey, {
        protectedHeaders: { content_type: 'text/plain' }
      });
      
      const { protectedHeaders } = getHeaders(signed);
      
      assert.ok(protectedHeaders instanceof Map);
      assert.strictEqual(protectedHeaders.get(1), -7); // ES256
      assert.strictEqual(protectedHeaders.get(3), 'text/plain'); // content_type
    });

    it('should extract unprotected headers from a signed message', async () => {
      const { privateKey } = generateKeyPair();
      const payload = Buffer.from('test');
      
      const signed = await sign(payload, privateKey, {
        kid: 'test-kid'
      });
      
      const { unprotectedHeaders } = getHeaders(signed);
      
      assert.ok(unprotectedHeaders instanceof Map);
      // kid must be a Uint8Array (bstr in COSE)
      const kidValue = unprotectedHeaders.get(4);
      assert.ok(kidValue instanceof Uint8Array, 'kid must be a Uint8Array');
      assert.deepStrictEqual(Buffer.from(kidValue), Buffer.from('test-kid'));
    });

    it('should throw for invalid input', () => {
      assert.throws(
        () => getHeaders(null),
        /COSE Sign1 message is required/
      );
    });

    it('should throw for invalid COSE structure', () => {
      const invalidCbor = Buffer.from([0xa0]); // empty map
      
      assert.throws(
        () => getHeaders(invalidCbor),
        /Invalid COSE.?Sign1 structure/
      );
    });
  });
});

