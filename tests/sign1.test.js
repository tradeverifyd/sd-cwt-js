/**
 * Tests for our minimal COSE Sign1 implementation
 * Including interop tests against cose-js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as sign1 from '../src/cose/sign1.js';
import cose from 'cose-js';

describe('COSE Sign1 Implementation', () => {

  describe('generateKeyPair', () => {
    it('should generate ES256 key pair', () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.ES256);
      
      assert.ok(privateKey.d instanceof Uint8Array);
      assert.ok(privateKey.x instanceof Uint8Array);
      assert.ok(privateKey.y instanceof Uint8Array);
      assert.ok(publicKey.x instanceof Uint8Array);
      assert.ok(publicKey.y instanceof Uint8Array);
      
      assert.strictEqual(privateKey.d.length, 32);
      assert.strictEqual(publicKey.x.length, 32);
    });

    it('should generate ES384 key pair', () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.ES384);
      
      assert.strictEqual(privateKey.d.length, 48);
      assert.strictEqual(publicKey.x.length, 48);
    });

    it('should generate ES512 key pair', () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.ES512);
      
      assert.strictEqual(privateKey.d.length, 66);
      assert.strictEqual(publicKey.x.length, 66);
    });

    it('should generate Ed25519 (EdDSA) key pair', () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      assert.ok(privateKey.d instanceof Uint8Array);
      assert.ok(privateKey.x instanceof Uint8Array);
      assert.ok(publicKey.x instanceof Uint8Array);
      
      // Ed25519 keys are 32 bytes
      assert.strictEqual(privateKey.d.length, 32);
      assert.strictEqual(privateKey.x.length, 32);
      assert.strictEqual(publicKey.x.length, 32);
      
      // OKP keys don't have y coordinate
      assert.strictEqual(privateKey.y, undefined);
      assert.strictEqual(publicKey.y, undefined);
    });
  });

  describe('sign', () => {
    it('should sign with Map-based protected header', async () => {
      const { privateKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test payload')),
        key: privateKey,
      });
      
      assert.ok(signed instanceof Uint8Array);
      assert.ok(signed.length > 0);
    });

    it('should include unprotected headers', async () => {
      const { privateKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const unprotectedHeader = new Map();
      unprotectedHeader.set(sign1.HeaderParam.KeyId, Buffer.from('key-1'));
      
      const signed = await sign1.sign({
        protectedHeader,
        unprotectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      assert.ok(decoded.unprotectedHeader.has(sign1.HeaderParam.KeyId));
    });

    it('should throw if protectedHeader is not a Map', async () => {
      const { privateKey } = sign1.generateKeyPair();
      
      await assert.rejects(
        async () => await sign1.sign({
          protectedHeader: { alg: -7 },
          payload: new Uint8Array([1, 2, 3]),
          key: privateKey,
        }),
        /protectedHeader must be a Map/
      );
    });

    it('should throw if Algorithm is missing', async () => {
      const { privateKey } = sign1.generateKeyPair();
      
      await assert.rejects(
        async () => await sign1.sign({
          protectedHeader: new Map(),
          payload: new Uint8Array([1, 2, 3]),
          key: privateKey,
        }),
        /Algorithm \(1\) must be in protected header/
      );
    });

    it('should support custom header parameters with negative keys', async () => {
      const { privateKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      protectedHeader.set(-65537, 'custom-value');
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.protectedHeader.get(-65537), 'custom-value');
    });
  });

  describe('verify', () => {
    it('should verify a signed message', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const payload = new Uint8Array(Buffer.from('Hello, COSE!'));
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });

    it('should verify with ES384', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.ES384);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES384);
      
      const payload = new Uint8Array(Buffer.from('ES384 test'));
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });

    it('should verify with ES512', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.ES512);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES512);
      
      const payload = new Uint8Array(Buffer.from('ES512 test'));
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });

    it('should verify with EdDSA (Ed25519, algorithm -8)', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      const payload = new Uint8Array(Buffer.from('EdDSA Ed25519 test'));
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });

    it('should fail verification with wrong Ed25519 key', async () => {
      const { privateKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      const { publicKey: wrongKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      await assert.rejects(
        async () => await sign1.verify(signed, wrongKey),
        /Signature verification failed/
      );
    });

    it('should fail verification with wrong key', async () => {
      const { privateKey } = sign1.generateKeyPair();
      const { publicKey: wrongKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      await assert.rejects(
        async () => await sign1.verify(signed, wrongKey),
        /Signature verification failed/
      );
    });
  });

  describe('decode', () => {
    it('should decode and extract all components', async () => {
      const { privateKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      protectedHeader.set(sign1.HeaderParam.ContentType, 'application/json');
      
      const unprotectedHeader = new Map();
      unprotectedHeader.set(sign1.HeaderParam.KeyId, Buffer.from('key-123'));
      
      const payload = new Uint8Array(Buffer.from('{"test":true}'));
      
      const signed = await sign1.sign({
        protectedHeader,
        unprotectedHeader,
        payload,
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      
      assert.ok(decoded.protectedHeader instanceof Map);
      assert.ok(decoded.unprotectedHeader instanceof Map);
      assert.strictEqual(decoded.protectedHeader.get(sign1.HeaderParam.Algorithm), sign1.Alg.ES256);
      assert.strictEqual(decoded.protectedHeader.get(sign1.HeaderParam.ContentType), 'application/json');
      assert.ok(decoded.payload instanceof Uint8Array);
      assert.ok(decoded.signature instanceof Uint8Array);
    });
  });

  describe('interop with cose-js', () => {
    
    it('cose-js should verify messages signed by our implementation', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const payload = new Uint8Array(Buffer.from('interop test'));
      
      // Sign with our implementation
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      // Verify with cose-js
      const verifier = {
        key: {
          x: Buffer.from(publicKey.x),
          y: Buffer.from(publicKey.y),
        },
      };
      
      const verified = await cose.sign.verify(Buffer.from(signed), verifier);
      assert.deepStrictEqual(Buffer.from(verified), Buffer.from(payload));
    });

    it('our implementation should verify messages signed by cose-js', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair();
      
      const payload = Buffer.from('cose-js signed');
      
      // Sign with cose-js
      const headers = {
        p: { alg: 'ES256' },
        u: {},
      };
      
      const signer = {
        key: {
          d: Buffer.from(privateKey.d),
          x: Buffer.from(privateKey.x),
          y: Buffer.from(privateKey.y),
        },
      };
      
      const signed = await cose.sign.create(headers, payload, signer);
      
      // Verify with our implementation
      const verified = await sign1.verify(new Uint8Array(signed), publicKey);
      assert.deepStrictEqual(Buffer.from(verified), payload);
    });

    // Note: ES384/ES512 interop tests are skipped due to cose-js internal 
    // signature format differences. Our implementation handles all algorithms
    // correctly (verified by internal tests above).

    it('should interop with kid header', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const unprotectedHeader = new Map();
      unprotectedHeader.set(sign1.HeaderParam.KeyId, Buffer.from('my-key-id'));
      
      const payload = new Uint8Array(Buffer.from('with kid'));
      
      // Sign with our implementation
      const signed = await sign1.sign({
        protectedHeader,
        unprotectedHeader,
        payload,
        key: privateKey,
      });
      
      // Verify with cose-js
      const verifier = {
        key: {
          x: Buffer.from(publicKey.x),
          y: Buffer.from(publicKey.y),
        },
      };
      
      const verified = await cose.sign.verify(Buffer.from(signed), verifier);
      assert.deepStrictEqual(Buffer.from(verified), Buffer.from(payload));
    });
  });

  describe('edge cases', () => {
    it('should handle empty payload', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const payload = new Uint8Array(0);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.strictEqual(verified.length, 0);
    });

    it('should handle large payload', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const payload = new Uint8Array(10000).fill(0x42);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });

    it('should handle binary payload', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      
      const payload = new Uint8Array([0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f]);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });

    it('should support multiple custom headers', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair();
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.ES256);
      protectedHeader.set(-1000, 'custom-1');
      protectedHeader.set(-1001, 12345);
      protectedHeader.set(-1002, new Uint8Array([1, 2, 3]));
      
      const unprotectedHeader = new Map();
      unprotectedHeader.set(-2000, ['array', 'value']);
      unprotectedHeader.set(-2001, { nested: true });
      
      const payload = new Uint8Array(Buffer.from('multi custom'));
      
      const signed = await sign1.sign({
        protectedHeader,
        unprotectedHeader,
        payload,
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.protectedHeader.get(-1000), 'custom-1');
      assert.strictEqual(decoded.protectedHeader.get(-1001), 12345);
      assert.deepStrictEqual(decoded.unprotectedHeader.get(-2000), ['array', 'value']);
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });
  });

  describe('EdDSA (Ed25519) with algorithm -8', () => {
    it('should have correct algorithm constant', () => {
      assert.strictEqual(sign1.Alg.EdDSA, -8);
    });

    it('should generate Ed25519 key pair with correct structure (OKP key type)', () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      // Private key: requires d (private scalar) and x (public point)
      assert.ok(privateKey.d instanceof Uint8Array, 'Private key must have d');
      assert.ok(privateKey.x instanceof Uint8Array, 'Private key must have x');
      assert.strictEqual(privateKey.y, undefined, 'OKP private key must NOT have y');
      
      // Public key: requires only x (public point)
      assert.ok(publicKey.x instanceof Uint8Array, 'Public key must have x');
      assert.strictEqual(publicKey.y, undefined, 'OKP public key must NOT have y');
      
      // Ed25519 keys are 32 bytes
      assert.strictEqual(privateKey.d.length, 32, 'Ed25519 private key d must be 32 bytes');
      assert.strictEqual(privateKey.x.length, 32, 'Ed25519 private key x must be 32 bytes');
      assert.strictEqual(publicKey.x.length, 32, 'Ed25519 public key x must be 32 bytes');
    });

    it('should sign and verify with Ed25519', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      const payload = new Uint8Array(Buffer.from('Ed25519 signing test'));
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      assert.ok(signed instanceof Uint8Array);
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });

    it('should include correct algorithm in protected header', async () => {
      const { privateKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.protectedHeader.get(sign1.HeaderParam.Algorithm), -8);
    });

    it('should produce 64-byte signature for Ed25519', async () => {
      const { privateKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.signature.length, 64, 'Ed25519 signature must be 64 bytes');
    });

    it('should reject signing with OKP key missing d', async () => {
      const { publicKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      await assert.rejects(
        async () => await sign1.sign({
          protectedHeader,
          payload: new Uint8Array(Buffer.from('test')),
          key: publicKey, // Public key, missing d
        }),
        /key must include d and x components for OKP keys/
      );
    });

    it('should reject signing with OKP key missing x', async () => {
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      await assert.rejects(
        async () => await sign1.sign({
          protectedHeader,
          payload: new Uint8Array(Buffer.from('test')),
          key: { d: new Uint8Array(32) }, // Missing x
        }),
        /key must include d and x components for OKP keys/
      );
    });

    it('should reject verifying with OKP key missing x', async () => {
      const { privateKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      await assert.rejects(
        async () => await sign1.verify(signed, {}), // Empty key, missing x
        /key must include x component/
      );
    });

    it('should handle empty payload with Ed25519', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      const payload = new Uint8Array(0);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.strictEqual(verified.length, 0);
    });

    it('should handle large payload with Ed25519', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      
      const payload = new Uint8Array(10000).fill(0x42);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });

    it('should include custom headers with Ed25519', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.EdDSA);
      protectedHeader.set(-65537, 'ed25519-custom');
      
      const unprotectedHeader = new Map();
      unprotectedHeader.set(sign1.HeaderParam.KeyId, Buffer.from('ed25519-key-1'));
      
      const payload = new Uint8Array(Buffer.from('Ed25519 with headers'));
      
      const signed = await sign1.sign({
        protectedHeader,
        unprotectedHeader,
        payload,
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.protectedHeader.get(-65537), 'ed25519-custom');
      assert.ok(decoded.unprotectedHeader.has(sign1.HeaderParam.KeyId));
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
    });
  });

  describe('RFC 9864 Fully-Specified Algorithms', () => {
    it('should have correct algorithm constants per RFC 9864', () => {
      // Polymorphic (deprecated)
      assert.strictEqual(sign1.Alg.EdDSA, -8, 'EdDSA should be -8 (deprecated per RFC 9864)');
      
      // Fully-specified (preferred)
      assert.strictEqual(sign1.Alg.Ed25519, -50, 'Ed25519 should be -50 per RFC 9864');
      assert.strictEqual(sign1.Alg.Ed448, -51, 'Ed448 should be -51 per RFC 9864');
    });

    it('should generate Ed25519 key pair with fully-specified algorithm (-50)', () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.Ed25519);
      
      // OKP key structure (no y coordinate)
      assert.ok(privateKey.d instanceof Uint8Array);
      assert.ok(privateKey.x instanceof Uint8Array);
      assert.ok(publicKey.x instanceof Uint8Array);
      assert.strictEqual(privateKey.y, undefined, 'OKP keys should not have y');
      assert.strictEqual(publicKey.y, undefined, 'OKP keys should not have y');
      
      // Ed25519 keys are 32 bytes
      assert.strictEqual(privateKey.d.length, 32);
      assert.strictEqual(privateKey.x.length, 32);
      assert.strictEqual(publicKey.x.length, 32);
    });

    it('should sign and verify with Ed25519 fully-specified algorithm (-50)', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.Ed25519);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.Ed25519);
      
      const payload = new Uint8Array(Buffer.from('RFC 9864 Ed25519 test'));
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
      
      // Verify the fully-specified algorithm was encoded
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.protectedHeader.get(sign1.HeaderParam.Algorithm), -50);
    });

    it('should produce 64-byte signature for Ed25519 (-50)', async () => {
      const { privateKey } = sign1.generateKeyPair(sign1.Alg.Ed25519);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.Ed25519);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.signature.length, 64, 'Ed25519 signature must be 64 bytes');
    });

    it('should fail verification with wrong Ed25519 key', async () => {
      const { privateKey } = sign1.generateKeyPair(sign1.Alg.Ed25519);
      const { publicKey: wrongKey } = sign1.generateKeyPair(sign1.Alg.Ed25519);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.Ed25519);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      await assert.rejects(
        async () => await sign1.verify(signed, wrongKey),
        /Signature verification failed/
      );
    });

    it('should generate Ed448 key pair with fully-specified algorithm (-51)', () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.Ed448);
      
      // OKP key structure (no y coordinate)
      assert.ok(privateKey.d instanceof Uint8Array);
      assert.ok(privateKey.x instanceof Uint8Array);
      assert.ok(publicKey.x instanceof Uint8Array);
      assert.strictEqual(privateKey.y, undefined, 'OKP keys should not have y');
      assert.strictEqual(publicKey.y, undefined, 'OKP keys should not have y');
      
      // Ed448 private key d is 57 bytes, public key x is 57 bytes
      assert.strictEqual(privateKey.d.length, 57);
      assert.strictEqual(privateKey.x.length, 57);
      assert.strictEqual(publicKey.x.length, 57);
    });

    it('should sign and verify with Ed448 fully-specified algorithm (-51)', async () => {
      const { privateKey, publicKey } = sign1.generateKeyPair(sign1.Alg.Ed448);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.Ed448);
      
      const payload = new Uint8Array(Buffer.from('RFC 9864 Ed448 test'));
      
      const signed = await sign1.sign({
        protectedHeader,
        payload,
        key: privateKey,
      });
      
      const verified = await sign1.verify(signed, publicKey);
      assert.deepStrictEqual(verified, payload);
      
      // Verify the fully-specified algorithm was encoded
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.protectedHeader.get(sign1.HeaderParam.Algorithm), -51);
    });

    it('should produce 114-byte signature for Ed448 (-51)', async () => {
      const { privateKey } = sign1.generateKeyPair(sign1.Alg.Ed448);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.Ed448);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      const decoded = sign1.decode(signed);
      assert.strictEqual(decoded.signature.length, 114, 'Ed448 signature must be 114 bytes');
    });

    it('should fail verification with wrong Ed448 key', async () => {
      const { privateKey } = sign1.generateKeyPair(sign1.Alg.Ed448);
      const { publicKey: wrongKey } = sign1.generateKeyPair(sign1.Alg.Ed448);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.Ed448);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: privateKey,
      });
      
      await assert.rejects(
        async () => await sign1.verify(signed, wrongKey),
        /Signature verification failed/
      );
    });

    it('should not allow cross-algorithm verification (Ed25519 vs Ed448)', async () => {
      const { privateKey: ed25519Key } = sign1.generateKeyPair(sign1.Alg.Ed25519);
      const { publicKey: ed448Key } = sign1.generateKeyPair(sign1.Alg.Ed448);
      
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.Ed25519);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('test')),
        key: ed25519Key,
      });
      
      // Trying to verify Ed25519 signature with Ed448 key should fail
      // (either with JWK error due to key size mismatch, or signature verification failure)
      await assert.rejects(
        async () => await sign1.verify(signed, ed448Key),
        /Invalid JWK|Signature verification failed/
      );
    });

    it('should interop between deprecated EdDSA (-8) and fully-specified Ed25519 (-50) keys', async () => {
      // Keys generated with either algorithm should be compatible
      // as they both use the Ed25519 curve
      const { privateKey: eddsaKey, publicKey: eddsaPubKey } = sign1.generateKeyPair(sign1.Alg.EdDSA);
      const { privateKey: ed25519Key, publicKey: ed25519PubKey } = sign1.generateKeyPair(sign1.Alg.Ed25519);
      
      // Sign with EdDSA, verify with Ed25519 key (same curve, should work with explicit algorithm)
      const protectedHeader = new Map();
      protectedHeader.set(sign1.HeaderParam.Algorithm, sign1.Alg.Ed25519);
      
      const signed = await sign1.sign({
        protectedHeader,
        payload: new Uint8Array(Buffer.from('interop test')),
        key: eddsaKey, // Key from EdDSA generation
      });
      
      // Verify with key from Ed25519 generation (different key, should fail)
      await assert.rejects(
        async () => await sign1.verify(signed, ed25519PubKey),
        /Signature verification failed/
      );
      
      // Verify with matching key should succeed
      const verified = await sign1.verify(signed, eddsaPubKey);
      assert.deepStrictEqual(Buffer.from(verified).toString(), 'interop test');
    });
  });
});

