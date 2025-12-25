import { describe, it } from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { sign, verify, generateKeyPair, Algorithm } from '../src/cose-sign1.js';

describe('COSE Sign1 Module', () => {

  describe('generateKeyPair', () => {
    it('should generate an ES256 key pair by default', () => {
      const { privateKey, publicKey } = generateKeyPair();
      
      assert.ok(privateKey.d, 'Private key should have d component');
      assert.ok(privateKey.x, 'Private key should have x component');
      assert.ok(privateKey.y, 'Private key should have y component');
      assert.ok(publicKey.x, 'Public key should have x component');
      assert.ok(publicKey.y, 'Public key should have y component');
      
      // P-256 keys should be 32 bytes
      assert.strictEqual(privateKey.d.length, 32);
      assert.strictEqual(privateKey.x.length, 32);
      assert.strictEqual(privateKey.y.length, 32);
    });

    it('should generate an ES384 key pair', () => {
      const { privateKey, publicKey } = generateKeyPair(Algorithm.ES384);
      
      // P-384 keys should be 48 bytes
      assert.strictEqual(privateKey.d.length, 48);
      assert.strictEqual(publicKey.x.length, 48);
      assert.strictEqual(publicKey.y.length, 48);
    });

    it('should generate an ES512 key pair', () => {
      const { privateKey, publicKey } = generateKeyPair(Algorithm.ES512);
      
      // P-521 keys should be 66 bytes
      assert.strictEqual(privateKey.d.length, 66);
      assert.strictEqual(publicKey.x.length, 66);
      assert.strictEqual(publicKey.y.length, 66);
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
});

