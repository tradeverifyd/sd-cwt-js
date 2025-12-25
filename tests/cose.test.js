import { describe, it } from 'node:test';
import assert from 'node:assert';
import cose from 'cose-js';
import crypto from 'node:crypto';

describe('cose-js sanity tests', () => {

  describe('module structure', () => {
    it('should export sign object', () => {
      assert.ok(cose.sign, 'cose.sign should exist');
    });

    it('should export mac object', () => {
      assert.ok(cose.mac, 'cose.mac should exist');
    });

    it('should export encrypt object', () => {
      assert.ok(cose.encrypt, 'cose.encrypt should exist');
    });
  });

  describe('COSE Sign1', () => {
    // ES256 key pair for testing
    const plaintext = Buffer.from('This is the content to sign');
    
    // Generate a P-256 key pair for ES256
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256'
    });

    // Export keys in JWK format for cose-js
    const privateJwk = privateKey.export({ format: 'jwk' });
    const publicJwk = publicKey.export({ format: 'jwk' });

    const headers = {
      p: { alg: 'ES256' },
      u: { kid: 'test-key-1' }
    };

    const signer = {
      key: {
        d: Buffer.from(privateJwk.d, 'base64url'),
        x: Buffer.from(privateJwk.x, 'base64url'),
        y: Buffer.from(privateJwk.y, 'base64url')
      }
    };

    const verifier = {
      key: {
        x: Buffer.from(publicJwk.x, 'base64url'),
        y: Buffer.from(publicJwk.y, 'base64url')
      }
    };

    it('should create a COSE Sign1 message', async () => {
      const signed = await cose.sign.create(headers, plaintext, signer);
      assert.ok(Buffer.isBuffer(signed) || signed instanceof Uint8Array);
      assert.ok(signed.length > plaintext.length, 'Signed message should be larger than plaintext');
    });

    it('should verify a COSE Sign1 message', async () => {
      const signed = await cose.sign.create(headers, plaintext, signer);
      const verified = await cose.sign.verify(signed, verifier);
      assert.ok(Buffer.isBuffer(verified) || verified instanceof Uint8Array);
      assert.deepStrictEqual(Buffer.from(verified), plaintext);
    });

    it('should fail verification with wrong key', async () => {
      // Generate a different key pair
      const { publicKey: wrongPublicKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-256'
      });
      const wrongPublicJwk = wrongPublicKey.export({ format: 'jwk' });

      const wrongVerifier = {
        key: {
          x: Buffer.from(wrongPublicJwk.x, 'base64url'),
          y: Buffer.from(wrongPublicJwk.y, 'base64url')
        }
      };

      const signed = await cose.sign.create(headers, plaintext, signer);
      
      await assert.rejects(
        async () => await cose.sign.verify(signed, wrongVerifier),
        'Verification should fail with wrong key'
      );
    });

    it('should handle different payloads', async () => {
      const payloads = [
        Buffer.from('short'),
        Buffer.from('a'.repeat(1000)),
        Buffer.from(JSON.stringify({ claim: 'value', arr: [1, 2, 3] })),
        Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe])
      ];

      for (const payload of payloads) {
        const signed = await cose.sign.create(headers, payload, signer);
        const verified = await cose.sign.verify(signed, verifier);
        assert.deepStrictEqual(Buffer.from(verified), payload);
      }
    });
  });

  describe('COSE MAC0', () => {
    const plaintext = Buffer.from('Content to authenticate');
    
    // Symmetric key for HMAC
    const symmetricKey = crypto.randomBytes(32);

    const headers = {
      p: { alg: 'HS256' },
      u: { kid: 'mac-key-1' }
    };

    const recipient = {
      key: symmetricKey
    };

    it('should create a COSE MAC0 message', async () => {
      const macced = await cose.mac.create(headers, plaintext, recipient);
      assert.ok(Buffer.isBuffer(macced) || macced instanceof Uint8Array);
      assert.ok(macced.length > 0);
    });

    it('should verify a COSE MAC0 message', async () => {
      const macced = await cose.mac.create(headers, plaintext, recipient);
      const verified = await cose.mac.read(macced, symmetricKey);
      assert.deepStrictEqual(Buffer.from(verified), plaintext);
    });

    it('should fail verification with wrong key', async () => {
      const wrongKey = crypto.randomBytes(32);
      const macced = await cose.mac.create(headers, plaintext, recipient);
      
      await assert.rejects(
        async () => await cose.mac.read(macced, wrongKey),
        'MAC verification should fail with wrong key'
      );
    });
  });

  describe('COSE Encrypt0', () => {
    const plaintext = Buffer.from('Secret content to encrypt');
    
    // AES key for encryption
    const encryptionKey = crypto.randomBytes(16); // 128-bit for A128GCM

    const headers = {
      p: { alg: 'A128GCM' },
      u: { kid: 'enc-key-1' }
    };

    const recipient = {
      key: encryptionKey
    };

    it('should create a COSE Encrypt0 message', async () => {
      const encrypted = await cose.encrypt.create(headers, plaintext, recipient);
      assert.ok(Buffer.isBuffer(encrypted) || encrypted instanceof Uint8Array);
      assert.ok(encrypted.length > 0);
    });

    it('should decrypt a COSE Encrypt0 message', async () => {
      const encrypted = await cose.encrypt.create(headers, plaintext, recipient);
      const decrypted = await cose.encrypt.read(encrypted, encryptionKey);
      assert.deepStrictEqual(Buffer.from(decrypted), plaintext);
    });

    it('should fail decryption with wrong key', async () => {
      const wrongKey = crypto.randomBytes(16);
      const encrypted = await cose.encrypt.create(headers, plaintext, recipient);
      
      await assert.rejects(
        async () => await cose.encrypt.read(encrypted, wrongKey),
        'Decryption should fail with wrong key'
      );
    });

    it('should produce different ciphertext for same plaintext (due to random IV)', async () => {
      const encrypted1 = await cose.encrypt.create(headers, plaintext, recipient);
      const encrypted2 = await cose.encrypt.create(headers, plaintext, recipient);
      
      // The two encrypted messages should be different due to random IV
      assert.notDeepStrictEqual(encrypted1, encrypted2);
      
      // But both should decrypt to the same plaintext
      const decrypted1 = await cose.encrypt.read(encrypted1, encryptionKey);
      const decrypted2 = await cose.encrypt.read(encrypted2, encryptionKey);
      assert.deepStrictEqual(Buffer.from(decrypted1), plaintext);
      assert.deepStrictEqual(Buffer.from(decrypted2), plaintext);
    });
  });
});
