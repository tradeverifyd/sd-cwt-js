import { describe, it } from 'node:test';
import assert from 'node:assert';
import cose, { legacyCbor } from './cose-js-compat.js';
import crypto from 'node:crypto';

describe('cose-js sanity tests', () => {

  describe('module structure', () => {
    it('should export sign object', () => {
      assert.ok(cose.sign, 'cose.sign should exist');
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

});

// Fixed bytes verify the collector retains every chunk, including nested headers.
it('legacy CBOR oracle preserves complete wire bytes', () => {
  const value = [new Map([[1, -7]]), Buffer.from([0, 1, 2]), [1, 2, 3]];
  const encoded = legacyCbor.encode(value);
  assert.equal(encoded.toString('hex'), '83a101264300010283010203');
  assert.equal(legacyCbor.decodeFirstSync(encoded)[1].toString('hex'), '000102');
  const large = Buffer.alloc(128 * 1024, 0xa5);
  assert.deepEqual(legacyCbor.decodeFirstSync(legacyCbor.encode(large)), large);
});
