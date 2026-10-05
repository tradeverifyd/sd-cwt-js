/**
 * AEAD encrypted disclosures (draft-ietf-spice-sd-cwt-08, Section 13).
 *
 * The draft vector pins the plaintext: it is the CBOR encoding of
 * `bstr .cbor salted-entry`, bstr header included -- the same bytes the
 * Redacted Claim Hash covers -- with zero-length associated data.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync, existsSync } from 'node:fs';

import * as cbor from 'cbor2';
import {
  Holder,
  Verifier,
  AeadAlgorithm,
  encryptDisclosure,
  decryptDisclosure,
  parseEncryptedDisclosure,
} from '../src/api.js';
import * as coseSign1 from '../src/cose-sign1.js';
import * as sdCwt from '../src/sd-cwt.js';

const FIXTURES = new URL('./fixtures/draft-08/', import.meta.url);
const read = name => new Uint8Array(readFileSync(new URL(name, FIXTURES)));
const hex = h => new Uint8Array(Buffer.from(h, 'hex'));
const toHex = b => Buffer.from(b).toString('hex');

const ISSUED = read('issuer_cwt.cbor');

const ISSUER_PUBLIC_KEY = {
  x: hex('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf'),
  y: hex('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554'),
};
const HOLDER_PRIVATE_KEY = {
  d: hex('5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5'),
  x: hex('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d'),
  y: hex('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'),
};
const AUDIENCE = 'https://verifier.example/app';

// Section 13 example.
const AEAD_KEY = hex('a061c27a3273721e210d031863ad81b6');
const AEAD_NONCE = hex('95d0040fe650e5baf51c907c');
const AEAD_CIPHERTEXT = '563a7d9f0f65d40b751fbc3fcc408e8fe27c375b60a4727b1f1e9572c07992eb5ec5a9';
const AEAD_TAG = '9f4d37da32187528416ed7ee95e0625f';
const DRAFT_ENTRY = [AEAD_NONCE, hex(AEAD_CIPHERTEXT), hex(AEAD_TAG)];
const FIRST_DISCLOSURE = hex('8350bae611067bb823486797da1ebbb52f836b414243442d3132333435361901f5');

const ALL = coseSign1.getHeaders(ISSUED).unprotectedHeaders.get(17);
const labelOf = d => {
  const entry = cbor.decode(d, sdCwt.cborDecodeOptions);
  return entry.length === 3 ? entry[2] : entry[1];
};
const disclosureFor = label => ALL.find(d => labelOf(d) === label);

const keyFor = key => () => key;

async function present(options) {
  return Holder.present({
    token: ISSUED,
    holderPrivateKey: HOLDER_PRIVATE_KEY,
    audience: AUDIENCE,
    algorithm: 'ES256',
    ...options,
  });
}

// Re-signs a KBT after rewriting the unprotected header of its embedded SD-CWT.
// The Issuer signature survives because the unprotected header is not signed.
async function withSdCwtUnprotected(kbt, mutate) {
  const outer = cbor.decode(kbt, sdCwt.cborDecodeOptions).contents;
  const protectedHeaders = cbor.decode(outer[0], sdCwt.cborDecodeOptions);
  const kcwt = protectedHeaders.get(13);
  const unprotected = new Map(kcwt.contents[1]);
  mutate(unprotected);
  protectedHeaders.set(13, new cbor.Tag(18, [kcwt.contents[0], unprotected, kcwt.contents[2], kcwt.contents[3]]));
  return coseSign1.sign(outer[2], HOLDER_PRIVATE_KEY, {
    algorithm: 'ES256',
    customProtectedHeaders: new Map([...protectedHeaders].filter(([k]) => k !== 1)),
  });
}

describe('AEAD encrypted disclosures: the draft Section 13 vector', () => {

  it('the draft\'s first disclosure is the one in issuer_cwt.cbor', () => {
    assert.strictEqual(toHex(disclosureFor(501)), toHex(FIRST_DISCLOSURE));
  });

  it('decrypts to the first disclosure', async () => {
    const disclosure = await decryptDisclosure(DRAFT_ENTRY, AEAD_KEY);
    assert.strictEqual(toHex(disclosure), toHex(FIRST_DISCLOSURE));
  });

  it('encrypts with the draft nonce to byte-identical ciphertext and tag', async () => {
    const entry = await encryptDisclosure(FIRST_DISCLOSURE, AEAD_KEY, { nonce: AEAD_NONCE });
    assert.strictEqual(entry.length, 3);
    assert.strictEqual(toHex(entry[0]), toHex(AEAD_NONCE));
    assert.strictEqual(toHex(entry[1]), AEAD_CIPHERTEXT);
    assert.strictEqual(toHex(entry[2]), AEAD_TAG);
  });

  it('encrypts the bstr with its header, not the bare salted-entry', async () => {
    // The ciphertext is two octets longer than the salted-entry: 0x58 0x21.
    assert.strictEqual(hex(AEAD_CIPHERTEXT).length, FIRST_DISCLOSURE.length + 2);
  });

});

describe('AEAD encrypted disclosures: primitives', () => {

  it('round-trips with a random nonce under every supported algorithm', async () => {
    for (const [algorithm, keyLength] of [
      [AeadAlgorithm.AES_128_GCM, 16],
      [AeadAlgorithm.AES_256_GCM, 32],
      [AeadAlgorithm.CHACHA20_POLY1305, 32],
    ]) {
      const key = crypto.getRandomValues(new Uint8Array(keyLength));
      const a = await encryptDisclosure(FIRST_DISCLOSURE, key, { algorithm });
      const b = await encryptDisclosure(FIRST_DISCLOSURE, key, { algorithm });
      assert.notStrictEqual(toHex(a[0]), toHex(b[0]), 'each encryption uses a fresh nonce');
      assert.strictEqual(toHex(await decryptDisclosure(a, key, { algorithm })), toHex(FIRST_DISCLOSURE));
    }
  });

  it('rejects the wrong key', async () => {
    await assert.rejects(() => decryptDisclosure(DRAFT_ENTRY, new Uint8Array(16)), /decryption failed/);
  });

  it('rejects a tampered tag or ciphertext', async () => {
    const tag = hex(AEAD_TAG); tag[0] ^= 1;
    await assert.rejects(() => decryptDisclosure([AEAD_NONCE, hex(AEAD_CIPHERTEXT), tag], AEAD_KEY), /decryption failed/);
    const ct = hex(AEAD_CIPHERTEXT); ct[5] ^= 1;
    await assert.rejects(() => decryptDisclosure([AEAD_NONCE, ct, hex(AEAD_TAG)], AEAD_KEY), /decryption failed/);
  });

  it('carries each kind of key context, and rejects other types', async () => {
    for (const keyContext of [7, 'rp-key-1', hex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')]) {
      const entry = await encryptDisclosure(FIRST_DISCLOSURE, AEAD_KEY, { keyContext });
      assert.strictEqual(entry.length, 4);
      const parsed = parseEncryptedDisclosure(entry);
      assert.deepStrictEqual(parsed.keyContext, keyContext);
      // The key context is not authenticated data, so it does not change decryption.
      assert.strictEqual(toHex(await decryptDisclosure(entry, AEAD_KEY)), toHex(FIRST_DISCLOSURE));
    }
    for (const bad of [-1, 1.5, true, new Map()]) {
      assert.throws(() => parseEncryptedDisclosure([...DRAFT_ENTRY, bad]), /key context/);
    }
  });

  it('rejects malformed entries', () => {
    assert.throws(() => parseEncryptedDisclosure(DRAFT_ENTRY.slice(0, 2)), /expected \[nonce/);
    assert.throws(() => parseEncryptedDisclosure([...DRAFT_ENTRY, 1, 2]), /expected \[nonce/);
    assert.throws(() => parseEncryptedDisclosure([AEAD_NONCE.slice(0, 8), DRAFT_ENTRY[1], DRAFT_ENTRY[2]]), /nonce must be 12/);
    assert.throws(() => parseEncryptedDisclosure([AEAD_NONCE, DRAFT_ENTRY[1], hex(AEAD_TAG).slice(0, 12)]), /tag must be 16/);
    assert.throws(() => parseEncryptedDisclosure([AEAD_NONCE, 'text', DRAFT_ENTRY[2]]), /ciphertext must be a bstr/);
  });

  it('rejects a nonce or key of the wrong length when encrypting', async () => {
    await assert.rejects(() => encryptDisclosure(FIRST_DISCLOSURE, AEAD_KEY, { nonce: new Uint8Array(8) }), /nonce must be 12/);
    await assert.rejects(() => encryptDisclosure(FIRST_DISCLOSURE, new Uint8Array(32)), /key must be 16/);
  });

  it('refuses algorithms it does not support, including short-tag ones', async () => {
    // 3 is AEAD_AES_128_CCM, 5 is AEAD_AES_128_GCM_8 (8-octet tag).
    for (const algorithm of [3, 5, 999]) {
      await assert.rejects(() => encryptDisclosure(FIRST_DISCLOSURE, AEAD_KEY, { algorithm }), /Unsupported AEAD algorithm/);
      await assert.rejects(() => decryptDisclosure(DRAFT_ENTRY, AEAD_KEY, { algorithm }), /Unsupported AEAD algorithm/);
    }
  });

  it('rejects a plaintext that is not a bstr', async () => {
    // Encrypt the bare salted-entry array instead of the bstr wrapping it.
    const key = AEAD_KEY;
    const subtle = globalThis.crypto.subtle;
    const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    const sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: AEAD_NONCE }, k, FIRST_DISCLOSURE));
    const entry = [AEAD_NONCE, sealed.slice(0, -16), sealed.slice(-16)];
    await assert.rejects(() => decryptDisclosure(entry, key), /expected bstr/);
  });

});

describe('AEAD encrypted disclosures: Holder and Verifier', () => {

  it('Holder moves encrypted disclosures from sd_claims to sd_aead_encrypted_claims', async () => {
    const kbt = await present({
      selectedDisclosures: [disclosureFor(501), disclosureFor('region')],
      encryptedDisclosures: [{ disclosure: disclosureFor(501), key: AEAD_KEY }],
    });
    const unprotected = coseSign1.getHeaders(kbt).protectedHeaders.get(13).contents[1];
    assert.strictEqual(unprotected.get(17).length, 1, 'only the plaintext one stays in sd_claims');
    assert.strictEqual(toHex(unprotected.get(17)[0]), toHex(disclosureFor('region')));
    assert.strictEqual(unprotected.get(171).length, 1);
  });

  it('Holder omits sd_claims entirely when every disclosure is encrypted', async () => {
    const kbt = await present({
      encryptedDisclosures: [{ disclosure: disclosureFor(501), key: AEAD_KEY }],
    });
    const unprotected = coseSign1.getHeaders(kbt).protectedHeaders.get(13).contents[1];
    assert.ok(!unprotected.has(17), 'no empty sd_claims');
    assert.ok(unprotected.has(171));
  });

  it('Holder omits sd_aead_encrypted_claims when nothing is encrypted', async () => {
    const kbt = await present({ selectedDisclosures: [disclosureFor(501)] });
    const unprotected = coseSign1.getHeaders(kbt).protectedHeaders.get(13).contents[1];
    assert.ok(!unprotected.has(171));
  });

  it('a Verifier with the key reconstructs encrypted and plaintext disclosures alike', async () => {
    const kbt = await present({
      selectedDisclosures: [disclosureFor('region')],
      encryptedDisclosures: [{ disclosure: disclosureFor(501), key: AEAD_KEY, keyContext: 'rp-1' }],
    });
    const seen = [];
    const { claims, decryptedDisclosures, undecryptedDisclosures } = await Verifier.verify({
      presentation: kbt,
      issuerPublicKey: ISSUER_PUBLIC_KEY,
      expectedAudience: AUDIENCE,
      aeadKeyResolver: ({ keyContext, algorithm }) => {
        seen.push([keyContext, algorithm]);
        return keyContext === 'rp-1' ? AEAD_KEY : undefined;
      },
    });
    assert.deepStrictEqual(seen, [['rp-1', AeadAlgorithm.AES_128_GCM]], 'default algorithm without sd_aead');
    assert.strictEqual(claims.get(501), 'ABCD-123456');
    assert.strictEqual(claims.get(503).get('region'), 'ca');
    assert.strictEqual(decryptedDisclosures.length, 1);
    assert.strictEqual(undecryptedDisclosures.length, 0);
  });

  it('tries each candidate key the resolver returns', async () => {
    const kbt = await present({ encryptedDisclosures: [{ disclosure: disclosureFor(501), key: AEAD_KEY }] });
    const { claims } = await Verifier.verify({
      presentation: kbt,
      issuerPublicKey: ISSUER_PUBLIC_KEY,
      expectedAudience: AUDIENCE,
      aeadKeyResolver: () => [new Uint8Array(16), AEAD_KEY],
    });
    assert.strictEqual(claims.get(501), 'ABCD-123456');
  });

  it('a Verifier without a key leaves the entries encrypted and still verifies', async () => {
    const kbt = await present({
      selectedDisclosures: [disclosureFor('region')],
      encryptedDisclosures: [{ disclosure: disclosureFor(501), key: AEAD_KEY }],
    });
    for (const aeadKeyResolver of [undefined, () => undefined]) {
      const { claims, undecryptedDisclosures } = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_PUBLIC_KEY,
        expectedAudience: AUDIENCE,
        aeadKeyResolver,
      });
      assert.ok(!claims.has(501), 'the encrypted claim stays redacted');
      assert.strictEqual(claims.get(503).get('region'), 'ca');
      assert.strictEqual(undecryptedDisclosures.length, 1, 'reported so it can be forwarded');
    }
  });

  it('rejects when the resolved key does not decrypt', async () => {
    const kbt = await present({ encryptedDisclosures: [{ disclosure: disclosureFor(501), key: AEAD_KEY }] });
    await assert.rejects(() => Verifier.verify({
      presentation: kbt,
      issuerPublicKey: ISSUER_PUBLIC_KEY,
      expectedAudience: AUDIENCE,
      aeadKeyResolver: keyFor(new Uint8Array(16)),
    }), /could not be decrypted/);
  });

  it('rejects a decrypted disclosure that matches no Redacted Claim Hash', async () => {
    const stray = sdCwt.createSaltedDisclosure(new Uint8Array(16), 'forged', 501);
    const kbt = await present({ encryptedDisclosures: [{ disclosure: stray, key: AEAD_KEY }] });
    await assert.rejects(() => Verifier.verify({
      presentation: kbt,
      issuerPublicKey: ISSUER_PUBLIC_KEY,
      expectedAudience: AUDIENCE,
      aeadKeyResolver: keyFor(AEAD_KEY),
    }), /match no Redacted Claim Hash/);
  });

  it('rejects a disclosure sent both in plaintext and encrypted', async () => {
    const kbt = await present({ selectedDisclosures: [disclosureFor(501)] });
    const both = await withSdCwtUnprotected(kbt, u => u.set(171, [DRAFT_ENTRY]));
    await assert.rejects(() => Verifier.verify({
      presentation: both,
      issuerPublicKey: ISSUER_PUBLIC_KEY,
      expectedAudience: AUDIENCE,
      aeadKeyResolver: keyFor(AEAD_KEY),
    }), /both in sd_claims and in sd_aead_encrypted_claims/);
  });

  it('rejects an empty sd_aead_encrypted_claims', async () => {
    const kbt = await present({ selectedDisclosures: [disclosureFor(501)] });
    const empty = await withSdCwtUnprotected(kbt, u => u.set(171, []));
    await assert.rejects(() => Verifier.verify({
      presentation: empty,
      issuerPublicKey: ISSUER_PUBLIC_KEY,
      expectedAudience: AUDIENCE,
    }), /empty array/);
  });

  it('rejects a malformed entry even without a key', async () => {
    const kbt = await present({ selectedDisclosures: [disclosureFor(501)] });
    const bad = await withSdCwtUnprotected(kbt, u => u.set(171, [[AEAD_NONCE.slice(0, 8), DRAFT_ENTRY[1], DRAFT_ENTRY[2]]]));
    await assert.rejects(() => Verifier.verify({
      presentation: bad,
      issuerPublicKey: ISSUER_PUBLIC_KEY,
      expectedAudience: AUDIENCE,
    }), /nonce must be 12/);
  });

});

describe('AEAD encrypted disclosures: interop fixtures', () => {

  const fixtures = [
    ['aead_kbt.js.cbor', 'produced by this library (scripts/generate-aead-fixture.js)'],
    ['aead_kbt.cbor', 'produced by the python implementation (tradeverifyd/sd-cwt)'],
  ];

  for (const [name, provenance] of fixtures) {
    const present = existsSync(new URL(name, FIXTURES));
    it(`${name} verifies, ${provenance}`, { skip: !present && `${name} not checked in yet` }, async () => {
      const kbt = read(name);
      const unprotected = coseSign1.getHeaders(kbt).protectedHeaders.get(13).contents[1];
      const entries = unprotected.get(171);
      assert.strictEqual(entries.length, 1);
      assert.strictEqual(toHex(entries[0][1]), AEAD_CIPHERTEXT, 'the 171 entry is the draft example');
      assert.strictEqual(toHex(entries[0][2]), AEAD_TAG);

      const { claims, decryptedDisclosures } = await Verifier.verify({
        presentation: kbt,
        issuerPublicKey: ISSUER_PUBLIC_KEY,
        expectedAudience: AUDIENCE,
        aeadKeyResolver: keyFor(AEAD_KEY),
      });
      assert.strictEqual(decryptedDisclosures.length, 1);
      assert.strictEqual(claims.get(501), 'ABCD-123456');
    });
  }

});
