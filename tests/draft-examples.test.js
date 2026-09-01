/**
 * Conformance tests against the canonical examples in draft-ietf-spice-sd-cwt-08.
 *
 * Every other test in this suite signs and verifies with this library on both
 * sides, so it passes whenever the library is self-consistent -- including when
 * it is self-consistently wrong. These tests are the opposite: the bytes are
 * fixed by the draft, and the library has to meet them.
 *
 * Fixtures and key provenance: tests/fixtures/draft-08/README.md
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

import { Verifier, Holder } from '../src/api.js';
import * as coseSign1 from '../src/cose-sign1.js';
import * as sdCwt from '../src/sd-cwt.js';
import * as cbor from 'cbor2';

const FIXTURES = new URL('./fixtures/draft-08/', import.meta.url);
const read = name => new Uint8Array(readFileSync(new URL(name, FIXTURES)));
const hex = h => new Uint8Array(Buffer.from(h, 'hex'));

const ISSUED = read('issuer_cwt.cbor');
const KBT = read('kbt.cbor');

// Appendix C.2: Issuer key, P-384 / ES384.
const ISSUER_PUBLIC_KEY = {
  x: hex('c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf'),
  y: hex('8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e84a055a31fb7f9214b27509522c159e764f8711e11609554'),
};

const AUDIENCE = 'https://verifier.example/app';
const CNONCE = hex('8c0f5f523b95bea44a9a48c649240803');

describe('draft-ietf-spice-sd-cwt-08 canonical examples', () => {

  describe('issuer_cwt.cbor', () => {

    it('parses, exposing the documented protected headers', () => {
      const { protectedHeaders, unprotectedHeaders } = Holder.parse(ISSUED);

      assert.strictEqual(protectedHeaders.get(1), -35, 'alg must be ES384');
      assert.strictEqual(protectedHeaders.get(16), 293, 'typ must be the CoAP content-format 293');
      assert.strictEqual(protectedHeaders.get(170), -16, 'sd_alg must be SHA-256');
      assert.ok(unprotectedHeaders.has(17), 'disclosures live in sd_claims (17)');
      assert.strictEqual(unprotectedHeaders.get(17).length, 5, 'the Issuer sends five disclosures');
    });

    it('verifies under the Appendix C issuer key', async () => {
      // Regression guard: the digest must come from the COSE alg, not from the
      // key's default. Hashing with SHA-256 for an ES384 key fails here.
      await coseSign1.verify(ISSUED, ISSUER_PUBLIC_KEY);
    });

  });

  describe('Redacted Claim Hash construction', () => {

    // The CDDL says `bstr-encoded-salted = bstr .cbor salted-entry`, so the
    // digest covers the byte string including its header. This is the exact
    // disclosure the draft walks through in Section 3.
    const SALTED_ENTRY = hex('8350bae611067bb823486797da1ebbb52f836b414243442d3132333435361901f5');
    const REDACTED_CLAIM_HASH = 'af375dc3fba1d082448642c00be7b2f7bb05c9d8fb61cfc230ddfdfb4616a693';

    it('hashes the bstr, matching the digest in the issued payload', () => {
      const digest = Buffer.from(sdCwt.hashDisclosure(SALTED_ENTRY, 'sha256')).toString('hex');
      assert.strictEqual(digest, REDACTED_CLAIM_HASH);
    });

    it('does not hash the bare salted-entry array encoding', () => {
      // d9df03da… is what you get by hashing SALTED_ENTRY directly. Two
      // independent implementations shipped that digest; nothing can verify it.
      const wrong = createHash('sha256').update(SALTED_ENTRY).digest('hex');
      assert.notStrictEqual(REDACTED_CLAIM_HASH, wrong);
    });

  });

  describe('kbt.cbor', () => {

    it('accepts the integer typ 294 rather than requiring the media type string', async () => {
      const { protectedHeaders } = coseSign1.getHeaders(KBT);
      assert.strictEqual(protectedHeaders.get(16), 294);
      assert.ok(sdCwt.isKbCwtTyp(protectedHeaders.get(16)));
      assert.ok(sdCwt.isKbCwtTyp('application/kb+cwt'), 'the string form stays valid too');
    });

    it('carries the SD-CWT in kcwt as the embedded tag 18 structure', () => {
      const { protectedHeaders } = coseSign1.getHeaders(KBT);
      const kcwt = protectedHeaders.get(13);
      assert.ok(kcwt instanceof cbor.Tag, 'kcwt must not be a bstr');
      assert.strictEqual(kcwt.tag, 18);
    });

    it('verifies end to end and reconstructs exactly the disclosed claims', async () => {
      const { claims, kbtPayload } = await Verifier.verify({
        presentation: KBT,
        issuerPublicKey: ISSUER_PUBLIC_KEY,
        expectedAudience: AUDIENCE,
        expectedNonce: CNONCE,
      });

      // Three of the five disclosures were selected by the Holder.
      assert.strictEqual(claims.get(501), 'ABCD-123456', 'inspector_license_number revealed');

      assert.deepStrictEqual(
        claims.get(502), [1549560720, 1674004740],
        'the disclosed inspection date is restored; the withheld one is dropped'
      );

      const location = claims.get(503);
      assert.strictEqual(location.get('country'), 'us');
      assert.strictEqual(location.get('region'), 'ca', 'nested region revealed');
      assert.ok(!location.has('postal_code'), 'postal_code was not disclosed and must stay hidden');

      // Claims that were never redactable.
      assert.strictEqual(claims.get(1), 'https://issuer.example');
      assert.strictEqual(claims.get(500), true);

      assert.strictEqual(kbtPayload.get(3), AUDIENCE);
      assert.strictEqual(kbtPayload.get(6), 1725244237);
    });

    it('rejects a presentation aimed at a different audience', async () => {
      await assert.rejects(() => Verifier.verify({
        presentation: KBT,
        issuerPublicKey: ISSUER_PUBLIC_KEY,
        expectedAudience: 'https://attacker.example',
      }));
    });

    it('rejects a replayed nonce', async () => {
      await assert.rejects(() => Verifier.verify({
        presentation: KBT,
        issuerPublicKey: ISSUER_PUBLIC_KEY,
        expectedAudience: AUDIENCE,
        expectedNonce: hex('00000000000000000000000000000000'),
      }));
    });

  });

});

describe('acting as Holder over the draft\'s own credential', () => {

  // Appendix C.1 Holder key, P-256 / ES256.
  const HOLDER_PRIVATE_KEY = {
    d: hex('5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5'),
    x: hex('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d'),
    y: hex('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'),
  };

  const labelOf = disclosure => {
    const entry = cbor.decode(disclosure, sdCwt.cborDecodeOptions);
    return entry.length === 3 ? entry[2] : entry[1]; // named claim vs array element
  };

  it('presents a chosen subset of the Issuer\'s disclosures, and verifies', async () => {
    // Take the Issuer's disclosures straight from the draft's token.
    const all = coseSign1.getHeaders(ISSUED).unprotectedHeaders.get(17);
    assert.strictEqual(all.length, 5, 'the Issuer supplies five disclosures');

    // The same three the draft's own kbt.cbor presents.
    const wanted = new Set([501, 1549560720, 'region']);
    const selected = all.filter(d => wanted.has(labelOf(d)));
    assert.strictEqual(selected.length, 3);

    const kbt = await Holder.present({
      token: ISSUED,
      selectedDisclosures: selected,
      holderPrivateKey: HOLDER_PRIVATE_KEY,
      audience: AUDIENCE,
      nonce: CNONCE,
      algorithm: 'ES256',
    });

    const { claims } = await Verifier.verify({
      presentation: kbt,
      issuerPublicKey: ISSUER_PUBLIC_KEY,
      expectedAudience: AUDIENCE,
      expectedNonce: CNONCE,
    });

    // Same reconstruction as the draft's own presentation.
    assert.strictEqual(claims.get(501), 'ABCD-123456');
    assert.deepStrictEqual(claims.get(502), [1549560720, 1674004740]);
    assert.strictEqual(claims.get(503).get('region'), 'ca');
    assert.ok(!claims.get(503).has('postal_code'), 'postal_code stays redacted');
  });

  it('produces a kcwt whose embedded SD-CWT is the Issuer\'s bytes, untouched', async () => {
    const all = coseSign1.getHeaders(ISSUED).unprotectedHeaders.get(17);
    const kbt = await Holder.present({
      token: ISSUED,
      selectedDisclosures: all.filter(d => labelOf(d) === 501),
      holderPrivateKey: HOLDER_PRIVATE_KEY,
      audience: AUDIENCE,
      algorithm: 'ES256',
    });

    const kcwt = coseSign1.getHeaders(kbt).protectedHeaders.get(13);
    assert.ok(kcwt instanceof cbor.Tag && kcwt.tag === 18);

    // Only sd_claims may be narrowed; the signed halves must be bit-identical
    // or the Issuer's signature would not survive.
    const issuedInner = cbor.decode(ISSUED, sdCwt.cborDecodeOptions).contents;
    const h = b => Buffer.from(b).toString('hex');
    assert.strictEqual(h(kcwt.contents[0]), h(issuedInner[0]), 'protected header unchanged');
    assert.strictEqual(h(kcwt.contents[2]), h(issuedInner[2]), 'payload unchanged');
    assert.strictEqual(h(kcwt.contents[3]), h(issuedInner[3]), 'signature unchanged');
    assert.strictEqual(kcwt.contents[1].get(17).length, 1, 'only the selected disclosure remains');
  });

});
