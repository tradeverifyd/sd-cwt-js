/**
 * Generate tests/fixtures/draft-08/aead_kbt.js.cbor
 *
 * The draft's issuer_cwt.cbor, presented with the Appendix C Holder key. The
 * first disclosure (501, inspector_license_number) is encrypted with the
 * draft's Section 13 AEAD key and nonce, so its sd_aead_encrypted_claims (171)
 * entry is byte-identical to the draft example. Two more disclosures (the
 * same ones kbt.cbor presents) stay in sd_claims.
 *
 * Usage: node scripts/generate-aead-fixture.js [output-path]
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as cbor from 'cbor2';
import { Holder } from '../src/api.js';
import * as coseSign1 from '../src/cose-sign1.js';
import * as sdCwt from '../src/sd-cwt.js';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = join(rootDir, 'tests/fixtures/draft-08');
const hex = h => new Uint8Array(Buffer.from(h, 'hex'));

const HOLDER_PRIVATE_KEY = {
  d: hex('5759a86e59bb3b002dde467da4b52f3d06e6c2cd439456cf0485b9b864294ce5'),
  x: hex('8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d'),
  y: hex('4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'),
};
const AEAD_KEY = hex('a061c27a3273721e210d031863ad81b6');
const AEAD_NONCE = hex('95d0040fe650e5baf51c907c');
const AUDIENCE = 'https://verifier.example/app';
const CNONCE = hex('8c0f5f523b95bea44a9a48c649240803');

const issued = new Uint8Array(readFileSync(join(fixtures, 'issuer_cwt.cbor')));
const all = coseSign1.getHeaders(issued).unprotectedHeaders.get(17);
const labelOf = d => {
  const entry = cbor.decode(d, sdCwt.cborDecodeOptions);
  return entry.length === 3 ? entry[2] : entry[1];
};

const first = all.find(d => labelOf(d) === 501);
const plaintext = all.filter(d => [1549560720, 'region'].includes(labelOf(d)));

const kbt = await Holder.present({
  token: issued,
  selectedDisclosures: plaintext,
  encryptedDisclosures: [{ disclosure: first, key: AEAD_KEY, nonce: AEAD_NONCE }],
  holderPrivateKey: HOLDER_PRIVATE_KEY,
  audience: AUDIENCE,
  nonce: CNONCE,
  algorithm: 'ES256',
});

const out = process.argv[2] || join(fixtures, 'aead_kbt.js.cbor');
writeFileSync(out, kbt);
console.log(`Wrote ${out} (${kbt.length} bytes)`);
