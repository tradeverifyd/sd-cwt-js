import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import * as cbor from 'cbor2';
import { Verifier } from '../src/api.js';
import * as cose from '../src/cose-sign1.js';
import * as sd from '../src/sd-cwt.js';

function key(curve) {
  const jwk = generateKeyPairSync('ec', { namedCurve: curve }).privateKey.export({format:'jwk'});
  return Object.fromEntries(['x','y','d'].map(k => [k,new Uint8Array(Buffer.from(jwk[k],'base64url'))]));
}
const issuer = key('P-384'), holder = key('P-256');
const AUD = 'https://verifier.example/app', NOW = Math.floor(Date.now()/1000);
const cnf = new Map([[1,new Map([[1,2],[-1,1],[-2,holder.x],[-3,holder.y]])]]);
async function token({ claims = [], kbt = [], header = [], unprotected = new Map() } = {}) {
  const payload = new Map([[1, 'issuer'], [2, 'holder'], [6, NOW-10], [4, NOW+3600], [8, cnf], ...claims]);
  const issued = await cose.sign(cbor.encode(payload), issuer, { algorithm: 'ES384',
    customProtectedHeaders: new Map([[16, 293], [170, -16], ...header]), customUnprotectedHeaders: unprotected });
  return cose.sign(cbor.encode(new Map([[3, AUD], [6, NOW], ...kbt])), holder, {
    algorithm: 'ES256', customProtectedHeaders: new Map([[16,294], [13,cbor.decode(issued,sd.cborDecodeOptions)]]) });
}
const verify = (presentation, options = {}) => Verifier.verify({ presentation, issuerPublicKey: issuer, expectedAudience: AUD, ...options });

describe('security review: authenticated adversarial inputs', () => {
  it('accepts the positive control', async () => { await verify(await token()); });
  for (const [name, options] of [
    ['expired credential', {claims:[[4,NOW-1]]}], ['not-yet-valid credential', {claims:[[5,NOW+100]]}],
    ['expired presentation', {kbt:[[4,NOW-1]]}], ['not-yet-valid presentation', {kbt:[[5,NOW+100]]}],
    ['non-finite expiry', {claims:[[4,NaN]]}], ['boolean issued-at', {kbt:[[6,true]]}],
    ['presentation outlives credential', {claims:[[4,NOW+10]], kbt:[[6,NOW+20]]}],
    ['unknown critical extension', {header:[[2,[999]],[999,true]]}],
    ['wrong credential type', {header:[[16,294]]}],
    ['duplicate header', {unprotected:new Map([[1,-35]])}],
  ]) it(`rejects ${name}`, async () => { await assert.rejects(() => token(options).then(verify)); });
  it('rejects an audience revealed by a disclosure', async () => {
    const d = sd.createSaltedDisclosure(new Uint8Array(16), 'another verifier', 3);
    const t = await token({claims:[[new cbor.Simple(59), [sd.hashDisclosure(d)]]], unprotected:new Map([[17,[d]]])});
    await assert.rejects(() => verify(t));
  });
  it('does not overwrite an existing claim during reconstruction', () => {
    const d = sd.createSaltedDisclosure(new Uint8Array(16), 'admin', 'role');
    assert.throws(() => sd.reconstructClaims(new Map([['role','user'], [new cbor.Simple(59),[sd.hashDisclosure(d)]]]), [d]));
  });
  it('rejects repeated plaintext disclosures', () => {
    const d = sd.createSaltedDisclosure(new Uint8Array(16), 'value', 'key');
    assert.throws(() => sd.reconstructClaims(new Map([[new cbor.Simple(59),[sd.hashDisclosure(d)]]]), [d,d]));
  });
});


describe('security review: policy boundaries and controls', () => {
  it('enforces the exact expiry boundary with explicit clock skew', async () => {
    const t = await token({claims:[[4,NOW]], kbt:[[6,NOW-1]]});
    await assert.rejects(() => verify(t, {now:NOW}));
    await verify(t, {now:NOW, leeway:1});
  });
  for (const bad of [NaN, Infinity, -1, true]) {
    it(`rejects invalid leeway ${bad}`, async () => {
      const t = await token();
      await assert.rejects(() => verify(t,{leeway:bad}));
    });
  }
  it('checks the expected challenge', async () => {
    const t = await token({kbt:[[39,Uint8Array.of(1,2,3)]]});
    await verify(t,{expectedNonce:Uint8Array.of(1,2,3)});
    await assert.rejects(() => verify(t,{expectedNonce:Uint8Array.of(3,2,1)}));
  });
  it('rejects a decoy without a matching hash', async () => {
    const t = await token({unprotected:new Map([[17,[cbor.encode([new Uint8Array(16)])]]])});
    await assert.rejects(() => verify(t));
  });
  it('accepts the understood critical algorithm parameter', async () => {
    await verify(await token({header:[[2,[1]]]}));
  });
  it('rejects reusing one disclosure at two hash locations', () => {
    const d = sd.createSaltedDisclosure(new Uint8Array(16),'value','key');
    const hashes = new Map([[new cbor.Simple(59),[sd.hashDisclosure(d)]]]);
    assert.throws(() => sd.reconstructClaims(new Map([['a',hashes],['b',hashes]]),[d]));
  });
});

it('requires KBT issuance strictly before issuer expiry even with leeway', async () => {
  await verify(await token({claims:[[4,NOW]], kbt:[[6,NOW-1]]}), {now:NOW,leeway:10});
  await assert.rejects(() => token({claims:[[4,NOW]], kbt:[[6,NOW]]}).then(t => verify(t,{now:NOW,leeway:10})));
});
