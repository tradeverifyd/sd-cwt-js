// Explicit clocks for historical examples. Security tests use the real API/default clock.
import * as cbor from 'cbor2';
import { Holder, Verifier } from '../src/api.js';
import { getHeaders } from '../src/cose-sign1.js';
import { cborDecodeOptions } from '../src/sd-cwt.js';
export function presentFixture(options) {
  const token = cbor.decode(options.token, cborDecodeOptions).contents;
  const claims = cbor.decode(token[0], cborDecodeOptions).get(15) ?? cbor.decode(token[2], cborDecodeOptions);
  const issuedAt = Math.max(claims.get(5) ?? 0, claims.get(6) ?? 0, 1725244200) + 1;
  return Holder.present({ issuedAt, ...options });
}
export function verifyFixture(options) {
  const token = cbor.decode(options.presentation, cborDecodeOptions).contents;
  const payload = cbor.decode(token[2], cborDecodeOptions);
  return Verifier.verify({ now: payload.get(6) ?? 1725244300, ...options });
}
