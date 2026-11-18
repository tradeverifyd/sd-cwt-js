// Policy is checked on authenticated, reconstructed claims, not the redacted payload.
export function validatePresentationClaims(credential, presentation, audience, now, leeway = 0, expectedNonce) {
  if (!Number.isFinite(now) || !Number.isFinite(leeway) || leeway < 0) throw new Error('Invalid verification clock or leeway');
  if (!(credential instanceof Map) || !(presentation instanceof Map)) throw new Error('Claims must be maps');
  for (const claims of [credential, presentation]) {
    if (claims.has(3) && (typeof claims.get(3) !== 'string' || claims.get(3) !== audience)) throw new Error('Audience mismatch');
    for (const label of [4,5,6]) if (claims.has(label) && !Number.isFinite(claims.get(label))) throw new Error('Time claim must be a finite number');
    if (claims.has(4) && now >= claims.get(4) + leeway) throw new Error('Token expired');
    if (claims.has(5) && now + leeway < claims.get(5)) throw new Error('Token not yet valid');
    if (claims.has(6) && now + leeway < claims.get(6)) throw new Error('Token issued in the future');
    for (const [a,b,strict] of [[5,6,false],[5,4,true],[6,4,true]]) {
      if (claims.has(a) && claims.has(b) && (strict ? claims.get(a) >= claims.get(b) : claims.get(a) > claims.get(b))) throw new Error('Inconsistent time claims');
    }
  }
  if (!presentation.has(3) || presentation.has(1) || presentation.has(2)) throw new Error('Invalid KBT registered claims');
  if (!presentation.has(6) && (!presentation.has(7) || presentation.has(4) || presentation.has(5))) throw new Error('KBT requires iat or cti; exp/nbf require iat');
  if (presentation.has(7) && !(presentation.get(7) instanceof Uint8Array)) throw new Error('cti must be a byte string');
  for (const [p,c,relation] of [[4,4,'max'],[5,5,'min'],[6,6,'min'],[6,5,'min'],[6,4,'max'],[5,4,'strictmax']]) {
    if (presentation.has(p) && credential.has(c)) {
      const a = presentation.get(p), b = credential.get(c);
      if ((relation === 'max' && a > b) || (relation === 'min' && a < b) || (relation === 'strictmax' && a >= b)) throw new Error('KBT time lies outside credential validity');
    }
  }
  if (presentation.has(39) && !(presentation.get(39) instanceof Uint8Array)) throw new Error('cnonce must be a byte string');
  if (expectedNonce !== undefined && (!(expectedNonce instanceof Uint8Array) || !presentation.has(39) || !Buffer.from(expectedNonce).equals(Buffer.from(presentation.get(39))))) throw new Error('Nonce mismatch');
}
