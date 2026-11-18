// Test-only compatibility for the independent cose-js oracle. Node 26 makes
// legacy cbor's pipe-to-NoFilter synchronous encoder return only its first chunk.
// Keep cbor's own encoding and cose-js's crypto; collect encoder chunks directly.
// This does not change production SD-CWT code or translate either wire format.
import { createRequire } from 'node:module';
import cose from 'cose-js';
const require = createRequire(import.meta.url);
const legacyRequire = createRequire(require.resolve('cose-js'));
export const legacyCbor = legacyRequire('cbor');
export const needsSynchronousCollector = legacyCbor.encode([1, 2, 3]).toString('hex') !== '83010203';
if (needsSynchronousCollector) {
  legacyCbor.Encoder.prototype._encodeAll = function (objects) {
    const chunks = [];
    this.on('data', chunk => chunks.push(chunk));
    for (const object of objects) this.pushAny(object);
    this.end();
    return Buffer.concat(chunks);
  };
}
export default cose;
