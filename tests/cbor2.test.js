import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as cbor from 'cbor2';

describe('cbor2 sanity tests', () => {
  
  describe('encode', () => {
    it('should encode a simple integer', () => {
      const encoded = cbor.encode(42);
      assert.ok(Buffer.isBuffer(encoded) || encoded instanceof Uint8Array);
      assert.ok(encoded.length > 0);
    });

    it('should encode a string', () => {
      const encoded = cbor.encode('hello world');
      assert.ok(encoded.length > 0);
    });

    it('should encode an array', () => {
      const encoded = cbor.encode([1, 2, 3]);
      assert.ok(encoded.length > 0);
    });

    it('should encode an object', () => {
      const encoded = cbor.encode({ foo: 'bar', num: 123 });
      assert.ok(encoded.length > 0);
    });

    it('should encode null and undefined', () => {
      const encodedNull = cbor.encode(null);
      const encodedUndefined = cbor.encode(undefined);
      assert.ok(encodedNull.length > 0);
      assert.ok(encodedUndefined.length > 0);
    });

    it('should encode booleans', () => {
      const encodedTrue = cbor.encode(true);
      const encodedFalse = cbor.encode(false);
      assert.ok(encodedTrue.length > 0);
      assert.ok(encodedFalse.length > 0);
    });

    it('should encode floating point numbers', () => {
      const encoded = cbor.encode(3.14159);
      assert.ok(encoded.length > 0);
    });

    it('should encode nested structures', () => {
      const nested = {
        array: [1, 2, { inner: 'value' }],
        nested: { deep: { deeper: true } }
      };
      const encoded = cbor.encode(nested);
      assert.ok(encoded.length > 0);
    });

    it('should encode Buffer/Uint8Array (byte strings)', () => {
      const bytes = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      const encoded = cbor.encode(bytes);
      assert.ok(encoded.length > 0);
    });
  });

  describe('decode', () => {
    it('should decode an encoded integer', () => {
      const original = 42;
      const encoded = cbor.encode(original);
      const decoded = cbor.decode(encoded);
      assert.strictEqual(decoded, original);
    });

    it('should decode an encoded string', () => {
      const original = 'hello world';
      const encoded = cbor.encode(original);
      const decoded = cbor.decode(encoded);
      assert.strictEqual(decoded, original);
    });

    it('should decode an encoded array', () => {
      const original = [1, 2, 3, 'four', true];
      const encoded = cbor.encode(original);
      const decoded = cbor.decode(encoded);
      assert.deepStrictEqual(decoded, original);
    });

    it('should decode an encoded object', () => {
      const original = { foo: 'bar', num: 123, bool: true };
      const encoded = cbor.encode(original);
      const decoded = cbor.decode(encoded);
      assert.deepStrictEqual(decoded, original);
    });

    it('should decode null', () => {
      const encoded = cbor.encode(null);
      const decoded = cbor.decode(encoded);
      assert.strictEqual(decoded, null);
    });

    it('should decode booleans', () => {
      assert.strictEqual(cbor.decode(cbor.encode(true)), true);
      assert.strictEqual(cbor.decode(cbor.encode(false)), false);
    });

    it('should decode floating point numbers', () => {
      const original = 3.14159;
      const encoded = cbor.encode(original);
      const decoded = cbor.decode(encoded);
      assert.strictEqual(decoded, original);
    });

    it('should decode nested structures', () => {
      const original = {
        array: [1, 2, { inner: 'value' }],
        nested: { deep: { deeper: true } }
      };
      const encoded = cbor.encode(original);
      const decoded = cbor.decode(encoded);
      assert.deepStrictEqual(decoded, original);
    });
  });

  describe('roundtrip', () => {
    it('should roundtrip negative integers', () => {
      const original = -12345;
      assert.strictEqual(cbor.decode(cbor.encode(original)), original);
    });

    it('should roundtrip large integers', () => {
      const original = 2147483647;
      assert.strictEqual(cbor.decode(cbor.encode(original)), original);
    });

    it('should roundtrip empty array', () => {
      const original = [];
      assert.deepStrictEqual(cbor.decode(cbor.encode(original)), original);
    });

    it('should roundtrip empty object', () => {
      const original = {};
      assert.deepStrictEqual(cbor.decode(cbor.encode(original)), original);
    });
  });
});
