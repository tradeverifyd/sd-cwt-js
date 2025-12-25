/**
 * Tests for EDN parsing and formatting
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Hex, EDN, cbor } from '../src/edn.js';

describe('Hex utilities', () => {
  describe('encode', () => {
    it('should encode empty bytes', () => {
      assert.strictEqual(Hex.encode(new Uint8Array(0)), '');
    });

    it('should encode single byte', () => {
      assert.strictEqual(Hex.encode(new Uint8Array([0])), '00');
      assert.strictEqual(Hex.encode(new Uint8Array([255])), 'ff');
      assert.strictEqual(Hex.encode(new Uint8Array([16])), '10');
    });

    it('should encode multiple bytes', () => {
      assert.strictEqual(Hex.encode(new Uint8Array([1, 2, 3, 4])), '01020304');
      assert.strictEqual(Hex.encode(new Uint8Array([0xde, 0xad, 0xbe, 0xef])), 'deadbeef');
    });

    it('should handle null/undefined', () => {
      assert.strictEqual(Hex.encode(null), '');
      assert.strictEqual(Hex.encode(undefined), '');
    });
  });

  describe('decode', () => {
    it('should decode empty string', () => {
      assert.deepStrictEqual(Hex.decode(''), new Uint8Array(0));
    });

    it('should decode hex string', () => {
      assert.deepStrictEqual(Hex.decode('01020304'), new Uint8Array([1, 2, 3, 4]));
      assert.deepStrictEqual(Hex.decode('deadbeef'), new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    });

    it('should handle whitespace', () => {
      assert.deepStrictEqual(Hex.decode('de ad be ef'), new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
      assert.deepStrictEqual(Hex.decode('de\nad\tbe ef'), new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    });

    it('should handle uppercase', () => {
      assert.deepStrictEqual(Hex.decode('DEADBEEF'), new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    });
  });

  describe('roundtrip', () => {
    it('should roundtrip bytes', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const encoded = Hex.encode(original);
      const decoded = Hex.decode(encoded);
      assert.deepStrictEqual(decoded, original);
    });
  });
});

describe('EDN.stringify', () => {
  describe('primitives', () => {
    it('should stringify null', () => {
      assert.strictEqual(EDN.stringify(null), 'null');
    });

    it('should stringify undefined', () => {
      assert.strictEqual(EDN.stringify(undefined), 'undefined');
    });

    it('should stringify booleans', () => {
      assert.strictEqual(EDN.stringify(true), 'true');
      assert.strictEqual(EDN.stringify(false), 'false');
    });

    it('should stringify numbers', () => {
      assert.strictEqual(EDN.stringify(42), '42');
      assert.strictEqual(EDN.stringify(-42), '-42');
      assert.strictEqual(EDN.stringify(3.14), '3.14');
      assert.strictEqual(EDN.stringify(0), '0');
    });

    it('should stringify strings', () => {
      assert.strictEqual(EDN.stringify('hello'), '"hello"');
      assert.strictEqual(EDN.stringify(''), '""');
      assert.strictEqual(EDN.stringify('with "quotes"'), '"with \\"quotes\\""');
    });
  });

  describe('bytes', () => {
    it('should stringify short byte arrays', () => {
      assert.strictEqual(EDN.stringify(new Uint8Array([1, 2, 3, 4])), "h'01020304'");
    });

    it('should stringify empty byte array', () => {
      assert.strictEqual(EDN.stringify(new Uint8Array(0)), "h''");
    });
  });

  describe('maps', () => {
    it('should stringify empty map', () => {
      assert.strictEqual(EDN.stringify(new Map()), '{}');
    });

    it('should stringify map with number keys', () => {
      const map = new Map([[1, 'value']]);
      const result = EDN.stringify(map);
      assert.ok(result.includes('1: "value"'));
    });

    it('should stringify map with string keys', () => {
      const map = new Map([['key', 'value']]);
      const result = EDN.stringify(map);
      assert.ok(result.includes('"key": "value"'));
    });

    it('should stringify nested maps', () => {
      const inner = new Map([[1, 2]]);
      const outer = new Map([['nested', inner]]);
      const result = EDN.stringify(outer);
      assert.ok(result.includes('"nested":'));
      assert.ok(result.includes('1: 2'));
    });
  });

  describe('arrays', () => {
    it('should stringify empty array', () => {
      assert.strictEqual(EDN.stringify([]), '[]');
    });

    it('should stringify array with values', () => {
      const result = EDN.stringify([1, 2, 3]);
      assert.ok(result.includes('1'));
      assert.ok(result.includes('2'));
      assert.ok(result.includes('3'));
    });
  });

  describe('CBOR tags', () => {
    it('should stringify CBOR tag', () => {
      const tag = new cbor.Tag(58, 'value');
      assert.strictEqual(EDN.stringify(tag), '58("value")');
    });

    it('should stringify CBOR tag with number content', () => {
      const tag = new cbor.Tag(60, 123);
      assert.strictEqual(EDN.stringify(tag), '60(123)');
    });

    it('should stringify nested CBOR tags', () => {
      const inner = new cbor.Tag(61, 'inner');
      const outer = new cbor.Tag(58, inner);
      assert.strictEqual(EDN.stringify(outer), '58(61("inner"))');
    });
  });

  describe('simple values', () => {
    it('should stringify simple value', () => {
      assert.strictEqual(EDN.stringify({ type: 'simple', value: 59 }), 'simple(59)');
    });
  });
});

describe('EDN.parse', () => {
  describe('primitives', () => {
    it('should parse null', () => {
      assert.strictEqual(EDN.parse('null'), null);
    });

    it('should parse booleans', () => {
      assert.strictEqual(EDN.parse('true'), true);
      assert.strictEqual(EDN.parse('false'), false);
    });

    it('should parse positive numbers', () => {
      assert.strictEqual(EDN.parse('42'), 42);
      assert.strictEqual(EDN.parse('0'), 0);
      assert.strictEqual(EDN.parse('123456'), 123456);
    });

    it('should parse negative numbers', () => {
      assert.strictEqual(EDN.parse('-42'), -42);
      assert.strictEqual(EDN.parse('-1'), -1);
    });

    it('should parse floating point numbers', () => {
      assert.strictEqual(EDN.parse('3.14'), 3.14);
      assert.strictEqual(EDN.parse('-3.14'), -3.14);
    });

    it('should parse strings', () => {
      assert.strictEqual(EDN.parse('"hello"'), 'hello');
      assert.strictEqual(EDN.parse('""'), '');
      assert.strictEqual(EDN.parse('"with spaces"'), 'with spaces');
    });

    it('should parse strings with escapes', () => {
      assert.strictEqual(EDN.parse('"hello\\nworld"'), 'hello\nworld');
      assert.strictEqual(EDN.parse('"tab\\there"'), 'tab\there');
      assert.strictEqual(EDN.parse('"quote\\"here"'), 'quote"here');
    });
  });

  describe('hex bytes', () => {
    it('should parse hex bytes', () => {
      const result = EDN.parse("h'01020304'");
      assert.ok(result instanceof Uint8Array);
      assert.deepStrictEqual(result, new Uint8Array([1, 2, 3, 4]));
    });

    it('should parse empty hex bytes', () => {
      const result = EDN.parse("h''");
      assert.ok(result instanceof Uint8Array);
      assert.strictEqual(result.length, 0);
    });

    it('should parse hex bytes with whitespace', () => {
      const result = EDN.parse("h'de ad be ef'");
      assert.deepStrictEqual(result, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
    });
  });

  describe('maps', () => {
    it('should parse empty map', () => {
      const result = EDN.parse('{}');
      assert.ok(result instanceof Map);
      assert.strictEqual(result.size, 0);
    });

    it('should parse map with number keys', () => {
      const result = EDN.parse('{ 1: "value" }');
      assert.ok(result instanceof Map);
      assert.strictEqual(result.get(1), 'value');
    });

    it('should parse map with string keys', () => {
      const result = EDN.parse('{ "key": "value" }');
      assert.ok(result instanceof Map);
      assert.strictEqual(result.get('key'), 'value');
    });

    it('should parse map with multiple entries', () => {
      const result = EDN.parse('{ 1: "a", 2: "b", 3: "c" }');
      assert.ok(result instanceof Map);
      assert.strictEqual(result.size, 3);
      assert.strictEqual(result.get(1), 'a');
      assert.strictEqual(result.get(2), 'b');
      assert.strictEqual(result.get(3), 'c');
    });

    it('should parse nested maps', () => {
      const result = EDN.parse('{ 1: { 2: 3 } }');
      assert.ok(result instanceof Map);
      const inner = result.get(1);
      assert.ok(inner instanceof Map);
      assert.strictEqual(inner.get(2), 3);
    });

    it('should parse map with comments', () => {
      const result = EDN.parse('{ / iss / 1: "issuer", / sub / 2: "subject" }');
      assert.ok(result instanceof Map);
      assert.strictEqual(result.get(1), 'issuer');
      assert.strictEqual(result.get(2), 'subject');
    });
  });

  describe('arrays', () => {
    it('should parse empty array', () => {
      const result = EDN.parse('[]');
      assert.ok(Array.isArray(result));
      assert.strictEqual(result.length, 0);
    });

    it('should parse array with values', () => {
      const result = EDN.parse('[1, 2, 3]');
      assert.ok(Array.isArray(result));
      assert.deepStrictEqual(result, [1, 2, 3]);
    });

    it('should parse array with mixed types', () => {
      const result = EDN.parse('[1, "hello", true, null]');
      assert.deepStrictEqual(result, [1, 'hello', true, null]);
    });

    it('should parse nested arrays', () => {
      const result = EDN.parse('[[1, 2], [3, 4]]');
      assert.deepStrictEqual(result, [[1, 2], [3, 4]]);
    });
  });

  describe('CBOR tags', () => {
    it('should parse CBOR tag with string content', () => {
      const result = EDN.parse('58("value")');
      assert.ok(result instanceof cbor.Tag);
      assert.strictEqual(result.tag, 58);
      assert.strictEqual(result.contents, 'value');
    });

    it('should parse CBOR tag with number content', () => {
      const result = EDN.parse('60(123)');
      assert.ok(result instanceof cbor.Tag);
      assert.strictEqual(result.tag, 60);
      assert.strictEqual(result.contents, 123);
    });

    it('should parse nested CBOR tags', () => {
      const result = EDN.parse('58(61("inner"))');
      assert.ok(result instanceof cbor.Tag);
      assert.strictEqual(result.tag, 58);
      assert.ok(result.contents instanceof cbor.Tag);
      assert.strictEqual(result.contents.tag, 61);
      assert.strictEqual(result.contents.contents, 'inner');
    });

    it('should parse CBOR tag as map key', () => {
      const result = EDN.parse('{ 58(501): "value" }');
      assert.ok(result instanceof Map);
      // Find the tagged key
      let foundTag = false;
      for (const [key, value] of result) {
        if (key instanceof cbor.Tag) {
          assert.strictEqual(key.tag, 58);
          assert.strictEqual(key.contents, 501);
          assert.strictEqual(value, 'value');
          foundTag = true;
        }
      }
      assert.ok(foundTag, 'Should have found a tagged key');
    });
  });

  describe('simple values', () => {
    it('should parse simple value', () => {
      const result = EDN.parse('simple(59)');
      assert.deepStrictEqual(result, { type: 'simple', value: 59 });
    });
  });

  describe('complex structures', () => {
    it('should parse spec-like claims', () => {
      const edn = `{
        / iss / 1: "https://issuer.example",
        / sub / 2: "https://device.example",
        / exp / 4: 1725330600,
        500: true,
        58(501): "ABCD-123456",
        503: {
          "country": "us",
          58("region"): "ca"
        }
      }`;
      
      const result = EDN.parse(edn);
      assert.ok(result instanceof Map);
      assert.strictEqual(result.get(1), 'https://issuer.example');
      assert.strictEqual(result.get(2), 'https://device.example');
      assert.strictEqual(result.get(4), 1725330600);
      assert.strictEqual(result.get(500), true);
      
      // Check tagged key
      let found501 = false;
      for (const [key, value] of result) {
        if (key instanceof cbor.Tag && key.tag === 58 && key.contents === 501) {
          assert.strictEqual(value, 'ABCD-123456');
          found501 = true;
        }
      }
      assert.ok(found501, 'Should have found tagged key 58(501)');
      
      // Check nested map
      const nested = result.get(503);
      assert.ok(nested instanceof Map);
      assert.strictEqual(nested.get('country'), 'us');
      
      // Check tagged key in nested map
      let foundRegion = false;
      for (const [key, value] of nested) {
        if (key instanceof cbor.Tag && key.tag === 58 && key.contents === 'region') {
          assert.strictEqual(value, 'ca');
          foundRegion = true;
        }
      }
      assert.ok(foundRegion, 'Should have found tagged key 58("region")');
    });
  });
});

describe('EDN.formatClaims', () => {
  it('should format empty claims', () => {
    assert.strictEqual(EDN.formatClaims(new Map()), '{}');
  });

  it('should add comments for known CWT claims', () => {
    const claims = new Map([
      [1, 'https://issuer.example'],
      [2, 'https://subject.example'],
    ]);
    const result = EDN.formatClaims(claims);
    assert.ok(result.includes('/ iss /'), 'Should have iss comment');
    assert.ok(result.includes('/ sub /'), 'Should have sub comment');
    assert.ok(result.includes('1:'), 'Should have key 1');
    assert.ok(result.includes('2:'), 'Should have key 2');
  });

  it('should not add comments for unknown claims', () => {
    const claims = new Map([
      [500, 'custom claim'],
    ]);
    const result = EDN.formatClaims(claims);
    assert.ok(!result.includes('/ '), 'Should not have comment');
    assert.ok(result.includes('500:'), 'Should have key 500');
  });

  it('should not add comments to nested maps', () => {
    const inner = new Map([[1, 2]]);
    const claims = new Map([[8, inner]]); // cnf claim
    const result = EDN.formatClaims(claims);
    // The outer cnf should have comment
    assert.ok(result.includes('/ cnf /'), 'Should have cnf comment');
    // But inner map with key 1 should NOT have iss comment
    const lines = result.split('\n');
    let innerHasComment = false;
    for (const line of lines) {
      // Look for lines that have "/ iss /" but are not the top level
      if (line.includes('/ iss /') && line.trim().startsWith('/ iss /')) {
        // This would be at the start of a key, check if it's indented
        if (line.startsWith('    ')) { // More than 2 spaces = nested
          innerHasComment = true;
        }
      }
    }
    assert.ok(!innerHasComment, 'Nested map should not have CWT claim comments');
  });
});

describe('EDN roundtrip', () => {
  it('should roundtrip simple map', () => {
    const original = new Map([
      [1, 'issuer'],
      [2, 'subject'],
    ]);
    const edn = EDN.stringify(original);
    const parsed = EDN.parse(edn);
    assert.strictEqual(parsed.get(1), original.get(1));
    assert.strictEqual(parsed.get(2), original.get(2));
  });

  it('should roundtrip nested structure', () => {
    const inner = new Map([[-1, 1], [-2, new Uint8Array([1, 2, 3, 4])]]);
    const original = new Map([
      [1, 'issuer'],
      [8, inner],
    ]);
    const edn = EDN.stringify(original);
    const parsed = EDN.parse(edn);
    
    assert.strictEqual(parsed.get(1), 'issuer');
    const parsedInner = parsed.get(8);
    assert.ok(parsedInner instanceof Map);
    assert.strictEqual(parsedInner.get(-1), 1);
    assert.deepStrictEqual(parsedInner.get(-2), new Uint8Array([1, 2, 3, 4]));
  });

  it('should roundtrip CBOR tags', () => {
    const original = new cbor.Tag(58, 'value');
    const edn = EDN.stringify(original);
    const parsed = EDN.parse(edn);
    
    assert.ok(parsed instanceof cbor.Tag);
    assert.strictEqual(parsed.tag, 58);
    assert.strictEqual(parsed.contents, 'value');
  });

  it('should roundtrip array', () => {
    const original = [1, 'hello', true, new Uint8Array([0xde, 0xad])];
    const edn = EDN.stringify(original);
    const parsed = EDN.parse(edn);
    
    assert.strictEqual(parsed[0], 1);
    assert.strictEqual(parsed[1], 'hello');
    assert.strictEqual(parsed[2], true);
    assert.deepStrictEqual(parsed[3], new Uint8Array([0xde, 0xad]));
  });
});

