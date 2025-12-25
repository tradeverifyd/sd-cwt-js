/**
 * EDN (Extended Diagnostic Notation) Parser and Formatter for CBOR
 * 
 * This module provides utilities for parsing and formatting EDN,
 * which is the diagnostic notation used for CBOR data.
 */

import * as cbor from 'cbor2';

// Buffer check - works in both Node.js and browser (with shim)
// In browser, the buffer-shim.js is injected by esbuild
const Buffer = globalThis.Buffer;

/**
 * Hex encoding utilities
 */
export const Hex = {
  /**
   * Encode bytes to hex string
   * @param {Uint8Array|Buffer} bytes 
   * @returns {string}
   */
  encode(bytes) {
    if (!bytes) return '';
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Decode hex string to Uint8Array
   * @param {string} hex 
   * @returns {Uint8Array}
   */
  decode(hex) {
    if (!hex) return new Uint8Array(0);
    const clean = hex.replace(/\s/g, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  },
};

// Known CWT claim names for EDN comments
const CWT_CLAIM_NAMES = {
  1: 'iss',
  2: 'sub',
  3: 'aud',
  4: 'exp',
  5: 'nbf',
  6: 'iat',
  7: 'cti',
  8: 'cnf',
  39: 'cnonce',
};

/**
 * Get EDN comment for a CWT claim key
 * @param {number} key 
 * @returns {string} Comment prefix like "/ iss / " or empty string
 */
function getClaimComment(key) {
  const name = CWT_CLAIM_NAMES[key];
  return name ? `/ ${name} / ` : '';
}

/**
 * Check if a key is a Tag 58 (to be redacted) and format with comment
 * @param {any} key - The map key
 * @returns {{ isRedacted: boolean, comment: string }} 
 */
function getRedactionComment(key) {
  if (key instanceof cbor.Tag && key.tag === 58) {
    // For numbered keys, include a hint about the claim name if known
    if (typeof key.contents === 'number') {
      return { isRedacted: true, comment: '/ to be redacted / ' };
    }
    // For string keys, just say "to be redacted"
    return { isRedacted: true, comment: '/ to be redacted / ' };
  }
  return { isRedacted: false, comment: '' };
}

/**
 * EDN formatting utilities
 */
export const EDN = {
  /**
   * Convert a JavaScript value to EDN string
   * @param {any} value 
   * @param {object} options
   * @param {number} options.indent - spaces per indent level (default 2)
   * @returns {string}
   */
  stringify(value, options = {}) {
    const indent = options.indent ?? 2;
    return ednStringify(value, indent, 0);
  },

  /**
   * Parse an EDN string into JavaScript values
   * Uses cbor2.Tag for CBOR tags, Map for objects, arrays for arrays
   * @param {string} ednString 
   * @returns {any}
   */
  parse(ednString) {
    return parseEdn(ednString);
  },

  /**
   * Format a CWT claims Map to EDN with named comments for known claims
   * Comments are only added at the top level
   * @param {Map} claims 
   * @returns {string}
   */
  formatClaims(claims) {
    return formatMapWithComments(claims, 0, true);
  },
};

/**
 * Internal EDN stringifier
 */
function ednStringify(value, indent, depth) {
  const padChar = ' '.repeat(indent);
  const pad = padChar.repeat(depth);
  const pad1 = padChar.repeat(depth + 1);

  if (value === null) {
    return 'null';
  }

  if (value === undefined) {
    return 'undefined';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    return String(value);
  }

  if (typeof value === 'string') {
    return JSON.stringify(value);
  }

  if (value instanceof Uint8Array || (Buffer && Buffer.isBuffer && Buffer.isBuffer(value))) {
    const hex = Hex.encode(value);
    if (hex.length <= 64) {
      return `h'${hex}'`;
    }
    // Multi-line for long hex
    const lines = [];
    for (let i = 0; i < hex.length; i += 64) {
      lines.push(hex.slice(i, i + 64));
    }
    return `h'${lines.join('\n' + pad1)}'`;
  }

  if (value instanceof cbor.Tag) {
    const tagContent = ednStringify(value.contents, indent, depth);
    return `${value.tag}(${tagContent})`;
  }

  // Check for CBOR simple value
  if (value && typeof value === 'object' && value.type === 'simple') {
    return `simple(${value.value})`;
  }

  if (value instanceof Map) {
    if (value.size === 0) {
      return '{}';
    }
    const entries = [];
    for (const [k, v] of value) {
      const keyStr = ednStringify(k, indent, depth + 1);
      const valStr = ednStringify(v, indent, depth + 1);
      entries.push(`${pad1}${keyStr}: ${valStr}`);
    }
    return `{\n${entries.join(',\n')}\n${pad}}`;
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return '[]';
    }
    const items = value.map(v => `${pad1}${ednStringify(v, indent, depth + 1)}`);
    return `[\n${items.join(',\n')}\n${pad}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) {
      return '{}';
    }
    const entries = keys.map(k => {
      const valStr = ednStringify(value[k], indent, depth + 1);
      return `${pad1}"${k}": ${valStr}`;
    });
    return `{\n${entries.join(',\n')}\n${pad}}`;
  }

  return String(value);
}

/**
 * Format a Map to EDN, optionally with CWT claim comments at top level
 */
function formatMapWithComments(map, depth, addComments = false) {
  if (!(map instanceof Map) || map.size === 0) {
    return '{}';
  }
  
  const pad = '  '.repeat(depth);
  const pad1 = '  '.repeat(depth + 1);
  const entries = [];
  
  for (const [key, value] of map) {
    let comment = '';
    
    // Check for redaction tag first (works at any level)
    const redaction = getRedactionComment(key);
    if (redaction.isRedacted) {
      comment = redaction.comment;
    } else if (addComments && typeof key === 'number') {
      // Only add CWT claim comments at the top level
      comment = getClaimComment(key);
    }
    
    const keyStr = formatValueWithComments(key, depth + 1);
    const valStr = formatValueWithComments(value, depth + 1);
    entries.push(`${pad1}${comment}${keyStr}: ${valStr}`);
  }
  
  return `{\n${entries.join(',\n')}\n${pad}}`;
}

/**
 * Stringify a value to EDN (internal helper for formatClaims)
 */
function formatValueWithComments(value, depth) {
  const pad = '  '.repeat(depth);
  const pad1 = '  '.repeat(depth + 1);

  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return JSON.stringify(value);

  if (value instanceof Uint8Array || (Buffer && Buffer.isBuffer && Buffer.isBuffer(value))) {
    const hex = Hex.encode(value);
    if (hex.length <= 64) {
      return `h'${hex}'`;
    }
    const lines = [];
    for (let i = 0; i < hex.length; i += 64) {
      lines.push(hex.slice(i, i + 64));
    }
    return `h'${lines.join('\n' + pad1)}'`;
  }

  if (value instanceof cbor.Tag) {
    // Tag 60 is RedactedClaimElement - display as null per spec
    // (undisclosed array elements should be null to preserve indices)
    if (value.tag === 60) {
      return 'null';
    }
    const tagContent = formatValueWithComments(value.contents, depth);
    return `${value.tag}(${tagContent})`;
  }

  if (value && typeof value === 'object' && value.type === 'simple') {
    return `simple(${value.value})`;
  }

  if (value instanceof Map) {
    // Nested maps don't get comments
    return formatMapWithComments(value, depth, false);
  }

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    const items = value.map(v => `${pad1}${formatValueWithComments(v, depth + 1)}`);
    return `[\n${items.join(',\n')}\n${pad}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return '{}';
    const entries = keys.map(k => {
      const valStr = formatValueWithComments(value[k], depth + 1);
      return `${pad1}"${k}": ${valStr}`;
    });
    return `{\n${entries.join(',\n')}\n${pad}}`;
  }

  return String(value);
}

/**
 * Parse an EDN string into JavaScript values
 * @param {string} ednString 
 * @returns {any}
 */
function parseEdn(ednString) {
  let pos = 0;
  const src = ednString;
  
  function skipWhitespace() {
    while (pos < src.length) {
      const ch = src[pos];
      if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
        pos++;
      } else {
        break;
      }
    }
  }
  
  function skipComment() {
    // Skip comments like "/ name /" - must end with " /"
    if (pos < src.length && src[pos] === '/') {
      pos++; // skip initial /
      // Find the closing " /"
      while (pos < src.length) {
        if (src[pos] === '/' && pos > 0 && src[pos - 1] === ' ') {
          pos++; // skip closing /
          break;
        }
        pos++;
      }
      return true;
    }
    return false;
  }
  
  function skipWhitespaceAndComments() {
    while (pos < src.length) {
      skipWhitespace();
      if (pos < src.length && src[pos] === '/') {
        skipComment();
      } else {
        break;
      }
    }
  }
  
  function parseValue() {
    skipWhitespaceAndComments();
    if (pos >= src.length) throw new Error('Unexpected end of input');
    
    const ch = src[pos];
    
    // String
    if (ch === '"') {
      return parseString();
    }
    
    // Map
    if (ch === '{') {
      return parseMap();
    }
    
    // Array
    if (ch === '[') {
      return parseArray();
    }
    
    // Tag (e.g., 58("value")) or number
    if (/\d/.test(ch)) {
      return parseNumberOrTag();
    }
    
    // Boolean or keyword
    if (/[a-z]/.test(ch)) {
      return parseKeywordOrHex();
    }
    
    // Negative number
    if (ch === '-') {
      return parseNumber();
    }
    
    throw new Error(`Unexpected character '${ch}' at position ${pos}`);
  }
  
  function parseString() {
    pos++; // skip opening quote
    let result = '';
    while (pos < src.length && src[pos] !== '"') {
      if (src[pos] === '\\') {
        pos++;
        if (pos >= src.length) throw new Error('Unterminated string');
        const escape = src[pos];
        if (escape === 'n') result += '\n';
        else if (escape === 't') result += '\t';
        else if (escape === 'r') result += '\r';
        else if (escape === '"') result += '"';
        else if (escape === '\\') result += '\\';
        else result += escape;
      } else {
        result += src[pos];
      }
      pos++;
    }
    if (pos >= src.length) throw new Error('Unterminated string');
    pos++; // skip closing quote
    return result;
  }
  
  function parseNumber() {
    const start = pos;
    if (src[pos] === '-') pos++;
    // Parse digits before decimal
    while (pos < src.length && /\d/.test(src[pos])) pos++;
    // Check for decimal part
    if (pos < src.length && src[pos] === '.') {
      pos++; // skip decimal point
      while (pos < src.length && /\d/.test(src[pos])) pos++;
    }
    const numStr = src.slice(start, pos);
    return numStr.includes('.') ? parseFloat(numStr) : parseInt(numStr, 10);
  }
  
  function parseNumberOrTag() {
    const start = pos;
    // Parse integer part
    while (pos < src.length && /\d/.test(src[pos])) pos++;
    
    // Check for decimal part (before checking for tag)
    let hasDecimal = false;
    if (pos < src.length && src[pos] === '.') {
      // Look ahead to see if this is a decimal number
      if (pos + 1 < src.length && /\d/.test(src[pos + 1])) {
        hasDecimal = true;
        pos++; // skip decimal point
        while (pos < src.length && /\d/.test(src[pos])) pos++;
      }
    }
    
    const numStr = src.slice(start, pos);
    
    // If it's a decimal number, return it now
    if (hasDecimal) {
      return parseFloat(numStr);
    }
    
    skipWhitespaceAndComments();
    
    // Check if this is a tag (number followed by parenthesis)
    if (pos < src.length && src[pos] === '(') {
      pos++; // skip (
      const tagNumber = parseInt(numStr, 10);
      const content = parseValue();
      skipWhitespaceAndComments();
      if (src[pos] !== ')') throw new Error('Expected ) after tag content');
      pos++; // skip )
      return new cbor.Tag(tagNumber, content);
    }
    
    // Just an integer
    return parseInt(numStr, 10);
  }
  
  function parseKeywordOrHex() {
    // Check for h'...' hex bytes
    if (src[pos] === 'h' && pos + 1 < src.length && src[pos + 1] === "'") {
      return parseHexBytes();
    }
    
    // Check for simple(...) 
    if (src.slice(pos, pos + 7) === 'simple(') {
      return parseSimple();
    }
    
    // Regular keyword (true, false, null)
    const start = pos;
    while (pos < src.length && /[a-z_]/.test(src[pos])) pos++;
    const keyword = src.slice(start, pos);
    if (keyword === 'true') return true;
    if (keyword === 'false') return false;
    if (keyword === 'null') return null;
    throw new Error(`Unknown keyword: ${keyword}`);
  }
  
  function parseHexBytes() {
    pos += 2; // skip h'
    const start = pos;
    while (pos < src.length && src[pos] !== "'") pos++;
    const hexStr = src.slice(start, pos).replace(/\s/g, ''); // Remove whitespace in hex
    pos++; // skip closing '
    return Hex.decode(hexStr);
  }
  
  function parseSimple() {
    pos += 7; // skip "simple("
    skipWhitespaceAndComments();
    const valueStr = [];
    while (pos < src.length && /\d/.test(src[pos])) {
      valueStr.push(src[pos]);
      pos++;
    }
    skipWhitespaceAndComments();
    if (src[pos] !== ')') throw new Error('Expected ) after simple value');
    pos++; // skip )
    return { type: 'simple', value: parseInt(valueStr.join(''), 10) };
  }
  
  function parseMap() {
    pos++; // skip {
    const result = new Map();
    
    while (true) {
      skipWhitespaceAndComments();
      if (pos >= src.length) throw new Error('Unterminated map');
      if (src[pos] === '}') {
        pos++;
        break;
      }
      
      const key = parseValue();
      
      skipWhitespaceAndComments();
      if (src[pos] !== ':') throw new Error(`Expected ':' after map key at position ${pos}, got '${src[pos]}'`);
      pos++; // skip :
      
      const value = parseValue();
      result.set(key, value);
      
      skipWhitespaceAndComments();
      if (src[pos] === ',') pos++;
    }
    
    return result;
  }
  
  function parseArray() {
    pos++; // skip [
    const result = [];
    
    while (true) {
      skipWhitespaceAndComments();
      if (pos >= src.length) throw new Error('Unterminated array');
      if (src[pos] === ']') {
        pos++;
        break;
      }
      
      result.push(parseValue());
      
      skipWhitespaceAndComments();
      if (src[pos] === ',') pos++;
    }
    
    return result;
  }
  
  return parseValue();
}

export { cbor };

