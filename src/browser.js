/**
 * SD-CWT Browser Entry Point
 * 
 * This module exports all SD-CWT functionality for browser use.
 * Built with esbuild and exposed as window.SDCWT
 */

// Re-export everything from api.js
export * from './api.js';

// Re-export low-level utilities
export * as sdCwt from './sd-cwt.js';
export * as coseSign1 from './cose-sign1.js';

// Re-export cbor2 for encoding/decoding
import * as cbor from 'cbor2';
export { cbor };

// Import Buffer for type checking (will use the shim in browser)
import { Buffer } from './buffer-shim.js';

/**
 * Hex encoding utilities for browser display
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

/**
 * EDN (Extended Diagnostic Notation) utilities for CBOR display
 */
export const EDN = {
  /**
   * Convert a JavaScript value to EDN string
   * @param {any} value 
   * @param {number} indent 
   * @returns {string}
   */
  stringify(value, indent = 0) {
    return ednStringify(value, indent);
  },
};

/**
 * Internal EDN stringifier
 */
function ednStringify(value, indent = 0, depth = 0) {
  const pad = '  '.repeat(depth);
  const pad1 = '  '.repeat(depth + 1);

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

  if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
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

// Known CWT claim names for better EDN output
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
 * Format claims with named keys for display
 * @param {Map} claims 
 * @returns {string}
 */
export function formatClaims(claims) {
  const formatted = new Map();
  for (const [key, value] of claims) {
    const name = CWT_CLAIM_NAMES[key] || key;
    const displayKey = typeof name === 'string' ? `/ ${name} / ${key}` : key;
    formatted.set(displayKey, value);
  }
  return EDN.stringify(formatted);
}

