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

// Re-export EDN utilities
export { Hex, EDN, cbor as ednCbor } from './edn.js';

/**
 * Format claims with named keys for display (convenience re-export)
 * @param {Map} claims 
 * @returns {string}
 */
import { EDN as EdnUtils } from './edn.js';
export function formatClaims(claims) {
  return EdnUtils.formatClaims(claims);
}
