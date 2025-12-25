/**
 * Tests for example templates used in the SD-CWT Sandbox
 * 
 * These tests verify the full issue → present → verify flow for each example:
 * - Facility Inspection (spec example)
 * - Multimodal Bill of Lading (MBL)
 * - Commercial Invoice
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { 
  Issuer, 
  Holder, 
  Verifier, 
  generateKeyPair,
  ClaimKey
} from '../src/api.js';
import { toBeRedacted, toBeDecoy } from '../src/sd-cwt.js';

// Helper to create cnf claim from public key (COSE Key Map)
function createCnfClaim(publicKey) {
  return new Map([
    [1, publicKey],  // 1 = COSE_Key
  ]);
}

describe('Example Templates', () => {
  describe('Facility Inspection Example', () => {
    // Tests nested arrays with redacted elements, redacted map keys, and decoys
    
    it('should issue, present, and verify with all disclosures', async () => {
      const holderKeyPair = generateKeyPair();
      const issuerKeyPair = generateKeyPair();
      
      const claims = new Map([
        [1, 'https://issuer.example'],
        [2, 'https://device.example'],
        [4, 1725330600],
        [5, 1725243900],
        [6, 1725244200],
        [ClaimKey.Cnf, createCnfClaim(holderKeyPair.publicKey)],
        [500, true],  // most_recent_inspection_passed
        [toBeRedacted(501), 'ABCD-123456'],  // inspector_license_number
        [502, [
          toBeRedacted(1549560720),  // date 7-Feb-2019
          toBeRedacted(1612560720),  // date 4-Feb-2021
          1674004740  // date 17-Jan-2023 (public)
        ]],
        [503, new Map([
          ['country', 'us'],
          [toBeRedacted('region'), 'ca'],
          [toBeRedacted('postal_code'), '94188'],
          [toBeDecoy(1), null]
        ])],
        [toBeDecoy(1), null]
      ]);

      // Issue
      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKeyPair.privateKey,
      });

      assert.ok(token instanceof Uint8Array);
      assert.ok(disclosures.length >= 4, `Should have at least 4 disclosures, got ${disclosures.length}`);

      // Present with all disclosures
      const presentation = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: holderKeyPair.privateKey,
        audience: 'https://verifier.example',
      });

      assert.ok(presentation instanceof Uint8Array);

      // Verify - throws on failure
      const result = await Verifier.verify({
        presentation,
        issuerPublicKey: issuerKeyPair.publicKey,
        expectedAudience: 'https://verifier.example'
      });

      // Check claims are returned
      assert.ok(result.claims instanceof Map);
      assert.strictEqual(result.claims.get(500), true);
      assert.strictEqual(result.claims.get(501), 'ABCD-123456');
      assert.ok(result.claims.get(502) instanceof Array);
    });

    it('should verify with partial disclosures', async () => {
      const holderKeyPair = generateKeyPair();
      const issuerKeyPair = generateKeyPair();
      
      const claims = new Map([
        [1, 'https://issuer.example'],
        [2, 'https://device.example'],
        [6, Math.floor(Date.now() / 1000)],
        [ClaimKey.Cnf, createCnfClaim(holderKeyPair.publicKey)],
        [500, true],
        [toBeRedacted(501), 'ABCD-123456'],
        [toBeRedacted(502), 'SECRET-DATA']
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKeyPair.privateKey,
      });

      // Present with only first disclosure
      const presentation = await Holder.present({
        token,
        selectedDisclosures: [disclosures[0]],
        holderPrivateKey: holderKeyPair.privateKey,
        audience: 'https://verifier.example',
      });

      const result = await Verifier.verify({
        presentation,
        issuerPublicKey: issuerKeyPair.publicKey,
        expectedAudience: 'https://verifier.example'
      });

      assert.ok(result.claims instanceof Map);
      // One claim disclosed, one redacted
      const disclosedCount = [result.claims.get(501), result.claims.get(502)]
        .filter(v => v !== undefined).length;
      assert.strictEqual(disclosedCount, 1);
    });
  });

  describe('Multimodal Bill of Lading (MBL) Example', () => {
    // Tests nested objects in arrays, complex structure
    
    it('should issue with nested transport modes and cargo arrays', async () => {
      const holderKeyPair = generateKeyPair();
      const issuerKeyPair = generateKeyPair();
      
      const claims = new Map([
        [1, 'https://carrier.example'],
        [2, 'https://consignee.example'],
        [4, 1756857600],
        [6, 1725244200],
        [ClaimKey.Cnf, createCnfClaim(holderKeyPair.publicKey)],
        [600, 'MBLX-2024-78542'],  // bl_number
        [toBeRedacted(601), {  // shipper (redacted)
          name: 'Acme Exports Ltd',
          address: '123 Trade St, Singapore'
        }],
        [602, [  // transport_modes with nested redactions
          new Map([
            ['mode', 'sea'],
            [toBeRedacted('vessel'), 'MV Pacific Star'],
            ['port_load', 'SGSIN'],
            ['port_discharge', 'USNYC']
          ]),
          new Map([
            ['mode', 'rail'],
            [toBeRedacted('carrier'), 'BNSF-4521']
          ])
        ]],
        [603, [  // cargo array with redacted elements
          toBeRedacted({
            description: 'Electronic Components',
            weight_kg: 2500,
            container: 'MSCU-1234567'
          }),
          toBeRedacted({
            description: 'Machine Parts',
            weight_kg: 1800,
            container: 'MSCU-7654321'
          })
        ]],
        [604, 4300],  // total_weight_kg
        [toBeDecoy(2), null]
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKeyPair.privateKey,
      });

      assert.ok(token instanceof Uint8Array);
      // Should have: shipper, vessel, carrier, 2 cargo items = 5+ disclosures
      assert.ok(disclosures.length >= 5, `Expected at least 5 disclosures, got ${disclosures.length}`);

      // Present and verify
      const presentation = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: holderKeyPair.privateKey,
        audience: 'https://verifier.example',
      });

      const result = await Verifier.verify({
        presentation,
        issuerPublicKey: issuerKeyPair.publicKey,
        expectedAudience: 'https://verifier.example'
      });

      assert.ok(result.claims instanceof Map);
      assert.strictEqual(result.claims.get(600), 'MBLX-2024-78542');
      assert.strictEqual(result.claims.get(604), 4300);
    });

    it('should verify with no disclosures (all cargo redacted)', async () => {
      const holderKeyPair = generateKeyPair();
      const issuerKeyPair = generateKeyPair();
      
      const claims = new Map([
        [1, 'https://carrier.example'],
        [2, 'https://consignee.example'],
        [6, Math.floor(Date.now() / 1000)],
        [ClaimKey.Cnf, createCnfClaim(holderKeyPair.publicKey)],
        [600, 'MBLX-2024-78542'],
        [603, [  // cargo array - redacted elements
          toBeRedacted({ description: 'Item A', weight_kg: 100 }),
          toBeRedacted({ description: 'Item B', weight_kg: 200 })
        ]],
        [604, 300]
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKeyPair.privateKey,
      });

      assert.strictEqual(disclosures.length, 2, 'Should have 2 cargo disclosures');

      // Present with NO cargo disclosures - all items stay redacted
      const presentation = await Holder.present({
        token,
        selectedDisclosures: [],
        holderPrivateKey: holderKeyPair.privateKey,
        audience: 'https://verifier.example',
      });

      const result = await Verifier.verify({
        presentation,
        issuerPublicKey: issuerKeyPair.publicKey,
        expectedAudience: 'https://verifier.example'
      });

      assert.ok(result.claims instanceof Map);
      assert.strictEqual(result.claims.get(600), 'MBLX-2024-78542');
      assert.strictEqual(result.claims.get(604), 300);
      // Cargo array should have redacted entries
      const cargo = result.claims.get(603);
      assert.ok(cargo instanceof Array);
      assert.strictEqual(cargo.length, 2);
    });
  });

  describe('Commercial Invoice Example', () => {
    // Tests deeply nested redactions in objects and arrays
    
    it('should issue with nested buyer and line items', async () => {
      const holderKeyPair = generateKeyPair();
      const issuerKeyPair = generateKeyPair();
      
      const claims = new Map([
        [1, 'https://exporter.example'],
        [2, 'https://importer.example'],
        [4, 1756857600],
        [6, 1725244200],
        [ClaimKey.Cnf, createCnfClaim(holderKeyPair.publicKey)],
        [700, 'INV-2024-00892'],  // invoice_number
        [toBeRedacted(701), new Map([  // buyer with nested redaction
          ['company', 'Global Imports Inc'],
          [toBeRedacted('tax_id'), 'US-EIN-12-3456789'],
          ['country', 'US']
        ])],
        [702, [  // line_items with nested price redactions
          new Map([
            ['hs_code', '8471.30'],
            ['description', 'Laptop Computers'],
            ['quantity', 100],
            [toBeRedacted('unit_price'), 850.00],
            [toBeRedacted('line_total'), 85000.00]
          ]),
          new Map([
            ['hs_code', '8471.60'],
            ['description', 'Computer Monitors'],
            ['quantity', 50],
            [toBeRedacted('unit_price'), 320.00],
            [toBeRedacted('line_total'), 16000.00]
          ])
        ]],
        [toBeRedacted(703), 101000.00],  // total_value
        [704, 'USD'],  // currency
        [705, 'CIF'],  // incoterms
        [706, new Map([  // payment_terms
          ['method', 'letter_of_credit'],
          [toBeRedacted('bank'), 'HSBC Hong Kong'],
          [toBeRedacted('lc_number'), 'LC-HK-2024-5567']
        ])],
        [toBeDecoy(1), null]
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKeyPair.privateKey,
      });

      assert.ok(token instanceof Uint8Array);
      // Disclosures: buyer, tax_id, 4 line item prices, total_value, bank, lc_number = 9+
      assert.ok(disclosures.length >= 8, `Expected at least 8 disclosures, got ${disclosures.length}`);

      // Present and verify with all disclosures
      const presentation = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: holderKeyPair.privateKey,
        audience: 'https://verifier.example',
      });

      const result = await Verifier.verify({
        presentation,
        issuerPublicKey: issuerKeyPair.publicKey,
        expectedAudience: 'https://verifier.example'
      });

      assert.ok(result.claims instanceof Map);
      assert.strictEqual(result.claims.get(700), 'INV-2024-00892');
      assert.strictEqual(result.claims.get(704), 'USD');
      assert.strictEqual(result.claims.get(705), 'CIF');
    });

    it('should verify with prices redacted but descriptions visible', async () => {
      const holderKeyPair = generateKeyPair();
      const issuerKeyPair = generateKeyPair();
      
      // Simplified invoice with just line items
      const claims = new Map([
        [1, 'https://exporter.example'],
        [2, 'https://importer.example'],
        [6, Math.floor(Date.now() / 1000)],
        [ClaimKey.Cnf, createCnfClaim(holderKeyPair.publicKey)],
        [700, 'INV-2024-00892'],
        [702, [
          new Map([
            ['description', 'Product A'],
            ['quantity', 10],
            [toBeRedacted('price'), 100.00]
          ])
        ]],
        [toBeRedacted(703), 1000.00],  // total
        [704, 'USD']
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKeyPair.privateKey,
      });

      // Don't disclose prices - present with no disclosures
      const presentation = await Holder.present({
        token,
        selectedDisclosures: [],
        holderPrivateKey: holderKeyPair.privateKey,
        audience: 'https://verifier.example',
      });

      const result = await Verifier.verify({
        presentation,
        issuerPublicKey: issuerKeyPair.publicKey,
        expectedAudience: 'https://verifier.example'
      });

      assert.ok(result.claims instanceof Map);
      assert.strictEqual(result.claims.get(700), 'INV-2024-00892');
      assert.strictEqual(result.claims.get(704), 'USD');
      // Total value should not be disclosed
      assert.strictEqual(result.claims.get(703), undefined);
    });
  });

  describe('Decoy handling across examples', () => {
    it('should handle multiple decoys in different positions', async () => {
      const holderKeyPair = generateKeyPair();
      const issuerKeyPair = generateKeyPair();
      
      const claims = new Map([
        [1, 'https://issuer.example'],
        [6, Math.floor(Date.now() / 1000)],
        [ClaimKey.Cnf, createCnfClaim(holderKeyPair.publicKey)],
        [100, 'public-claim'],
        [toBeRedacted(101), 'redacted-claim'],
        [toBeDecoy(3), null],  // 3 decoys at top level
        [102, new Map([
          ['nested', 'value'],
          [toBeDecoy(2), null]  // 2 decoys in nested map
        ])]
      ]);

      const { token, disclosures } = await Issuer.issue({
        claims,
        privateKey: issuerKeyPair.privateKey,
      });

      assert.ok(token instanceof Uint8Array);
      // 1 actual disclosure (101), decoys don't add to disclosures
      assert.strictEqual(disclosures.length, 1);

      const presentation = await Holder.present({
        token,
        selectedDisclosures: disclosures,
        holderPrivateKey: holderKeyPair.privateKey,
        audience: 'https://verifier.example',
      });

      const result = await Verifier.verify({
        presentation,
        issuerPublicKey: issuerKeyPair.publicKey,
        expectedAudience: 'https://verifier.example'
      });

      assert.ok(result.claims instanceof Map);
      assert.strictEqual(result.claims.get(100), 'public-claim');
      assert.strictEqual(result.claims.get(101), 'redacted-claim');
    });
  });
});
