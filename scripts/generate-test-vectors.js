/**
 * Generate JSON Test Vectors for SD-CWT
 * 
 * Generates test vectors for multiple key and algorithm combinations:
 * - ES256 (P-256)
 * - ES384 (P-384)
 * - ES512 (P-521)
 * 
 * Each test vector includes:
 * - Issuer and Holder key pairs (COSE Key format, hex-encoded)
 * - Claims with redactable fields
 * - Issued SD-CWT token (hex)
 * - Disclosures (hex)
 * - Presentation (SD-KBT, hex)
 * - Verified claims
 * 
 * Output: docs/test-vectors.json
 */

import * as cbor from 'cbor2';
import {
  Issuer,
  Holder,
  Verifier,
  generateKeyPair,
  Algorithm,
  toBeRedacted,
  toBeDecoy,
  ClaimKey,
  coseKeyToHex,
} from '../src/api.js';

// Helper to encode bytes to hex
function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper to create a cnf claim with a holder's public key
function createCnfClaim(holderPublicKey) {
  return new Map([
    [1, holderPublicKey], // 1 = COSE_Key
  ]);
}

// Sample claims for test vectors - demonstrates SD-CWT features
function createTestClaims(holderPublicKey, scenario) {
  const baseTime = 1725244200; // Fixed timestamp for reproducibility
  
  switch (scenario) {
    case 'simple':
      // Simple case: single redactable claim
      return new Map([
        [ClaimKey.Iss, 'https://issuer.example'],
        [ClaimKey.Sub, 'https://subject.example'],
        [ClaimKey.Iat, baseTime],
        [ClaimKey.Exp, baseTime + 86400], // +1 day
        [ClaimKey.Cnf, createCnfClaim(holderPublicKey)],
        [toBeRedacted(500), 'sensitive-license-number'],
        [501, true], // public claim
      ]);
      
    case 'nested':
      // Nested redactions in maps
      return new Map([
        [ClaimKey.Iss, 'https://issuer.example'],
        [ClaimKey.Iat, baseTime],
        [ClaimKey.Cnf, createCnfClaim(holderPublicKey)],
        [503, new Map([
          ['country', 'us'],
          [toBeRedacted('region'), 'ca'],
          [toBeRedacted('postal_code'), '94188'],
        ])],
        [toBeRedacted(501), 'INSPECTOR-12345'],
      ]);
      
    case 'array':
      // Array element redactions
      return new Map([
        [ClaimKey.Iss, 'https://issuer.example'],
        [ClaimKey.Iat, baseTime],
        [ClaimKey.Cnf, createCnfClaim(holderPublicKey)],
        [502, [
          toBeRedacted(1549560720), // redacted date
          toBeRedacted(1612560720), // redacted date
          1674004740, // public date
        ]],
        [500, true],
      ]);
      
    case 'decoy':
      // With decoys for privacy
      return new Map([
        [ClaimKey.Iss, 'https://issuer.example'],
        [ClaimKey.Iat, baseTime],
        [ClaimKey.Cnf, createCnfClaim(holderPublicKey)],
        [toBeRedacted(500), 'secret-value'],
        [501, 'public-value'],
        [toBeDecoy(2), null], // 2 decoys
      ]);
      
    default:
      throw new Error(`Unknown scenario: ${scenario}`);
  }
}

async function generateTestVector(algorithm, scenario) {
  console.log(`  Generating ${algorithm}/${scenario}...`);
  
  // Generate key pairs
  const issuerKeyPair = generateKeyPair(algorithm);
  const holderKeyPair = generateKeyPair(algorithm);
  
  // Create claims
  const claims = createTestClaims(holderKeyPair.publicKey, scenario);
  
  // Issue SD-CWT
  const { token, disclosures } = await Issuer.issue({
    claims,
    privateKey: issuerKeyPair.privateKey,
    algorithm,
  });
  
  // Create presentation with all disclosures
  const audience = 'https://verifier.example';
  const presentation = await Holder.present({
    token,
    selectedDisclosures: disclosures,
    holderPrivateKey: holderKeyPair.privateKey,
    audience,
    algorithm,
  });
  
  // Verify presentation
  const result = await Verifier.verify({
    presentation,
    issuerPublicKey: issuerKeyPair.publicKey,
    expectedAudience: audience,
  });
  
  // Build partial presentation (disclose only first disclosure if any)
  let partialPresentation = null;
  let partialClaims = null;
  if (disclosures.length > 0) {
    const partialDisclosures = [disclosures[0]];
    partialPresentation = await Holder.present({
      token,
      selectedDisclosures: partialDisclosures,
      holderPrivateKey: holderKeyPair.privateKey,
      audience,
      algorithm,
    });
    
    const partialResult = await Verifier.verify({
      presentation: partialPresentation,
      issuerPublicKey: issuerKeyPair.publicKey,
      expectedAudience: audience,
    });
    
    partialClaims = mapToJson(partialResult.claims);
  }
  
  // Serialize claims to JSON-compatible format
  const verifiedClaims = mapToJson(result.claims);
  
  return {
    algorithm,
    scenario,
    description: getScenarioDescription(scenario),
    keys: {
      issuer: {
        privateKey: coseKeyToHex(issuerKeyPair.privateKey),
        publicKey: coseKeyToHex(issuerKeyPair.publicKey),
      },
      holder: {
        privateKey: coseKeyToHex(holderKeyPair.privateKey),
        publicKey: coseKeyToHex(holderKeyPair.publicKey),
      },
    },
    audience,
    token: toHex(token),
    disclosures: disclosures.map(d => ({
      cbor_hex: toHex(d),
      decoded: decodeDisclosure(d),
    })),
    presentation: {
      full: toHex(presentation),
      partial: partialPresentation ? toHex(partialPresentation) : null,
    },
    verified_claims: {
      full: verifiedClaims,
      partial: partialClaims,
    },
  };
}

function getScenarioDescription(scenario) {
  const descriptions = {
    simple: 'Simple SD-CWT with single redactable claim',
    nested: 'SD-CWT with nested map redactions',
    array: 'SD-CWT with redactable array elements',
    decoy: 'SD-CWT with decoy entries for privacy',
  };
  return descriptions[scenario] || scenario;
}

// Convert Map to JSON-compatible object
function mapToJson(map) {
  if (!(map instanceof Map)) {
    if (Array.isArray(map)) {
      return map.map(mapToJson);
    }
    if (map instanceof Uint8Array) {
      return { _type: 'bytes', hex: toHex(map) };
    }
    if (typeof map === 'object' && map !== null) {
      const result = {};
      for (const [k, v] of Object.entries(map)) {
        result[k] = mapToJson(v);
      }
      return result;
    }
    return map;
  }
  
  const result = {};
  for (const [key, value] of map) {
    const keyStr = typeof key === 'number' ? String(key) : key;
    result[keyStr] = mapToJson(value);
  }
  return result;
}

// Decode disclosure for display
function decodeDisclosure(disclosure) {
  const decoded = cbor.decode(disclosure, { preferMap: true });
  
  if (decoded.length === 1) {
    // Decoy
    return { type: 'decoy', salt: toHex(decoded[0]) };
  } else if (decoded.length === 2) {
    // Array element
    return {
      type: 'array_element',
      salt: toHex(decoded[0]),
      value: mapToJson(decoded[1]),
    };
  } else if (decoded.length === 3) {
    // Named claim
    return {
      type: 'claim',
      salt: toHex(decoded[0]),
      value: mapToJson(decoded[1]),
      claim_key: decoded[2],
    };
  }
  return { type: 'unknown' };
}

async function main() {
  console.log('Generating SD-CWT Test Vectors...\n');
  
  const algorithms = [Algorithm.ES256, Algorithm.ES384, Algorithm.ES512];
  const scenarios = ['simple', 'nested', 'array', 'decoy'];
  
  const testVectors = {
    metadata: {
      generator: 'sd-cwt-js',
      version: '1.0.0',
      generated_at: new Date().toISOString(),
      specification: 'draft-ietf-spice-sd-cwt',
      description: 'Test vectors for SD-CWT (Selective Disclosure CBOR Web Token)',
    },
    vectors: [],
  };
  
  for (const algorithm of algorithms) {
    console.log(`\nGenerating vectors for ${algorithm}:`);
    for (const scenario of scenarios) {
      const vector = await generateTestVector(algorithm, scenario);
      testVectors.vectors.push(vector);
    }
  }
  
  // Write to file
  const outputPath = new URL('../docs/test-vectors.json', import.meta.url);
  const fs = await import('fs');
  fs.writeFileSync(outputPath, JSON.stringify(testVectors, null, 2));
  
  console.log(`\n✓ Generated ${testVectors.vectors.length} test vectors`);
  console.log(`✓ Saved to docs/test-vectors.json`);
}

main().catch(err => {
  console.error('Error generating test vectors:', err);
  process.exit(1);
});
