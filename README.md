# SD-CWT

A JavaScript implementation of [Selective Disclosure CBOR Web Tokens (SD-CWT)](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/).

SD-CWT enables issuers to create tokens with claims that can be selectively disclosed by holders to verifiers, protecting privacy while maintaining cryptographic integrity.

## Installation

```bash
git clone https://github.com/tradeverifyd/sd-cwt-js.git
cd sd-cwt-js
npm install
```

## Quick Start

### Run Tests

```bash
npm test
```

### Launch Interactive Sandbox

```bash
npm run playground
```

Then open http://localhost:3000 in your browser.

## Usage

### Facility Inspection Example

This example demonstrates a facility inspection credential with:
- Redacted inspector license number
- Partially redacted inspection dates (some public, some redactable)
- Nested location data with redacted region and postal code
- Decoy digests to hide the number of redacted claims

```javascript
import { 
  Issuer, 
  Holder, 
  Verifier, 
  generateKeyPair,
  ClaimKey
} from 'sd-cwt';
import { toBeRedacted, toBeDecoy } from 'sd-cwt/sd-cwt';

// Generate key pairs
const holderKeyPair = generateKeyPair();
const issuerKeyPair = generateKeyPair();

// Create holder's confirmation claim
const cnf = new Map([[1, holderKeyPair.publicKey]]);

// Define claims with selective disclosure markers
const claims = new Map([
  [1, 'https://issuer.example'],           // iss
  [2, 'https://device.example'],           // sub
  [4, 1725330600],                         // exp
  [5, 1725243900],                         // nbf
  [6, 1725244200],                         // iat
  [ClaimKey.Cnf, cnf],                     // cnf (holder's public key)
  [500, true],                             // most_recent_inspection_passed
  [toBeRedacted(501), 'ABCD-123456'],      // inspector_license_number (redactable)
  [502, [                                  // inspection_dates array
    toBeRedacted(1549560720),              //   date 1 (redactable)
    toBeRedacted(1612560720),              //   date 2 (redactable)
    1674004740                             //   date 3 (always visible)
  ]],
  [503, new Map([                          // inspection_location
    ['country', 'us'],                     //   country (always visible)
    [toBeRedacted('region'), 'ca'],        //   region (redactable)
    [toBeRedacted('postal_code'), '94188'],//   postal_code (redactable)
    [toBeDecoy(1), null]                   //   decoy entry
  ])],
  [toBeDecoy(1), null]                     // top-level decoy entry
]);

// Step 1: Issuer creates the SD-CWT
const { token, disclosures } = await Issuer.issue({
  claims,
  privateKey: issuerKeyPair.privateKey,
});

console.log('Issued token:', token);
console.log('Available disclosures:', disclosures.length);

// Step 2: Holder creates a presentation with selected disclosures
// (e.g., only reveal region, keep postal_code hidden)
const selectedDisclosures = disclosures.filter(d => {
  // Filter logic based on disclosure content
  return true; // or selectively include specific disclosures
});

const presentation = await Holder.present({
  token,
  selectedDisclosures,
  holderPrivateKey: holderKeyPair.privateKey,
  audience: 'https://verifier.example',
  nonce: 'unique-request-nonce',
});

// Step 3: Verifier validates the presentation
const result = await Verifier.verify({
  presentation,
  issuerPublicKey: issuerKeyPair.publicKey,
  expectedAudience: 'https://verifier.example',
  expectedNonce: 'unique-request-nonce',
});

console.log('Verified:', result.verified);
console.log('Claims:', result.claims);
```

## API Reference

### `generateKeyPair(algorithm?)`

Generates a COSE key pair for signing operations.

- **algorithm**: `'ES256'` (default), `'ES384'`, or `'ES512'`
- **Returns**: `{ privateKey: Map, publicKey: Map }` - COSE Key Maps with algorithm and thumbprint

### `Issuer.issue(options)`

Creates a signed SD-CWT from claims.

- **options.claims**: `Map` - Claims including `toBeRedacted()` and `toBeDecoy()` markers
- **options.privateKey**: `Map` - Issuer's private COSE Key
- **options.algorithm**: `string` - Signing algorithm (optional, auto-detected from key)
- **Returns**: `{ token: Uint8Array, disclosures: Array }`

### `Holder.present(options)`

Creates a presentation with selected disclosures.

- **options.token**: `Uint8Array` - The issued SD-CWT
- **options.selectedDisclosures**: `Array` - Disclosures to reveal
- **options.holderPrivateKey**: `Map` - Holder's private COSE Key
- **options.audience**: `string` - Intended verifier
- **options.nonce**: `string` - Optional replay protection
- **Returns**: `Uint8Array` - The presentation token

### `Verifier.verify(options)`

Verifies a presentation and extracts disclosed claims.

- **options.presentation**: `Uint8Array` - The presentation token
- **options.issuerPublicKey**: `Map` - Issuer's public COSE Key
- **options.expectedAudience**: `string` - Expected audience claim
- **options.expectedNonce**: `string` - Expected nonce (optional)
- **Returns**: `{ verified: boolean, claims: Map }`

### Claim Markers

- **`toBeRedacted(key)`**: Marks a claim key or array element as redactable
- **`toBeDecoy(count)`**: Adds decoy digests to hide redaction count (per §10 of spec)

## Browser Usage

Build the browser bundle:

```bash
npm run build
```

Include in your HTML:

```html
<script src="docs/js/sd-cwt.js"></script>
<script>
  const { Issuer, Holder, Verifier, generateKeyPair } = SDCWT;
  // ... use the API
</script>
```

## Project Structure

```
sd-cwt-js/
├── src/           # Source modules
│   ├── api.js     # High-level Issuer/Holder/Verifier API
│   ├── sd-cwt.js  # Core SD-CWT implementation
│   └── cose-sign1.js  # COSE signing operations
├── tests/         # Test suites
├── docs/          # Interactive sandbox
└── scripts/       # Build scripts
```

## Specification

This implementation follows [draft-ietf-spice-sd-cwt](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/).

## License

Apache-2.0

