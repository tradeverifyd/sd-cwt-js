# Verification security review — 18 November 2026

Scope: `Verifier.verify`, COSE Sign1 processing, disclosure reconstruction, and
AEAD processing. Base revision: `55b32be`; this branch also carries the preceding
interop regression work. This is a focused source review with signed reproductions,
not an independent audit or a complete security/conformance guarantee.

## Confirmed findings and fixes

| Finding | Impact and prerequisite | Change |
|---|---|---|
| No validity-window enforcement | High: a holder could successfully present an expired or not-yet-valid credential, or a KBT outside its credential's validity. | Validate finite numeric dates, expiry/not-before/future issuance, internal ordering, and KBT/credential bounds, using the system clock by default. |
| Disclosed audience bypass | High when an issuer restricts audience using a disclosed claim: the redacted payload was checked before the audience was reconstructed. | Revalidate authenticated reconstructed claims, including the issuer audience. |
| Claim overwrite and duplicate consumption | Medium, malformed/ambiguous issued-claim prerequisite: reconstruction could overwrite a public map key, deduplicate repeated disclosures silently, or consume one disclosure at multiple locations. | Reject semantic map-key collisions, duplicate hashes, repeated consumption and wrong map/array shapes. Unmatched decoys now fail like other unmatched disclosures. |
| Ignored critical headers and header conflicts | Medium: unsupported extension semantics could be ignored. | Reject unsupported `crit`, unprotected `crit`, overlapping protected/unprotected labels, and incorrect COSE tags/field types. Only understood critical algorithm semantics are accepted. Enforce credential type and the supported signed disclosure hash. |

AEAD duplicate-plaintext checks from the earlier interop work remain included.
The signed positive control passed before and after this review. Before these
fixes, all 13 initial security rejection cases failed: the verifier accepted the
adversarial inputs. `tests/security-review.test.js` now also covers explicit
clock skew, expected nonces, understood critical parameters, unmatched decoys,
and one disclosure referenced at multiple locations.

References: [RFC 8392 claim semantics](https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1),
[COSE header processing](https://www.rfc-editor.org/rfc/rfc9052.html#section-3), and
the checked draft-08 verifier procedure. Tests distinguish validly signed invalid
claims from an ordinary signature failure.

## API and fixture changes

`Verifier.verify` accepts `now` (epoch seconds; system clock by default) and
`leeway` (finite nonnegative seconds, default zero). A supplied `now` must come
from a trusted application clock, never from untrusted token claims. Existing
`expectedNonce` validation remains available; profiles must enforce replay state.
`Holder.present` accepts `issuedAt` for controlled clocks and reproducible vectors.

Historical tests supply an explicit clock rather than disabling validation.
AEAD fixture generators use epoch 1725244300 inside the original issuer validity
window. The two-key fixture's KBT was re-signed with public Appendix C keys;
issuer signatures and ciphertext are unchanged. Tests in `fixture-clock.js` are
fixture utilities, not production verification examples.

`verifyWithoutKeyBinding` remains a deliberately deprecated, signature-only
compatibility/test API, not an authentication substitute. SHA-256 remains the
supported high-level disclosure hash; unsupported or mismatched hash selection
fails closed instead of silently diverging from the signed header.

## Validation and residual scope

- Full suite: **541/541 passed on Node 20, Node 24, and Node 26**.
- The five Node 26 failures were isolated to legacy `cbor`'s synchronous
  pipe-to-NoFilter encoder in the development-only `cose-js` oracle. The test-only
  `cose-js-compat.js` helper collects that encoder's output chunks directly when
  a fixed-byte probe detects truncation. It retains the independent encoder and
  cryptographic implementation, does not translate wire formats, and does not
  skip tests. Fixed-byte and large-payload regressions cover the collector.
- `npm run build` succeeded.
- Cross-implementation profile runner: **316/316 passed** with explicit historical
  clocks; Rust participates in the cases supported by its existing adapter.
- `npm audit --omit=dev`: **zero reported production advisories** at review time.
- PR CI now runs the complete test suite and build on Node 20/24/26.
- Updated esbuild and the transitive bn.js development dependency. The full npm
  audit retains two low-severity findings for elliptic/cose-js (one underlying
  advisory); no fixed elliptic version is available in the audit. Do not downgrade
  the independent oracle to an obsolete COSE implementation merely to clear it.
- Added a signed regression requiring KBT `iat < credential exp` even with leeway.
- Expanded Rust interop covers nested/array Holder production, 32/48/64-byte
  contexts, and AES-256. It exposes a real non-default algorithm gap: Rust
  reads/writes header 172 in unprotected headers. Our protected-header and
  duplicate-header checks remain enforced.

Advisory matching does not prove dependency security. This review does not establish
exhaustive fuzzing coverage, resistance to all input/resource exhaustion, complete
algorithm coverage, or stateful replay prevention. Applications must enforce
trusted-issuer policy, required claims, revocation, maximum lifetime where needed,
nonce/cti replay state, and input/resource limits. A required critical claim cannot
be left undisclosed. Alternative hashes, complete claims-in-header profiles, and
Rust's protected/unprotected header-172 difference remain separate interop work.

## Spec-first follow-up

The accepted credential media type is `application/sd-cwt`, not
`application/sd+cwt`. Signed positive controls cover content-format 293, the
registered media type, and an application subtype with `+sd-cwt`; negative
controls cover the incorrect spelling and malformed types. KBT protected
header 15 (CWT Claims) is rejected as required by the current draft.

Expanded encrypted-profile evidence: **511 passed, 20 failed, 8 blocked out of
539 checks**. Every failure involves Rust AES-256/header-172 handling; blocked
negative cases have a failed positive control and do not count as demonstrated
rejections. The 261-case suite reports 259 passes and two Rust failures (header
placement and protected AES-256 selection). The original 54 default-algorithm
cross-pair assertions pass. Counts overlap and must not be added.

These results do not establish full specification conformance or maximal
interoperability. Remaining coverage includes complete issuance/Holder validation,
all permitted signature/hash and confirmation-method profiles, claims split
between payload and protected header 15, full map-key/nesting rules, and stateful
replay/revocation. Default AES-128 interoperability does not make Rust's header
placement conformant. No fallback reads an algorithm from unprotected header 172
or suppresses a duplicate-header error to increase the passing count.
