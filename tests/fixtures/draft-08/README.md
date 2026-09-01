# Canonical SD-CWT examples from the Internet-Draft

Copied verbatim from `examples/` in
[ietf-wg-spice/draft-ietf-spice-sd-cwt](https://github.com/ietf-wg-spice/draft-ietf-spice-sd-cwt)
at `draft-ietf-spice-sd-cwt-08`.

| File | What it is |
|---|---|
| `issuer_cwt.cbor` | Issued SD-CWT, ES384 issuer key, five disclosures in `sd_claims` |
| `kbt.cbor` | SD-KBT presentation, ES256 holder key, three disclosures selected |

The signing keys are in Appendix C of the draft: the Holder key is P-256, the
Issuer key is P-384.

These bytes are the interoperability contract. A test that only round-trips
this library against itself will pass even when the library and the draft
disagree, so any change to hashing, header encoding, or signature construction
must be checked against these files.

## Keys

The signing keys are Appendix C of the draft: Holder P-256, Issuer P-384. They
are published sample keys with no value. Never use them for anything real.
