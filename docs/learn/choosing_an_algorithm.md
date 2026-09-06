# Choosing an Algorithm

SignetDSA implements nine single-key algorithms plus one threshold protocol.
This page is a decision guide; each algorithm's own page has the full theory,
code, and caveats.

## Quick Comparison

| Algorithm | Category | Security basis | Private key | Public key | Signature | Deterministic? |
|---|---|---|---|---|---|---|
| [RSA (PKCS#1 v1.5)](../algorithms/rsa.md) | Classical | Integer factorization | ~1.2 KB (DER) | ~270 B (DER) | 256 B | No (randomized padding) |
| [RSA-PSS (RFC 8017)](../algorithms/rsa_pss.md) | Modern Classical | Integer factorization | ~1.2 KB (DER) | ~270 B (DER) | 256 B | No (random salt) |
| [DSA](../algorithms/dsa.md) | Classical | Discrete log (finite field) | ~440 B (DER) | ~270 B (DER) | ~46–72 B (DER, variable) | No |
| [ECDSA (P-256)](../algorithms/ecdsa.md) | Classical | Discrete log (NIST curve) | 32 B | 33 B (compressed) | 64 B | No |
| [ECDSA (P-384)](../algorithms/ecdsa_p384.md) | Classical | Discrete log (NIST curve, ~192-bit CNSA) | 48 B | 49 B (compressed) | 96 B | **Yes** (RFC 6979) |
| [ECDSA (secp256k1)](../algorithms/ecdsa_secp256k1.md) | Classical | Discrete log (Bitcoin/Ethereum curve) | 32 B | 33 B (compressed) | 64 B | No |
| [EdDSA (Ed25519)](../algorithms/eddsa.md) | Classical | Discrete log (Curve25519) | 32 B | 32 B | 64 B | **Yes** |
| [Ed448](../algorithms/ed448.md) | Classical | Discrete log (Curve448) | 57 B | 57 B | 114 B | **Yes** |
| [Schnorr (BIP340)](../algorithms/schnorr.md) | Classical | Discrete log (secp256k1) | 32 B | 32 B (x-only) | 64 B | **Yes** (fixed `aux_rand`) |
| [FROST](../algorithms/frost.md) | Threshold | Discrete log (secp256k1) | *split across signers* | 32 B (group key) | 64 B (standard Schnorr) | No |
| [BLS](../algorithms/bls.md) | Aggregatable | Pairing (BLS12-381) | 32 B | 48 B (G1, compressed) | 96 B (G2, compressed) | **Yes** |
| [ML-DSA](../algorithms/mldsa.md) | Post-quantum | Module lattices (MLWE) | 4032 B | 1952 B | 3309 B | No |

## By Scenario

**"I need to interoperate with Bitcoin or Ethereum."**
Use [ECDSA (secp256k1)](../algorithms/ecdsa_secp256k1.md) for Ethereum-style
transaction signing (it includes `ecrecover`-style public-key recovery), or
[Schnorr (BIP340)](../algorithms/schnorr.md) for Bitcoin Taproot.

**"I want the smallest, fastest classical signature, with no other constraint."**
[EdDSA (Ed25519)](../algorithms/eddsa.md) — 32-byte keys, 64-byte signatures,
deterministic, and the most battle-tested implementation in this crate
(`ed25519-dalek`). It also has [batch verification](../features/batch_verification.md).

**"I want Ed25519's shape but a larger security margin."**
[Ed448](../algorithms/ed448.md) trades larger keys/signatures (57/114 bytes) for
a ~224-bit security level instead of Ed25519's ~128-bit, at the cost of a
less battle-tested implementation — see its
[known limitations](../security.md#known-limitations).

**"No single party should ever hold the complete private key."**
[FROST](../algorithms/frost.md) — a `t`-of-`n` threshold ceremony that produces
an ordinary Schnorr signature nobody could forge alone. Not reachable through
the `Signet` factory (a multi-round ceremony doesn't fit a single-key
sign/verify shape); call `SignetDSA::algo::frost` directly.

**"I need to compress many signatures into one, or check many at once."**
[BLS](../algorithms/bls.md) aggregation collapses many signatures over many
distinct `(message, public key)` pairs into a single signature the size of
one. Also not reachable through `Signet` — see
[BLS Aggregation](../features/aggregation.md).

**"I need to plan for large-scale quantum computers."**
[ML-DSA](../algorithms/mldsa.md) (CRYSTALS-Dilithium, FIPS 204) — much larger
keys and signatures than any classical scheme here, in exchange for security
that doesn't rely on the hardness of factoring or discrete logs.

**"I'm integrating with an existing system that already speaks RSA or DSA."**
[RSA](../algorithms/rsa.md) and [DSA](../algorithms/dsa.md) are here for that —
otherwise prefer a classical elliptic-curve scheme; see the RSA page's
[known limitation](../security.md#known-limitations) before choosing it for new
designs.

## What the Comparison Doesn't Capture

- **Signing speed** isn't in the table because it's dominated by key
  generation cost for RSA/DSA (seconds) versus curve-based schemes
  (milliseconds) — if your workload generates many keys, that gap matters
  more than signature size.
- **Verification cost for BLS** is dominated by pairing operations, the most
  expensive single operation in this crate. Aggregation over *N* **distinct**
  messages doesn't reduce that to one pairing — it's still *N* pairings'
  worth of work, just shareable across one batched check instead of *N*
  fully separate ones. What aggregation actually buys you there is
  bandwidth (one signature instead of *N*), not fewer pairings. See
  [BLS's own complexity breakdown](../algorithms/bls.md#complexity) for the
  case that genuinely is O(1) regardless of signer count.
- **RSA/DSA signature sizes above are approximate** because DER encoding
  length varies with the specific key's numeric values (leading-zero
  handling, `q` size for DSA); Ed25519/Ed448/Schnorr/BLS have fixed sizes
  because they use raw fixed-width encodings instead.
