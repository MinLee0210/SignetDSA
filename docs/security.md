# Security & Interoperability

## Known Limitations

- **RSA** — the underlying `rsa` crate carries an open, unfixed advisory,
  [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
  ("Marvin Attack"), covering timing side-channels in signing/decryption.
  Only exploitable by an attacker able to measure signing latency (a shared
  network, or a co-tenant on the same machine) — local, non-adversarial use
  is unaffected. Avoid [RSA](algorithms/rsa.md) where that threat applies;
  prefer [ECDSA](algorithms/ecdsa.md), [EdDSA](algorithms/eddsa.md), or
  [Schnorr](algorithms/schnorr.md) otherwise.
- **ML-DSA** — the `ml-dsa` crate has not undergone an independent security
  audit. This crate pins `ml-dsa >= 0.1.0-rc.3`; earlier versions carry
  [RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144.html),
  a timing side-channel in signature generation. See
  [ML-DSA](algorithms/mldsa.md).
- **Ed448** — `ed448-goldilocks-plus` is a less battle-tested implementation
  than `ed25519-dalek` (no independent audit, smaller deployment base).
  Verified against the official RFC 8032 §7.4 test vectors, but prefer
  [Ed25519](algorithms/eddsa.md) unless Ed448's larger security margin is
  specifically required.
- **BLS** — aggregation is only safe over **distinct** messages. The
  `bls-signatures` crate enforces this (rejecting an aggregate built from
  repeated messages, the classic rogue-key setup), but same-message
  multisig needs a proof-of-possession scheme this crate does not provide.
  See [BLS Aggregation](features/aggregation.md).

## Continuous Auditing

CI runs [`cargo audit`](https://docs.rs/cargo-audit) against the RustSec
advisory database on every build. [`.cargo/audit.toml`](https://github.com/MinLee0210/SignetDSA/blob/main/.cargo/audit.toml)
ignores exactly one advisory — RUSTSEC-2023-0071 above, the RSA timing
side-channel already documented as an accepted, known limitation — so CI
reflects genuinely new findings instead of being permanently red over a
risk that's already been weighed and accepted. Everything else RustSec
flags (currently a small number of `unmaintained`/`unsound`/`yanked`
warnings on transitive dependencies, none rising to a tracked vulnerability)
surfaces normally.

## Interoperability: Verified Against Official Test Vectors

Three algorithms are checked against their official specification test
vectors — not just this crate's own internal round-trip consistency, which
only proves sign and verify agree with *each other*, not that either one
implements the actual standard:

| Algorithm | Test vectors | Source |
|---|---|---|
| [Ed25519](algorithms/eddsa.md) | [`tests/rfc8032_ed25519.rs`](https://github.com/MinLee0210/SignetDSA/blob/main/tests/rfc8032_ed25519.rs) | RFC 8032 §7.1 |
| [Ed448](algorithms/ed448.md) | [`tests/rfc8032_ed448.rs`](https://github.com/MinLee0210/SignetDSA/blob/main/tests/rfc8032_ed448.rs) | RFC 8032 §7.4 |
| [Schnorr (BIP340)](algorithms/schnorr.md) | [`tests/bip340_schnorr.rs`](https://github.com/MinLee0210/SignetDSA/blob/main/tests/bip340_schnorr.rs) | [Official BIP340 CSV](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv), all 19 vectors including invalid-signature edge cases |
| [ECDSA (P-384)](algorithms/ecdsa_p384.md) | [`tests/rfc6979_p384.rs`](https://github.com/MinLee0210/SignetDSA/blob/main/tests/rfc6979_p384.rs) | RFC 6979 §A.2.6 deterministic ECDSA vectors |
| [RSA-PSS](algorithms/rsa_pss.md) | [`tests/rfc8017_rsa_pss.rs`](https://github.com/MinLee0210/SignetDSA/blob/main/tests/rfc8017_rsa_pss.rs) | RFC 8017 PKCS#1 v2.2 RSASSA-PSS verification |

### The Bug These Vectors Caught

The BIP340 test vectors caught a real, since-fixed conformance bug in this
crate: Schnorr signing/verification originally went through k256's plain
`Signer`/`Verifier` traits, which SHA-256-hash the message *before* applying
BIP340's algorithm. Real BIP340 feeds the message directly into the tagged
challenge hash, with no such pre-hash. The bug was internally
self-consistent — sign and verify agreed with each other — which is exactly
why round-trip tests alone didn't catch it; it took verifying against
vectors from an independent source (the actual standard) to surface it. See
[Schnorr's `# BIP340 conformance` section](algorithms/schnorr.md#bip340-conformance)
for the fix.

This is the general argument for spec test vectors over round-trip tests
alone: round-trip tests prove an implementation is *consistent*; spec
vectors prove it's *correct*.

## Reporting a Vulnerability

This is a personal/educational project without a formal security disclosure
process. If you find a vulnerability, open an issue on the
[GitHub repository](https://github.com/MinLee0210/SignetDSA) describing the
class of problem — please avoid posting a full working exploit in a public
issue.
