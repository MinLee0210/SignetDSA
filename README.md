# SignetDSA

A Rust library implementing digital signature algorithms — classical, threshold,
and post-quantum — backed by the RustCrypto ecosystem crates.

## Documentation

**https://minlee0210.github.io/SignetDSA** — per-algorithm deep dives
(theory, pseudocode, complexity), feature guides, a CLI reference, security
notes, and architecture. Built with [MkDocs](https://www.mkdocs.org/) +
[Material](https://squidfunk.github.io/mkdocs-material/) from
[`docs/`](docs/), and deployed to GitHub Pages by
[`.github/workflows/docs.yml`](.github/workflows/docs.yml) on every push to
`main` that touches `docs/` or `mkdocs.yml`.

To run it locally:

```bash
pip install -r requirements-docs.txt
mkdocs serve   # http://127.0.0.1:8000
```

The Pages site itself needs a one-time setup step in the repo: **Settings →
Pages → Build and deployment → Source → "GitHub Actions"**. Until that's
set, the workflow will build successfully but the deploy step will fail
with a permissions/environment error.

## Algorithms

| Algorithm | Category | Key Scheme | Crate |
|-----------|----------|------------|-------|
| **RSA** | Classical | PKCS#1 v1.5 + SHA-256 | `rsa` |
| **DSA** | Classical | 2048-bit + SHA-256 | `dsa` |
| **ECDSA** | Classical | NIST P-256 + SHA-256 | `p256` |
| **ECDSA/secp256k1** | Classical | Bitcoin/Ethereum curve + SHA-256, with `ecrecover`-style public-key recovery | `k256` |
| **EdDSA** | Classical | Curve25519 (Ed25519) | `ed25519-dalek` |
| **Ed448** | Classical | Curve448 "Goldilocks" (~224-bit security margin) | `ed448-goldilocks-plus` |
| **Schnorr** | Deterministic | BIP340 / secp256k1 | `k256` |
| **FROST** | Threshold (t-of-n) | Schnorr over secp256k1 | `frost-secp256k1` |
| **BLS** | Aggregatable | BLS12-381 (basic scheme) | `bls-signatures` |
| **ML-DSA** | Post-quantum | FIPS 204 / Dilithium-65 | `ml-dsa` |

### Known limitations

- **RSA** — the underlying `rsa` crate carries an open, unfixed advisory,
  [RUSTSEC-2023-0071][marvin] ("Marvin Attack"), covering timing side-channels
  in signing/decryption. Avoid it where an attacker can measure signing
  latency; prefer ECDSA, EdDSA, or Schnorr otherwise.
- **ML-DSA** — the `ml-dsa` crate has not undergone an independent security
  audit. Pin `ml-dsa >= 0.1.0-rc.3`; earlier versions carry
  [RUSTSEC-2025-0144][mldsa-timing], a timing side-channel in signature
  generation.
- **Ed448** — `ed448-goldilocks-plus` is a less battle-tested implementation
  than `ed25519-dalek` (no independent audit, smaller deployment base).
  Verified against the official RFC 8032 §7.4 test vectors here, but prefer
  Ed25519 unless Ed448's larger security margin is specifically required.
- **BLS** — aggregation is only safe over **distinct** messages; the
  `bls-signatures` crate enforces this and refuses to verify an aggregate
  built from repeated messages (the classic BLS rogue-key setup). Same-message
  multisig needs a separate proof-of-possession scheme this crate does not
  provide. See the `# Rogue public-key attacks` section in
  [`src/algo/bls.rs`](src/algo/bls.rs).

[marvin]: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
[mldsa-timing]: https://rustsec.org/advisories/RUSTSEC-2025-0144.html

### Interoperability

Ed25519, Ed448, and Schnorr are checked against the official specification
test vectors, not just internal round-trip consistency — see
[`tests/rfc8032_ed25519.rs`](tests/rfc8032_ed25519.rs) (RFC 8032 §7.1),
[`tests/rfc8032_ed448.rs`](tests/rfc8032_ed448.rs) (RFC 8032 §7.4), and
[`tests/bip340_schnorr.rs`](tests/bip340_schnorr.rs) (the full [BIP340 CSV
vectors][bip340-vectors], including its invalid-signature edge cases).

Schnorr signing/verification go through k256's `sign_prehash`/`verify_prehash`
(`PrehashSigner`/`PrehashVerifier`), which feed the message directly into the
BIP340 challenge hash with a fixed all-zero `aux_rand`, matching the standard
exactly and keeping signatures deterministic. k256 also exposes plain
`Signer`/`Verifier`, but those SHA-256-hash the message first — a variant that
would not interoperate with real Bitcoin Taproot signatures over the same
message, so this crate does not use it.

[bip340-vectors]: https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv

## Extra capabilities beyond sign/verify

A few algorithms expose functionality the generic `Signature` trait has no
room for (each as inherent associated functions alongside the trait impl):

- **ECDSA/secp256k1 public-key recovery** — `EcdsaSecp256k1::sign_recoverable`
  returns a signature plus a 1-byte recovery id; `EcdsaSecp256k1::recover_public_key`
  reconstructs the signer's public key from `(message, signature, recovery_id)`
  alone, the pattern behind Ethereum's `ecrecover`.
- **BLS aggregation** — `Bls::aggregate_signatures` combines many signatures
  into one the same size as a single signature; `Bls::verify_aggregated`
  checks it against the list of `(message, public_key)` pairs it covers.
- **Ed25519 batch verification** — `EdDsa::verify_batch` verifies many
  `(message, public_key, signature)` triples in one call, faster than
  verifying each individually (at the cost of not identifying which one
  failed, if any did).
- **PKCS#8/SPKI PEM import-export** — `Ecdsa`, `EdDsa`, `Rsa`, and `Dsa` each
  have `private_key_to_pem`/`private_key_from_pem` and
  `public_key_to_pem`/`public_key_from_pem`, for interop with keys generated
  by OpenSSL or other PKCS#8-speaking tools.

## Command-line interface

The `signetdsa` binary exposes the factory API from the shell — keys and
signatures are stored as hex-encoded text files:

```console
$ cargo run --bin signetdsa -- list
rsa
dsa
ecdsa
ecdsa-secp256k1
eddsa
ed448
schnorr
mldsa
bls

$ cargo run --bin signetdsa -- keygen --algo ed25519 --priv-out alice.key --pub-out alice.pub
$ cargo run --bin signetdsa -- sign --algo ed25519 --key alice.key --message "hello" --sig-out hello.sig
$ cargo run --bin signetdsa -- verify --algo ed25519 --pubkey alice.pub --message "hello" --sig hello.sig
VALID
```

`sign`/`verify` also accept `--message-file <path>` for messages that don't
fit on a command line. `verify` exits non-zero on an invalid signature or
parse error.

## Two APIs

### 1. Typed API — `Signature` trait

Each algorithm implements the `Signature` trait with its own key types:

```rust
pub trait Signature {
    type PrivateKey;
    type PublicKey;
    type Error;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey);
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &[u8]) -> Result<bool, Self::Error>;
}
```

Usage:

```rust
use SignetDSA::algo::ecdsa::Ecdsa;
use SignetDSA::Signature;

let (sk, pk) = Ecdsa::generate_keys();
let sig = Ecdsa::sign(&sk, b"Hello, world!").unwrap();
assert!(Ecdsa::verify(&pk, b"Hello, world!", &sig).unwrap());
```

### 2. Factory API — `Signet::from_name()`

Select an algorithm by name at runtime, behind a unified `SignetSigner` interface.
Inspired by HuggingFace's `AutoTokenizer.from_pretrained()`.

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("ecdsa").expect("Unknown algorithm");

let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

Supported names and aliases:

| Name | Aliases |
|------|---------|
| `"rsa"` | — |
| `"dsa"` | — |
| `"ecdsa"` | `"p256"` |
| `"ecdsa-secp256k1"` | `"secp256k1"` |
| `"eddsa"` | `"ed25519"` |
| `"ed448"` | `"ed448-goldilocks"` |
| `"schnorr"` | `"bip340"` |
| `"mldsa"` | `"ml-dsa"`, `"dilithium"` |
| `"bls"` | `"bls12-381"` |

List all supported algorithms:

```rust
Signet::available();
// -> ["rsa", "dsa", "ecdsa", "ecdsa-secp256k1", "eddsa", "ed448", "schnorr", "mldsa", "bls"]
```

Note: FROST (threshold signing) and BLS aggregation aren't reachable through
`Signet` — a threshold ceremony and an aggregate-many-signatures workflow
don't fit the factory's single-key sign/verify shape. Use
[`crate::algo::frost`] and [`crate::algo::bls::Bls`]'s aggregate functions
directly.