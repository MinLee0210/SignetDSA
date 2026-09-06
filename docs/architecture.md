# Design & Architecture

## Project Structure

```
SignetDSA/
├── src/
│   ├── lib.rs                     # Crate root, re-exports, top-level docs
│   ├── signature.rs                # The generic `Signature` trait
│   ├── signet.rs                   # The object-safe `SignetSigner` trait + `Signet` factory
│   ├── algo/
│   │   ├── mod.rs
│   │   ├── rsa.rs                  # RSA (PKCS#1 v1.5 + SHA-256)
│   │   ├── dsa.rs                  # DSA (2048-bit + SHA-256)
│   │   ├── ecdsa.rs                # ECDSA (NIST P-256)
│   │   ├── ecdsa_secp256k1.rs      # ECDSA (secp256k1) + public-key recovery
│   │   ├── eddsa.rs                # EdDSA (Ed25519) + batch verification
│   │   ├── ed448.rs                # Ed448 (Curve448)
│   │   ├── schnorr.rs              # Schnorr (BIP340 / secp256k1)
│   │   ├── frost.rs                # FROST (threshold Schnorr) — ceremony, no `Signature` impl
│   │   ├── bls.rs                  # BLS (BLS12-381) + aggregation
│   │   └── mldsa.rs                # ML-DSA-65 (post-quantum)
│   └── bin/
│       └── signetdsa.rs            # `signetdsa` CLI
├── tests/                          # Integration tests: official spec test vectors
│   ├── rfc8032_ed25519.rs
│   ├── rfc8032_ed448.rs
│   └── bip340_schnorr.rs
├── .cargo/
│   └── audit.toml                  # `cargo audit` advisory allowlist (see Security & Interoperability)
└── .github/workflows/ci.yml        # fmt, clippy, tests, docs, `cargo audit`
```

Each `algo/*.rs` module owns exactly one algorithm end to end: its
`PrivateKey`/`PublicKey`/`Error` types, `generate_keys`/`sign`/`verify`, and
its own unit tests (round-trip and tampered-message rejection at minimum).
`signet.rs`'s `adapters` submodule then wraps each one in a `SignetSigner`
implementation that serializes to/from `Vec<u8>`. Neither module depends on
the other's internals — `algo::ecdsa::Ecdsa` and `signet::adapters::EcdsaAdapter`
both wrap the same underlying `p256` types independently, rather than one
being built in terms of the other.

## Design Principles

### 1. Two APIs, Not One Compromise

Rather than picking one interface and living with its tradeoff, this crate
keeps both:

- The **typed API** (`Signature` trait) gives compile-time-checked,
  zero-cost usage when the algorithm is known at compile time — see
  [Getting Started](getting_started.md#core-concepts).
- The **factory API** (`Signet`/`SignetSigner`) trades that compile-time
  precision for runtime flexibility, when the algorithm is a string that
  arrives at runtime — see [Factory API](features/factory.md).

Neither is a subset of the other's capability by accident: `Signature`'s
associated types are exactly what makes it impossible to box, which is
exactly why `SignetSigner` exists as a separate, deliberately less precise
trait rather than a blanket impl.

### 2. Extra Capabilities Live on the Typed Struct, Not the Trait

[Public-key recovery](features/recovery.md), [batch verification](features/batch_verification.md),
[BLS aggregation](features/aggregation.md), and [PEM import/export](features/pem.md)
all have no equivalent in the generic `Signature` trait — they're specific
to one or two algorithms, not universal. Rather than growing the trait with
optional methods (which would need default implementations that panic or
return errors for every algorithm that doesn't support them), each lives as
an inherent associated function on that algorithm's own struct
(`EcdsaSecp256k1::recover_public_key`, `EdDsa::verify_batch`,
`Bls::aggregate_signatures`, and so on). This keeps the trait itself small
and universally implementable, at the cost of those capabilities not being
reachable through the `Signet` factory — a deliberate tradeoff, documented
on [Factory API](features/factory.md#what-isnt-here).

### 3. FROST Doesn't Implement `Signature` at All

[FROST](algorithms/frost.md)'s threshold ceremony is fundamentally a
multi-round, multi-party protocol — `generate_keys() -> sign() -> verify()`
doesn't describe it honestly, so `algo::frost` doesn't try to force it into
that shape. It exposes the ceremony (`ceremony`/`ceremony_2_of_3`) directly
instead, keeping the multi-round structure visible in the API rather than
hidden behind a single function call that would misrepresent what's
actually happening.

### 4. Extensibility: Adding a New Algorithm

1. Create `src/algo/my_algorithm.rs`.
2. Define the type, its `PrivateKey`/`PublicKey`/`Error` types, and
   implement `Signature` for it (or don't, if it doesn't fit the single-key
   sign/verify shape — see FROST above).
3. Add unit tests: at minimum, sign-then-verify succeeds, and verifying
   against a tampered message fails.
4. Register the module in `src/algo/mod.rs`.
5. If it fits the factory shape, add a `SignetSigner` adapter in
   `src/signet.rs`'s `adapters` module, register its name (and any aliases)
   in `Signet::from_name`, and add it to `Signet::available()`.
6. If the algorithm has an official specification test vector suite,
   prefer verifying against it in `tests/` over relying on round-trip tests
   alone — see [Security & Interoperability](security.md#interoperability-verified-against-official-test-vectors)
   for why that distinction matters.

## Dependencies

| Crate | Why |
|---|---|
| `rsa` | RSA |
| `dsa` | DSA |
| `p256` | ECDSA (NIST P-256) |
| `k256` | ECDSA (secp256k1) and Schnorr (BIP340), both over secp256k1 |
| `ed25519-dalek` | EdDSA (Ed25519), including batch verification |
| `ed448-goldilocks-plus` | Ed448 — the actively maintained fork with EdDSA support; plain `ed448-goldilocks` is curve arithmetic only as of 0.9 |
| `frost-secp256k1` | FROST threshold Schnorr |
| `bls-signatures` | BLS over BLS12-381, pure-Rust `pairing` backend (not `blst`, to avoid a C build dependency) |
| `ml-dsa` | ML-DSA-65 (post-quantum) |
| `pkcs8` | Forces the `pem` feature on for PEM import/export — see [PEM/DER Import-Export](features/pem.md#how-this-is-wired-up) |
| `sha2` | Hashing |
| `rand` | Randomness (`OsRng`) |
| `signature` | RustCrypto's generic signing/verification traits |
| `zeroize` | Zeroizes private key bytes on drop at the factory layer |
| `clap`, `hex` | The `signetdsa` CLI |

## CI

[`.github/workflows/ci.yml`](https://github.com/MinLee0210/LightDSA/blob/main/.github/workflows/ci.yml)
runs on every push and pull request against `main`:

1. `cargo fmt -- --check`
2. `cargo clippy -- -D warnings`
3. `cargo test --verbose`
4. `cargo doc --no-deps`
5. `cargo audit` (a separate job), against the allowlist in
   [`.cargo/audit.toml`](https://github.com/MinLee0210/LightDSA/blob/main/.cargo/audit.toml)
   — see [Security & Interoperability](security.md#continuous-auditing).
