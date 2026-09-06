# SignetDSA

<div align="center">
  <img src="assets/logo.svg" alt="SignetDSA logo" width="160"/>
</div>

<br>

**SignetDSA** is a comprehensive, enterprise-grade Rust library for digital signatures — classical, threshold, aggregatable, and post-quantum — providing two complementary APIs: a typed `Signature` trait for compile-time-checked static usage, and a runtime `Signet` factory (inspired by HuggingFace's `AutoTokenizer.from_pretrained()`) for dynamic algorithm selection.

## Highlights & Capabilities

| Category | What you get |
|---|---|
| **11 Factory-Selectable Algorithms** | RSA, RSA-PSS, DSA, ECDSA (NIST P-256 & P-384), ECDSA (secp256k1), EdDSA (Ed25519), Ed448, Schnorr (BIP340), ML-DSA-65, BLS12-381 |
| **Signed Envelopes & JWS** | Self-verifying JSON message containers (`SignetEnvelope`) and RFC 7515 URL-safe compact tokens (`JwsCompact`) |
| **Performance Benchmarking** | Built-in micro-benchmarking harness (`Signet::benchmark_all` and `signetdsa bench`) |
| **Threshold Signing** | FROST — 2-round interactive Schnorr threshold ceremony on secp256k1 (`SignetDSA::algo::frost`) |
| **Signature Aggregation** | BLS aggregate signatures — condense many signatures into one, verified via a single pairing equation |
| **Public-Key Recovery** | `ecrecover`-style recovery for ECDSA/secp256k1 (`EcdsaSecp256k1::recover_public_key`) |
| **Batch Verification** | Verify many Ed25519 `(message, key, signature)` triples simultaneously for accelerated throughput |
| **PEM/SPKI Import-Export** | PKCS#8 PEM encoding for RSA, RSA-PSS, DSA, ECDSA (P-256/P-384), and Ed25519 |
| **Post-Quantum Security** | ML-DSA-65 (CRYSTALS-Dilithium, NIST FIPS 204) lattice-based digital signatures |
| **Specification Verified** | Tested against official RFC 8032 (Ed25519/Ed448), BIP340 (Schnorr), RFC 6979 (P-384), and RFC 8017 (RSA-PSS) vectors |
| **Command-Line Tool** | `signetdsa` — generate keys, sign, verify, recover, aggregate, and benchmark directly from the shell |

## Quick Start

```toml
[dependencies]
SignetDSA = { git = "https://github.com/MinLee0210/SignetDSA" }
```

=== "Factory API"

    ```rust
    use SignetDSA::{Signet, SignetSigner};

    // Dynamically select algorithm by name
    let signer = Signet::from_name("eddsa").expect("Unknown algorithm");
    let (sk, pk) = signer.generate_keys();
    let message = b"Hello, SignetDSA!";

    let signature = signer.sign(&sk, message).unwrap();
    assert!(signer.verify(&pk, message, &signature).unwrap());
    ```

=== "JWS Compact Tokens (RFC 7515)"

    ```rust
    use SignetDSA::{Signet, envelope::JwsCompact};

    let signer = Signet::from_name("ecdsa-p384").unwrap();
    let (sk, pk) = signer.generate_keys();

    // Sign payload into URL-safe compact token: header.payload.signature
    let token = JwsCompact::sign("ecdsa-p384", &sk, b"sub=user123").unwrap();
    let payload = JwsCompact::verify(&token, &pk).unwrap();
    assert_eq!(payload, b"sub=user123");
    ```

=== "Typed API"

    ```rust
    use SignetDSA::algo::ecdsa::Ecdsa;
    use SignetDSA::Signature;

    let (sk, pk) = Ecdsa::generate_keys();
    let sig = Ecdsa::sign(&sk, b"Hello, world!").unwrap();
    assert!(Ecdsa::verify(&pk, b"Hello, world!", &sig).unwrap());
    ```

=== "CLI"

    ```console
    $ cargo run --bin signetdsa -- keygen --algo ed25519 --priv-out alice.key --pub-out alice.pub
    $ cargo run --bin signetdsa -- sign --algo ed25519 --key alice.key --message "hello" --sig-out hello.sig
    $ cargo run --bin signetdsa -- verify --algo ed25519 --pubkey alice.pub --message "hello" --sig hello.sig
    VALID
    ```

## Navigation

- **[Getting Started](getting_started.md)** — installation, both APIs, first signature
- **[Learn](learn/intuition.md)** — what a digital signature actually is, a decision guide across all 11 algorithms, and a glossary
- **[Algorithms](algorithms/rsa.md)** — deep-dive pages for every scheme: theory, code, parameters, security analysis
- **[Features](features/factory.md)** — factory API, signed envelopes, benchmarking, PEM, batch verification, recovery, aggregation
- **[CLI Reference](cli.md)** — the `signetdsa` command-line utility
- **[Security & Interoperability](security.md)** — known limitations, RUSTSEC advisories, spec test vectors
- **[Design & Architecture](architecture.md)** — design philosophy, project layout, and extensibility
