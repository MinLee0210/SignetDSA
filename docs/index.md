# SignetDSA

**SignetDSA** is a Rust library of digital signature algorithms — classical,
threshold, aggregatable, and post-quantum — behind two APIs: a typed
`Signature` trait for compile-time-checked usage, and a runtime `Signet`
factory (inspired by HuggingFace's `AutoTokenizer.from_pretrained()`) for
selecting an algorithm by name.

## Highlights

| Category | What you get |
|---|---|
| **9 factory-selectable algorithms** | RSA, DSA, ECDSA (P-256), ECDSA (secp256k1), EdDSA (Ed25519), Ed448, Schnorr (BIP340), ML-DSA, BLS |
| **Threshold signing** | FROST — 2-round Schnorr threshold ceremony, exposed directly (not through the factory; see [Choosing an Algorithm](choosing_an_algorithm.md)) |
| **Aggregation** | BLS aggregate signatures — many signatures collapse into one, verified in a single pairing check |
| **Public-key recovery** | `ecrecover`-style recovery for ECDSA/secp256k1 |
| **Batch verification** | Verify many Ed25519 `(message, key, signature)` triples faster than one at a time |
| **PEM/SPKI import-export** | PKCS#8 PEM for RSA, DSA, ECDSA, and EdDSA keys — interop with OpenSSL-generated files |
| **Post-quantum** | ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) |
| **Spec-verified** | Ed25519, Ed448, and Schnorr are checked against their official RFC 8032 / BIP340 test vectors, not just internal round-trips |
| **A CLI** | `signetdsa` — generate keys, sign, and verify from the shell, for any registered algorithm |

## Quick Start

```toml
[dependencies]
SignetDSA = { git = "https://github.com/MinLee0210/LightDSA" }
```

=== "Typed API"

    ```rust
    use SignetDSA::algo::ecdsa::Ecdsa;
    use SignetDSA::Signature;

    let (sk, pk) = Ecdsa::generate_keys();
    let sig = Ecdsa::sign(&sk, b"Hello, world!").unwrap();
    assert!(Ecdsa::verify(&pk, b"Hello, world!", &sig).unwrap());
    ```

=== "Factory API"

    ```rust
    use SignetDSA::{Signet, SignetSigner};

    let signer = Signet::from_name("ecdsa").expect("Unknown algorithm");
    let (sk, pk) = signer.generate_keys();
    let sig = signer.sign(&sk, b"Hello, world!").unwrap();
    assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
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
- **[Choosing an Algorithm](choosing_an_algorithm.md)** — a decision guide across all nine
- **[Algorithms](algorithms/rsa.md)** — one deep-dive page per algorithm: theory, code, caveats
- **[Features](features/factory.md)** — the factory API, PEM, batch verification, recovery, aggregation
- **[CLI](cli.md)** — the `signetdsa` command-line tool
- **[Security & Interoperability](security.md)** — known limitations, RUSTSEC advisories, spec test vectors
- **[Design & Architecture](architecture.md)** — project layout and extensibility
