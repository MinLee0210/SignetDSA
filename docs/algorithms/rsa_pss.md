# RSA-PSS (RSASSA-PSS, RFC 8017)

RSA-PSS (Probabilistic Signature Scheme) is the modern, provably secure digital signature scheme for RSA, standardized in [RFC 8017 §8.1](https://www.rfc-editor.org/rfc/rfc8017#section-8.1) (PKCS#1 v2.2) and [FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final).

Unlike legacy PKCS#1 v1.5 padding, RSA-PSS introduces a random salt during signature generation. This eliminates deterministic structure in the padded message, making RSA-PSS provably secure against existential forgery under chosen-message attacks in the Random Oracle Model.

## Specification

| Property | Value |
|---|---|
| **Underlying Problem** | Integer Factorization |
| **Padding Scheme** | RSASSA-PSS (MGF1 with SHA-256) |
| **Hash Function** | SHA-256 |
| **Salt Length** | 32 bytes (equal to digest length) |
| **Modulus Size** | 2048-bit |
| **Key Encoding** | PKCS#8 DER / PEM (`-----BEGIN PRIVATE KEY-----`) |
| **Crate** | `rsa` |

## Usage

### Typed API

```rust
use SignetDSA::algo::rsa_pss::RsaPss;
use SignetDSA::Signature;

// Generate 2048-bit keypair
let (private_key, public_key) = RsaPss::generate_keys();

// Sign message (randomized salt ensures different signatures per run)
let message = b"Confidential instruction";
let signature = RsaPss::sign(&private_key, message).unwrap();

// Verify signature
let is_valid = RsaPss::verify(&public_key, message, &signature).unwrap();
assert!(is_valid);
```

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("rsa-pss").expect("Unknown algorithm");
let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, RSA-PSS!").unwrap();
assert!(signer.verify(&pk, b"Hello, RSA-PSS!", &sig).unwrap());
```

Accepted aliases: `"rsa-pss"`, `"pss"`, `"rsassa-pss"`.

## Security Comparison: PSS vs PKCS#1 v1.5

| Feature | RSA PKCS#1 v1.5 | RSA-PSS |
|---|---|---|
| **Randomization** | Deterministic (no salt) | Probabilistic (random salt per sign) |
| **Security Proof** | Heuristic | Provably secure (Random Oracle Model) |
| **Padding Oracle Resistance** | Vulnerable (e.g. Bleichenbacher/Marvin) | Resistant |
| **NIST / FIPS Status** | Deprecated for new applications | Recommended standard |
