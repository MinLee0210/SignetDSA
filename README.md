# SignetDSA

A Rust library implementing digital signature algorithms — classical, threshold,
and post-quantum — backed by audited cryptographic crates.

## Algorithms

| Algorithm | Category | Key Scheme | Crate |
|-----------|----------|------------|-------|
| **RSA** | Classical | PKCS#1 v1.5 + SHA-256 | `rsa` |
| **DSA** | Classical | 2048-bit + SHA-256 | `dsa` |
| **ECDSA** | Classical | NIST P-256 + SHA-256 | `p256` |
| **EdDSA** | Classical | Curve25519 (Ed25519) | `ed25519-dalek` |
| **Schnorr** | Deterministic | BIP340 / secp256k1 | `k256` |
| **FROST** | Threshold (2-of-3) | Schnorr over secp256k1 | `frost-secp256k1` |
| **ML-DSA** | Post-quantum | FIPS 204 / Dilithium-65 | `ml-dsa` |


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
| `"eddsa"` | `"ed25519"` |
| `"schnorr"` | `"bip340"` |
| `"mldsa"` | `"ml-dsa"`, `"dilithium"` |

List all supported algorithms:

```rust
Signet::available(); // -> ["rsa", "dsa", "ecdsa", "eddsa", "schnorr", "mldsa"]
```