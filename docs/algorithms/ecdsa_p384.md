# ECDSA over NIST P-384 (secp384r1)

ECDSA over NIST P-384 (also known as `secp384r1`) is a high-security elliptic curve signature algorithm standardized in [FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final) and [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979).

It provides approximately **192 bits of classical security margin** (compared to ~128 bits for P-256 and Ed25519), making it compliant with the NSA's Commercial National Security Algorithm (CNSA) Suite 1.0 specifications for protecting classified information.

## Specification

| Property | Value |
|---|---|
| **Curve** | NIST P-384 (`secp384r1`, 384-bit prime field) |
| **Hash Function** | SHA-384 |
| **Security Level** | ~192-bit classical |
| **Private Key Size** | 48 bytes (scalar) |
| **Public Key Size** | 49 bytes (SEC1 compressed) |
| **Signature Size** | 96 bytes (`r` [48B] + `s` [48B]) |
| **Key Encoding** | PKCS#8 / SPKI PEM & SEC1 DER |
| **Crate** | `p384` |

## Usage

### Typed API

```rust
use SignetDSA::algo::ecdsa_p384::EcdsaP384;
use SignetDSA::Signature;

// Generate P-384 keypair
let (private_key, public_key) = EcdsaP384::generate_keys();

// Sign message with deterministic ECDSA (RFC 6979 + SHA-384)
let message = b"CNSA compliant data payload";
let signature = EcdsaP384::sign(&private_key, message).unwrap();

// Verify signature
let is_valid = EcdsaP384::verify(&public_key, message, &signature).unwrap();
assert!(is_valid);
```

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("ecdsa-p384").expect("Unknown algorithm");
let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, P-384!").unwrap();
assert!(signer.verify(&pk, b"Hello, P-384!", &sig).unwrap());
```

Accepted aliases: `"ecdsa-p384"`, `"p384"`, `"secp384r1"`.
