# ECDSA (NIST P-256)

**ECDSA** is DSA's elliptic-curve analogue — same $(r, s)$ signature shape,
but over a curve group instead of a modular-exponentiation subgroup, giving
much smaller keys and signatures for the same security level. SignetDSA uses
the **NIST P-256** curve with **SHA-256**, via the
[`p256`](https://docs.rs/p256) crate.

For the Bitcoin/Ethereum curve instead of the NIST one, see
[ECDSA (secp256k1)](ecdsa_secp256k1.md), which also adds `ecrecover`-style
public-key recovery.

## The Algorithm

Given a base point $G$ of order $n$ and private key $d$, the public key is
$Q = dG$. Signing digest $z = H(m)$ picks a per-signature random nonce $k$
and computes:

$$
(x_1, y_1) = kG \qquad r = x_1 \bmod n \qquad s = k^{-1}(z + rd) \bmod n
$$

Verification recomputes the curve point from $(r, s, Q, z)$ and checks its
$x$-coordinate matches $r$.

## How to Use

### Typed API

```rust
use SignetDSA::algo::ecdsa::Ecdsa;
use SignetDSA::Signature;

let (private_key, public_key) = Ecdsa::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = Ecdsa::sign(&private_key, message).expect("signing failed");
assert!(Ecdsa::verify(&public_key, message, &signature).unwrap());
```

Keys and signatures are fixed-width: a 32-byte private scalar, a 33-byte
SEC1-compressed public point, and a 64-byte `(r, s)` signature.

### PEM Import/Export

```rust
use SignetDSA::algo::ecdsa::Ecdsa;

let (private_key, public_key) = Ecdsa::generate_keys();

let private_pem = Ecdsa::private_key_to_pem(&private_key).unwrap();
let public_pem = Ecdsa::public_key_to_pem(&public_key).unwrap();

let restored_private = Ecdsa::private_key_from_pem(&private_pem).unwrap();
let restored_public = Ecdsa::public_key_from_pem(&public_pem).unwrap();
```

PKCS#8/SPKI PEM — see [PEM/DER Import-Export](../features/pem.md).

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("ecdsa").unwrap(); // alias: "p256"
let (sk, pk) = signer.generate_keys(); // 32-byte scalar, 33-byte SEC1 point
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

## Errors

`Ecdsa::Error` is `EcdsaError`, with variants for invalid signature encoding,
verification failure, and PEM encode/decode errors for both key types.

## When to Use

ECDSA/P-256 is the right default when you need a NIST-standard curve for
compliance reasons (FIPS 186-4/186-5, TLS, many government and enterprise
contexts). If nonce-reuse risk or determinism matters more than NIST
compliance, prefer [EdDSA](eddsa.md) or [Schnorr](schnorr.md) — both are
deterministic and don't depend on a fresh random nonce per signature.
