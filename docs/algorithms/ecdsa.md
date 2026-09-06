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

## Pseudocode

```text
KeyGen():
    d <- random in [1, n - 1]           # private key
    Q <- d * G                          # public key (one scalar multiplication)
    return (d, Q)

Sign(d, message):
    z <- SHA-256(message) mod n
    loop:
        k <- random in [1, n - 1]       # MUST be fresh every call
        (x1, _) <- k * G
        r <- x1 mod n
        if r == 0: retry
        s <- k^-1 * (z + r * d) mod n
        if s == 0: retry
    return (r, s)

Verify(Q, message, (r, s)):
    if r not in [1, n-1] or s not in [1, n-1]: return false
    z    <- SHA-256(message) mod n
    w    <- s^-1 mod n
    u1   <- z * w mod n
    u2   <- r * w mod n
    (x1, _) <- u1 * G + u2 * Q          # multi-scalar multiplication
    return (x1 mod n) == r
```

## Complexity

| Operation | Cost | Why |
|---|---|---|
| KeyGen | $O(\log n)$ point operations | One scalar multiplication $dG$, via double-and-add (or the `p256` crate's constant-time equivalent) |
| Sign | $O(\log n)$ point operations | One scalar multiplication $kG$ dominates; the modular inverse and multiplications that follow are comparatively cheap |
| Verify | $O(\log n)$ point operations, ~2× signing | A multi-scalar multiplication $u_1 G + u_2 Q$ — computable together more cheaply than two separate scalar multiplications, but still roughly twice sign's cost |

$n$ is the curve order (a fixed ~256-bit constant for P-256), so in practice
every operation above runs in a small, fixed number of point operations —
the $\log n$ term doesn't grow with anything in your program, unlike RSA/DSA
where the equivalent exponent size is tied to a key size you might
reasonably want to increase. This is the core reason elliptic-curve
algorithms get RSA-equivalent security from far smaller keys.

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
