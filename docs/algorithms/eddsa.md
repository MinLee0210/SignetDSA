# EdDSA (Ed25519)

**EdDSA over Curve25519** ("Ed25519") is the most widely deployed modern
signature scheme — used by SSH, TLS 1.3, Signal, and most new protocols that
don't have a legacy reason to use something else. SignetDSA uses
[`ed25519-dalek`](https://docs.rs/ed25519-dalek), the most mature and
battle-tested implementation in this crate.

## The Algorithm

Given base point $B$ of order $L$ on Curve25519, a 32-byte random seed is
hashed with SHA-512 and split in two: the first half is clamped into a
scalar $s$ (the actual private scalar used for curve math), the second half
("`prefix`") is used only for nonce derivation below. The public key is
$A = sB$.

$$
r = H(\text{prefix} \,\|\, M) \bmod L \qquad R = rB \qquad
k = H(R \,\|\, A \,\|\, M) \bmod L \qquad S = (r + ks) \bmod L
$$

The signature is $(R, S)$. This is where determinism comes from: $r$ is a
hash of the message and a secret derived from the key — never externally
supplied randomness — so the same $(key, message)$ always reproduces the
same $r$, and therefore the same signature. Verification checks
$SB \stackrel{?}{=} R + kA$.

## What Sets EdDSA Apart

Unlike [ECDSA](ecdsa.md) and [DSA](dsa.md), EdDSA signing needs **no random
nonce per signature** — the nonce is derived deterministically from the
private key and the message itself (via a hash), so signing the same
message twice with the same key always produces the same signature. This
eliminates the entire class of nonce-reuse key-recovery attacks that DSA and
plain ECDSA are vulnerable to if their random number generator is ever weak
or predictable.

## Pseudocode

```text
KeyGen():
    seed          <- 32 random bytes
    (s, prefix)   <- split(SHA-512(seed))   # s is clamped into a valid scalar
    A             <- s * B                   # public key (fixed-base scalar mult)
    return (private_key = seed, public_key = A)

Sign(seed, message):
    (s, prefix) <- split(SHA-512(seed))
    r <- SHA-512(prefix || message) mod L
    R <- r * B                               # fixed-base scalar mult
    k <- SHA-512(R || A || message) mod L
    S <- (r + k * s) mod L
    return (R, S)

Verify(A, message, (R, S)):
    k        <- SHA-512(R || A || message) mod L
    lhs      <- S * B                        # fixed-base scalar mult
    rhs      <- R + k * A                    # variable-base scalar mult + point add
    return lhs == rhs
```

## Complexity

| Operation | Cost | Why |
|---|---|---|
| KeyGen | $O(\log L)$ point operations | One fixed-base scalar multiplication $sB$ — "fixed-base" because $B$ never changes, which lets an implementation precompute a lookup table and turn most of the work into table lookups instead of point doublings |
| Sign | $O(\log L)$ point operations | One fixed-base scalar multiplication $rB$ — same fixed-base speedup as KeyGen applies |
| Verify | $O(\log L)$ point operations | One fixed-base ($SB$) plus one variable-base ($kA$) scalar multiplication — the variable-base one can't use a precomputed table (a different $A$ every time), making verify the one operation here that can't get the full fixed-base speedup |

$L$ is Curve25519's group order (a fixed ~253-bit constant). The `fast`
Cargo feature this crate enables on `ed25519-dalek` by default specifically
turns on `curve25519-dalek`'s precomputed tables for fixed-base
multiplication — the concrete reason Ed25519 signing here is faster in
practice than its asymptotic complexity class alone would suggest.

## How to Use

### Typed API

```rust
use SignetDSA::algo::eddsa::EdDsa;
use SignetDSA::Signature;

let (private_key, public_key) = EdDsa::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = EdDsa::sign(&private_key, message).expect("signing failed");
assert!(EdDsa::verify(&public_key, message, &signature).unwrap());
```

Keys and signatures are fixed-width: a 32-byte private key, a 32-byte public
key, a 64-byte signature.

### Batch Verification

```rust
use SignetDSA::algo::eddsa::EdDsa;

let valid = EdDsa::verify_batch(&messages, &signatures, &public_keys).unwrap();
```

Verifies many `(message, public key, signature)` triples in one call, faster
than verifying each individually — at the cost of not identifying which one
was invalid if the batch fails. See
[Batch Verification](../features/batch_verification.md).

### PEM Import/Export

```rust
use SignetDSA::algo::eddsa::EdDsa;

let (private_key, public_key) = EdDsa::generate_keys();

let private_pem = EdDsa::private_key_to_pem(&private_key).unwrap();
let public_pem = EdDsa::public_key_to_pem(&public_key).unwrap();

let restored_private = EdDsa::private_key_from_pem(&private_pem).unwrap();
let restored_public = EdDsa::public_key_from_pem(&public_pem).unwrap();
```

PKCS#8/SPKI PEM — see [PEM/DER Import-Export](../features/pem.md).

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("eddsa").unwrap(); // alias: "ed25519"
let (sk, pk) = signer.generate_keys(); // 32-byte raw arrays
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

!!! note "No batch verification through the factory"
    `verify_batch` is an inherent associated function on `EdDsa` itself, not
    part of `SignetSigner` — call the typed API directly to use it.

## Interoperability

Ed25519 is checked against the official
[RFC 8032 §7.1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) test
vectors in [`tests/rfc8032_ed25519.rs`](https://github.com/MinLee0210/SignetDSA/blob/main/tests/rfc8032_ed25519.rs),
not just internal round-trip consistency. See
[Security & Interoperability](../security.md).

## Errors

`EdDsa::Error` is `EdDsaError`, with variants for invalid signature
encoding, single-signature verification failure, batch verification
failure, and PEM encode/decode errors.

## When to Use

Ed25519 is the right **default** for new designs with no interop constraint
pulling toward a specific curve or algorithm — smallest keys and signatures
of any classical algorithm here, deterministic, fast, and the most
extensively deployed and audited implementation this crate depends on. Reach
for [Ed448](ed448.md) instead only if you specifically need its larger
security margin.
