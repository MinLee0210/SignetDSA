# ML-DSA (Post-Quantum)

**ML-DSA-65** (CRYSTALS-Dilithium, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final))
is a post-quantum digital signature algorithm based on the hardness of
**Module Learning With Errors (MLWE)** — a lattice problem believed to
resist attacks from both classical *and* quantum computers, unlike every
other algorithm in this crate, all of which rely on integer factorization
or discrete logarithms that [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
would break. SignetDSA uses the [`ml-dsa`](https://docs.rs/ml-dsa) crate.

ML-DSA-65 targets **NIST Level 3** (~192-bit classical security).

!!! warning "Known limitation"
    The `ml-dsa` crate has not undergone an independent security audit.
    This crate pins `ml-dsa >= 0.1.0-rc.3` — earlier versions carry
    [RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144.html),
    a timing side-channel in the decompose step of signature generation
    that can leak signing-key data.

## The Size Tradeoff

Post-quantum security comes at a real cost in key and signature size —
worth seeing concretely:

| | ML-DSA-65 | Ed25519 (for comparison) |
|---|---|---|
| Public key | 1952 B | 32 B |
| Private key | 4032 B | 32 B |
| Signature | 3309 B | 64 B |

A single ML-DSA-65 signature is over **50× larger** than an Ed25519
signature. If bandwidth or storage is tightly constrained and quantum
resistance isn't an immediate requirement, a classical algorithm like
[EdDSA](eddsa.md) remains the more practical choice today.

## How to Use

### Typed API

```rust
use SignetDSA::algo::mldsa::MlDsa;
use SignetDSA::Signature;

let (private_key, public_key) = MlDsa::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = MlDsa::sign(&private_key, message).expect("signing failed");
assert!(MlDsa::verify(&public_key, message, &signature).unwrap());

assert_eq!(signature.len(), 3309);
```

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("mldsa").unwrap(); // aliases: "ml-dsa", "dilithium"
let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

## Errors

`MlDsa::Error` is `MlDsaError`, with variants for invalid signature
encoding and verification failure.

## When to Use

Use ML-DSA when you need to plan **now** for a threat model that includes
large-scale quantum computers within the lifetime of the data or system
being protected — this is often driven by "harvest now, decrypt later"
concerns for long-lived secrets, or by emerging compliance requirements
(NIST's post-quantum migration timelines). For everything else, a classical
algorithm elsewhere in this crate will be smaller, faster, and more mature.
