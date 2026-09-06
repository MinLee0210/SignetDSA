# BLS

**BLS signatures over BLS12-381** (the "basic"
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` ciphersuite — public keys in
G1, signatures in G2) are pairing-based signatures whose defining feature is
**aggregation**: many signatures collapse into one the same size as a single
signature, verifiable against the full list of `(message, public key)` pairs
in one pairing check. SignetDSA uses
[`bls-signatures`](https://docs.rs/bls-signatures) (the pure-Rust
`pairing`/`bls12_381` backend, not `blst`, to avoid a C build dependency).

## Ordinary Sign/Verify

`Bls` implements the same [`Signature`](../getting_started.md#core-concepts)
trait every other algorithm here does, for the single-key case:

```rust
use SignetDSA::algo::bls::Bls;
use SignetDSA::Signature;

let (private_key, public_key) = Bls::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = Bls::sign(&private_key, message).expect("signing failed");
assert!(Bls::verify(&public_key, message, &signature).unwrap());
```

Keys and signatures are fixed-width: a 32-byte private scalar, a 48-byte
compressed G1 public key, and a 96-byte compressed G2 signature.

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("bls").unwrap(); // alias: "bls12-381"
let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

## Aggregation

What sets BLS apart — combining many signatures into one, and verifying
that one aggregate in a single check — is covered in full on the
[BLS Aggregation](../features/aggregation.md) feature page, including the
rogue public-key attack this crate's aggregation deliberately guards
against.

!!! danger "Read the aggregation page before aggregating"
    BLS aggregation is only safe under specific conditions — the underlying
    crate enforces one of them (rejecting repeated messages) but the other
    (proof-of-possession for same-message multisig) isn't provided by this
    crate at all. See [BLS Aggregation](../features/aggregation.md) and this
    module's own `# Rogue public-key attacks` doc comment before using it
    for anything beyond the distinct-message case.

## Errors

`Bls::Error` is `BlsError`, with variants for invalid public key/signature
encoding, plain verification failure, an empty aggregation input, an
aggregation-library failure, and a mismatched message/public-key count for
aggregate verification.

## When to Use

Reach for BLS specifically when you need aggregation — many validators
each signing a distinct message, and a verifier who wants to check them all
in one operation instead of one-by-one (this is the pattern used by
Ethereum's consensus layer, among others). For ordinary single-signer use
with no aggregation need, a classical algorithm like [EdDSA](eddsa.md) is
simpler, faster to verify individually, and has a more mature Rust
implementation.
