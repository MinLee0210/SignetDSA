# ECDSA (secp256k1)

**ECDSA over secp256k1** is the curve behind Bitcoin and Ethereum signatures
— algorithmically identical to [ECDSA (P-256)](ecdsa.md), just over a
different curve, via the [`k256`](https://docs.rs/k256) crate. This is
deliberately a separate type from `Ecdsa`: same shape, different curve, and
the two are **not** interchangeable — a secp256k1 key will not verify a
P-256 signature or vice versa.

Unlike [Schnorr (BIP340)](schnorr.md) — the *other* secp256k1 algorithm in
this crate — plain ECDSA signing genuinely does hash the message with
SHA-256 before the curve math. That's the standard, not a shortcut; there is
no double-hashing subtlety to worry about here the way there was for
Schnorr (see that page's `# BIP340 conformance` note).

## What Sets This Apart: Public-Key Recovery

Because the curve math that produces $(r, s)$ only needs 2 extra bits of
information (a "recovery id") to be inverted, a verifier who already trusts
a signature was made by *some* legitimate key can recover **which** public
key that was — without the signer ever transmitting it. This is the
`ecrecover` pattern Ethereum uses to identify transaction senders from their
signature alone.

```rust
use SignetDSA::algo::ecdsa_secp256k1::EcdsaSecp256k1;

let (private_key, public_key) = EcdsaSecp256k1::generate_keys();
let message = b"ecrecover me";

let (signature, recovery_id) =
    EcdsaSecp256k1::sign_recoverable(&private_key, message).unwrap();

let recovered =
    EcdsaSecp256k1::recover_public_key(message, &signature, recovery_id).unwrap();

assert_eq!(recovered, public_key);
```

See [Public-Key Recovery](../features/recovery.md) for the full mechanics
and its security caveats.

## How to Use

### Typed API (ordinary sign/verify)

```rust
use SignetDSA::algo::ecdsa_secp256k1::EcdsaSecp256k1;
use SignetDSA::Signature;

let (private_key, public_key) = EcdsaSecp256k1::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = EcdsaSecp256k1::sign(&private_key, message).expect("signing failed");
assert!(EcdsaSecp256k1::verify(&public_key, message, &signature).unwrap());
```

Keys and signatures are the same fixed widths as P-256: a 32-byte private
scalar, a 33-byte SEC1-compressed public point, a 64-byte `(r, s)`
signature — plus the extra 1-byte recovery id when using
`sign_recoverable`/`recover_public_key`.

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("ecdsa-secp256k1").unwrap(); // alias: "secp256k1"
let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

!!! note "No recovery through the factory"
    `SignetSigner` only exposes ordinary sign/verify. `sign_recoverable` and
    `recover_public_key` are inherent associated functions on
    `EcdsaSecp256k1` itself — call the typed API directly to use them.

## Errors

`EcdsaSecp256k1::Error` is `EcdsaSecp256k1Error`, with variants for signing
failure, invalid signature encoding, an out-of-range recovery id,
verification failure, and recovery failure.

## When to Use

Use this over [ECDSA (P-256)](ecdsa.md) specifically when interoperating
with Bitcoin- or Ethereum-adjacent systems that expect secp256k1. For new
designs with no such constraint, [Schnorr (BIP340)](schnorr.md) over the
same curve is deterministic and — through
[FROST](frost.md) — supports threshold signing, which plain ECDSA here does
not.
