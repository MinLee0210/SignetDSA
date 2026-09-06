# Public-Key Recovery

[ECDSA (secp256k1)](../algorithms/ecdsa_secp256k1.md) exposes
`EcdsaSecp256k1::sign_recoverable`/`recover_public_key` — the `ecrecover`
pattern Ethereum uses to identify a transaction's sender from its signature
alone, with no public key transmitted alongside it.

## Why Recovery Is Possible at All

An ECDSA signature is a pair $(r, s)$ where $r$ is the $x$-coordinate of a
point $R = kG$ (for the signer's random nonce $k$) reduced modulo the curve
order. Reconstructing the full point $R$ from just its $x$-coordinate needs
one more bit (which of the two possible $y$-values it has), and — because
the field is larger than the curve order — occasionally one more bit beyond
that for values of $r$ that could correspond to a point at $r$ or at
$r + n$. Together, that's the 2-bit **recovery id** returned alongside the
signature. With $R$ reconstructed, the same equation the signer used to
compute $s$ can be solved for the public key instead of the private key.

## Usage

```rust
use SignetDSA::algo::ecdsa_secp256k1::EcdsaSecp256k1;

let (private_key, public_key) = EcdsaSecp256k1::generate_keys();
let message = b"ecrecover me";

let (signature, recovery_id) =
    EcdsaSecp256k1::sign_recoverable(&private_key, message).unwrap();

// Anyone with (message, signature, recovery_id) — no public key needed —
// can now recover the signer's public key:
let recovered =
    EcdsaSecp256k1::recover_public_key(message, &signature, recovery_id).unwrap();

assert_eq!(recovered, public_key);
```

`recovery_id` is a single byte in `0..=3`; `recover_public_key` rejects
anything outside that range as `EcdsaSecp256k1Error::InvalidRecoveryId`
before it ever reaches the curve math.

## What Recovery Does *Not* Give You

Recovery reconstructs *a* public key that is consistent with
`(message, signature, recovery_id)` — it does not, by itself, tell you
whether that public key is one you should trust. Feed it the wrong message
and you'll still get *a* public key back, just not the real signer's:

```rust
let tampered = b"not the signed message";
let recovered = EcdsaSecp256k1::recover_public_key(tampered, &signature, recovery_id).unwrap();
assert_ne!(recovered, public_key); // recovery "succeeds" — to the wrong key
```

Recovery is a convenience for **not having to transmit the public key**
when the verifier already has an independent way to decide whether the
recovered key is the one they expected (an on-chain address derived from
it, an allowlist, a prior registration) — it is not a substitute for that
check.

## Not Part of the Factory

`sign_recoverable` and `recover_public_key` are inherent associated
functions on `EcdsaSecp256k1`, not part of `SignetSigner` — they aren't
reachable through `Signet::from_name`. See [Factory API](factory.md).
