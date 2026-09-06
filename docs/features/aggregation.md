# BLS Aggregation

[BLS](../algorithms/bls.md) signatures over pairing-friendly curves have a
property no other algorithm in this crate has: many signatures — over many
**distinct** messages, from many different signers — collapse into a
single aggregate signature the same size as one individual signature, and
that one aggregate can be verified against the full list of
`(message, public key)` pairs in a single pairing check.

`SignetDSA::algo::bls::Bls` exposes this as two associated functions
alongside its ordinary `Signature` trait implementation.

## Usage

```rust
use SignetDSA::algo::bls::Bls;
use SignetDSA::Signature;

// Three independent signers, each signing their own distinct message.
let signers: Vec<_> = (0..3).map(|_| Bls::generate_keys()).collect();
let messages: [&[u8]; 3] = [b"alice's message", b"bob's message", b"carol's message"];

let signatures: Vec<Vec<u8>> = signers
    .iter()
    .zip(messages.iter())
    .map(|((sk, _), msg)| Bls::sign(sk, msg).unwrap())
    .collect();

// Combine all three into one aggregate signature.
let aggregate_signature = Bls::aggregate_signatures(&signatures).unwrap();

// Verify the aggregate against all three (message, public_key) pairs at once.
let public_keys: Vec<Vec<u8>> = signers.iter().map(|(_, pk)| pk.as_bytes()).collect();
let valid = Bls::verify_aggregated(&aggregate_signature, &messages, &public_keys).unwrap();
assert!(valid);
```

`aggregate_signatures` takes any non-empty slice of individually-produced
signatures and combines them; it doesn't need to know who signed what.
`verify_aggregated` takes the aggregate plus the parallel lists of messages
and public keys it claims to cover, and does need those lists in matching
order.

## Rogue Public-Key Attacks

Aggregation is only safe under specific conditions, and getting this wrong
is a well-known, real-world class of BLS vulnerability — worth understanding
before reaching for this feature.

The problem: if an attacker can choose their own public key *after* seeing
another signer's honest public key, they can construct a key that makes an
aggregate signature verify successfully even though they never actually
signed the message they're claiming to have co-signed. This is the "rogue
key" attack described in
[§3.1 of the IRTF BLS signature draft](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1).

There are two standard defenses:

1. **Require every signer to sign a distinct message.** This is what
   `verify_aggregated` is built for, and the `bls-signatures` crate
   underneath **enforces it by construction** — it refuses to verify an
   aggregate if any two messages in the batch coincide, rather than
   silently allowing it:

    ```rust
    // All three signers sign the SAME message — a common multisig pattern —
    // and the crate rejects verifying the aggregate outright:
    let messages = [message; 3];
    let result = Bls::verify_aggregated(&aggregate_signature, &messages, &public_keys);
    assert!(result.is_err());
    ```

2. **Require a proof-of-possession for same-message multisig.** If every
   signer genuinely needs to approve the *same* message (a governance vote,
   a co-signed transaction), each public key must first be authenticated
   via a proof-of-possession protocol, so an attacker can no longer choose
   a key adversarially in response to others' honest keys.

!!! danger "This crate does not implement proof-of-possession"
    `Bls::aggregate_signatures`/`verify_aggregated` only provide defense #1
    (the distinct-message enforcement above). Same-message multisig needs
    defense #2, which this crate does not provide. Do not attempt to work
    around the distinct-message rejection (for example, by appending a
    per-signer nonce to an otherwise-shared message) as a substitute for
    real proof-of-possession — that changes what each signer is
    cryptographically attesting to, and needs its own careful protocol
    design, not a workaround here.

## Not Part of the Factory

`aggregate_signatures` and `verify_aggregated` are inherent associated
functions on `Bls`, not part of `SignetSigner` — they aren't reachable
through `Signet::from_name`. See [Factory API](factory.md).
