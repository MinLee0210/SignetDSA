# Batch Verification

[EdDSA (Ed25519)](../algorithms/eddsa.md) exposes `EdDsa::verify_batch`, a
single call that checks many `(message, public key, signature)` triples at
once — meaningfully faster than verifying each one individually, because
the underlying elliptic-curve operations can be combined across the whole
batch instead of repeated per signature.

## Usage

```rust
use SignetDSA::algo::eddsa::EdDsa;
use SignetDSA::Signature;

let keypairs: Vec<_> = (0..8).map(|_| EdDsa::generate_keys()).collect();
let messages: Vec<&[u8]> = vec![b"msg0", b"msg1", b"msg2", b"msg3",
                                 b"msg4", b"msg5", b"msg6", b"msg7"];

let signatures: Vec<Vec<u8>> = keypairs
    .iter()
    .zip(&messages)
    .map(|((sk, _), msg)| EdDsa::sign(sk, msg).unwrap())
    .collect();
let public_keys: Vec<_> = keypairs.iter().map(|(_, pk)| *pk).collect();

let valid = EdDsa::verify_batch(&messages, &signatures, &public_keys).unwrap();
assert!(valid);
```

## The Tradeoff: All-or-Nothing

`verify_batch` returns a single `Result<bool, EdDsaError>` for the *whole*
batch. If one signature in a batch of a thousand is invalid, the call fails
— but it doesn't tell you *which* one. If you need to identify the bad
signature (to reject just that one sender, say, rather than the whole
batch), fall back to verifying each triple individually with
`EdDsa::verify` once batch verification fails; don't try to bisect the batch
yourself unless you've measured that it's actually faster than the
straightforward one-at-a-time fallback for your batch sizes.

```rust
match EdDsa::verify_batch(&messages, &signatures, &public_keys) {
    Ok(true) => { /* all valid */ }
    _ => {
        // Fall back to individual checks to find which one failed.
        for (i, ((sk_pk, msg), sig)) in keypairs.iter().zip(&messages).zip(&signatures).enumerate() {
            let (_, pk) = sk_pk;
            if EdDsa::verify(pk, msg, sig).is_err() {
                eprintln!("signature {i} is invalid");
            }
        }
    }
}
```

## Why Only Ed25519

Batch verification is exposed here specifically because `ed25519-dalek`
provides a ready-made, well-tested `verify_batch` free function — this
crate's implementation is a thin wrapper around it, not new cryptographic
code. No other algorithm in this crate currently has an equivalent batch
API wired up.

## Not Part of the Factory

`verify_batch` is an inherent associated function on `EdDsa`, not part of
`SignetSigner` — it isn't reachable through `Signet::from_name`. See
[Factory API](factory.md) for what is and isn't covered by the factory.
