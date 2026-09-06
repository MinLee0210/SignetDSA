# Factory API (Signet)

The typed `Signature` trait (one page per algorithm — see
[Choosing an Algorithm](../learn/choosing_an_algorithm.md)) gives every algorithm
its own `PrivateKey`/`PublicKey`/`Error` types, checked at compile time. That
precision comes at a cost: you can't write `Box<dyn Signature>`, because
[associated types make a trait object-unsafe](https://doc.rust-lang.org/reference/items/traits.html#object-safety).
When the algorithm is only known at runtime — a config value, a CLI flag, a
database column — you need something else.

`Signet` is that something else: a factory, in the spirit of HuggingFace's
`AutoTokenizer.from_pretrained()`, that resolves a string to a boxed
`SignetSigner` trait object.

## The Object-Safe Trait

```rust
pub trait SignetSigner: Send + Sync {
    fn name(&self) -> &'static str;
    fn generate_keys(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>);
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String>;
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String>;
}
```

`SignetSigner` gets object safety by replacing every algorithm-specific type
with `Vec<u8>` (or, for the private key, `Zeroizing<Vec<u8>>` — see
[below](#private-keys-are-zeroized)) and every algorithm-specific error type
with `String`. Each adapter internally serializes to and deserializes from
its algorithm's native key/signature encoding; callers only ever see bytes.

## Usage

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("ecdsa").expect("Unknown algorithm");

let (private_key, public_key) = signer.generate_keys();
let signature = signer.sign(&private_key, b"Hello, world!").unwrap();
assert!(signer.verify(&public_key, b"Hello, world!", &signature).unwrap());
```

`Signet::from_name` is case-insensitive and returns `None` for an
unrecognized name rather than panicking.

## Names and Aliases

| Name | Aliases |
|---|---|
| `"rsa"` | — |
| `"dsa"` | — |
| `"ecdsa"` | `"p256"` |
| `"ecdsa-secp256k1"` | `"secp256k1"` |
| `"eddsa"` | `"ed25519"` |
| `"ed448"` | `"ed448-goldilocks"` |
| `"schnorr"` | `"bip340"` |
| `"mldsa"` | `"ml-dsa"`, `"dilithium"` |
| `"bls"` | `"bls12-381"` |

```rust
Signet::available();
// -> ["rsa", "dsa", "ecdsa", "ecdsa-secp256k1", "eddsa", "ed448", "schnorr", "mldsa", "bls"]
```

## What Isn't Here

[FROST](../algorithms/frost.md) (threshold signing) and
[BLS aggregation](aggregation.md) aren't reachable through `Signet` — a
multi-round threshold ceremony and an aggregate-many-signatures workflow
don't fit the factory's single-key sign/verify shape. Call
`SignetDSA::algo::frost` and `SignetDSA::algo::bls::Bls`'s aggregate
functions directly for those. Likewise,
[batch verification](batch_verification.md),
[public-key recovery](recovery.md), and [PEM import/export](pem.md) are
inherent associated functions on their respective typed structs (`EdDsa`,
`EcdsaSecp256k1`, and the four PEM-capable types), not part of
`SignetSigner` — the factory covers what every algorithm has in common,
nothing more.

## Private Keys Are Zeroized

`generate_keys()` wraps the private key in
[`Zeroizing<Vec<u8>>`](https://docs.rs/zeroize/latest/zeroize/struct.Zeroizing.html)
rather than a plain `Vec<u8>` — its backing memory is overwritten when it
goes out of scope, rather than left sitting in freed heap memory for an
attacker with memory access to potentially recover later. This applies at
the factory layer specifically; the typed API's own key types (a
`p256::ecdsa::SigningKey`, an `ed25519_dalek::SigningKey`, and so on) rely on
whatever zeroizing behavior their own crate provides.
