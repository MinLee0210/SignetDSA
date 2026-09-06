# Getting Started

## Installation

SignetDSA isn't published on crates.io yet — depend on it directly from the
repository:

=== "Git dependency"

    ```toml
    [dependencies]
    SignetDSA = { git = "https://github.com/MinLee0210/SignetDSA" }
    ```

=== "Path dependency (local checkout)"

    ```toml
    [dependencies]
    SignetDSA = { path = "../SignetDSA" }
    ```

=== "From source"

    ```bash
    git clone https://github.com/MinLee0210/SignetDSA.git
    cd SignetDSA
    cargo build
    cargo test
    ```

!!! note "Crate name casing"
    The crate is named `SignetDSA` (capitalized, matching the package name in
    `Cargo.toml`) rather than the conventional `snake_case` — that's an
    intentional brand name, not an oversight, and `src/lib.rs` explicitly
    allows it with `#![allow(non_snake_case)]`.

## Core Concepts

Every algorithm implements the same generic [`Signature`](https://docs.rs/SignetDSA) trait:

| Step | Method | What it does |
|---|---|---|
| 1. Generate | `generate_keys()` | Create a fresh `(private_key, public_key)` pair |
| 2. Sign | `sign(private_key, message)` | Produce a signature over `message` |
| 3. Verify | `verify(public_key, message, signature)` | Check that `signature` covers `message` under `public_key` |

```rust
pub trait Signature {
    type PrivateKey;
    type PublicKey;
    type Error;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey);
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn verify(public_key: &Self::PublicKey, message: &[u8], signature: &[u8]) -> Result<bool, Self::Error>;
}
```

Each algorithm also defines its **own** `PrivateKey`/`PublicKey`/`Error` types
— an `Ecdsa::PrivateKey` and an `EdDsa::PrivateKey` are unrelated Rust types,
so mixing up which key belongs to which algorithm is a compile error, not a
runtime one.

## Your First Signature

```rust
use SignetDSA::algo::ecdsa::Ecdsa;
use SignetDSA::Signature;

let (private_key, public_key) = Ecdsa::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = Ecdsa::sign(&private_key, message).expect("signing failed");
let valid = Ecdsa::verify(&public_key, message, &signature).expect("verification failed");

assert!(valid);
```

Swap `Ecdsa` for any other algorithm's type (`Rsa`, `Dsa`, `EdDsa`, `Ed448`,
`Schnorr`, `EcdsaSecp256k1`, `MlDsa`, `Bls`) and the same three calls work
identically — that uniformity is the whole point of the typed API.

## Selecting an Algorithm at Runtime

When the algorithm is a string that arrives at runtime (a config file, a CLI
flag, a database column), use the factory instead:

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("ecdsa").expect("Unknown algorithm");

let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

`SignetSigner` is [object-safe](https://doc.rust-lang.org/reference/items/traits.html#object-safety)
— unlike `Signature`, whose associated types make `Box<dyn Signature>`
impossible to write — by using `Vec<u8>` for every key and signature instead
of per-algorithm types. See [Factory API](features/factory.md) for the full
list of names and aliases, and why the two traits exist side by side.

## What's Next?

- **[Digital Signatures, Intuition First](learn/intuition.md)** — the concepts
  above, explained from scratch, if any of them felt hand-wavy
- **[Choosing an Algorithm](learn/choosing_an_algorithm.md)** — which of the nine fits your use case
- **[RSA](algorithms/rsa.md)**, **[EdDSA](algorithms/eddsa.md)**, **[Schnorr](algorithms/schnorr.md)** — start with a classical algorithm
- **[FROST](algorithms/frost.md)** — threshold signing, if no single party should hold the full key
- **[BLS](algorithms/bls.md)** — aggregate signatures, if you need to compress many signatures into one
- **[CLI](cli.md)** — sign and verify from the shell without writing any Rust
