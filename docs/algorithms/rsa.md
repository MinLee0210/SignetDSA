# RSA

**RSA** is the oldest public-key signature scheme in this crate, based on the
difficulty of factoring large integers. SignetDSA uses 2048-bit keys with
**PKCS#1 v1.5** padding and **SHA-256**, via the [`rsa`](https://docs.rs/rsa) crate.

!!! warning "Known limitation"
    The underlying `rsa` crate carries an open, unfixed advisory,
    [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
    ("Marvin Attack"), covering timing side-channels in signing/decryption.
    It's only exploitable by an attacker who can measure signing latency
    (over a shared network, or as a co-tenant on the same machine) — local,
    non-adversarial use is unaffected. Avoid RSA here if that threat applies
    to you; prefer [ECDSA](ecdsa.md), [EdDSA](eddsa.md), or [Schnorr](schnorr.md)
    otherwise. See [Security & Interoperability](../security.md) for the full
    list of advisories tracked in this crate.

## The Algorithm

RSA signing computes $s = m^d \bmod n$ where $d$ is the private exponent and
$n$ the modulus; verification checks $s^e \bmod n$ recovers the expected
padded message, where $e$ is the public exponent. PKCS#1 v1.5 padding wraps
the SHA-256 digest of the message in a fixed structure before this
exponentiation, so that a valid padded value can't easily be forged without
knowing $d$.

## How to Use

### Typed API

```rust
use SignetDSA::algo::rsa::Rsa;
use SignetDSA::Signature;

let (private_key, public_key) = Rsa::generate_keys(); // ~seconds — 2048-bit keygen isn't free
let message = b"Hello, SignetDSA!";

let signature = Rsa::sign(&private_key, message).expect("signing failed");
assert!(Rsa::verify(&public_key, message, &signature).unwrap());
```

!!! tip "Key generation is slow"
    Generating a 2048-bit RSA keypair takes noticeably longer than any
    elliptic-curve algorithm in this crate — expect low seconds, not
    milliseconds. Don't call `generate_keys()` in a hot loop.

### PEM Import/Export

```rust
use SignetDSA::algo::rsa::Rsa;

let (private_key, public_key) = Rsa::generate_keys();

let private_pem = Rsa::private_key_to_pem(&private_key).unwrap();
let public_pem = Rsa::public_key_to_pem(&public_key).unwrap();

let restored_private = Rsa::private_key_from_pem(&private_pem).unwrap();
let restored_public = Rsa::public_key_from_pem(&public_pem).unwrap();
```

!!! note "PKCS#8, not PKCS#1, PEM"
    `private_key_to_pem` produces a `-----BEGIN PRIVATE KEY-----` (PKCS#8)
    document, not the RSA-specific `-----BEGIN RSA PRIVATE KEY-----`
    (PKCS#1) header some older tools expect. PKCS#8 is algorithm-agnostic —
    the same header is used by [DSA](dsa.md), [ECDSA](ecdsa.md), and
    [EdDSA](eddsa.md) here — and is what modern `openssl genpkey` produces
    by default. This is purely about how the *key* is encoded on disk; the
    *signature* itself still uses PKCS#1 v1.5 padding as described above.
    See [PEM/DER Import-Export](../features/pem.md) for the shared design
    across all four PEM-capable algorithms.

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("rsa").unwrap();
let (sk, pk) = signer.generate_keys(); // sk: Zeroizing<Vec<u8>> (PKCS#1 DER), pk: Vec<u8> (PKCS#1 DER)
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

The factory adapter serializes keys as **PKCS#1 DER** (not PKCS#8) — a
different, more compact wire format than the typed API's PEM helpers above.
The two aren't required to agree; each API layer picks the encoding that
suits it.

## Errors

`Rsa::Error` is `RsaError`, with variants for key generation failure,
signing failure, invalid signature encoding, verification failure, and PEM
encode/decode errors for both private and public keys.
