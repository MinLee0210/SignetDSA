# Schnorr (BIP340)

**Schnorr signatures over secp256k1**, following the
[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
standard used by Bitcoin Taproot, via the [`k256`](https://docs.rs/k256)
crate. Like [EdDSA](eddsa.md), BIP340 Schnorr is deterministic: signing the
same message with the same key always produces the same signature — a
stronger property than [ECDSA](ecdsa_secp256k1.md), which needs a fresh
random nonce every time.

Schnorr signatures are also the basis for [FROST](frost.md) threshold
signing: a FROST ceremony's output is an ordinary Schnorr signature, no
different from one produced by this module directly.

## BIP340 Conformance

This is worth stating precisely, because it was the subject of a real bug
this crate had and fixed.

Signing and verification go through k256's `PrehashSigner`/`PrehashVerifier`
(`sign_prehash`/`verify_prehash`) — which, despite the name, feed `message`
**directly** into the BIP340 tagged challenge hash exactly as the standard
specifies, with a fixed all-zero `aux_rand` for determinism.

k256 also exposes plain `Signer`/`Verifier` traits, which instead SHA-256
the message **first**, before applying the same underlying algorithm. That
variant is internally self-consistent (sign and verify agree with each
other) but is **not BIP340** — it would not validate against the official
BIP340 test vectors, and would not interoperate with a real Bitcoin Taproot
signature over the same message. This crate deliberately avoids that pair.

```rust
// What this crate uses — message fed directly into the challenge hash:
private_key.sign_prehash(message)?;
public_key.verify_prehash(message, &sig)?;

// What this crate does NOT use — message is SHA-256'd first, silently
// producing a signature that looks valid but isn't standard BIP340:
// private_key.sign(message);
// public_key.verify(message, &sig);
```

## Pseudocode

```text
KeyGen():
    d'  <- random in [1, n - 1]
    P   <- d' * G
    d   <- d'         if y-coordinate of P is even
         <- n - d'     otherwise            # BIP340: public key's y is always even
    return (private_key = d, public_key = x-coordinate of d*G)

Sign(d, message):                      # aux_rand fixed to 32 zero bytes in this crate
    t <- d XOR TaggedHash("BIP0340/aux", aux_rand)
    rand <- TaggedHash("BIP0340/nonce", t || public_key || message)
    k'  <- rand mod n
    R   <- k' * G
    k   <- k'         if y-coordinate of R is even
         <- n - k'     otherwise
    e   <- TaggedHash("BIP0340/challenge", R.x || public_key || message) mod n
    s   <- (k + e * d) mod n
    return (R.x, s)

Verify(public_key, message, (r, s)):
    e <- TaggedHash("BIP0340/challenge", r || public_key || message) mod n
    R <- s * G - e * P                 # P reconstructed from public_key (lift_x)
    return R is not the point at infinity
       and y-coordinate of R is even
       and R.x == r
```

`TaggedHash(tag, data) = SHA-256(SHA-256(tag) || SHA-256(tag) || data)` —
domain-separates each hash use so a value computed for one purpose (a
nonce, say) can never be replayed as if it were computed for another (a
challenge). This is exactly the mechanism [Schnorr's `# BIP340
conformance`](#bip340-conformance) section above depends on `message` being
fed into directly, rather than pre-hashed by the caller first.

## Complexity

| Operation | Cost | Why |
|---|---|---|
| KeyGen | $O(\log n)$ point operations | One fixed-base scalar multiplication $d'G$ |
| Sign | $O(\log n)$ point operations | One fixed-base scalar multiplication for the nonce point $R = k'G$; the rest is hashing and scalar arithmetic |
| Verify | $O(\log n)$ point operations | One multi-scalar multiplication $sG - eP$, comparable in cost to [ECDSA](ecdsa_secp256k1.md#pseudocode-complexity)'s verify equation |

$n$ is the secp256k1 curve order, fixed regardless of any input size — the
same "small, fixed number of point operations in practice" property
[ECDSA (P-256)](ecdsa.md#complexity) has.

## How to Use

### Typed API

```rust
use SignetDSA::algo::schnorr::Schnorr;
use SignetDSA::Signature;

let (private_key, public_key) = Schnorr::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = Schnorr::sign(&private_key, message).expect("signing failed");
assert!(Schnorr::verify(&public_key, message, &signature).unwrap());

// Determinism: signing twice gives the identical signature.
let signature2 = Schnorr::sign(&private_key, message).unwrap();
assert_eq!(signature, signature2);
```

Keys and signatures are fixed-width: a 32-byte private scalar, a 32-byte
x-only public key (BIP340 drops the y-coordinate's sign, unlike ECDSA's
33-byte compressed point), and a 64-byte signature.

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("schnorr").unwrap(); // alias: "bip340"
let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

## Interoperability

Verified against the **full official BIP340 CSV test vector suite**
(19 vectors, including its invalid-signature edge cases — a public key not
on the curve, a negated `s` value, non-canonical field elements, and more)
in [`tests/bip340_schnorr.rs`](https://github.com/MinLee0210/SignetDSA/blob/main/tests/bip340_schnorr.rs).
See [Security & Interoperability](../security.md).

## Errors

`Schnorr::Error` is `SchnorrError`, with variants for signing failure,
invalid signature encoding, and verification failure.

## When to Use

Use Schnorr over [ECDSA (secp256k1)](ecdsa_secp256k1.md) whenever you don't
specifically need ECDSA (e.g. Bitcoin Taproot compatibility, or wanting
determinism without switching curves). Use [FROST](frost.md) instead of
plain Schnorr if the private key should be split across multiple parties
rather than held by one.
