# Digital Signatures, Intuition First

Before the algorithm pages get into curves, lattices, and pairings, it's
worth building the mental model those details all sit on top of. This page
has no code — just the idea, explained through the analogy this crate is
named after.

## The Signet Ring

A **signet ring** is a ring carved with a unique pattern. Press it into hot
wax at the bottom of a letter, and you get an impression anyone can look at.
Two things make this useful:

1. **Anyone who's seen your seal before can recognize it's yours again.**
   They don't need the ring itself — just a memory (or a public record) of
   what your impression looks like.
2. **Nobody without the ring can produce that impression.** Carving a
   convincing forgery by hand, from just looking at wax, is — for a
   sufficiently detailed pattern — impractically hard.

A digital signature is the same idea, minus the wax:

| Signet ring | Digital signature |
|---|---|
| The ring itself, kept in your pocket | The **private key** — never shared |
| The pattern it presses into wax | The **public key** — shared freely |
| Pressing the ring into wax on a letter | **Signing** a message |
| Comparing a new wax impression to what you remember | **Verifying** a signature |
| Someone tries to carve a fake ring from memory of the wax pattern | An attacker tries to **forge** a signature without the private key |

## Two Keys, One Relationship

Every algorithm in this crate generates a **key pair**: a private key and a
public key, mathematically linked such that:

- The public key can be *derived* from the private key.
- The private key **cannot** (practically) be derived back from the public
  key — that direction is the computationally hard part, and it's the
  entire reason any of this works. [Choosing an Algorithm](choosing_an_algorithm.md)
  tags each algorithm with which hard problem it leans on (factoring,
  discrete logarithms, lattices, pairings) — the [Glossary](glossary.md)
  defines each in one line, and each algorithm's own page has the actual
  math.
- Signing needs the private key. Verifying only ever needs the public key,
  the message, and the signature — never the private key. This asymmetry is
  the whole point: anyone can check a signature is genuine, but only the
  key's owner could have produced it.

```
generate_keys() -> (private_key, public_key)   # carve the ring
sign(private_key, message) -> signature         # press it into wax
verify(public_key, message, signature) -> bool  # compare to the known pattern
```

This is, almost verbatim, [`SignetDSA`'s `Signature` trait](../getting_started.md#core-concepts)
— every algorithm in this crate implements exactly these three operations,
under exactly this shape.

## Why Sign a Digest, Not the Message

Most algorithms here don't feed your message directly into the hard math —
they first run it through a cryptographic hash function (like SHA-256) to
produce a short, fixed-size **digest**, and sign *that*. A hash function
takes an input of any length and deterministically produces a small,
fixed-size fingerprint, with the property that finding two different inputs
that hash to the same fingerprint is itself computationally infeasible.

This matters for two reasons:

- **Efficiency.** The underlying signature math (modular exponentiation,
  elliptic-curve point operations) is far more expensive per byte than
  hashing. Signing a 32-byte digest costs the same regardless of whether
  the original message was 10 bytes or 10 gigabytes.
- **Safety.** Signing a fixed-size digest sidesteps a class of subtle
  attacks that can arise from feeding variable-length, attacker-influenced
  data directly into certain signature constructions.

Not every algorithm here delegates hashing to the *caller* the same way,
though — this is worth being precise about, because getting it wrong is a
real bug this crate has actually shipped and fixed:

- [RSA](../algorithms/rsa.md) and [DSA](../algorithms/dsa.md) sign a
  SHA-256 digest computed up front, exactly as described above.
- [Ed25519](../algorithms/eddsa.md), [Ed448](../algorithms/ed448.md), and
  [Schnorr (BIP340)](../algorithms/schnorr.md) instead feed the **message
  itself** into their own internal hashing as part of the signature
  algorithm's definition — pre-hashing it yourself and signing *that*
  digest instead would silently produce a non-standard, non-interoperable
  variant. That's exactly the bug [Schnorr's own page](../algorithms/schnorr.md#bip340-conformance)
  documents: an earlier version of this crate did an extra, incorrect hash
  before applying BIP340's own hashing, which was self-consistent (signing
  and verifying agreed with each other) but not actually BIP340.

The lesson generalizes beyond this crate: "hash-then-sign" is a common
pattern, not a universal rule — always check what a specific algorithm's
specification actually says to hash.

## Why You Can Trust a Verified Signature

Verification succeeding tells you two specific things, and — this is the
part worth being precise about — nothing more:

1. **Authenticity** — whoever holds the private key that matches this
   public key produced this signature.
2. **Integrity** — the exact message you're checking is the exact message
   that was signed; change even one bit and verification fails.

It does **not** tell you:

- *who* the key belongs to, unless you've independently confirmed that (a
  certificate, a prior registration, an on-chain address — see
  [Public-Key Recovery](../features/recovery.md) for a case where this
  distinction is especially important).
- that the message is *true*, only that it's *unmodified* and came from
  that key.
- anything about *when* it was signed, unless the message itself contains a
  timestamp.

## Determinism: Does Signing Need Randomness?

Some algorithms here need a fresh random number (a **nonce**) every single
time they sign, even for the exact same message and key twice. Others are
**deterministic** — same key, same message, always the same signature,
because the "randomness" is instead derived mathematically from the key and
message themselves.

This isn't a stylistic detail. For the algorithms that need a fresh nonce
per signature ([DSA](../algorithms/dsa.md),
[ECDSA](../algorithms/ecdsa.md)/[secp256k1](../algorithms/ecdsa_secp256k1.md)),
reusing that nonce across two different signed messages leaks the private
key directly — not "weakens" it, *leaks it outright*, from simple algebra
on the two signatures. The deterministic algorithms
([EdDSA](../algorithms/eddsa.md), [Ed448](../algorithms/ed448.md),
[Schnorr](../algorithms/schnorr.md), [BLS](../algorithms/bls.md)) remove
this entire risk by construction — there's no fresh randomness to
accidentally reuse. See [Choosing an Algorithm](choosing_an_algorithm.md)'s
comparison table for which is which.

## What's Next

- **[Choosing an Algorithm](choosing_an_algorithm.md)** — now that the shared
  shape makes sense, see how the nine algorithms actually differ
- **[Glossary](glossary.md)** — one-line definitions for every term used
  across these docs (digest, nonce, curve, pairing, lattice, and more)
- **[Getting Started](../getting_started.md)** — the same three operations,
  now in actual Rust
