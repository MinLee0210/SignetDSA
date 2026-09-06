# Glossary

One-line definitions for terms used across these docs, grouped by theme.
Each links to where it's covered in depth.

## Core Concepts

**Private key**
: The secret half of a key pair. Only its holder can produce valid
signatures under it. Never shared, never logged, and — at the
[factory API](../features/factory.md) layer — actively zeroized from memory
once dropped.

**Public key**
: The shareable half of a key pair, derived from the private key. Anyone
holding it can verify signatures, but cannot forge one or recover the
private key from it.

**Digest / hash**
: A fixed-size fingerprint of an arbitrary-length input, produced by a hash
function (SHA-256 throughout this crate, except where an algorithm's own
spec calls for something else). See
[Why Sign a Digest, Not the Message](intuition.md#why-sign-a-digest-not-the-message).

**Nonce**
: A number used once — specifically, the per-signature random value some
algorithms need. Reusing it across two signatures with the same key leaks
the private key outright for [DSA](../algorithms/dsa.md) and
[ECDSA](../algorithms/ecdsa.md). See
[Determinism](intuition.md#determinism-does-signing-need-randomness).

**Deterministic signature**
: A signature scheme where the same key and message always produce the
same signature, because its "randomness" is derived mathematically instead
of generated fresh each time — [EdDSA](../algorithms/eddsa.md),
[Ed448](../algorithms/ed448.md), [Schnorr](../algorithms/schnorr.md), and
[BLS](../algorithms/bls.md) all work this way.

**Known-answer test (KAT)**
: A test that checks an implementation's output against fixed,
pre-computed values from an independent source (typically the official
specification), rather than only checking that the implementation agrees
with itself. See [Security & Interoperability](../security.md#interoperability-verified-against-official-test-vectors).

## Hard Problems (What Makes Forgery Hard)

Each of these is a computational problem believed to have no efficient
solution — every algorithm here rests its security on one of them. See
[Choosing an Algorithm](choosing_an_algorithm.md) for which algorithm uses
which.

**Integer factorization**
: Given a large number that's the product of two large primes, finding
those primes. [RSA](../algorithms/rsa.md)'s hard problem.

**Discrete logarithm problem (DLP)**
: Given $g$ and $g^x$ in some group, finding $x$. Underlies
[DSA](../algorithms/dsa.md) (over a finite field) and every elliptic-curve
algorithm here (over a curve group): [ECDSA](../algorithms/ecdsa.md),
[ECDSA/secp256k1](../algorithms/ecdsa_secp256k1.md),
[EdDSA](../algorithms/eddsa.md), [Ed448](../algorithms/ed448.md),
[Schnorr](../algorithms/schnorr.md), and [FROST](../algorithms/frost.md).

**Elliptic curve**
: A curve group used in place of the finite-field group DSA uses — the
same discrete-log hardness, but with much smaller keys for equivalent
security, which is why every curve-based algorithm here has keys measured
in tens of bytes rather than DSA/RSA's hundreds.

**Pairing (bilinear pairing)**
: A special map between elliptic-curve groups that lets you check a
relationship between values *without* knowing the underlying private
values — the mechanism [BLS](../algorithms/bls.md) verification and
[aggregation](../features/aggregation.md) rely on. Slower per-operation than
plain curve math, which is the tradeoff for what pairings make possible.

**Lattice / MLWE**
: A geometric structure in high-dimensional space; **Module Learning With
Errors** is a hard problem defined over lattices, believed to resist
attacks from quantum computers — unlike factorization or discrete logs,
both of which [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
breaks. [ML-DSA](../algorithms/mldsa.md)'s hard problem.

## Encoding Formats

**DER (Distinguished Encoding Rules)**
: A binary encoding for structured data (keys, signatures) — compact, but
not human-readable.

**PEM**
: A base64-text wrapper around DER data, delimited by
`-----BEGIN ...-----`/`-----END ...-----` lines — the format
[PEM/DER Import-Export](../features/pem.md) produces and reads.

**PKCS#8 / SPKI**
: The modern, algorithm-agnostic standard formats for private keys
(PKCS#8, `-----BEGIN PRIVATE KEY-----`) and public keys (SPKI,
`-----BEGIN PUBLIC KEY-----`) — what this crate's
[PEM helpers](../features/pem.md) always produce, as opposed to older
algorithm-specific formats like RSA's traditional PKCS#1
(`-----BEGIN RSA PRIVATE KEY-----`).

**SEC1 compressed point**
: A compact encoding for an elliptic-curve public key: the $x$-coordinate
plus one bit for which of the two possible $y$-values it has (33 bytes for
a 256-bit curve) — used by [ECDSA (P-256)](../algorithms/ecdsa.md) and
[ECDSA (secp256k1)](../algorithms/ecdsa_secp256k1.md).

**x-only public key**
: [Schnorr (BIP340)](../algorithms/schnorr.md)'s public key format — just
the $x$-coordinate, 32 bytes, with no sign bit at all (BIP340 fixes a
convention for which $y$-value is implied instead).

## Advanced Features

**Threshold signature**
: A scheme where `t` out of `n` participants must cooperate to produce a
valid signature, and no `t - 1` of them can — see [FROST](../algorithms/frost.md).

**Aggregation**
: Combining many individual signatures into one, verifiable as a group —
see [BLS Aggregation](../features/aggregation.md).

**Rogue public-key attack**
: An attack where a participant chooses their public key *after* seeing
another signer's honest public key, specifically to make a forged
aggregate signature verify. See
[BLS Aggregation § Rogue Public-Key Attacks](../features/aggregation.md#rogue-public-key-attacks).

**Proof-of-possession**
: A mechanism proving a party actually knows the private key behind a
public key they're presenting — the missing piece needed for safe
same-message [BLS](../algorithms/bls.md) multisig, which this crate does
not implement.

**Public-key recovery (`ecrecover`)**
: Reconstructing a signer's public key from just their message, signature,
and a small recovery id — no public key transmitted separately. See
[Public-Key Recovery](../features/recovery.md).

**Batch verification**
: Checking many `(message, public key, signature)` triples in one call,
faster than one at a time but without identifying which one failed if the
batch is invalid. See [Batch Verification](../features/batch_verification.md).

## Testing & Security

**RUSTSEC advisory**
: A published entry in the [RustSec Advisory Database](https://rustsec.org/)
describing a known vulnerability, unsoundness, or maintenance issue in a
Rust crate. See [Security & Interoperability](../security.md) for the
advisories tracked against this crate's own dependencies.

**Timing side-channel**
: A vulnerability where the *time* an operation takes leaks information
about secret data, even though the operation's output alone reveals
nothing — the class of issue behind both RSA's and (pre-`0.1.0-rc.3`)
ML-DSA's tracked advisories. See [Security & Interoperability](../security.md#known-limitations).
