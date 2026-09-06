# BLS

**BLS signatures over BLS12-381** (the "basic"
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` ciphersuite — public keys in
G1, signatures in G2) are pairing-based signatures whose defining feature is
**aggregation**: many signatures collapse into one the same size as a single
signature, verifiable against the full list of `(message, public key)` pairs
in one pairing check. SignetDSA uses
[`bls-signatures`](https://docs.rs/bls-signatures) (the pure-Rust
`pairing`/`bls12_381` backend, not `blst`, to avoid a C build dependency).

## The Algorithm

Public keys live in $\mathbb{G}_1$, signatures in $\mathbb{G}_2$ — two
distinct elliptic-curve groups over which a special bilinear **pairing**
$e(\cdot, \cdot)$ is defined, satisfying $e(aP, bQ) = e(P, Q)^{ab}$ for any
scalars $a, b$. Given generator $G_1 \in \mathbb{G}_1$ and private key $sk$,
the public key is $PK = sk \cdot G_1$. Signing hashes the message directly
onto a point in $\mathbb{G}_2$ (not a fixed-size digest first, unlike every
other algorithm in this crate) and scales it by the private key:

$$
\sigma = sk \cdot H(m) \qquad \text{where } H(m) \in \mathbb{G}_2
$$

Verification exploits the pairing's bilinearity — both sides below equal
$e(G_1, H(m))^{sk}$ if and only if $\sigma$ was really produced by the
holder of $PK$, without either side ever containing $sk$ in the clear:

$$
e(G_1, \sigma) \stackrel{?}{=} e(PK, H(m))
$$

Aggregation ([below](#pseudocode)) is a direct consequence of this
structure: signatures in the same group ($\mathbb{G}_2$) can simply be
added together, and the pairing equation above generalizes to a product
over every signer.

## Ordinary Sign/Verify

`Bls` implements the same [`Signature`](../getting_started.md#core-concepts)
trait every other algorithm here does, for the single-key case:

```rust
use SignetDSA::algo::bls::Bls;
use SignetDSA::Signature;

let (private_key, public_key) = Bls::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = Bls::sign(&private_key, message).expect("signing failed");
assert!(Bls::verify(&public_key, message, &signature).unwrap());
```

Keys and signatures are fixed-width: a 32-byte private scalar, a 48-byte
compressed G1 public key, and a 96-byte compressed G2 signature.

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("bls").unwrap(); // alias: "bls12-381"
let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

## Aggregation

What sets BLS apart — combining many signatures into one, and verifying
that one aggregate in a single check — is covered in full on the
[BLS Aggregation](../features/aggregation.md) feature page, including the
rogue public-key attack this crate's aggregation deliberately guards
against.

!!! danger "Read the aggregation page before aggregating"
    BLS aggregation is only safe under specific conditions — the underlying
    crate enforces one of them (rejecting repeated messages) but the other
    (proof-of-possession for same-message multisig) isn't provided by this
    crate at all. See [BLS Aggregation](../features/aggregation.md) and this
    module's own `# Rogue public-key attacks` doc comment before using it
    for anything beyond the distinct-message case.

## Pseudocode

```text
KeyGen():
    sk <- random scalar
    PK <- sk * G1
    return (sk, PK)

Sign(sk, message):
    H  <- HashToCurveG2(message)        # maps message directly onto a G2 point
    sig <- sk * H
    return sig

Verify(PK, message, sig):
    H <- HashToCurveG2(message)
    return pairing(G1, sig) == pairing(PK, H)

Aggregate(sig_1, ..., sig_t):
    return sig_1 + sig_2 + ... + sig_t   # simple point addition in G2

VerifyAggregated(aggregate_sig, [(message_1, PK_1), ..., (message_t, PK_t)]):
    if any two message_i are equal: reject     # rogue-key countermeasure — see
                                                 # BLS Aggregation § Rogue Public-Key Attacks
    lhs <- pairing(G1, aggregate_sig)
    rhs <- pairing(PK_1, HashToCurveG2(message_1))
         * pairing(PK_2, HashToCurveG2(message_2))
         * ...
         * pairing(PK_t, HashToCurveG2(message_t))
    return lhs == rhs
```

## Complexity

| Operation | Cost | Why |
|---|---|---|
| KeyGen | $O(\log n)$ group operations in $\mathbb{G}_1$ | One scalar multiplication — $\mathbb{G}_1$ is the cheaper of the two groups, which is why public keys (not signatures) live there |
| Sign | Dominated by `HashToCurveG2` + one $\mathbb{G}_2$ scalar multiplication | Mapping an arbitrary message onto a valid curve point (the SWU map) costs roughly as much as several regular field operations, and $\mathbb{G}_2$ arithmetic itself is more expensive than $\mathbb{G}_1$'s (points are defined over a field *extension*) |
| Verify | Two pairings | Pairings are the single most expensive operation in this crate — commonly one to two orders of magnitude slower than an elliptic-curve scalar multiplication of comparable security level, dominated by a "Miller loop" plus a "final exponentiation" step |
| Aggregate | $O(t)$ point additions | Cheap — this is *why* aggregation is worth doing: combining signatures costs almost nothing |
| Verify (aggregate, $t$ **distinct** messages) | $t + 1$ pairings | Aggregation does **not** reduce pairing count below verifying each signature separately — see below |

The last row is worth being precise about, because it's easy to
over-claim: aggregating $t$ signatures over $t$ distinct messages into one
still costs $t + 1$ pairings to verify (one per message, plus one for the
aggregate side) — asymptotically the *same* work as $t$ separate ordinary
verifications, not $O(1)$. What aggregation buys you in this case is
**bandwidth and storage** (one signature instead of $t$), and a
constant-factor speedup from sharing the final-exponentiation step across
the batch — not a reduction in pairing count. The case that genuinely *is*
$O(1)$ regardless of $t$ — verifying one aggregate signature against **one
shared message** from $t$ signers — is exactly the case this crate's
distinct-message check refuses to let you use safely without
proof-of-possession; see [BLS Aggregation](../features/aggregation.md).

## Errors

`Bls::Error` is `BlsError`, with variants for invalid public key/signature
encoding, plain verification failure, an empty aggregation input, an
aggregation-library failure, and a mismatched message/public-key count for
aggregate verification.

## When to Use

Reach for BLS specifically when you need aggregation — many validators
each signing a distinct message, and a verifier who wants to check them all
in one operation instead of one-by-one (this is the pattern used by
Ethereum's consensus layer, among others). For ordinary single-signer use
with no aggregation need, a classical algorithm like [EdDSA](eddsa.md) is
simpler, faster to verify individually, and has a more mature Rust
implementation.
