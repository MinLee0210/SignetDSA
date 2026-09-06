# ML-DSA (Post-Quantum)

**ML-DSA-65** (CRYSTALS-Dilithium, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final))
is a post-quantum digital signature algorithm based on the hardness of
**Module Learning With Errors (MLWE)** — a lattice problem believed to
resist attacks from both classical *and* quantum computers, unlike every
other algorithm in this crate, all of which rely on integer factorization
or discrete logarithms that [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
would break. SignetDSA uses the [`ml-dsa`](https://docs.rs/ml-dsa) crate.

ML-DSA-65 targets **NIST Level 3** (~192-bit classical security).

!!! warning "Known limitation"
    The `ml-dsa` crate has not undergone an independent security audit.
    This crate pins `ml-dsa >= 0.1.0-rc.3` — earlier versions carry
    [RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144.html),
    a timing side-channel in the decompose step of signature generation
    that can leak signing-key data.

## The Size Tradeoff

Post-quantum security comes at a real cost in key and signature size —
worth seeing concretely:

| | ML-DSA-65 | Ed25519 (for comparison) |
|---|---|---|
| Public key | 1952 B | 32 B |
| Private key | 4032 B | 32 B |
| Signature | 3309 B | 64 B |

A single ML-DSA-65 signature is over **50× larger** than an Ed25519
signature. If bandwidth or storage is tightly constrained and quantum
resistance isn't an immediate requirement, a classical algorithm like
[EdDSA](eddsa.md) remains the more practical choice today.

## The Algorithm

ML-DSA works over polynomial rings $R_q = \mathbb{Z}_q[x]/(x^{256}+1)$
rather than integers or curve points. The private key is a pair of "small"
(short-coefficient) polynomial vectors $(s_1, s_2)$; the public key is a
matrix $A$ (derived deterministically from a public seed — effectively
free to store) together with:

$$
t = A s_1 + s_2
$$

Forging a signature requires either recovering $(s_1, s_2)$ from $(A, t)$
— the MLWE problem — or finding a *different* small $(s_1', s_2')$
satisfying the same equation, both believed computationally infeasible even
for a quantum computer. Signing uses **rejection sampling**: pick a random
short vector $y$, compute a commitment $w = Ay$, derive a challenge $c$ from
$(w, \text{message})$, and combine $z = y + cs_1$ — but only accept and
return $z$ if its coefficients stay within a bound; otherwise, discard
everything and retry with a fresh $y$. This bounded-coefficient requirement
is what keeps the signature from leaking information about $s_1$.

## Pseudocode

```text
KeyGen():
    seed       <- random bytes
    A          <- ExpandA(seed)            # pseudorandom matrix, k x l polynomials
    (s1, s2)   <- SampleShortVectors()      # small-coefficient secret vectors
    t          <- A * s1 + s2               # ring arithmetic (NTT-accelerated)
    return (private_key = (s1, s2, A), public_key = (A, t))

Sign(s1, s2, A, message):
    loop:
        y  <- SampleShortVector()           # fresh randomness every attempt
        w  <- A * y
        c  <- H(w, message)                 # challenge, derived from a commitment
        z  <- y + c * s1
        if coefficients of z exceed the bound: retry     # rejection sampling
    return (z, c)

Verify(A, t, message, (z, c)):
    if coefficients of z exceed the bound: return false
    w' <- A * z - c * t
    return H(w', message) == c
```

## Complexity

| Operation | Cost | Why |
|---|---|---|
| KeyGen | $O(k \cdot l \cdot n \log n)$ | Computing $t = As_1 + s_2$ is a matrix-vector product of polynomials, each multiplication done via the Number-Theoretic Transform (NTT) in $O(n \log n)$ instead of $O(n^2)$ schoolbook |
| Sign | Expected $O(c \cdot k \cdot l \cdot n \log n)$ | Same NTT-accelerated matrix-vector cost per attempt, repeated an expected small constant $c$ times (a handful of attempts for ML-DSA-65) due to rejection sampling |
| Verify | $O(k \cdot l \cdot n \log n)$ | One matrix-vector product, no rejection loop — verification never retries |

$n = 256$ is the polynomial ring dimension (fixed by the standard); $k = 6,
l = 5$ are ML-DSA-65's matrix dimensions. The NTT is the specific technique
that keeps lattice-based signing practical at all — without it, the
$O(n^2)$ schoolbook alternative would make every operation here meaningfully
slower, on top of the size overhead already documented above.

## How to Use

### Typed API

```rust
use SignetDSA::algo::mldsa::MlDsa;
use SignetDSA::Signature;

let (private_key, public_key) = MlDsa::generate_keys();
let message = b"Hello, SignetDSA!";

let signature = MlDsa::sign(&private_key, message).expect("signing failed");
assert!(MlDsa::verify(&public_key, message, &signature).unwrap());

assert_eq!(signature.len(), 3309);
```

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("mldsa").unwrap(); // aliases: "ml-dsa", "dilithium"
let (sk, pk) = signer.generate_keys();
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

## Errors

`MlDsa::Error` is `MlDsaError`, with variants for invalid signature
encoding and verification failure.

## When to Use

Use ML-DSA when you need to plan **now** for a threat model that includes
large-scale quantum computers within the lifetime of the data or system
being protected — this is often driven by "harvest now, decrypt later"
concerns for long-lived secrets, or by emerging compliance requirements
(NIST's post-quantum migration timelines). For everything else, a classical
algorithm elsewhere in this crate will be smaller, faster, and more mature.
