# FROST (Threshold Schnorr)

**FROST** (Flexible Round-Optimized Schnorr Threshold signatures) lets `t`
out of `n` participants collaboratively produce a [Schnorr](schnorr.md)
signature without any single party ever holding the complete private key —
the cryptographic foundation of modern multi-signature wallets. SignetDSA
uses [`frost-secp256k1`](https://docs.rs/frost-secp256k1).

!!! note "Not reachable through the `Signet` factory"
    FROST signing is a two-round interactive ceremony among multiple
    parties, not a single `sign(private_key, message)` call — it doesn't fit
    the object-safe `SignetSigner` shape the rest of this crate's factory
    relies on. `SignetDSA::algo::frost` deliberately does **not** implement
    the `Signature` trait either, for the same reason; it exposes the
    ceremony directly instead, so the multi-round structure stays visible
    rather than being hidden behind an API that implies a single function
    call.

## The Ceremony

1. **Key generation** — a (simulated, in this module) trusted dealer runs
   distributed key generation (DKG), splitting a group private key into `n`
   shares such that any `t` of them can reconstruct a valid signature, but
   no `t - 1` can.
2. **Round 1: Commit** — each of the `t` participating signers generates a
   nonce commitment and broadcasts it to the others.
3. **Round 2: Sign** — each participant, having received every commitment,
   computes a signature share from their own nonce and key share.
4. **Aggregate** — any party (a coordinator, or a public aggregator) combines
   the `t` signature shares into one standard Schnorr signature.
5. **Verify** — the result is an ordinary Schnorr signature over the group's
   public key. A verifier doesn't need to know — or care — that it was
   produced by a threshold ceremony rather than a single signer.

## Pseudocode

```text
# --- Key Generation (trusted dealer, simulated in this module) -----------
DKG(t, n):
    f(x) <- random polynomial of degree (t - 1), with f(0) = group_secret
    for i in 1..=n:
        share_i <- f(i)                       # this participant's secret share
        Y_i     <- share_i * G                # this participant's public verification share
    Y <- group_secret * G                     # group public key
    return ({share_i}, {Y_i}, Y)

# --- Round 1: each of the t signing participants, independently ----------
Commit(i):
    d_i, e_i <- two random scalars            # "hiding" and "binding" nonces
    D_i, E_i <- d_i * G, e_i * G
    broadcast (D_i, E_i)
    keep (d_i, e_i) secret, locally, until Round 2

# --- Round 2: each participant, after receiving all t commitments --------
Sign(i, share_i, message, all_commitments):
    for each participant j in the signing set:
        rho_j <- H(j, message, all_commitments)     # binding factor
    R <- sum_j (D_j + rho_j * E_j)             # group nonce commitment
    c <- H(R, Y, message)                      # standard Schnorr challenge
    lambda_i <- LagrangeCoefficient(i, signing_set)
    z_i <- d_i + (e_i * rho_i) + (lambda_i * share_i * c)
    return z_i

# --- Aggregation: any party, once it has every z_i ------------------------
Aggregate({z_i}, R):
    z <- sum_i z_i
    return (R, z)                              # an ordinary Schnorr signature
```

## Complexity

| Phase | Cost | Why |
|---|---|---|
| DKG | $O(n \cdot t)$ | Each of $n$ participants' share and verification data comes from evaluating/committing a degree-$(t-1)$ polynomial |
| Round 1 (Commit) | $O(1)$ per participant | Two scalar multiplications ($d_iG$, $e_iG$), independent of both $t$ and $n$ |
| Round 2 (Sign) | $O(t)$ per participant | Computing every binding factor $\rho_j$ requires processing all $t$ commitments, even though each participant only contributes one share |
| Aggregate | $O(t^2)$ naively, $O(t)$ with shared precomputation | Summing $t$ shares is $O(t)$, but each Lagrange coefficient $\lambda_i$ itself costs $O(t)$ to compute from the signing set — $t$ coefficients, each $O(t)$, is $O(t^2)$ unless those coefficients are precomputed once and reused |

Compare this to plain [Schnorr](schnorr.md#complexity): a single signer
there does one $O(\log n)$-point-operation multiplication and is done. The
entire point of paying FROST's extra $O(t)$-ish coordination cost across two
rounds is that no participant — and no coalition smaller than $t$ of
them — ever reconstructs the full private key at any point in the process.

## How to Use

```rust
use SignetDSA::algo::frost;

let message = b"Hello, SignetDSA!";

// 2-of-3: any 2 of the 3 participants can produce a valid signature.
let valid = frost::ceremony_2_of_3(message).expect("FROST ceremony failed");
assert!(valid);

// Or pick your own threshold and group size:
let valid = frost::ceremony(3, 5, message).expect("FROST ceremony failed");
assert!(valid);
```

`ceremony(min_signers, max_signers, message)` runs the full flow above in
one call and returns whether the resulting aggregated signature verifies.
`ceremony_2_of_3` is a convenience alias for `ceremony(2, 3, message)`.

!!! warning "This module simulates all participants in one process"
    In production, each participant would run their part of the DKG and
    signing rounds independently and exchange only commitments and shares
    over a secure channel — never their private key material. This module
    runs every step in a single process for demonstration and testing; treat
    it as a reference for the protocol shape, not a production multi-party
    deployment.

## Errors

`ceremony`/`ceremony_2_of_3` return `Result<bool, frost::Error>`, where
`frost::Error` comes directly from the `frost-secp256k1` crate.

## When to Use

Use FROST instead of plain [Schnorr](schnorr.md) whenever no single party
should be trusted with the complete private key — custody splits, co-signing
policies, or reducing the blast radius of any one compromised device. FROST
produces one signature that *is* the group's approval; it isn't the right
tool if you instead want to keep each signer's individual signature
distinguishable — for that, see [BLS](bls.md)'s aggregation, which combines
already-independent signatures rather than jointly producing one.
