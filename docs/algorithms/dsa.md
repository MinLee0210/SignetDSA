# DSA

**DSA** (Digital Signature Algorithm) is the classical discrete-log signature
scheme standardized in FIPS 186. SignetDSA uses 2048-bit parameters (a
2048-bit modulus $p$, 256-bit subgroup order $q$) with **SHA-256**, via the
[`dsa`](https://docs.rs/dsa) crate.

## The Algorithm

Given domain parameters $(p, q, g)$ and private key $x$, the public key is
$y = g^x \bmod p$. Signing a message digest $H(m)$ picks a per-signature
random nonce $k$ and computes:

$$
r = (g^k \bmod p) \bmod q \qquad s = k^{-1}(H(m) + xr) \bmod q
$$

The signature is the pair $(r, s)$. Verification recomputes $r$ from $(s, y,
H(m))$ and checks it matches.

!!! danger "Nonce reuse breaks everything"
    If the same nonce $k$ is ever reused across two different messages
    signed with the same key, the private key $x$ can be recovered directly
    from the two signatures. SignetDSA relies on the `dsa` crate's own
    nonce generation for this — it doesn't add its own nonce derivation on
    top.

## Pseudocode

```text
KeyGen(k, n):                           # k = modulus bits (2048), n = subgroup bits (256)
    p, q  <- primes such that p is k bits, q is n bits, and q divides (p - 1)
    g     <- element of order q in (Z/pZ)*        # generator of the subgroup
    x     <- random in [1, q - 1]                  # private key
    y     <- g^x mod p                             # public key
    return (private_key = x, public_key = y, params = (p, q, g))

Sign(private_key = x, params = (p, q, g), message):
    digest <- SHA-256(message)
    loop:
        k_nonce <- random in [1, q - 1]            # MUST be fresh every call
        r <- (g^k_nonce mod p) mod q
        if r == 0: retry
        s <- k_nonce^-1 * (digest + x * r) mod q
        if s == 0: retry
    return (r, s)

Verify(public_key = y, params = (p, q, g), message, (r, s)):
    if r not in [1, q-1] or s not in [1, q-1]: return false
    digest <- SHA-256(message)
    w   <- s^-1 mod q
    u1  <- (digest * w) mod q
    u2  <- (r * w) mod q
    v   <- ((g^u1 * y^u2) mod p) mod q
    return v == r
```

## Complexity

| Operation | Cost | Why |
|---|---|---|
| KeyGen | $O(k^4)$ bit operations | Dominated by finding a $k$-bit prime $p$ and $n$-bit prime $q$ with $q \mid (p-1)$ — the same order of cost as RSA's prime search, and the reason `generate_keys()` is this crate's slowest |
| Sign | $O(n \cdot k^2)$ | One modular exponentiation mod $p$, but the exponent ($k_{\text{nonce}}$) is only $n$ bits — cheaper than a full-$k$-bit-exponent exponentiation, plus a cheap $O(n^2)$ modular inverse mod $q$ |
| Verify | $O(n \cdot k^2)$, roughly 2× signing | Two exponentiations mod $p$ with $n$-bit exponents (combinable into one multi-exponentiation), each costing about what signing's single exponentiation does |

$k$ is the modulus bit length (2048), $n$ the subgroup order bit length
(256). Because the exponents in sign/verify are only $n$ bits rather than
the full $k$-bit modulus, DSA's sign/verify cost is closer to an
elliptic-curve algorithm's than to RSA's — the expensive part specific to
DSA is entirely front-loaded into key generation.

## How to Use

### Typed API

```rust
use SignetDSA::algo::dsa::Dsa;
use SignetDSA::Signature;

let (private_key, public_key) = Dsa::generate_keys(); // slow — see below
let message = b"Hello, SignetDSA!";

let signature = Dsa::sign(&private_key, message).expect("signing failed");
assert!(Dsa::verify(&public_key, message, &signature).unwrap());
```

!!! warning "Key generation is the slowest in this crate"
    Generating fresh 2048-bit DSA domain parameters (`Components::generate`)
    is considerably slower than RSA key generation — tens of seconds is not
    unusual. This isn't specific to SignetDSA; it's inherent to generating
    safe-prime-adjacent DSA parameters from scratch every time, rather than
    reusing a standard fixed parameter set. Avoid calling `generate_keys()`
    more than you need to (e.g. in a test suite that runs it in a loop).

### PEM Import/Export

```rust
use SignetDSA::algo::dsa::Dsa;

let (private_key, public_key) = Dsa::generate_keys();

let private_pem = Dsa::private_key_to_pem(&private_key).unwrap();
let public_pem = Dsa::public_key_to_pem(&public_key).unwrap();

let restored_private = Dsa::private_key_from_pem(&private_pem).unwrap();
let restored_public = Dsa::public_key_from_pem(&public_pem).unwrap();
```

Both are PKCS#8/SPKI PEM, matching [RSA](rsa.md), [ECDSA](ecdsa.md), and
[EdDSA](eddsa.md) — see [PEM/DER Import-Export](../features/pem.md).

### Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("dsa").unwrap();
let (sk, pk) = signer.generate_keys(); // PKCS#8 DER
let sig = signer.sign(&sk, b"Hello, world!").unwrap();
assert!(signer.verify(&pk, b"Hello, world!", &sig).unwrap());
```

## Errors

`Dsa::Error` is `DsaError`, with variants for key generation failure,
signing failure, invalid signature encoding, verification failure, and PEM
encode/decode errors.

## When to Use

DSA is included for interoperability with systems that already require it.
For new designs, prefer [ECDSA](ecdsa.md), [EdDSA](eddsa.md), or
[Schnorr](schnorr.md) — smaller keys and signatures, faster key generation,
and (for EdDSA/Schnorr) determinism that removes the nonce-reuse risk above
entirely.
