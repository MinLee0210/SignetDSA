# SLH-DSA (SPHINCS+, FIPS 205)

**SLH-DSA** (Stateless Hash-based Digital Signature Algorithm) is the post-quantum signature standard specified in [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).

Unlike lattice-based schemes (such as [ML-DSA / Dilithium](mldsa.md)), the security of SLH-DSA relies solely on the hardness of finding collisions and preimages in standard cryptographic hash functions (such as SHAKE-256 and SHA-256). It provides a fundamental security hedge against any future mathematical breakthroughs against lattice problems.

---

## Technical Specifications

| Parameter | Value | Standard Reference |
|---|---|---|
| **Parameter Set** | `SLH-DSA-SHAKE-128f` | NIST FIPS 205 §11.1 |
| **NIST Security Category** | Level 1 (~128-bit classical / quantum security) | NIST FIPS 205 |
| **Private Key Size** | `64 bytes` | FIPS 205 §11 |
| **Public Key Size** | `32 bytes` | FIPS 205 §11 |
| **Signature Size** | `17,088 bytes` (~17.1 KB) | FIPS 205 §11 |
| **Underlying Crate** | `slh-dsa` (RustCrypto) | RustCrypto |

---

## Comparison: ML-DSA vs SLH-DSA

| Feature | ML-DSA-65 (FIPS 204) | SLH-DSA-SHAKE-128f (FIPS 205) |
|---|---|---|
| **Mathematical Basis** | Module Lattices (MLWE / MSIS) | Stateless Hash Trees (W-OTS+ / FORS / Hypertree) |
| **Public Key Size** | 1,952 B (~1.9 KB) | **32 B** |
| **Private Key Size** | 4,032 B (~4.0 KB) | **64 B** |
| **Signature Size** | **3,309 B** (~3.3 KB) | 17,088 B (~17.1 KB) |
| **Signing Speed** | Very Fast | Fast (`-f` parameter set) |
| **Quantum Risk** | Low (if lattices hold) | **Zero lattice assumption** (pure hash security) |

---

## Rust Usage

### Typed Static API

```rust
use SignetDSA::algo::slhdsa::SlhDsa;
use SignetDSA::Signature;

let (sk, pk) = SlhDsa::generate_keys();
let message = b"Quantum-proof hash-based payload";

let signature = SlhDsa::sign(&sk, message).unwrap();
assert_eq!(signature.len(), 17088);

let is_valid = SlhDsa::verify(&pk, message, &signature).unwrap();
assert!(is_valid);
```

### Dynamic Factory API

```rust
use SignetDSA::{Signet, SignetSigner};

let signer = Signet::from_name("slhdsa").unwrap(); // or "sphincs+"
let (sk, pk) = signer.generate_keys();

let signature = signer.sign(&sk, b"Secure message").unwrap();
assert!(signer.verify(&pk, b"Secure message", &signature).unwrap());
```

---

## Python Usage

```python
import signetdsa

signer = signetdsa.Signet.from_name("slhdsa")
sk, pk = signer.generate_keys()

print(f"Public Key: {len(pk)} B, Secret Key: {len(sk)} B")

sig = signer.sign(sk, b"Hash-based post-quantum payload")
print(f"Signature Size: {len(sig)} bytes")

assert signer.verify(pk, b"Hash-based post-quantum payload", sig) is True
```
