# SignetDSA Examples

This directory contains standalone, runnable code examples demonstrating SignetDSA in both **Rust** and **Python**.

---

## Rust Examples

Run any Rust example with `cargo run --example <name>`:

| Example | Command | Description |
|---|---|---|
| **Basic Usage** | `cargo run --example basic_usage` | Typed static API (`Signature`) vs dynamic factory API (`Signet`). |
| **JWS Compact Tokens** | `cargo run --example jws_tokens` | URL-safe JWS compact token signing & validation (RFC 7515). |
| **JSON Web Keys (JWK & JWKS)** | `cargo run --example jwk_and_jwks` | Standard JWK / JWKS export, RFC 7638 thumbprints, and parsing. |
| **COSE Binary Envelopes** | `cargo run --example cose_binary_envelopes` | Compact CBOR `COSE_Sign1` envelopes for IoT / WebAuthn. |
| **W3C did:key Identifiers** | `cargo run --example did_key` | Derive and resolve standard W3C `did:key:z...` decentralized IDs. |
| **Signed Envelopes** | `cargo run --example signed_envelopes` | Self-contained, portable JSON envelopes (`SignetEnvelope`). |
| **FROST Threshold** | `cargo run --example frost_threshold` | Distributed 2-of-3 and 3-of-5 threshold signing ceremony. |
| **BLS Aggregation** | `cargo run --example bls_aggregation` | Multi-signer BLS12-381 signature aggregation and batch verification. |
| **Post-Quantum ML-DSA** | `cargo run --example post_quantum_mldsa` | NIST FIPS 204 ML-DSA (Dilithium-65) lattice signatures. |

---

## Python Examples

Ensure `signetdsa` is installed in your Python environment (`pip install .` or `maturin develop --release`), then run:

```bash
# 1. Basic usage and algorithm inspection
python3 examples/python/01_basic_usage.py

# 2. JSON Web Signatures (JWS RFC 7515)
python3 examples/python/02_jws_tokens.py

# 3. Self-contained signed envelopes
python3 examples/python/03_signed_envelopes.py

# 4. FROST threshold multi-signature ceremony
python3 examples/python/04_frost_threshold.py

# 5. BLS12-381 signature aggregation & verification
python3 examples/python/05_bls_aggregation.py

# 6. Ethereum ecrecover & public key recovery
python3 examples/python/06_ecrecover.py

# 7. In-process micro-benchmark across all 12 schemes
python3 examples/python/07_benchmarks.py

# 8. JSON Web Keys (JWK & JWKS RFC 7517)
python3 examples/python/08_jwk_and_jwks.py

# 9. COSE Compact Binary Envelopes (RFC 9052)
python3 examples/python/09_cose_envelopes.py

# 10. W3C did:key Decentralized Identifiers
python3 examples/python/10_did_key.py
```
