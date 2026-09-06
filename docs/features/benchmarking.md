# Micro-Benchmarking & Performance

SignetDSA includes an integrated benchmarking harness to profile and compare key generation latency, signing throughput, verification latency, and key/signature size tradeoffs across all schemes.

## Programmatic API

```rust
use SignetDSA::bench::{benchmark_algo, benchmark_all, format_table};

// Benchmark a single algorithm (e.g. Ed25519 over 100 iterations)
let res = benchmark_algo("eddsa", 100).unwrap();
println!("Ed25519 signing throughput: {:.0} ops/sec", res.sign_ops_per_sec());

// Benchmark all supported algorithms and print a formatted ASCII table
let results = benchmark_all(10);
println!("{}", format_table(&results));
```

## CLI Benchmarking

Run the built-in benchmark directly from the shell:

```bash
# Benchmark all supported algorithms
cargo run --release --bin signetdsa -- bench --iterations 50

# Benchmark a specific algorithm
cargo run --release --bin signetdsa -- bench --algo ecdsa-p384 --iterations 100
```

### Typical Relative Comparison

| Algorithm | Keygen Latency | Signing Latency | Verification Latency | Public Key Size | Signature Size |
|---|---|---|---|---|---|
| **Ed25519** | ~140 µs | ~300 µs | ~6 ms | 32 B | 64 B |
| **ECDSA (secp256k1)** | ~750 µs | ~2.2 ms | ~1.4 ms | 33 B | 64 B |
| **ECDSA (P-256)** | ~1.9 ms | ~4.2 ms | ~4.1 ms | 33 B | 64 B |
| **Schnorr (BIP340)** | ~1.5 ms | ~4.3 ms | ~1.3 ms | 32 B | 64 B |
| **ECDSA (P-384)** | ~11 ms | ~23 ms | ~21 ms | 49 B | 96 B |
| **BLS (BLS12-381)** | ~3.9 ms | ~22 ms | ~34 ms | 48 B | 96 B |
| **ML-DSA (Post-Quantum)** | ~13 ms | ~18 ms | ~9 ms | 1952 B | 3309 B |
| **RSA-PSS (2048-bit)** | ~2.5 s | ~50 ms | ~4.5 ms | 270 B | 256 B |
