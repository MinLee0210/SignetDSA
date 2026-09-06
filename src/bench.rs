//! Micro-benchmarking and performance comparison harness for digital signature algorithms.
//!
//! Measures key generation latency, signing throughput, verification throughput,
//! and serialized key/signature sizes across all algorithms supported by [`Signet`].

use crate::signet::Signet;
use std::time::{Duration, Instant};

/// Performance measurement metrics for a signature algorithm.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Canonical algorithm name.
    pub algo: &'static str,
    /// Average duration per key generation.
    pub keygen_avg: Duration,
    /// Average duration per signing operation.
    pub sign_avg: Duration,
    /// Average duration per verification operation.
    pub verify_avg: Duration,
    /// Serialized private key size in bytes.
    pub priv_key_bytes: usize,
    /// Serialized public key size in bytes.
    pub pub_key_bytes: usize,
    /// Serialized signature size in bytes.
    pub sig_bytes: usize,
    /// Number of iterations executed.
    pub iterations: usize,
}

impl BenchmarkResult {
    /// Estimated keygen operations per second.
    pub fn keygen_ops_per_sec(&self) -> f64 {
        if self.keygen_avg.as_nanos() == 0 {
            0.0
        } else {
            1_000_000_000.0 / self.keygen_avg.as_nanos() as f64
        }
    }

    /// Estimated signing operations per second.
    pub fn sign_ops_per_sec(&self) -> f64 {
        if self.sign_avg.as_nanos() == 0 {
            0.0
        } else {
            1_000_000_000.0 / self.sign_avg.as_nanos() as f64
        }
    }

    /// Estimated verification operations per second.
    pub fn verify_ops_per_sec(&self) -> f64 {
        if self.verify_avg.as_nanos() == 0 {
            0.0
        } else {
            1_000_000_000.0 / self.verify_avg.as_nanos() as f64
        }
    }
}

/// Run a benchmark for a single algorithm by name.
pub fn benchmark_algo(name: &str, iterations: usize) -> Result<BenchmarkResult, String> {
    let iterations = iterations.max(1);
    let signer = Signet::from_name(name).ok_or_else(|| format!("unknown algorithm {name:?}"))?;

    let canonical_name = signer.name();
    let message =
        b"SignetDSA benchmarking payload: measuring cryptographic performance across algorithms.";

    // Measure Keygen
    let start_keygen = Instant::now();
    let mut last_sk = None;
    let mut last_pk = None;
    for _ in 0..iterations {
        let (sk, pk) = signer.generate_keys();
        last_sk = Some(sk);
        last_pk = Some(pk);
    }
    let keygen_total = start_keygen.elapsed();
    let keygen_avg = keygen_total / iterations as u32;

    let sk = last_sk.unwrap();
    let pk = last_pk.unwrap();
    let priv_key_bytes = sk.len();
    let pub_key_bytes = pk.len();

    // Measure Sign
    let start_sign = Instant::now();
    let mut last_sig = None;
    for _ in 0..iterations {
        let sig = signer.sign(&sk, message)?;
        last_sig = Some(sig);
    }
    let sign_total = start_sign.elapsed();
    let sign_avg = sign_total / iterations as u32;

    let sig = last_sig.unwrap();
    let sig_bytes = sig.len();

    // Measure Verify
    let start_verify = Instant::now();
    for _ in 0..iterations {
        let valid = signer.verify(&pk, message, &sig)?;
        if !valid {
            return Err(format!(
                "{canonical_name}: signature verification failed during benchmark"
            ));
        }
    }
    let verify_total = start_verify.elapsed();
    let verify_avg = verify_total / iterations as u32;

    Ok(BenchmarkResult {
        algo: canonical_name,
        keygen_avg,
        sign_avg,
        verify_avg,
        priv_key_bytes,
        pub_key_bytes,
        sig_bytes,
        iterations,
    })
}

/// Run benchmarks across all canonical algorithms in [`Signet::available()`].
pub fn benchmark_all(iterations: usize) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();
    for &name in Signet::available() {
        // RSA / DSA keygen is naturally slower; adjust iterations slightly if large
        let iters = if (name.starts_with("rsa") || name == "dsa") && iterations > 5 {
            5
        } else {
            iterations
        };

        if let Ok(res) = benchmark_algo(name, iters) {
            results.push(res);
        }
    }
    results
}

fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos} ns")
    } else if nanos < 1_000_000 {
        format!("{:.2} µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", nanos as f64 / 1_000_000_000.0)
    }
}

/// Format benchmark results as a pretty markdown/ASCII table.
pub fn format_table(results: &[BenchmarkResult]) -> String {
    let mut out = String::new();
    out.push_str("+------------------+-------------+-------------+-------------+------------+-----------+------------+\n");
    out.push_str("| Algorithm        | Keygen Time | Sign Time   | Verify Time | Sign ops/s | Key (Priv/Pub) | Sig Size   |\n");
    out.push_str("+------------------+-------------+-------------+-------------+------------+-----------+------------+\n");

    for r in results {
        let key_str = format!("{}/{} B", r.priv_key_bytes, r.pub_key_bytes);
        let sig_str = format!("{} B", r.sig_bytes);
        out.push_str(&format!(
            "| {:<16} | {:>11} | {:>11} | {:>11} | {:>10.0} | {:>13} | {:>10} |\n",
            r.algo,
            format_duration(r.keygen_avg),
            format_duration(r.sign_avg),
            format_duration(r.verify_avg),
            r.sign_ops_per_sec(),
            key_str,
            sig_str
        ));
    }
    out.push_str("+------------------+-------------+-------------+-------------+------------+-----------+------------+\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_single_algo() {
        let res = benchmark_algo("eddsa", 2).expect("benchmark failed");
        assert_eq!(res.algo, "eddsa");
        assert_eq!(res.priv_key_bytes, 32);
        assert_eq!(res.pub_key_bytes, 32);
        assert_eq!(res.sig_bytes, 64);
        assert!(res.sign_ops_per_sec() > 0.0);
    }

    #[test]
    fn benchmark_format_table() {
        let res = benchmark_algo("ecdsa", 1).expect("benchmark failed");
        let table = format_table(&[res]);
        assert!(table.contains("ecdsa"));
        assert!(table.contains("Keygen Time"));
    }
}
