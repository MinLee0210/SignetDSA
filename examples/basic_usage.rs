//! Basic usage example for SignetDSA.
//!
//! Demonstrates:
//! 1. Static Typed API (`Signature` trait) with compile-time type safety.
//! 2. Dynamic Factory API (`Signet` / `SignetSigner`) for runtime algorithm selection.
//!
//! Run with:
//! ```bash
//! cargo run --example basic_usage
//! ```

use SignetDSA::algo::eddsa::EdDsa;
use SignetDSA::{Signature, Signet};

fn main() {
    println!("=== SignetDSA Basic Usage Example ===\n");

    // -----------------------------------------------------------------------
    // 1. Static Typed API (Zero-cost, compile-time verified)
    // -----------------------------------------------------------------------
    println!("1. Static Typed API (Ed25519 / EdDSA):");
    let (private_key, public_key) = EdDsa::generate_keys();
    let message = b"SignetDSA: Enterprise-grade cryptography in Rust";

    let signature = EdDsa::sign(&private_key, message).expect("signing should succeed");
    let is_valid = EdDsa::verify(&public_key, message, &signature).expect("verification failed");

    println!("   Message:   {}", String::from_utf8_lossy(message));
    println!("   Signature: {} bytes", signature.len());
    println!("   Verified:  {}\n", is_valid);
    assert!(is_valid);

    // -----------------------------------------------------------------------
    // 2. Dynamic Factory API (Runtime algorithm selection)
    // -----------------------------------------------------------------------
    println!("2. Dynamic Factory API (Runtime Selection):");
    let algorithm_names = ["eddsa", "ecdsa-p384", "schnorr", "bls", "mldsa"];

    for algo_name in algorithm_names {
        let signer = Signet::from_name(algo_name)
            .unwrap_or_else(|| panic!("Algorithm '{algo_name}' should be available"));

        // Generate keys as byte vectors (secret key automatically zeroized on drop)
        let (sk, pk) = signer.generate_keys();
        let payload = b"Universal signing across 11 schemes";

        let sig = signer
            .sign(&sk, payload)
            .unwrap_or_else(|e| panic!("Sign error: {e}"));
        let valid = signer
            .verify(&pk, payload, &sig)
            .unwrap_or_else(|e| panic!("Verify error: {e}"));

        println!(
            "   [✓] {:<14} | SecretKey: {:>4} B | PublicKey: {:>4} B | Sig: {:>4} B | Valid: {}",
            signer.name(),
            sk.len(),
            pk.len(),
            sig.len(),
            valid
        );
        assert!(valid);
    }

    println!("\nAll basic usage checks passed successfully!");
}
