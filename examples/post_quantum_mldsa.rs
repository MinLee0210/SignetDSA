//! Post-Quantum ML-DSA (CRYSTALS-Dilithium-65, NIST FIPS 204) example for SignetDSA.
//!
//! Demonstrates post-quantum digital signature generation and verification
//! based on Module Learning With Errors (MLWE).
//!
//! Run with:
//! ```bash
//! cargo run --example post_quantum_mldsa
//! ```

use SignetDSA::Signature;
use SignetDSA::algo::mldsa::MlDsa;

fn main() {
    println!("=== SignetDSA Post-Quantum ML-DSA Example (NIST FIPS 204) ===\n");

    println!("1. Generating quantum-resistant keypair (Dilithium-65 / NIST Security Level 3)...");
    let (sk, pk) = MlDsa::generate_keys();

    println!("   Private Key: SigningKey<MlDsa65> (4,032 bytes)");
    println!("   Public Key:  VerifyingKey<MlDsa65> (1,952 bytes)");

    let payload = b"CRITICAL_SYSTEM_KERNEL_UPDATE_V4.19_FIPS204_SIGNED";

    println!("\n2. Signing message with ML-DSA private key...");
    let signature = MlDsa::sign(&sk, payload).expect("ML-DSA signing failed");
    println!("   Signature Size:   {} bytes (~3.3 KB)", signature.len());

    println!("\n3. Verifying post-quantum signature...");
    let is_valid = MlDsa::verify(&pk, payload, &signature).expect("ML-DSA verification failed");
    println!("   Verification:     {}\n", is_valid);
    assert!(is_valid);

    println!("4. Demonstrating tamper rejection...");
    let tampered_payload = b"CRITICAL_SYSTEM_KERNEL_UPDATE_MALICIOUS_BACKDOOR";
    let tamper_check = MlDsa::verify(&pk, tampered_payload, &signature);
    assert!(matches!(tamper_check, Err(_) | Ok(false)));
    println!("   [✓] Tampered payload rejected as expected.\n");

    println!("Post-Quantum ML-DSA example completed successfully!");
}
