//! BLS12-381 Signature Aggregation example for SignetDSA.
//!
//! Demonstrates aggregating N independent signatures over N distinct messages
//! into a single 96-byte signature verified via a single pairing equation.
//!
//! Run with:
//! ```bash
//! cargo run --example bls_aggregation
//! ```

use SignetDSA::Signature;
use SignetDSA::algo::bls::Bls;
use bls_signatures::Serialize;

fn main() {
    println!("=== SignetDSA BLS12-381 Signature Aggregation Example ===\n");

    let num_validators = 5;
    println!(
        "Simulating {} independent blockchain validators...",
        num_validators
    );

    let mut keypairs = Vec::new();
    let mut messages = Vec::new();
    let mut raw_signatures = Vec::new();

    for i in 0..num_validators {
        let (sk, pk) = Bls::generate_keys();
        let msg = format!("Validator #{} approves block height #100000{}", i + 1, i);
        let sig = Bls::sign(&sk, msg.as_bytes()).expect("signing failed");

        keypairs.push((sk, pk));
        messages.push(msg);
        raw_signatures.push(sig);
    }

    println!(
        "Generated {} individual signatures (each 96 bytes).",
        num_validators
    );
    println!(
        "Total uncompressed signature size: {} bytes",
        num_validators * 96
    );

    // 1. Aggregate all 5 signatures into a single 96-byte BLS signature
    println!("\n1. Aggregating signatures...");
    let aggregated_sig =
        Bls::aggregate_signatures(&raw_signatures).expect("signature aggregation failed");

    println!(
        "   Aggregated Signature Size: {} bytes (constant size regardless of N)",
        aggregated_sig.len()
    );
    assert_eq!(aggregated_sig.len(), 96);

    // 2. Batch verify all validator signatures against distinct messages in one step
    println!("\n2. Verifying aggregated signature over distinct messages...");
    let public_keys: Vec<Vec<u8>> = keypairs
        .iter()
        .map(|(_, pk)| pk.as_bytes().to_vec())
        .collect();
    let msg_slices: Vec<&[u8]> = messages.iter().map(|m| m.as_bytes()).collect();

    let is_valid = Bls::verify_aggregated(&aggregated_sig, &msg_slices, &public_keys)
        .expect("batch aggregate verification failed");

    println!("   Batch Verification Result: {}\n", is_valid);
    assert!(is_valid);

    // 3. Rogue message tampering detection
    println!("3. Testing tampering detection (altering message #3)...");
    let mut tampered_messages = msg_slices.clone();
    tampered_messages[2] = b"Tampered validator payload!";

    let tamper_result = Bls::verify_aggregated(&aggregated_sig, &tampered_messages, &public_keys);
    assert!(matches!(tamper_result, Err(_) | Ok(false)));
    println!("   [✓] Tampered message correctly rejected.\n");

    println!("BLS signature aggregation example completed successfully!");
}
