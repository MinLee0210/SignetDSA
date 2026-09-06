//! FROST Threshold Signature example for SignetDSA.
//!
//! Demonstrates distributed t-of-n threshold signing over secp256k1
//! (IETF FROST draft / BIP340 Schnorr).
//!
//! In a (t, n) threshold scheme:
//! - n participants hold individual secret shares.
//! - Any subset of t signers can jointly sign a message.
//! - The resulting signature is standard Schnorr, indistinguishable from a single-key signature.
//! - The full private key is NEVER assembled or reconstructed anywhere.
//!
//! Run with:
//! ```bash
//! cargo run --example frost_threshold
//! ```

use SignetDSA::algo::frost;

fn main() {
    println!("=== SignetDSA FROST Threshold Signing Example ===\n");

    let transaction = b"RELEASE ESCROW FUNDS: $250,000 to Supplier";

    // -----------------------------------------------------------------------
    // Scenario 1: Standard 2-of-3 Threshold Ceremony
    // -----------------------------------------------------------------------
    println!("1. Running 2-of-3 FROST Ceremony (e.g. 2 of 3 company officers):");
    let result_2_of_3 =
        frost::ceremony_2_of_3(transaction).expect("2-of-3 FROST threshold ceremony failed");

    println!("   Message:   {}", String::from_utf8_lossy(transaction));
    println!("   Threshold: 2 of 3 signers participated");
    println!("   Verified:  {}\n", result_2_of_3);
    assert!(result_2_of_3);

    // -----------------------------------------------------------------------
    // Scenario 2: Dynamic 3-of-5 Threshold Ceremony
    // -----------------------------------------------------------------------
    println!("2. Running 3-of-5 FROST Ceremony (e.g. 3 of 5 board members):");
    let result_3_of_5 =
        frost::ceremony(3, 5, transaction).expect("3-of-5 FROST threshold ceremony failed");

    println!("   Threshold: 3 of 5 signers participated");
    println!("   Verified:  {}\n", result_3_of_5);
    assert!(result_3_of_5);

    println!("FROST threshold signature examples completed successfully!");
}
