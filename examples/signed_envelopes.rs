//! Self-Contained Signed Envelope example for SignetDSA.
//!
//! Demonstrates sealing messages into portable JSON envelopes (`SignetEnvelope`)
//! containing the message payload, public key, timestamp, and signature for autonomous verification.
//!
//! Run with:
//! ```bash
//! cargo run --example signed_envelopes
//! ```

use SignetDSA::{Signet, SignetEnvelope};

fn main() {
    println!("=== SignetDSA Signed Envelopes Example ===\n");

    let signer = Signet::from_name("schnorr").expect("schnorr algorithm");
    let (private_key, public_key) = signer.generate_keys();

    let transaction_payload = b"TRANSFER 50.0 BTC TO bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

    // 1. Seal message into an envelope
    println!("1. Sealing payload into SignetEnvelope...");
    let envelope = SignetEnvelope::seal(
        signer.as_ref(),
        &private_key,
        &public_key,
        transaction_payload,
    )
    .expect("sealing failed");

    // 2. Export to formatted JSON for network transport or persistence
    let json_string = envelope.to_json();
    println!("2. Serialized JSON Envelope:\n{}\n", json_string);

    // 3. Autonomous verification: receiver parses JSON and self-verifies
    println!("3. Parsing and verifying envelope at receiver...");
    let parsed_envelope = SignetEnvelope::from_json(&json_string).expect("JSON parsing failed");

    let is_valid = parsed_envelope
        .verify()
        .expect("verification execution failed");

    println!("   Algorithm:  {}", parsed_envelope.algo);
    println!("   Timestamp:  {}", parsed_envelope.created_at);
    println!(
        "   Message:    {}",
        String::from_utf8_lossy(&parsed_envelope.message)
    );
    println!("   Is Valid:   {}\n", is_valid);
    assert!(is_valid);

    // 4. Tamper resistance demonstration
    println!("4. Demonstrating tamper resistance...");
    let mut tampered_envelope = parsed_envelope.clone();
    tampered_envelope.message = b"TRANSFER 5000.0 BTC TO attacker".to_vec();

    let tamper_check = tampered_envelope.verify();
    assert!(tamper_check.is_err() || tamper_check == Ok(false));
    println!("   [✓] Tampered payload successfully rejected.\n");

    println!("Signed envelope example completed successfully!");
}
