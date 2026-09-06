//! JWS Compact Token (RFC 7515) example for SignetDSA.
//!
//! Demonstrates creating and validating compact URL-safe JWS tokens
//! (`<header>.<payload>.<signature>`) across multiple signature schemes.
//!
//! Run with:
//! ```bash
//! cargo run --example jws_tokens
//! ```

use SignetDSA::{Signet, envelope::JwsCompact};

fn main() {
    println!("=== SignetDSA JWS Compact Token Example (RFC 7515) ===\n");

    let algos = ["ecdsa-p384", "eddsa", "schnorr", "rsa-pss"];
    let claims =
        br#"{"sub":"user_84719","iss":"auth.signetdsa.internal","role":"admin","exp":1893456000}"#;

    for algo in algos {
        let signer = Signet::from_name(algo).expect("algorithm should exist");
        let (sk, pk) = signer.generate_keys();

        // 1. Sign claims into compact JWS format
        let token = JwsCompact::sign(algo, &sk, claims).expect("JWS signing failed");

        println!("Algorithm: {}", algo);
        println!("Generated Token ({} chars):", token.len());
        println!("  {}\n", token);

        // 2. Verify token and decode original payload
        let verified_payload = JwsCompact::verify(&token, &pk).expect("JWS verification failed");
        assert_eq!(verified_payload, claims);

        println!(
            "  [✓] Verified payload: {}\n",
            String::from_utf8_lossy(&verified_payload)
        );

        // 3. Verify tampering detection
        let mut tampered_token = token.clone();
        tampered_token.replace_range(10..15, "XXXXX");
        let tamper_result = JwsCompact::verify(&tampered_token, &pk);
        assert!(tamper_result.is_err());
        println!("  [✓] Tampered token successfully rejected.\n");
    }

    println!("JWS examples completed successfully!");
}
