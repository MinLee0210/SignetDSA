//! COSE Compact Binary Envelopes (RFC 9052) example for SignetDSA.
//!
//! Demonstrates:
//! 1. Sealing payloads into compact binary `COSE_Sign1` structures (CBOR Tag 18).
//! 2. Authenticating payloads without JSON or Base64 string encoding overhead.
//! 3. Verifying signatures against sender public keys.
//!
//! Run with:
//! ```bash
//! cargo run --example cose_binary_envelopes
//! ```

use SignetDSA::{CoseSign1, Signet};

fn main() {
    println!("=== SignetDSA COSE Binary Envelopes Example (RFC 9052) ===\n");

    let algos = ["eddsa", "ecdsa", "ecdsa-p384", "ecdsa-secp256k1"];
    let payload = b"FIDO2_WEBAUTHN_ASSERTION_DATA: { clientDataHash: 0x8f..., userHandle: 0x42 }";

    for algo in algos {
        let signer = Signet::from_name(algo).expect("algorithm should exist");
        let (sk, pk) = signer.generate_keys();

        // 1. Sign into binary COSE_Sign1 envelope
        let cose_bytes = CoseSign1::sign(algo, &sk, payload).expect("COSE sign failed");

        println!("Algorithm: {}", algo);
        println!("  Payload Size:    {} bytes", payload.len());
        println!(
            "  COSE_Sign1 Size: {} bytes (Tag 18 prefix: 0x{:02x})",
            cose_bytes.len(),
            cose_bytes[0]
        );

        // 2. Verify signature and extract authentic payload
        let verified_payload = CoseSign1::verify(&cose_bytes, &pk).expect("COSE verify failed");
        assert_eq!(&verified_payload, payload);
        println!("  [✓] Successfully verified binary envelope.\n");

        // 3. Test tampering rejection
        let mut corrupted_cose = cose_bytes.clone();
        let last = corrupted_cose.len() - 1;
        corrupted_cose[last] ^= 0xff;

        let tamper_check = CoseSign1::verify(&corrupted_cose, &pk);
        assert!(tamper_check.is_err());
        println!("  [✓] Corrupted COSE envelope correctly rejected.\n");
    }

    println!("[✓] All COSE binary envelope operations completed successfully!");
}
