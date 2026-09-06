//! W3C `did:key` Decentralized Identifier example for SignetDSA.
//!
//! Demonstrates:
//! 1. Deriving deterministic `did:key:z...` URIs from public keys across multicodecs.
//! 2. Resolving `did:key` URIs back to algorithm names and raw public key bytes.
//!
//! Run with:
//! ```bash
//! cargo run --example did_key
//! ```

use SignetDSA::{DidKey, Signet};

fn main() {
    println!("=== SignetDSA W3C did:key Decentralized Identifiers Example ===\n");

    let schemes = [
        ("eddsa", "Ed25519 (0xed01)"),
        ("ecdsa-secp256k1", "secp256k1 (0xe701)"),
        ("ecdsa", "NIST P-256 (0x1200)"),
        ("ecdsa-p384", "NIST P-384 (0x1201)"),
    ];

    for (algo, label) in schemes {
        let signer = Signet::from_name(algo).expect("algorithm should exist");
        let (_sk, pk) = signer.generate_keys();

        // 1. Derive DID URI
        let did = DidKey::to_did(algo, &pk).expect("DID derivation failed");

        println!("Scheme: {}", label);
        println!("  Derived DID: {}", did);

        // 2. Resolve DID URI
        let doc = DidKey::resolve(&did).expect("DID resolution failed");
        println!("  Resolved Algo: {}", doc.algo);
        println!("  Public Key Bytes: {} bytes", doc.public_key.len());
        assert_eq!(doc.algo, signer.name());
        assert_eq!(doc.public_key, pk);

        println!("  [✓] Verified round-trip resolution.\n");
    }

    println!("[✓] All W3C did:key operations completed successfully!");
}
