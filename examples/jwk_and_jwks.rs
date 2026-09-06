//! JSON Web Keys (JWK, RFC 7517) and JWKS example for SignetDSA.
//!
//! Demonstrates:
//! 1. Exporting public keys to standard JWK format across curves (Ed25519, P-256, secp256k1).
//! 2. Computing RFC 7638 SHA-256 JWK thumbprints.
//! 3. Aggregating JWKs into standard JWKS sets (`.well-known/jwks.json`).
//! 4. Parsing JWK JSON and reconstructing cryptographic public keys.
//!
//! Run with:
//! ```bash
//! cargo run --example jwk_and_jwks
//! ```

use SignetDSA::{Jwk, Jwks, Signet};

fn main() {
    println!("=== SignetDSA JWK & JWKS Example (RFC 7517 / RFC 7638) ===\n");

    let algos = ["eddsa", "ecdsa", "ecdsa-secp256k1", "ecdsa-p384"];
    let mut jwk_list = Vec::new();

    for algo in algos {
        let signer = Signet::from_name(algo).expect("algorithm should exist");
        let (_sk, pk) = signer.generate_keys();

        // 1. Export to JWK
        let jwk = Jwk::from_public_key(algo, &pk).expect("JWK creation failed");
        let thumbprint = jwk.thumbprint();

        println!("Algorithm: {}", algo);
        println!("  Key Type (kty):   {}", jwk.kty);
        println!(
            "  Curve (crv):      {}",
            jwk.crv.as_deref().unwrap_or("none")
        );
        println!("  Thumbprint (kid): {}", thumbprint);
        println!("  JWK JSON:\n    {}\n", jwk.to_json());

        // 2. Round-trip recovery from JSON
        let parsed = Jwk::from_json(&jwk.to_json()).expect("JWK parse failed");
        let recovered_pk = parsed.to_public_key().expect("Public key recovery failed");
        assert_eq!(recovered_pk, pk);

        jwk_list.push(jwk);
    }

    // 3. Construct and export JWKS set
    println!("Exporting JWKS set (.well-known/jwks.json):");
    let jwks = Jwks::new(jwk_list);
    let jwks_json = jwks.to_json();
    println!("{}\n", jwks_json);

    let parsed_jwks = Jwks::from_json(&jwks_json).expect("JWKS parse failed");
    assert_eq!(parsed_jwks.keys.len(), algos.len());

    println!("[✓] All JWK & JWKS operations completed successfully!");
}
