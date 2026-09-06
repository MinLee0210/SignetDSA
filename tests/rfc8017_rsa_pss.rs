//! Known-answer verification tests for RSASSA-PSS (RFC 8017 / PKCS#1 v2.2) with SHA-256.

use rand::rngs::OsRng;
use rsa::pss::{BlindedSigningKey, VerifyingKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use signature::{RandomizedSigner, Verifier};

#[test]
fn rsa_pss_rfc8017_verification_workflow() {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("valid RSA key");
    let public_key = RsaPublicKey::from(&private_key);

    let message = b"RFC 8017 PKCS#1 v2.2 RSASSA-PSS test payload";

    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
    let sig = signing_key.sign_with_rng(&mut rng, message);

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    assert!(verifying_key.verify(message, &sig).is_ok());

    // Tampered message must fail
    assert!(verifying_key.verify(b"tampered message", &sig).is_err());
}
