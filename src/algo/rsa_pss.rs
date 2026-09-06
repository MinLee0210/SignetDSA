//! RSA-PSS (Probabilistic Signature Scheme) implementation.
//!
//! Provides the [`RsaPss`] struct implementing the [`crate::Signature`] trait
//! using RSASSA-PSS padding with SHA-256 and MGF1, backed by the `rsa` crate.
//!
//! RSA-PSS (standardized in RFC 8017 / PKCS#1 v2.2 and FIPS 186-4/5) is the modern,
//! provably secure alternative to legacy PKCS#1 v1.5 padding. It incorporates a
//! random salt into the signature generation, eliminating mathematical structure
//! that could otherwise be targeted by padding oracle or chosen-ciphertext attacks.

use crate::signature::Signature;
use ::rsa::{
    RsaPrivateKey, RsaPublicKey,
    pss::{BlindedSigningKey, Signature as PssSignature, VerifyingKey},
};
use ::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rand::rngs::OsRng;
use sha2::Sha256;

/// RSA-PSS digital signature using RSASSA-PSS padding with SHA-256 (2048-bit modulus).
pub struct RsaPss;

#[derive(Debug)]
pub enum RsaPssError {
    KeyGeneration(::rsa::Error),
    Signing(::rsa::Error),
    InvalidSignatureEncoding,
    Verification(::signature::Error),
    PrivateKeyPem(pkcs8::Error),
    PublicKeyPem(pkcs8::spki::Error),
}

impl std::fmt::Display for RsaPssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsaPssError::KeyGeneration(e) => write!(f, "RSA-PSS key generation failed: {e}"),
            RsaPssError::Signing(e) => write!(f, "RSA-PSS signing failed: {e}"),
            RsaPssError::InvalidSignatureEncoding => {
                write!(f, "Invalid RSA-PSS signature encoding")
            }
            RsaPssError::Verification(e) => write!(f, "RSA-PSS verification failed: {e}"),
            RsaPssError::PrivateKeyPem(e) => write!(f, "RSA-PSS private key PEM error: {e}"),
            RsaPssError::PublicKeyPem(e) => write!(f, "RSA-PSS public key PEM error: {e}"),
        }
    }
}

impl std::error::Error for RsaPssError {}

impl Signature for RsaPss {
    type PrivateKey = RsaPrivateKey;
    type PublicKey = RsaPublicKey;
    type Error = RsaPssError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let private_key =
            RsaPrivateKey::new(&mut OsRng, 2048).expect("Failed to generate RSA-PSS private key");
        let public_key = RsaPublicKey::from(&private_key);
        (private_key, public_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signing_key = BlindedSigningKey::<Sha256>::new(private_key.clone());
        let sig = signing_key.sign_with_rng(&mut OsRng, message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
        let sig =
            PssSignature::try_from(signature).map_err(|_| RsaPssError::InvalidSignatureEncoding)?;
        verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(RsaPssError::Verification)
    }
}

impl RsaPss {
    /// Encode a private key as a PKCS#8 PEM document (`-----BEGIN PRIVATE KEY-----`).
    pub fn private_key_to_pem(private_key: &RsaPrivateKey) -> Result<String, RsaPssError> {
        use pkcs8::EncodePrivateKey;
        private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(RsaPssError::PrivateKeyPem)
    }

    /// Decode a private key from a PKCS#8 PEM document.
    pub fn private_key_from_pem(pem: &str) -> Result<RsaPrivateKey, RsaPssError> {
        use pkcs8::DecodePrivateKey;
        RsaPrivateKey::from_pkcs8_pem(pem).map_err(RsaPssError::PrivateKeyPem)
    }

    /// Encode a public key as a SubjectPublicKeyInfo PEM document (`-----BEGIN PUBLIC KEY-----`).
    pub fn public_key_to_pem(public_key: &RsaPublicKey) -> Result<String, RsaPssError> {
        use pkcs8::EncodePublicKey;
        public_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(RsaPssError::PublicKeyPem)
    }

    /// Decode a public key from a SubjectPublicKeyInfo PEM document.
    pub fn public_key_from_pem(pem: &str) -> Result<RsaPublicKey, RsaPssError> {
        use pkcs8::DecodePublicKey;
        RsaPublicKey::from_public_key_pem(pem).map_err(RsaPssError::PublicKeyPem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_pss_sign_and_verify() {
        let (private_key, public_key) = RsaPss::generate_keys();
        let message = b"Hello, SignetDSA RSA-PSS!";

        let signature = RsaPss::sign(&private_key, message).expect("Signing failed");
        let valid = RsaPss::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn rsa_pss_probabilistic_signatures() {
        // PSS is probabilistic — same key + message produces different signatures due to random salt
        let (private_key, _) = RsaPss::generate_keys();
        let message = b"Hello, SignetDSA RSA-PSS!";

        let sig1 = RsaPss::sign(&private_key, message).expect("Signing failed");
        let sig2 = RsaPss::sign(&private_key, message).expect("Signing failed");
        assert_ne!(sig1, sig2, "RSA-PSS signatures must be randomized by salt");
    }

    #[test]
    fn rsa_pss_tampered_message_fails() {
        let (private_key, public_key) = RsaPss::generate_keys();
        let message = b"Hello, SignetDSA RSA-PSS!";
        let tampered = b"Tampered message!";

        let signature = RsaPss::sign(&private_key, message).expect("Signing failed");
        let result = RsaPss::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn rsa_pss_keys_round_trip_through_pem() {
        let (private_key, public_key) = RsaPss::generate_keys();
        let message = b"Hello, SignetDSA RSA-PSS!";

        let private_pem = RsaPss::private_key_to_pem(&private_key).expect("PEM encoding failed");
        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let restored_private =
            RsaPss::private_key_from_pem(&private_pem).expect("PEM decoding failed");

        let public_pem = RsaPss::public_key_to_pem(&public_key).expect("PEM encoding failed");
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let restored_public =
            RsaPss::public_key_from_pem(&public_pem).expect("PEM decoding failed");

        let signature = RsaPss::sign(&restored_private, message).expect("Signing failed");
        let valid =
            RsaPss::verify(&restored_public, message, &signature).expect("Verification failed");
        assert!(valid, "Keys round-tripped through PEM should still work");
    }
}
