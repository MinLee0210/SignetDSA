//! DSA (Digital Signature Algorithm) implementation.
//!
//! This module provides the [`Dsa`] type implementing the [`crate::Signature`] trait
//! via the `dsa` crate, utilizing 2048-bit parameters and SHA-256.

use crate::signature::Signature;
use ::dsa::{
    Components, KeySize, SigningKey, VerifyingKey,
    signature::{DigestSigner, DigestVerifier, SignatureEncoding},
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// DSA digital signature using 2048-bit parameters and SHA-256.
pub struct Dsa;

#[derive(Debug)]
pub enum DsaError {
    KeyGeneration(String),
    Signing(String),
    InvalidSignatureEncoding,
    Verification(::dsa::signature::Error),
    PrivateKeyPem(pkcs8::Error),
    PublicKeyPem(pkcs8::spki::Error),
}

impl std::fmt::Display for DsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsaError::KeyGeneration(e) => write!(f, "DSA key generation failed: {e}"),
            DsaError::Signing(e) => write!(f, "DSA signing failed: {e}"),
            DsaError::InvalidSignatureEncoding => write!(f, "Invalid DSA signature encoding"),
            DsaError::Verification(e) => write!(f, "DSA verification failed: {e}"),
            DsaError::PrivateKeyPem(e) => write!(f, "DSA private key PEM error: {e}"),
            DsaError::PublicKeyPem(e) => write!(f, "DSA public key PEM error: {e}"),
        }
    }
}

impl std::error::Error for DsaError {}

impl Signature for Dsa {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Error = DsaError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let components = Components::generate(&mut OsRng, KeySize::DSA_2048_256);
        let signing_key = SigningKey::generate(&mut OsRng, components);
        let verifying_key = signing_key.verifying_key().clone();
        (signing_key, verifying_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let digest = Sha256::new_with_prefix(message);
        let sig: ::dsa::Signature = private_key.sign_digest(digest);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let sig = ::dsa::Signature::try_from(signature)
            .map_err(|_| DsaError::InvalidSignatureEncoding)?;
        let digest = Sha256::new_with_prefix(message);
        public_key
            .verify_digest(digest, &sig)
            .map(|_| true)
            .map_err(DsaError::Verification)
    }
}

impl Dsa {
    /// Encode a private key as a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub fn private_key_to_pem(private_key: &SigningKey) -> Result<String, DsaError> {
        use pkcs8::EncodePrivateKey;
        private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(DsaError::PrivateKeyPem)
    }

    /// Decode a private key from a PKCS#8 PEM document.
    pub fn private_key_from_pem(pem: &str) -> Result<SigningKey, DsaError> {
        use pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(pem).map_err(DsaError::PrivateKeyPem)
    }

    /// Encode a public key as a SubjectPublicKeyInfo PEM document
    /// (`-----BEGIN PUBLIC KEY-----`).
    pub fn public_key_to_pem(public_key: &VerifyingKey) -> Result<String, DsaError> {
        use pkcs8::EncodePublicKey;
        public_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(DsaError::PublicKeyPem)
    }

    /// Decode a public key from a SubjectPublicKeyInfo PEM document.
    pub fn public_key_from_pem(pem: &str) -> Result<VerifyingKey, DsaError> {
        use pkcs8::DecodePublicKey;
        VerifyingKey::from_public_key_pem(pem).map_err(DsaError::PublicKeyPem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsa_sign_and_verify() {
        let (private_key, public_key) = Dsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let signature = Dsa::sign(&private_key, message).expect("Signing failed");
        let valid = Dsa::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn dsa_tampered_message_fails() {
        let (private_key, public_key) = Dsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";
        let tampered = b"Tampered message!";

        let signature = Dsa::sign(&private_key, message).expect("Signing failed");
        let result = Dsa::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn dsa_keys_round_trip_through_pem() {
        let (private_key, public_key) = Dsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let private_pem = Dsa::private_key_to_pem(&private_key).expect("PEM encoding failed");
        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let restored_private =
            Dsa::private_key_from_pem(&private_pem).expect("PEM decoding failed");

        let public_pem = Dsa::public_key_to_pem(&public_key).expect("PEM encoding failed");
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let restored_public = Dsa::public_key_from_pem(&public_pem).expect("PEM decoding failed");

        let signature = Dsa::sign(&restored_private, message).expect("Signing failed");
        let valid =
            Dsa::verify(&restored_public, message, &signature).expect("Verification failed");
        assert!(valid, "Keys round-tripped through PEM should still work");
    }
}
