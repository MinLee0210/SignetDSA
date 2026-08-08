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
}

impl std::fmt::Display for DsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsaError::KeyGeneration(e) => write!(f, "DSA key generation failed: {e}"),
            DsaError::Signing(e) => write!(f, "DSA signing failed: {e}"),
            DsaError::InvalidSignatureEncoding => write!(f, "Invalid DSA signature encoding"),
            DsaError::Verification(e) => write!(f, "DSA verification failed: {e}"),
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
}
