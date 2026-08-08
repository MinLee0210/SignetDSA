//! EdDSA (Edwards-curve Digital Signature Algorithm) implementation.
//!
//! Provides the [`EdDsa`] type implementing the [`crate::Signature`] trait over
//! Curve25519 (Ed25519), backed by the `ed25519-dalek` crate.

use crate::signature::Signature;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// EdDSA digital signature over Curve25519 (Ed25519).
pub struct EdDsa;

#[derive(Debug)]
pub enum EdDsaError {
    InvalidSignatureEncoding,
    Verification(ed25519_dalek::SignatureError),
}

impl std::fmt::Display for EdDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdDsaError::InvalidSignatureEncoding => write!(f, "Invalid EdDSA signature encoding"),
            EdDsaError::Verification(e) => write!(f, "EdDSA verification failed: {e}"),
        }
    }
}

impl std::error::Error for EdDsaError {}

impl Signature for EdDsa {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Error = EdDsaError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let sig: Ed25519Signature = private_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| EdDsaError::InvalidSignatureEncoding)?;
        let sig = Ed25519Signature::from_bytes(&sig_bytes);
        public_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(EdDsaError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eddsa_sign_and_verify() {
        let (private_key, public_key) = EdDsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let signature = EdDsa::sign(&private_key, message).expect("Signing failed");
        let valid = EdDsa::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn eddsa_tampered_message_fails() {
        let (private_key, public_key) = EdDsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";
        let tampered = b"Tampered message!";

        let signature = EdDsa::sign(&private_key, message).expect("Signing failed");
        let result = EdDsa::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }
}
