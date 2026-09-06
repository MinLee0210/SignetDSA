//! ECDSA (Elliptic Curve Digital Signature Algorithm) implementation.
//!
//! Provides the [`Ecdsa`] type implementing the [`crate::Signature`] trait over
//! the NIST P-256 curve using SHA-256, backed by the `p256` crate.

use crate::signature::Signature;
use ::p256::ecdsa::{
    Signature as EcdsaSignature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::rngs::OsRng;

/// ECDSA digital signature over NIST P-256 with SHA-256 (SHA2-256).
pub struct Ecdsa;

#[derive(Debug)]
pub enum EcdsaError {
    InvalidSignatureEncoding,
    Verification(::p256::ecdsa::Error),
    PrivateKeyPem(pkcs8::Error),
    PublicKeyPem(pkcs8::spki::Error),
}

impl std::fmt::Display for EcdsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcdsaError::InvalidSignatureEncoding => write!(f, "Invalid ECDSA signature encoding"),
            EcdsaError::Verification(e) => write!(f, "ECDSA verification failed: {e}"),
            EcdsaError::PrivateKeyPem(e) => write!(f, "ECDSA private key PEM error: {e}"),
            EcdsaError::PublicKeyPem(e) => write!(f, "ECDSA public key PEM error: {e}"),
        }
    }
}

impl std::error::Error for EcdsaError {}

impl Signature for Ecdsa {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Error = EcdsaError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let sig: EcdsaSignature = private_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let sig = EcdsaSignature::try_from(signature)
            .map_err(|_| EcdsaError::InvalidSignatureEncoding)?;
        public_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(EcdsaError::Verification)
    }
}

impl Ecdsa {
    /// Encode a private key as a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub fn private_key_to_pem(private_key: &SigningKey) -> Result<String, EcdsaError> {
        use pkcs8::EncodePrivateKey;
        private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(EcdsaError::PrivateKeyPem)
    }

    /// Decode a private key from a PKCS#8 PEM document.
    pub fn private_key_from_pem(pem: &str) -> Result<SigningKey, EcdsaError> {
        use pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(pem).map_err(EcdsaError::PrivateKeyPem)
    }

    /// Encode a public key as a SubjectPublicKeyInfo PEM document
    /// (`-----BEGIN PUBLIC KEY-----`).
    pub fn public_key_to_pem(public_key: &VerifyingKey) -> Result<String, EcdsaError> {
        use pkcs8::EncodePublicKey;
        public_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(EcdsaError::PublicKeyPem)
    }

    /// Decode a public key from a SubjectPublicKeyInfo PEM document.
    pub fn public_key_from_pem(pem: &str) -> Result<VerifyingKey, EcdsaError> {
        use pkcs8::DecodePublicKey;
        VerifyingKey::from_public_key_pem(pem).map_err(EcdsaError::PublicKeyPem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_sign_and_verify() {
        let (private_key, public_key) = Ecdsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let signature = Ecdsa::sign(&private_key, message).expect("Signing failed");
        let valid = Ecdsa::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn ecdsa_tampered_message_fails() {
        let (private_key, public_key) = Ecdsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";
        let tampered = b"Tampered message!";

        let signature = Ecdsa::sign(&private_key, message).expect("Signing failed");
        let result = Ecdsa::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn ecdsa_keys_round_trip_through_pem() {
        let (private_key, public_key) = Ecdsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let private_pem = Ecdsa::private_key_to_pem(&private_key).expect("PEM encoding failed");
        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let restored_private =
            Ecdsa::private_key_from_pem(&private_pem).expect("PEM decoding failed");

        let public_pem = Ecdsa::public_key_to_pem(&public_key).expect("PEM encoding failed");
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let restored_public = Ecdsa::public_key_from_pem(&public_pem).expect("PEM decoding failed");

        let signature = Ecdsa::sign(&restored_private, message).expect("Signing failed");
        let valid =
            Ecdsa::verify(&restored_public, message, &signature).expect("Verification failed");
        assert!(valid, "Keys round-tripped through PEM should still work");
    }
}
