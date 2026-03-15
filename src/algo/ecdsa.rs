use crate::signature::Signature;
use ::p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as EcdsaSignature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;

/// ECDSA digital signature over NIST P-256 with SHA-256 (SHA2-256).
pub struct Ecdsa;

#[derive(Debug)]
pub enum EcdsaError {
    InvalidSignatureEncoding,
    Verification(::p256::ecdsa::Error),
}

impl std::fmt::Display for EcdsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcdsaError::InvalidSignatureEncoding => write!(f, "Invalid ECDSA signature encoding"),
            EcdsaError::Verification(e) => write!(f, "ECDSA verification failed: {e}"),
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
}
