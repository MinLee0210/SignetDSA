use crate::signature::Signature;
use ::rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    RsaPrivateKey, RsaPublicKey,
};
use rand::rngs::OsRng;
use sha2::Sha256;
use ::signature::{RandomizedSigner, SignatureEncoding, Verifier};

/// RSA digital signature using PKCS#1 v1.5 padding with SHA-256.
pub struct Rsa;

#[derive(Debug)]
pub enum RsaError {
    KeyGeneration(::rsa::Error),
    Signing(::rsa::Error),
    InvalidSignatureEncoding,
    Verification(::signature::Error),
}

impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsaError::KeyGeneration(e) => write!(f, "RSA key generation failed: {e}"),
            RsaError::Signing(e) => write!(f, "RSA signing failed: {e}"),
            RsaError::InvalidSignatureEncoding => write!(f, "Invalid RSA signature encoding"),
            RsaError::Verification(e) => write!(f, "RSA verification failed: {e}"),
        }
    }
}

impl std::error::Error for RsaError {}

impl Signature for Rsa {
    type PrivateKey = RsaPrivateKey;
    type PublicKey = RsaPublicKey;
    type Error = RsaError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .expect("Failed to generate RSA private key");
        let public_key = RsaPublicKey::from(&private_key);
        (private_key, public_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let sig = signing_key.sign_with_rng(&mut OsRng, message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());
        let sig = ::rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|_| RsaError::InvalidSignatureEncoding)?;
        verifying_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(RsaError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_sign_and_verify() {
        let (private_key, public_key) = Rsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let signature = Rsa::sign(&private_key, message).expect("Signing failed");
        let valid = Rsa::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn rsa_tampered_message_fails() {
        let (private_key, public_key) = Rsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";
        let tampered = b"Tampered message!";

        let signature = Rsa::sign(&private_key, message).expect("Signing failed");
        let result = Rsa::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }
}
