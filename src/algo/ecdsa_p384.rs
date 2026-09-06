//! ECDSA over NIST P-384 (secp384r1) implementation.
//!
//! Provides the [`EcdsaP384`] type implementing the [`crate::Signature`] trait over
//! the NIST P-384 curve using SHA-384, backed by the `p384` crate.
//!
//! NIST P-384 offers ~192-bit security level, matching the requirements for NSA's
//! Commercial National Security Algorithm (CNSA) Suite 1.0.

use crate::signature::Signature;
use ::p384::ecdsa::{
    Signature as Ecdsa384Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::rngs::OsRng;

/// ECDSA digital signature over NIST P-384 with SHA-384.
pub struct EcdsaP384;

#[derive(Debug)]
pub enum EcdsaP384Error {
    InvalidSignatureEncoding,
    Verification(::p384::ecdsa::Error),
    PrivateKeyPem(pkcs8::Error),
    PublicKeyPem(pkcs8::spki::Error),
}

impl std::fmt::Display for EcdsaP384Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcdsaP384Error::InvalidSignatureEncoding => {
                write!(f, "Invalid ECDSA P-384 signature encoding")
            }
            EcdsaP384Error::Verification(e) => write!(f, "ECDSA P-384 verification failed: {e}"),
            EcdsaP384Error::PrivateKeyPem(e) => write!(f, "ECDSA P-384 private key PEM error: {e}"),
            EcdsaP384Error::PublicKeyPem(e) => write!(f, "ECDSA P-384 public key PEM error: {e}"),
        }
    }
}

impl std::error::Error for EcdsaP384Error {}

impl Signature for EcdsaP384 {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Error = EcdsaP384Error;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let sig: Ecdsa384Signature = private_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let sig = Ecdsa384Signature::try_from(signature)
            .map_err(|_| EcdsaP384Error::InvalidSignatureEncoding)?;
        public_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(EcdsaP384Error::Verification)
    }
}

impl EcdsaP384 {
    /// Encode a private key as a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub fn private_key_to_pem(private_key: &SigningKey) -> Result<String, EcdsaP384Error> {
        use pkcs8::EncodePrivateKey;
        private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(EcdsaP384Error::PrivateKeyPem)
    }

    /// Decode a private key from a PKCS#8 PEM document.
    pub fn private_key_from_pem(pem: &str) -> Result<SigningKey, EcdsaP384Error> {
        use pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(pem).map_err(EcdsaP384Error::PrivateKeyPem)
    }

    /// Encode a public key as a SubjectPublicKeyInfo PEM document
    /// (`-----BEGIN PUBLIC KEY-----`).
    pub fn public_key_to_pem(public_key: &VerifyingKey) -> Result<String, EcdsaP384Error> {
        use pkcs8::EncodePublicKey;
        public_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(EcdsaP384Error::PublicKeyPem)
    }

    /// Decode a public key from a SubjectPublicKeyInfo PEM document.
    pub fn public_key_from_pem(pem: &str) -> Result<VerifyingKey, EcdsaP384Error> {
        use pkcs8::DecodePublicKey;
        VerifyingKey::from_public_key_pem(pem).map_err(EcdsaP384Error::PublicKeyPem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_p384_sign_and_verify() {
        let (private_key, public_key) = EcdsaP384::generate_keys();
        let message = b"Hello, SignetDSA ECDSA P-384!";

        let signature = EcdsaP384::sign(&private_key, message).expect("Signing failed");
        let valid =
            EcdsaP384::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn ecdsa_p384_tampered_message_fails() {
        let (private_key, public_key) = EcdsaP384::generate_keys();
        let message = b"Hello, SignetDSA ECDSA P-384!";
        let tampered = b"Tampered message!";

        let signature = EcdsaP384::sign(&private_key, message).expect("Signing failed");
        let result = EcdsaP384::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn ecdsa_p384_keys_round_trip_through_pem() {
        let (private_key, public_key) = EcdsaP384::generate_keys();
        let message = b"Hello, SignetDSA ECDSA P-384!";

        let private_pem = EcdsaP384::private_key_to_pem(&private_key).expect("PEM encoding failed");
        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let restored_private =
            EcdsaP384::private_key_from_pem(&private_pem).expect("PEM decoding failed");

        let public_pem = EcdsaP384::public_key_to_pem(&public_key).expect("PEM encoding failed");
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let restored_public =
            EcdsaP384::public_key_from_pem(&public_pem).expect("PEM decoding failed");

        let signature = EcdsaP384::sign(&restored_private, message).expect("Signing failed");
        let valid =
            EcdsaP384::verify(&restored_public, message, &signature).expect("Verification failed");
        assert!(valid, "Keys round-tripped through PEM should still work");
    }
}
