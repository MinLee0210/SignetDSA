//! RSA signature algorithm implementation.
//!
//! Provides the [`Rsa`] struct, implementing the [`crate::Signature`] trait using
//! PKCS#1 v1.5 padding and SHA-256, backed by the `rsa` crate.

use crate::signature::Signature;
use ::rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{SigningKey, VerifyingKey},
};
use ::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rand::rngs::OsRng;
use sha2::Sha256;

/// RSA digital signature using PKCS#1 v1.5 padding with SHA-256.
///
/// # Security note
///
/// The `rsa` crate has an open, unfixed advisory — [RUSTSEC-2023-0071]
/// ("Marvin Attack") — covering timing side-channels in RSA signing and
/// decryption. It is only exploitable by an attacker able to measure signing
/// latency (e.g. over a shared network or as a co-tenant on the same
/// machine); local, non-adversarial use is unaffected. Avoid this algorithm
/// for signing in settings where such timing observation is possible, and
/// prefer [`crate::algo::ecdsa::Ecdsa`], [`crate::algo::eddsa::EdDsa`], or
/// [`crate::algo::schnorr::Schnorr`] where a classical scheme is acceptable.
///
/// [RUSTSEC-2023-0071]: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
pub struct Rsa;

#[derive(Debug)]
pub enum RsaError {
    KeyGeneration(::rsa::Error),
    Signing(::rsa::Error),
    InvalidSignatureEncoding,
    Verification(::signature::Error),
    PrivateKeyPem(pkcs8::Error),
    PublicKeyPem(pkcs8::spki::Error),
}

impl std::fmt::Display for RsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RsaError::KeyGeneration(e) => write!(f, "RSA key generation failed: {e}"),
            RsaError::Signing(e) => write!(f, "RSA signing failed: {e}"),
            RsaError::InvalidSignatureEncoding => write!(f, "Invalid RSA signature encoding"),
            RsaError::Verification(e) => write!(f, "RSA verification failed: {e}"),
            RsaError::PrivateKeyPem(e) => write!(f, "RSA private key PEM error: {e}"),
            RsaError::PublicKeyPem(e) => write!(f, "RSA public key PEM error: {e}"),
        }
    }
}

impl std::error::Error for RsaError {}

impl Signature for Rsa {
    type PrivateKey = RsaPrivateKey;
    type PublicKey = RsaPublicKey;
    type Error = RsaError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let private_key =
            RsaPrivateKey::new(&mut OsRng, 2048).expect("Failed to generate RSA private key");
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

impl Rsa {
    /// Encode a private key as a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`) — the modern, algorithm-agnostic
    /// format, as opposed to RSA's traditional PKCS#1
    /// (`-----BEGIN RSA PRIVATE KEY-----`).
    pub fn private_key_to_pem(private_key: &RsaPrivateKey) -> Result<String, RsaError> {
        use pkcs8::EncodePrivateKey;
        private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(RsaError::PrivateKeyPem)
    }

    /// Decode a private key from a PKCS#8 PEM document.
    pub fn private_key_from_pem(pem: &str) -> Result<RsaPrivateKey, RsaError> {
        use pkcs8::DecodePrivateKey;
        RsaPrivateKey::from_pkcs8_pem(pem).map_err(RsaError::PrivateKeyPem)
    }

    /// Encode a public key as a SubjectPublicKeyInfo PEM document
    /// (`-----BEGIN PUBLIC KEY-----`).
    pub fn public_key_to_pem(public_key: &RsaPublicKey) -> Result<String, RsaError> {
        use pkcs8::EncodePublicKey;
        public_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(RsaError::PublicKeyPem)
    }

    /// Decode a public key from a SubjectPublicKeyInfo PEM document.
    pub fn public_key_from_pem(pem: &str) -> Result<RsaPublicKey, RsaError> {
        use pkcs8::DecodePublicKey;
        RsaPublicKey::from_public_key_pem(pem).map_err(RsaError::PublicKeyPem)
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

    #[test]
    fn rsa_keys_round_trip_through_pem() {
        let (private_key, public_key) = Rsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let private_pem = Rsa::private_key_to_pem(&private_key).expect("PEM encoding failed");
        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let restored_private =
            Rsa::private_key_from_pem(&private_pem).expect("PEM decoding failed");

        let public_pem = Rsa::public_key_to_pem(&public_key).expect("PEM encoding failed");
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let restored_public = Rsa::public_key_from_pem(&public_pem).expect("PEM decoding failed");

        let signature = Rsa::sign(&restored_private, message).expect("Signing failed");
        let valid =
            Rsa::verify(&restored_public, message, &signature).expect("Verification failed");
        assert!(valid, "Keys round-tripped through PEM should still work");
    }
}
