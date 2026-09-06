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
    BatchVerification(ed25519_dalek::SignatureError),
    PrivateKeyPem(pkcs8::Error),
    PublicKeyPem(pkcs8::spki::Error),
}

impl std::fmt::Display for EdDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdDsaError::InvalidSignatureEncoding => write!(f, "Invalid EdDSA signature encoding"),
            EdDsaError::Verification(e) => write!(f, "EdDSA verification failed: {e}"),
            EdDsaError::BatchVerification(e) => write!(f, "EdDSA batch verification failed: {e}"),
            EdDsaError::PrivateKeyPem(e) => write!(f, "EdDSA private key PEM error: {e}"),
            EdDsaError::PublicKeyPem(e) => write!(f, "EdDSA public key PEM error: {e}"),
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

impl EdDsa {
    /// Verify many (message, public key, signature) triples in a single call
    /// — meaningfully faster than verifying each one individually, at the
    /// cost of losing the ability to tell *which* signature was invalid if
    /// verification fails (fall back to verifying one at a time to find it).
    pub fn verify_batch(
        messages: &[&[u8]],
        signatures: &[Vec<u8>],
        public_keys: &[VerifyingKey],
    ) -> Result<bool, EdDsaError> {
        let signatures = signatures
            .iter()
            .map(|s| {
                let bytes: [u8; 64] = s
                    .as_slice()
                    .try_into()
                    .map_err(|_| EdDsaError::InvalidSignatureEncoding)?;
                Ok(Ed25519Signature::from_bytes(&bytes))
            })
            .collect::<Result<Vec<_>, EdDsaError>>()?;

        ed25519_dalek::verify_batch(messages, &signatures, public_keys)
            .map(|_| true)
            .map_err(EdDsaError::BatchVerification)
    }

    /// Encode a private key as a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub fn private_key_to_pem(private_key: &SigningKey) -> Result<String, EdDsaError> {
        use pkcs8::EncodePrivateKey;
        private_key
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(EdDsaError::PrivateKeyPem)
    }

    /// Decode a private key from a PKCS#8 PEM document.
    pub fn private_key_from_pem(pem: &str) -> Result<SigningKey, EdDsaError> {
        use pkcs8::DecodePrivateKey;
        SigningKey::from_pkcs8_pem(pem).map_err(EdDsaError::PrivateKeyPem)
    }

    /// Encode a public key as a SubjectPublicKeyInfo PEM document
    /// (`-----BEGIN PUBLIC KEY-----`).
    pub fn public_key_to_pem(public_key: &VerifyingKey) -> Result<String, EdDsaError> {
        use pkcs8::EncodePublicKey;
        public_key
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .map_err(EdDsaError::PublicKeyPem)
    }

    /// Decode a public key from a SubjectPublicKeyInfo PEM document.
    pub fn public_key_from_pem(pem: &str) -> Result<VerifyingKey, EdDsaError> {
        use pkcs8::DecodePublicKey;
        VerifyingKey::from_public_key_pem(pem).map_err(EdDsaError::PublicKeyPem)
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

    #[test]
    fn eddsa_verify_batch_accepts_all_valid() {
        let keypairs: Vec<_> = (0..8).map(|_| EdDsa::generate_keys()).collect();
        let messages: Vec<&[u8]> = (0..8).map(|i| MESSAGES[i]).collect();
        let signatures: Vec<Vec<u8>> = keypairs
            .iter()
            .zip(&messages)
            .map(|((sk, _), msg)| EdDsa::sign(sk, msg).expect("Signing failed"))
            .collect();
        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|(_, pk)| *pk).collect();

        let valid = EdDsa::verify_batch(&messages, &signatures, &public_keys)
            .expect("Batch verification failed");
        assert!(valid, "A batch of all-valid signatures should verify");
    }

    #[test]
    fn eddsa_verify_batch_rejects_one_bad_signature() {
        let keypairs: Vec<_> = (0..8).map(|_| EdDsa::generate_keys()).collect();
        let messages: Vec<&[u8]> = (0..8).map(|i| MESSAGES[i]).collect();
        let mut signatures: Vec<Vec<u8>> = keypairs
            .iter()
            .zip(&messages)
            .map(|((sk, _), msg)| EdDsa::sign(sk, msg).expect("Signing failed"))
            .collect();
        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|(_, pk)| *pk).collect();

        // Corrupt one signature in the batch.
        signatures[3][0] ^= 0xff;

        let result = EdDsa::verify_batch(&messages, &signatures, &public_keys);
        assert!(
            result.is_err(),
            "A batch with one bad signature should fail"
        );
    }

    #[test]
    fn eddsa_keys_round_trip_through_pem() {
        let (private_key, public_key) = EdDsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let private_pem = EdDsa::private_key_to_pem(&private_key).expect("PEM encoding failed");
        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let restored_private =
            EdDsa::private_key_from_pem(&private_pem).expect("PEM decoding failed");

        let public_pem = EdDsa::public_key_to_pem(&public_key).expect("PEM encoding failed");
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let restored_public = EdDsa::public_key_from_pem(&public_pem).expect("PEM decoding failed");

        let signature = EdDsa::sign(&restored_private, message).expect("Signing failed");
        let valid =
            EdDsa::verify(&restored_public, message, &signature).expect("Verification failed");
        assert!(valid, "Keys round-tripped through PEM should still work");
    }

    const MESSAGES: [&[u8]; 8] = [
        b"message 0",
        b"message 1",
        b"message 2",
        b"message 3",
        b"message 4",
        b"message 5",
        b"message 6",
        b"message 7",
    ];
}
