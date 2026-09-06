//! EdDSA over Ed448 ("Curve448"/Goldilocks) implementation — RFC 8032 §5.2.
//!
//! Provides the [`Ed448`] type implementing the [`crate::Signature`] trait,
//! backed by the `ed448-goldilocks-plus` crate. Same shape as
//! [`crate::algo::eddsa::EdDsa`] (Ed25519) but at a higher security margin
//! (~224-bit vs ~128-bit), at the cost of larger keys/signatures (57-byte
//! keys, 114-byte signatures) and a less battle-tested implementation —
//! prefer Ed25519 unless the extra security margin is specifically required.
//!
//! # Why keys aren't generated via the crate's own `SigningKey::generate`
//!
//! `ed448-goldilocks-plus` depends on `rand_core` 0.10, while the rest of
//! this crate (and its `rand::rngs::OsRng`) is on the `rand` 0.8 / `rand_core`
//! 0.6 generation — an incompatible trait, not just an incompatible version.
//! Rather than pull in a second `rand_core` major version, keys are seeded by
//! filling 57 bytes from the same `OsRng` every other module here uses and
//! handed to `SigningKey::from_bytes`, which is exactly what `generate` does
//! internally.

use crate::signature::Signature;
use ed448_goldilocks_plus::{
    SECRET_KEY_LENGTH, SecretKey, Signature as Ed448Signature, SigningKey, VerifyingKey,
};
use rand::RngCore;
use rand::rngs::OsRng;

/// EdDSA digital signature over Curve448 (Ed448), per RFC 8032 §5.2.
pub struct Ed448;

#[derive(Debug)]
pub enum Ed448Error {
    InvalidSignatureEncoding(ed448_goldilocks_plus::SigningError),
    InvalidPublicKeyEncoding,
    Verification(String),
}

impl std::fmt::Display for Ed448Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ed448Error::InvalidSignatureEncoding(e) => {
                write!(f, "Invalid Ed448 signature encoding: {e}")
            }
            Ed448Error::InvalidPublicKeyEncoding => write!(f, "Invalid Ed448 public key encoding"),
            Ed448Error::Verification(e) => write!(f, "Ed448 verification failed: {e}"),
        }
    }
}

impl std::error::Error for Ed448Error {}

impl Signature for Ed448 {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Error = Ed448Error;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        OsRng.fill_bytes(&mut seed);
        let secret_key: SecretKey = seed.into();

        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let sig = private_key.sign_raw(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let sig =
            Ed448Signature::from_slice(signature).map_err(Ed448Error::InvalidSignatureEncoding)?;
        public_key
            .verify_raw(&sig, message)
            .map(|_| true)
            .map_err(|e| Ed448Error::Verification(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed448_sign_and_verify() {
        let (private_key, public_key) = Ed448::generate_keys();
        let message = b"Hello, SignetDSA!";

        let signature = Ed448::sign(&private_key, message).expect("Signing failed");
        let valid = Ed448::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn ed448_tampered_message_fails() {
        let (private_key, public_key) = Ed448::generate_keys();
        let message = b"Hello, SignetDSA!";
        let tampered = b"Tampered message!";

        let signature = Ed448::sign(&private_key, message).expect("Signing failed");
        let result = Ed448::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn ed448_signature_and_key_sizes_match_rfc8032() {
        let (private_key, public_key) = Ed448::generate_keys();
        let message = b"size check";
        let signature = Ed448::sign(&private_key, message).expect("Signing failed");

        assert_eq!(
            public_key.to_bytes().len(),
            57,
            "Ed448 public key is 57 bytes"
        );
        assert_eq!(signature.len(), 114, "Ed448 signature is 114 bytes");
    }
}
