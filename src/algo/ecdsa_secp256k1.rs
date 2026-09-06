//! ECDSA over secp256k1 (the Bitcoin/Ethereum curve) implementation.
//!
//! Provides the [`EcdsaSecp256k1`] type implementing the [`crate::Signature`]
//! trait over secp256k1 with SHA-256, backed by the `k256` crate. This is
//! deliberately a separate type from [`crate::algo::ecdsa::Ecdsa`] (NIST
//! P-256) — same algorithm shape, different curve, and the two are not
//! interchangeable.
//!
//! Unlike [`crate::algo::schnorr::Schnorr`], plain ECDSA signing genuinely
//! *does* hash the message with SHA-256 before the curve math (that's the
//! standard, not a shortcut), so this module uses k256's ordinary
//! `Signer`/`Verifier` traits.

use crate::signature::Signature;
use k256::ecdsa::{
    RecoveryId, Signature as EcdsaSignature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use rand::rngs::OsRng;

/// ECDSA digital signature over secp256k1 with SHA-256.
pub struct EcdsaSecp256k1;

#[derive(Debug)]
pub enum EcdsaSecp256k1Error {
    Signing(k256::ecdsa::Error),
    InvalidSignatureEncoding,
    InvalidRecoveryId,
    Verification(k256::ecdsa::Error),
    Recovery(k256::ecdsa::Error),
}

impl std::fmt::Display for EcdsaSecp256k1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcdsaSecp256k1Error::Signing(e) => write!(f, "ECDSA/secp256k1 signing failed: {e}"),
            EcdsaSecp256k1Error::InvalidSignatureEncoding => {
                write!(f, "Invalid ECDSA/secp256k1 signature encoding")
            }
            EcdsaSecp256k1Error::InvalidRecoveryId => {
                write!(f, "Recovery id must be 0-3")
            }
            EcdsaSecp256k1Error::Verification(e) => {
                write!(f, "ECDSA/secp256k1 verification failed: {e}")
            }
            EcdsaSecp256k1Error::Recovery(e) => {
                write!(f, "ECDSA/secp256k1 public key recovery failed: {e}")
            }
        }
    }
}

impl std::error::Error for EcdsaSecp256k1Error {}

impl Signature for EcdsaSecp256k1 {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Error = EcdsaSecp256k1Error;

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
            .map_err(|_| EcdsaSecp256k1Error::InvalidSignatureEncoding)?;
        public_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(EcdsaSecp256k1Error::Verification)
    }
}

impl EcdsaSecp256k1 {
    /// Sign `message`, additionally returning the 1-byte recovery id needed
    /// to recover the signer's public key from the signature alone (the
    /// `ecrecover` pattern used by Ethereum and similar systems).
    pub fn sign_recoverable(
        private_key: &SigningKey,
        message: &[u8],
    ) -> Result<(Vec<u8>, u8), EcdsaSecp256k1Error> {
        let (sig, recid) = private_key
            .sign_recoverable(message)
            .map_err(EcdsaSecp256k1Error::Signing)?;
        Ok((sig.to_bytes().to_vec(), recid.to_byte()))
    }

    /// Recover the public key that produced `signature` over `message`,
    /// given the recovery id returned alongside it by
    /// [`sign_recoverable`](Self::sign_recoverable).
    pub fn recover_public_key(
        message: &[u8],
        signature: &[u8],
        recovery_id: u8,
    ) -> Result<VerifyingKey, EcdsaSecp256k1Error> {
        let sig = EcdsaSignature::try_from(signature)
            .map_err(|_| EcdsaSecp256k1Error::InvalidSignatureEncoding)?;
        let recid = RecoveryId::try_from(recovery_id)
            .map_err(|_| EcdsaSecp256k1Error::InvalidRecoveryId)?;
        VerifyingKey::recover_from_msg(message, &sig, recid).map_err(EcdsaSecp256k1Error::Recovery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_secp256k1_sign_and_verify() {
        let (private_key, public_key) = EcdsaSecp256k1::generate_keys();
        let message = b"Hello, SignetDSA!";

        let signature = EcdsaSecp256k1::sign(&private_key, message).expect("Signing failed");
        let valid =
            EcdsaSecp256k1::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn ecdsa_secp256k1_tampered_message_fails() {
        let (private_key, public_key) = EcdsaSecp256k1::generate_keys();
        let message = b"Hello, SignetDSA!";
        let tampered = b"Tampered message!";

        let signature = EcdsaSecp256k1::sign(&private_key, message).expect("Signing failed");
        let result = EcdsaSecp256k1::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn ecdsa_secp256k1_recovers_signer_public_key() {
        let (private_key, public_key) = EcdsaSecp256k1::generate_keys();
        let message = b"ecrecover me";

        let (signature, recovery_id) =
            EcdsaSecp256k1::sign_recoverable(&private_key, message).expect("Signing failed");
        let recovered = EcdsaSecp256k1::recover_public_key(message, &signature, recovery_id)
            .expect("Recovery failed");

        assert_eq!(recovered, public_key, "Recovered key should match signer");
    }

    #[test]
    fn ecdsa_secp256k1_recovery_rejects_wrong_message() {
        let (private_key, public_key) = EcdsaSecp256k1::generate_keys();
        let message = b"ecrecover me";
        let tampered = b"not the signed message";

        let (signature, recovery_id) =
            EcdsaSecp256k1::sign_recoverable(&private_key, message).expect("Signing failed");
        let recovered = EcdsaSecp256k1::recover_public_key(tampered, &signature, recovery_id)
            .expect("Recovery should still succeed, just to the wrong key");

        assert_ne!(
            recovered, public_key,
            "Recovering against a different message must not yield the real signer's key"
        );
    }
}
