//! Schnorr signature (BIP340) implementation.
//!
//! Provides the [`Schnorr`] type implementing the [`crate::Signature`] trait
//! over secp256k1 following the BIP340 standard, backed by the `k256` crate.

use crate::signature::Signature;
use k256::schnorr::{
    Signature as SchnorrSignature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use rand::rngs::OsRng;

/// Schnorr signature over secp256k1 following BIP340 (Bitcoin Taproot standard).
///
/// BIP340 Schnorr is deterministic — signing the same message with
/// the same key always produces the same signature. This is a stronger
/// security property than ECDSA, which requires a fresh random nonce per sign.
///
/// # BIP340 conformance
///
/// Signing and verification go through k256's `PrehashSigner`/`PrehashVerifier`
/// (`sign_prehash`/`verify_prehash`), which — despite the name — feed `message`
/// directly into the tagged challenge hash exactly as BIP340 specifies, with a
/// fixed (all-zero) `aux_rand` for determinism. k256's `Signer`/`Verifier`
/// traits instead SHA-256-hash the message first, which is *not* BIP340 and
/// would not interoperate with real Taproot signatures over the same message
/// — that pair is deliberately avoided here.
pub struct Schnorr;

#[derive(Debug)]
pub enum SchnorrError {
    Signing(k256::schnorr::signature::Error),
    InvalidSignatureEncoding,
    Verification(k256::schnorr::signature::Error),
}

impl std::fmt::Display for SchnorrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchnorrError::Signing(e) => write!(f, "Schnorr signing failed: {e}"),
            SchnorrError::InvalidSignatureEncoding => {
                write!(f, "Invalid Schnorr signature encoding")
            }
            SchnorrError::Verification(e) => write!(f, "Schnorr verification failed: {e}"),
        }
    }
}

impl std::error::Error for SchnorrError {}

impl Signature for Schnorr {
    type PrivateKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Error = SchnorrError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let sig: SchnorrSignature = private_key
            .sign_prehash(message)
            .map_err(SchnorrError::Signing)?;
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let sig = SchnorrSignature::try_from(signature)
            .map_err(|_| SchnorrError::InvalidSignatureEncoding)?;
        public_key
            .verify_prehash(message, &sig)
            .map(|_| true)
            .map_err(SchnorrError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schnorr_sign_and_verify() {
        let (private_key, public_key) = Schnorr::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let signature = Schnorr::sign(&private_key, message).expect("Signing failed");
        let valid = Schnorr::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn schnorr_deterministic() {
        // BIP340 Schnorr is deterministic — same key + message = same signature
        let (private_key, _) = Schnorr::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let sig1 = Schnorr::sign(&private_key, message).expect("Signing failed");
        let sig2 = Schnorr::sign(&private_key, message).expect("Signing failed");
        assert_eq!(sig1, sig2, "Schnorr signatures must be deterministic");
    }

    #[test]
    fn schnorr_tampered_message_fails() {
        let (private_key, public_key) = Schnorr::generate_keys();
        let message = b"Hello, GrimoireDSA!";
        let tampered = b"Tampered message!";

        let signature = Schnorr::sign(&private_key, message).expect("Signing failed");
        let result = Schnorr::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }
}
