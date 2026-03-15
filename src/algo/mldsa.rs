use crate::signature::Signature;
use ml_dsa::{KeyGen, MlDsa65, SigningKey, VerifyingKey};
use ml_dsa::signature::{Signer, Verifier};
use signature::SignatureEncoding;
use rand::rngs::OsRng;

/// ML-DSA-65 (CRYSTALS-Dilithium), NIST FIPS 204.
///
/// A post-quantum digital signature algorithm based on the hardness of
/// Module Learning With Errors (MLWE) — a lattice problem believed to
/// be resistant to attacks by quantum computers.
///
/// ML-DSA-65 targets NIST Level 3 (~192-bit classical security).
/// Key sizes are much larger than classical schemes:
///   - Public key:  1952 bytes
///   - Private key: 4032 bytes
///   - Signature:   3309 bytes
pub struct MlDsa;

#[derive(Debug)]
pub enum MlDsaError {
    InvalidSignatureEncoding,
    Verification(ml_dsa::Error),
}

impl std::fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlDsaError::InvalidSignatureEncoding => {
                write!(f, "Invalid ML-DSA signature encoding")
            }
            MlDsaError::Verification(e) => write!(f, "ML-DSA verification failed: {e}"),
        }
    }
}

impl std::error::Error for MlDsaError {}

impl Signature for MlDsa {
    type PrivateKey = SigningKey<MlDsa65>;
    type PublicKey = VerifyingKey<MlDsa65>;
    type Error = MlDsaError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let kp = MlDsa65::key_gen(&mut OsRng);
        let signing_key = kp.signing_key().clone();
        let verifying_key = kp.verifying_key().clone();
        (signing_key, verifying_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let sig = private_key.sign(message);
        Ok(sig.to_vec())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature)
            .map_err(|_| MlDsaError::InvalidSignatureEncoding)?;
        public_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(MlDsaError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa_sign_and_verify() {
        let (private_key, public_key) = MlDsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";

        let signature = MlDsa::sign(&private_key, message).expect("Signing failed");
        let valid = MlDsa::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn mldsa_tampered_message_fails() {
        let (private_key, public_key) = MlDsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";
        let tampered = b"Tampered message!";

        let signature = MlDsa::sign(&private_key, message).expect("Signing failed");
        let result = MlDsa::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn mldsa_signature_is_large() {
        // Document the post-quantum size overhead vs classical schemes.
        // ML-DSA-65 signatures are 3309 bytes vs 64 bytes for Ed25519.
        let (private_key, _) = MlDsa::generate_keys();
        let message = b"Hello, GrimoireDSA!";
        let signature = MlDsa::sign(&private_key, message).expect("Signing failed");
        assert_eq!(signature.len(), 3309, "ML-DSA-65 signature should be 3309 bytes");
    }
}
