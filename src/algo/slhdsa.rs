//! SLH-DSA (SPHINCS+) stateless hash-based post-quantum signature implementation.
//!
//! Provides the [`SlhDsa`] type implementing the [`crate::Signature`] trait
//! for SLH-DSA-SHAKE-128f (FIPS 205), backed by the `slh-dsa` crate.

use crate::signature::Signature;
use slh_dsa::signature::{Keypair, Signer, Verifier};
use slh_dsa::{Shake128f, SigningKey, VerifyingKey};

/// SLH-DSA-SHAKE-128f (SPHINCS+), NIST FIPS 205.
///
/// A stateless hash-based digital signature algorithm whose security depends
/// solely on the collision resistance and preimage resistance of cryptographic hash functions (SHAKE-256).
///
/// Unlike lattice-based schemes (like ML-DSA), SLH-DSA makes zero algebraic lattice assumptions,
/// providing an essential quantum-safe cryptographic hedge.
///
/// SLH-DSA-SHAKE-128f parameters:
///   - Private key: 64 bytes (16B sk_seed + 16B sk_prf + 16B pk_seed + 16B pk_root)
///   - Public key:  32 bytes (16B pk_seed + 16B pk_root)
///   - Signature:   17,088 bytes
pub struct SlhDsa;

#[derive(Debug)]
pub enum SlhDsaError {
    InvalidSignatureEncoding,
    Verification(slh_dsa::signature::Error),
    KeyEncoding(String),
}

impl std::fmt::Display for SlhDsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlhDsaError::InvalidSignatureEncoding => {
                write!(f, "Invalid SLH-DSA signature encoding")
            }
            SlhDsaError::Verification(e) => write!(f, "SLH-DSA verification failed: {e}"),
            SlhDsaError::KeyEncoding(s) => write!(f, "SLH-DSA key encoding error: {s}"),
        }
    }
}

impl std::error::Error for SlhDsaError {}

impl Signature for SlhDsa {
    type PrivateKey = SigningKey<Shake128f>;
    type PublicKey = VerifyingKey<Shake128f>;
    type Error = SlhDsaError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let mut sk_seed = [0u8; 16];
        let mut sk_prf = [0u8; 16];
        let mut pk_seed = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk_seed);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sk_prf);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut pk_seed);

        let signing_key = SigningKey::<Shake128f>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
        let verifying_key = signing_key.verifying_key();
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
        let sig = slh_dsa::Signature::<Shake128f>::try_from(signature)
            .map_err(|_| SlhDsaError::InvalidSignatureEncoding)?;
        public_key
            .verify(message, &sig)
            .map(|_| true)
            .map_err(SlhDsaError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slhdsa_sign_and_verify() {
        let (sk, pk) = SlhDsa::generate_keys();
        let msg = b"Post-quantum hash-based signature test payload";
        let sig = SlhDsa::sign(&sk, msg).expect("signing should succeed");
        assert_eq!(sig.len(), 17088);

        let valid = SlhDsa::verify(&pk, msg, &sig).expect("verification should succeed");
        assert!(valid);
    }

    #[test]
    fn slhdsa_tampered_message_fails() {
        let (sk, pk) = SlhDsa::generate_keys();
        let msg = b"Original transaction payload";
        let sig = SlhDsa::sign(&sk, msg).unwrap();

        let res = SlhDsa::verify(&pk, b"Tampered transaction payload", &sig);
        assert!(res.is_err());
    }
}
