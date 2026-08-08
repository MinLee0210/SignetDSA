//! `Signet` — factory API for digital signature algorithms.
//!
//! Inspired by HuggingFace's `AutoTokenizer.from_pretrained()` pattern.
//! A string identifier selects and returns the correct algorithm implementation
//! at runtime, behind a unified object-safe interface.
//!
//! # Why a separate trait?
//!
//! The generic `Signature` trait uses associated types (`PrivateKey`, `PublicKey`,
//! `Error`), which makes it object-unsafe — you cannot write `Box<dyn Signature>`.
//! `SignetSigner` solves this by replacing typed keys with `Vec<u8>`.
//! Each adapter handles its own internal serialization and deserialization.
//!
//! # Usage
//!
//! ```rust
//! use SignetDSA::{Signet, SignetSigner};
//!
//! let signer = Signet::from_name("ecdsa").expect("Unknown algorithm");
//! let (sk, pk) = signer.generate_keys();
//! let sig = signer.sign(&sk, b"Hello, SignetDSA!").unwrap();
//! assert!(signer.verify(&pk, b"Hello, SignetDSA!", &sig).unwrap());
//! ```

use rand::rngs::OsRng;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Object-safe trait
// ---------------------------------------------------------------------------

/// A unified, object-safe interface for all signature algorithms.
///
/// All keys and signatures are plain byte vectors so implementations can be
/// stored as `Box<dyn SignetSigner>` and chosen at runtime.
pub trait SignetSigner: Send + Sync {
    /// Short algorithm identifier, e.g. `"rsa"`, `"ecdsa"`.
    fn name(&self) -> &'static str;

    /// Generate a fresh `(private_key_bytes, public_key_bytes)` pair.
    ///
    /// The private key is wrapped in [`Zeroizing`] so its backing memory is
    /// wiped when it goes out of scope — plain `Vec<u8>` gives no such
    /// guarantee and would leave secret key material sitting in freed heap
    /// memory.
    fn generate_keys(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>);

    /// Sign `message` using the serialized `private_key`.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String>;

    /// Verify that `signature` was produced over `message` by the holder of `public_key`.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Factory that instantiates signature algorithm implementations by name.
///
/// This is the Rust equivalent of `AutoTokenizer.from_pretrained()`:
/// a string selects the algorithm, a unified trait covers all usage.
pub struct Signet;

impl Signet {
    /// Return a boxed [`SignetSigner`] for the given algorithm name.
    ///
    /// Names are **case-insensitive**. Aliases are accepted:
    /// - `"ecdsa"` or `"p256"`
    /// - `"eddsa"` or `"ed25519"`
    /// - `"schnorr"` or `"bip340"`
    /// - `"mldsa"`, `"ml-dsa"`, or `"dilithium"`
    ///
    /// Returns `None` if the name is not recognised.
    pub fn from_name(name: &str) -> Option<Box<dyn SignetSigner>> {
        match name.to_lowercase().as_str() {
            "rsa" => Some(Box::new(adapters::RsaAdapter)),
            "dsa" => Some(Box::new(adapters::DsaAdapter)),
            "ecdsa" | "p256" => Some(Box::new(adapters::EcdsaAdapter)),
            "eddsa" | "ed25519" => Some(Box::new(adapters::EdDsaAdapter)),
            "schnorr" | "bip340" => Some(Box::new(adapters::SchnorrAdapter)),
            "mldsa" | "ml-dsa" | "dilithium" => Some(Box::new(adapters::MlDsaAdapter)),
            _ => None,
        }
    }

    /// All canonical algorithm names supported by [`Signet::from_name`].
    pub fn available() -> &'static [&'static str] {
        &["rsa", "dsa", "ecdsa", "eddsa", "schnorr", "mldsa"]
    }
}

// ---------------------------------------------------------------------------
// Adapters (private — each wraps one algorithm and handles key serialization)
// ---------------------------------------------------------------------------

mod adapters {
    use super::{OsRng, SignetSigner, Zeroizing};

    // -------------------------------------------------------------------------
    // RSA  — keys serialized as PKCS#1 DER
    // -------------------------------------------------------------------------
    pub struct RsaAdapter;

    impl SignetSigner for RsaAdapter {
        fn name(&self) -> &'static str {
            "rsa"
        }

        fn generate_keys(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
            use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
            use rsa::{RsaPrivateKey, RsaPublicKey};

            let sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA keygen failed");
            let pk = RsaPublicKey::from(&sk);
            (
                Zeroizing::new(
                    sk.to_pkcs1_der()
                        .expect("RSA sk encode")
                        .as_bytes()
                        .to_vec(),
                ),
                pk.to_pkcs1_der()
                    .expect("RSA pk encode")
                    .as_bytes()
                    .to_vec(),
            )
        }

        fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
            use ::signature::{RandomizedSigner, SignatureEncoding};
            use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs1v15::SigningKey};
            use sha2::Sha256;

            let sk = RsaPrivateKey::from_pkcs1_der(private_key).map_err(|e| e.to_string())?;
            let signing_key = SigningKey::<Sha256>::new(sk);
            Ok(signing_key
                .sign_with_rng(&mut OsRng, message)
                .to_bytes()
                .to_vec())
        }

        fn verify(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            use ::signature::Verifier;
            use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs1v15::VerifyingKey};
            use sha2::Sha256;

            let pk = RsaPublicKey::from_pkcs1_der(public_key).map_err(|e| e.to_string())?;
            let vk = VerifyingKey::<Sha256>::new(pk);
            let sig = rsa::pkcs1v15::Signature::try_from(signature).map_err(|e| e.to_string())?;
            vk.verify(message, &sig)
                .map(|_| true)
                .map_err(|e| e.to_string())
        }
    }

    // -------------------------------------------------------------------------
    // DSA  — keys serialized as PKCS#8 DER
    // -------------------------------------------------------------------------
    pub struct DsaAdapter;

    impl SignetSigner for DsaAdapter {
        fn name(&self) -> &'static str {
            "dsa"
        }

        fn generate_keys(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
            use dsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
            use dsa::{Components, KeySize, SigningKey};

            let components = Components::generate(&mut OsRng, KeySize::DSA_2048_256);
            let sk = SigningKey::generate(&mut OsRng, components);
            let vk = sk.verifying_key().clone();
            (
                Zeroizing::new(
                    sk.to_pkcs8_der()
                        .expect("DSA sk encode")
                        .as_bytes()
                        .to_vec(),
                ),
                vk.to_public_key_der()
                    .expect("DSA pk encode")
                    .as_bytes()
                    .to_vec(),
            )
        }

        fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
            use dsa::signature::{DigestSigner, SignatureEncoding};
            use dsa::{SigningKey, pkcs8::DecodePrivateKey};
            use sha2::{Digest, Sha256};

            let sk = SigningKey::from_pkcs8_der(private_key).map_err(|e| e.to_string())?;
            let digest = Sha256::new_with_prefix(message);
            let sig: ::dsa::Signature = sk.sign_digest(digest);
            Ok(sig.to_bytes().to_vec())
        }

        fn verify(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            use dsa::signature::DigestVerifier;
            use dsa::{VerifyingKey, pkcs8::DecodePublicKey};
            use sha2::{Digest, Sha256};

            let vk = VerifyingKey::from_public_key_der(public_key).map_err(|e| e.to_string())?;
            let sig = ::dsa::Signature::try_from(signature)
                .map_err(|_| "Invalid DSA signature bytes".to_string())?;
            let digest = Sha256::new_with_prefix(message);
            vk.verify_digest(digest, &sig)
                .map(|_| true)
                .map_err(|e| e.to_string())
        }
    }

    // -------------------------------------------------------------------------
    // ECDSA P-256  — private: 32-byte scalar, public: 33-byte SEC1 compressed
    // -------------------------------------------------------------------------
    pub struct EcdsaAdapter;

    impl SignetSigner for EcdsaAdapter {
        fn name(&self) -> &'static str {
            "ecdsa"
        }

        fn generate_keys(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
            use p256::ecdsa::SigningKey;

            let sk = SigningKey::random(&mut OsRng);
            let pk_point = sk.verifying_key().to_encoded_point(true);
            (
                Zeroizing::new(sk.to_bytes().to_vec()),
                pk_point.as_bytes().to_vec(),
            )
        }

        fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
            use p256::ecdsa::{Signature, SigningKey, signature::Signer};

            let sk = SigningKey::from_bytes(private_key.into()).map_err(|e| e.to_string())?;
            let sig: Signature = sk.sign(message);
            Ok(sig.to_bytes().to_vec())
        }

        fn verify(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            use p256::elliptic_curve::sec1::EncodedPoint;

            let point = EncodedPoint::<p256::NistP256>::from_bytes(public_key)
                .map_err(|e| e.to_string())?;
            let vk = VerifyingKey::from_encoded_point(&point).map_err(|e| e.to_string())?;
            let sig = Signature::try_from(signature).map_err(|e| e.to_string())?;
            vk.verify(message, &sig)
                .map(|_| true)
                .map_err(|e| e.to_string())
        }
    }

    // -------------------------------------------------------------------------
    // EdDSA (Ed25519)  — keys as raw 32-byte arrays
    // -------------------------------------------------------------------------
    pub struct EdDsaAdapter;

    impl SignetSigner for EdDsaAdapter {
        fn name(&self) -> &'static str {
            "eddsa"
        }

        fn generate_keys(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
            use ed25519_dalek::SigningKey;

            let sk = SigningKey::generate(&mut OsRng);
            let pk = sk.verifying_key();
            (
                Zeroizing::new(sk.to_bytes().to_vec()),
                pk.to_bytes().to_vec(),
            )
        }

        fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
            use ed25519_dalek::{Signer, SigningKey};

            let bytes: [u8; 32] = private_key
                .try_into()
                .map_err(|_| "EdDSA private key must be 32 bytes".to_string())?;
            let sk = SigningKey::from_bytes(&bytes);
            Ok(sk.sign(message).to_bytes().to_vec())
        }

        fn verify(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            let pk_bytes: [u8; 32] = public_key
                .try_into()
                .map_err(|_| "EdDSA public key must be 32 bytes".to_string())?;
            let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| e.to_string())?;
            let sig_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| "EdDSA signature must be 64 bytes".to_string())?;
            let sig = Signature::from_bytes(&sig_bytes);
            vk.verify(message, &sig)
                .map(|_| true)
                .map_err(|e| e.to_string())
        }
    }

    // -------------------------------------------------------------------------
    // Schnorr BIP340 (secp256k1)  — private: 32-byte scalar, public: 32-byte x-only
    // -------------------------------------------------------------------------
    pub struct SchnorrAdapter;

    impl SignetSigner for SchnorrAdapter {
        fn name(&self) -> &'static str {
            "schnorr"
        }

        fn generate_keys(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
            use k256::schnorr::SigningKey;

            let sk = SigningKey::random(&mut OsRng);
            let pk = sk.verifying_key().to_bytes();
            (Zeroizing::new(sk.to_bytes().to_vec()), pk.to_vec())
        }

        fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
            use k256::schnorr::{Signature, SigningKey, signature::Signer};

            let sk = SigningKey::from_bytes(private_key).map_err(|e| e.to_string())?;
            let sig: Signature = sk.sign(message);
            Ok(sig.to_bytes().to_vec())
        }

        fn verify(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            use k256::schnorr::{Signature, VerifyingKey, signature::Verifier};

            let vk = VerifyingKey::from_bytes(public_key).map_err(|e| e.to_string())?;
            let sig = Signature::try_from(signature)
                .map_err(|_| "Invalid Schnorr signature bytes".to_string())?;
            vk.verify(message, &sig)
                .map(|_| true)
                .map_err(|e| e.to_string())
        }
    }

    // -------------------------------------------------------------------------
    // ML-DSA-65 (post-quantum)  — keys via crate-native encoding
    // -------------------------------------------------------------------------
    pub struct MlDsaAdapter;

    impl SignetSigner for MlDsaAdapter {
        fn name(&self) -> &'static str {
            "mldsa"
        }

        fn generate_keys(&self) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
            use ml_dsa::{Generate, KeyExport, MlDsa65, SigningKey, signature::Keypair};

            let sk = SigningKey::<MlDsa65>::generate();
            let vk = sk.verifying_key();
            (
                Zeroizing::new(sk.to_bytes().as_slice().to_vec()),
                vk.to_bytes().as_slice().to_vec(),
            )
        }

        fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
            use ml_dsa::signature::{SignatureEncoding, Signer};
            use ml_dsa::{KeyInit, MlDsa65, SigningKey};

            let sk = SigningKey::<MlDsa65>::new_from_slice(private_key)
                .map_err(|_| "ML-DSA: private key must have the correct length".to_string())?;
            let sig = sk.sign(message);
            Ok(sig.to_vec())
        }

        fn verify(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, String> {
            use ml_dsa::signature::Verifier;
            use ml_dsa::{KeyInit, MlDsa65, VerifyingKey};

            let vk = VerifyingKey::<MlDsa65>::new_from_slice(public_key)
                .map_err(|_| "ML-DSA: public key must have the correct length".to_string())?;
            let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature)
                .map_err(|_| "ML-DSA: invalid signature bytes".to_string())?;
            vk.verify(message, &sig)
                .map(|_| true)
                .map_err(|e: ml_dsa::Error| e.to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_name_returns_correct_algorithm() {
        for name in Signet::available() {
            let signer = Signet::from_name(name);
            assert!(
                signer.is_some(),
                "Signet::from_name({name:?}) should return Some"
            );
            assert_eq!(signer.unwrap().name(), *name);
        }
    }

    #[test]
    fn from_name_aliases_work() {
        assert_eq!(Signet::from_name("p256").unwrap().name(), "ecdsa");
        assert_eq!(Signet::from_name("ed25519").unwrap().name(), "eddsa");
        assert_eq!(Signet::from_name("bip340").unwrap().name(), "schnorr");
        assert_eq!(Signet::from_name("dilithium").unwrap().name(), "mldsa");
    }

    #[test]
    fn from_name_unknown_returns_none() {
        assert!(Signet::from_name("aes").is_none());
        assert!(Signet::from_name("").is_none());
        assert!(Signet::from_name("UNKNOWN").is_none());
    }

    #[test]
    fn from_name_is_case_insensitive() {
        assert!(Signet::from_name("RSA").is_some());
        assert!(Signet::from_name("Ecdsa").is_some());
        assert!(Signet::from_name("EDDSA").is_some());
    }

    // Round-trip test for every algorithm through the factory.
    // This is the key test — one loop covers all algorithms.
    #[test]
    fn all_algorithms_round_trip() {
        let message = b"Hello, SignetDSA!";

        for &name in Signet::available() {
            let signer = Signet::from_name(name).unwrap();
            let (sk, pk) = signer.generate_keys();

            let sig = signer
                .sign(&sk, message)
                .unwrap_or_else(|e| panic!("{name}: sign failed: {e}"));

            let valid = signer
                .verify(&pk, message, &sig)
                .unwrap_or_else(|e| panic!("{name}: verify failed: {e}"));

            assert!(valid, "{name}: signature should be valid");
        }
    }

    #[test]
    fn all_algorithms_reject_tampered_message() {
        let message = b"Hello, SignetDSA!";
        let tampered = b"Tampered!";

        for &name in Signet::available() {
            let signer = Signet::from_name(name).unwrap();
            let (sk, pk) = signer.generate_keys();
            let sig = signer.sign(&sk, message).unwrap();

            let result = signer.verify(&pk, tampered, &sig);
            assert!(
                result.is_err() || result == Ok(false),
                "{name}: tampered message should fail verification"
            );
        }
    }
}
