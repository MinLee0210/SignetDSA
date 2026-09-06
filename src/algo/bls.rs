//! BLS signatures over BLS12-381 implementation.
//!
//! Provides the [`Bls`] type implementing the [`crate::Signature`] trait for
//! ordinary single-key sign/verify, backed by the `bls-signatures` crate
//! (the "basic" `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` ciphersuite —
//! public keys in G1, signatures in G2).
//!
//! What sets BLS apart from every other algorithm in this crate is
//! **aggregation**: many signatures over many (message, public key) pairs
//! collapse into a single signature the same size as one individual
//! signature, and that one aggregate can be verified against the list of
//! (message, public key) pairs in one pairing check. [`Bls::aggregate_signatures`]
//! and [`Bls::verify_aggregated`] expose this; it has no equivalent in the
//! generic [`crate::Signature`] trait, which is single-signature only.
//!
//! # Rogue public-key attacks
//!
//! [`Bls::verify_aggregated`] is for the case where every signer signs a
//! **distinct** message — that's what the underlying `bls-signatures` crate
//! actually supports: it rejects the call outright (safe by construction) if
//! any two messages in the batch coincide, per the countermeasure in
//! [§3.1 of the IRTF BLS signature draft][irtf-bls] against the rogue-key
//! attack. Same-message multisig (every signer approving one shared
//! message) needs a different, proof-of-possession-based scheme that this
//! module does not provide — do not work around the distinct-message check
//! to force that use case through this API.
//!
//! [irtf-bls]: https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1

use crate::signature::Signature;
use bls_signatures::{
    PrivateKey, PublicKey, Serialize as BlsSerialize, Signature as BlsSignature, aggregate,
    verify_messages,
};
use rand::rngs::OsRng;

/// BLS digital signature over BLS12-381.
pub struct Bls;

#[derive(Debug)]
pub enum BlsError {
    InvalidPublicKeyEncoding(bls_signatures::Error),
    InvalidSignatureEncoding(bls_signatures::Error),
    Verification,
    EmptyAggregateInput,
    Aggregation(bls_signatures::Error),
    MismatchedAggregateLengths { messages: usize, public_keys: usize },
}

impl std::fmt::Display for BlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlsError::InvalidPublicKeyEncoding(e) => write!(f, "Invalid BLS public key: {e}"),
            BlsError::InvalidSignatureEncoding(e) => write!(f, "Invalid BLS signature: {e}"),
            BlsError::Verification => write!(f, "BLS verification failed"),
            BlsError::EmptyAggregateInput => write!(f, "Cannot aggregate zero signatures"),
            BlsError::Aggregation(e) => write!(f, "BLS aggregation failed: {e}"),
            BlsError::MismatchedAggregateLengths {
                messages,
                public_keys,
            } => write!(
                f,
                "Aggregate verification needs one public key per message, got {messages} messages and {public_keys} public keys"
            ),
        }
    }
}

impl std::error::Error for BlsError {}

impl Signature for Bls {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;
    type Error = BlsError;

    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey) {
        let private_key = PrivateKey::generate(&mut OsRng);
        let public_key = private_key.public_key();
        (private_key, public_key)
    }

    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(private_key.sign(message).as_bytes())
    }

    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let sig =
            BlsSignature::from_bytes(signature).map_err(BlsError::InvalidSignatureEncoding)?;
        if public_key.verify(sig, message) {
            Ok(true)
        } else {
            Err(BlsError::Verification)
        }
    }
}

impl Bls {
    /// Combine many signatures into one aggregate signature the same size as
    /// a single signature.
    pub fn aggregate_signatures(signatures: &[Vec<u8>]) -> Result<Vec<u8>, BlsError> {
        if signatures.is_empty() {
            return Err(BlsError::EmptyAggregateInput);
        }
        let parsed = signatures
            .iter()
            .map(|s| BlsSignature::from_bytes(s).map_err(BlsError::InvalidSignatureEncoding))
            .collect::<Result<Vec<_>, _>>()?;
        let aggregated = aggregate(&parsed).map_err(BlsError::Aggregation)?;
        Ok(aggregated.as_bytes())
    }

    /// Verify an aggregate signature against the list of `(message, public_key)`
    /// pairs it claims to cover — one public key per message, in matching order.
    ///
    /// See the module-level docs for when it's safe to reuse the same message
    /// across multiple signers.
    pub fn verify_aggregated(
        aggregate_signature: &[u8],
        messages: &[&[u8]],
        public_keys: &[Vec<u8>],
    ) -> Result<bool, BlsError> {
        if messages.len() != public_keys.len() {
            return Err(BlsError::MismatchedAggregateLengths {
                messages: messages.len(),
                public_keys: public_keys.len(),
            });
        }
        let sig = BlsSignature::from_bytes(aggregate_signature)
            .map_err(BlsError::InvalidSignatureEncoding)?;
        let keys = public_keys
            .iter()
            .map(|pk| PublicKey::from_bytes(pk).map_err(BlsError::InvalidPublicKeyEncoding))
            .collect::<Result<Vec<_>, _>>()?;

        if verify_messages(&sig, messages, &keys) {
            Ok(true)
        } else {
            Err(BlsError::Verification)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bls_sign_and_verify() {
        let (private_key, public_key) = Bls::generate_keys();
        let message = b"Hello, SignetDSA!";

        let signature = Bls::sign(&private_key, message).expect("Signing failed");
        let valid = Bls::verify(&public_key, message, &signature).expect("Verification failed");
        assert!(valid, "Signature should be valid");
    }

    #[test]
    fn bls_tampered_message_fails() {
        let (private_key, public_key) = Bls::generate_keys();
        let message = b"Hello, SignetDSA!";
        let tampered = b"Tampered message!";

        let signature = Bls::sign(&private_key, message).expect("Signing failed");
        let result = Bls::verify(&public_key, tampered, &signature);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn bls_aggregate_over_distinct_messages() {
        let signers: Vec<_> = (0..3).map(|_| Bls::generate_keys()).collect();
        let messages: [&[u8]; 3] = [b"alice's message", b"bob's message", b"carol's message"];

        let signatures: Vec<Vec<u8>> = signers
            .iter()
            .zip(messages.iter())
            .map(|((sk, _), msg)| Bls::sign(sk, msg).expect("Signing failed"))
            .collect();

        let aggregate_signature =
            Bls::aggregate_signatures(&signatures).expect("Aggregation failed");
        let public_keys: Vec<Vec<u8>> = signers.iter().map(|(_, pk)| pk.as_bytes()).collect();

        let valid = Bls::verify_aggregated(&aggregate_signature, &messages, &public_keys)
            .expect("Aggregate verification failed");
        assert!(
            valid,
            "Aggregate signature over distinct messages should be valid"
        );
    }

    #[test]
    fn bls_aggregate_rejects_tampered_message() {
        let signers: Vec<_> = (0..3).map(|_| Bls::generate_keys()).collect();
        let messages: [&[u8]; 3] = [b"alice's message", b"bob's message", b"carol's message"];

        let signatures: Vec<Vec<u8>> = signers
            .iter()
            .zip(messages.iter())
            .map(|((sk, _), msg)| Bls::sign(sk, msg).expect("Signing failed"))
            .collect();
        let aggregate_signature =
            Bls::aggregate_signatures(&signatures).expect("Aggregation failed");
        let public_keys: Vec<Vec<u8>> = signers.iter().map(|(_, pk)| pk.as_bytes()).collect();

        let tampered_messages: [&[u8]; 3] =
            [b"alice's message", b"NOT bob's message", b"carol's message"];
        let result = Bls::verify_aggregated(&aggregate_signature, &tampered_messages, &public_keys);
        assert!(
            result.is_err(),
            "Tampering with one message should fail aggregate verification"
        );
    }

    #[test]
    fn bls_aggregate_rejects_repeated_message() {
        // Same-message aggregation is the classic BLS rogue-key setup;
        // `bls-signatures` refuses to verify it rather than let a caller
        // reach for it by accident. See the module-level docs.
        let signers: Vec<_> = (0..3).map(|_| Bls::generate_keys()).collect();
        let message: &[u8] = b"multisig approval";

        let signatures: Vec<Vec<u8>> = signers
            .iter()
            .map(|(sk, _)| Bls::sign(sk, message).expect("Signing failed"))
            .collect();
        let aggregate_signature =
            Bls::aggregate_signatures(&signatures).expect("Aggregation failed");

        let messages = [message; 3];
        let public_keys: Vec<Vec<u8>> = signers.iter().map(|(_, pk)| pk.as_bytes()).collect();

        let result = Bls::verify_aggregated(&aggregate_signature, &messages, &public_keys);
        assert!(
            result.is_err(),
            "Aggregating over a repeated message must be rejected, not silently accepted"
        );
    }
}
