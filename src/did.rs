//! W3C `did:key` Decentralized Identifier (DID) derivation and resolution.
//!
//! Implements the W3C `did:key` specification, mapping public keys to/from
//! deterministic decentralized identifiers using multicodec headers and Base58BTC encoding.
//!
//! Supported multicodecs:
//! - `Ed25519`: `0xed01` (`did:key:z6Mk...`)
//! - `secp256k1`: `0xe701` (`did:key:zQ3s...`)
//! - `P-256`: `0x1200` (`did:key:zDna...`)
//! - `P-384`: `0x1201` (`did:key:z82L...`)

/// Resolved DID Document details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidKeyDocument {
    /// Full DID URI, e.g. `did:key:z6Mku...`
    pub did: String,
    /// SignetDSA canonical algorithm name: `"eddsa"`, `"ecdsa-secp256k1"`, `"ecdsa"`, `"ecdsa-p384"`.
    pub algo: String,
    /// Raw public key bytes.
    pub public_key: Vec<u8>,
}

pub struct DidKey;

impl DidKey {
    /// Derive a standard W3C `did:key` URI from algorithm name and public key bytes.
    pub fn to_did(algo: &str, public_key: &[u8]) -> Result<String, String> {
        let (prefix, expected_len) = match algo.to_lowercase().as_str() {
            "eddsa" | "ed25519" => (&[0xed, 0x01][..], 32),
            "ecdsa-secp256k1" | "secp256k1" => (&[0xe7, 0x01][..], 33),
            "ecdsa" | "p256" => (&[0x80, 0x24][..], 33),
            "ecdsa-p384" | "p384" | "secp384r1" => (&[0x81, 0x24][..], 49),
            other => {
                return Err(format!(
                    "algorithm {other:?} is not supported by standard did:key multicodec specifications"
                ));
            }
        };

        if public_key.len() != expected_len {
            return Err(format!(
                "{algo} public key must be {expected_len} bytes for did:key, got {}",
                public_key.len()
            ));
        }

        let mut data = Vec::with_capacity(prefix.len() + public_key.len());
        data.extend_from_slice(prefix);
        data.extend_from_slice(public_key);

        let encoded = bs58::encode(&data).into_string();
        Ok(format!("did:key:z{encoded}"))
    }

    /// Resolve a `did:key:z...` identifier into its algorithm and public key bytes.
    pub fn resolve(did: &str) -> Result<DidKeyDocument, String> {
        if !did.starts_with("did:key:z") {
            return Err(format!(
                "invalid did:key format (expected did:key:z...): {did:?}"
            ));
        }

        let b58_part = &did["did:key:z".len()..];
        let bytes = bs58::decode(b58_part)
            .into_vec()
            .map_err(|e| format!("Base58BTC decoding failed: {e}"))?;

        if bytes.len() < 2 {
            return Err("did:key payload too short".to_string());
        }

        let (algo, pk_slice) = if bytes.starts_with(&[0xed, 0x01]) {
            ("eddsa", &bytes[2..])
        } else if bytes.starts_with(&[0xe7, 0x01]) {
            ("ecdsa-secp256k1", &bytes[2..])
        } else if bytes.starts_with(&[0x80, 0x24]) {
            ("ecdsa", &bytes[2..])
        } else if bytes.starts_with(&[0x81, 0x24]) {
            ("ecdsa-p384", &bytes[2..])
        } else {
            return Err(format!(
                "unrecognized multicodec prefix: {:02x?}",
                &bytes[..2]
            ));
        };

        Ok(DidKeyDocument {
            did: did.to_string(),
            algo: algo.to_string(),
            public_key: pk_slice.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signet;

    #[test]
    fn did_key_ed25519_roundtrip() {
        let signer = Signet::from_name("eddsa").unwrap();
        let (_sk, pk) = signer.generate_keys();

        let did = DidKey::to_did("eddsa", &pk).unwrap();
        assert!(did.starts_with("did:key:z6Mk"));

        let doc = DidKey::resolve(&did).unwrap();
        assert_eq!(doc.algo, "eddsa");
        assert_eq!(doc.public_key, pk);
    }

    #[test]
    fn did_key_secp256k1_roundtrip() {
        let signer = Signet::from_name("ecdsa-secp256k1").unwrap();
        let (_sk, pk) = signer.generate_keys();

        let did = DidKey::to_did("ecdsa-secp256k1", &pk).unwrap();
        assert!(did.starts_with("did:key:zQ3s"));

        let doc = DidKey::resolve(&did).unwrap();
        assert_eq!(doc.algo, "ecdsa-secp256k1");
        assert_eq!(doc.public_key, pk);
    }

    #[test]
    fn did_key_p256_roundtrip() {
        let signer = Signet::from_name("ecdsa").unwrap();
        let (_sk, pk) = signer.generate_keys();

        let did = DidKey::to_did("ecdsa", &pk).unwrap();
        assert!(did.starts_with("did:key:zDna"));

        let doc = DidKey::resolve(&did).unwrap();
        assert_eq!(doc.algo, "ecdsa");
        assert_eq!(doc.public_key, pk);
    }
}
