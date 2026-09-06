//! Self-contained signed envelopes and JSON Web Signature (JWS) compact token formatting.
//!
//! Provides [`SignetEnvelope`] and [`JwsCompact`] for packaging messages, signatures,
//! algorithm metadata, and public keys into self-verifying, portable formats.
//!
//! # Why Signed Envelopes?
//!
//! In distributed architectures, transmitting raw signature bytes alongside separate
//! public keys and algorithm identifiers requires complex glue code and error-prone
//! manual pairing. A signed envelope bundles the algorithm identifier, signer public key,
//! message content, and signature into a single verifiable unit.
//!
//! # JWS Compact Format (RFC 7515)
//!
//! [`JwsCompact`] provides RFC 7515 compliant URL-safe string serialization:
//! `BASE64URL(UTF8(Header)) . BASE64URL(Payload) . BASE64URL(Signature)`
//!
//! ```rust
//! use SignetDSA::{Signet, envelope::JwsCompact};
//!
//! let signer = Signet::from_name("eddsa").unwrap();
//! let (sk, pk) = signer.generate_keys();
//! let payload = b"user_id:42,role:admin";
//!
//! // Sign into compact JWS string
//! let token = JwsCompact::sign("eddsa", &sk, payload).unwrap();
//!
//! // Verify and extract payload
//! let verified_payload = JwsCompact::verify(&token, &pk).unwrap();
//! assert_eq!(verified_payload, payload);
//! ```

use crate::signet::{Signet, SignetSigner};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Base64URL Encoding/Decoding (RFC 4648 §5)
// ---------------------------------------------------------------------------

/// RFC 4648 §5 URL-safe Base64 encoding without padding.
pub mod base64url {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Encode arbitrary bytes to a URL-safe Base64 string (no padding).
    pub fn encode(data: &[u8]) -> String {
        let mut result = String::with_capacity((data.len() * 4).div_ceil(3));
        let mut i = 0;
        while i < data.len() {
            let b0 = data[i] as u32;
            let b1 = if i + 1 < data.len() {
                data[i + 1] as u32
            } else {
                0
            };
            let b2 = if i + 2 < data.len() {
                data[i + 2] as u32
            } else {
                0
            };

            let triple = (b0 << 16) | (b1 << 8) | b2;

            result.push(CHARSET[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARSET[((triple >> 12) & 0x3F) as usize] as char);

            if i + 1 < data.len() {
                result.push(CHARSET[((triple >> 6) & 0x3F) as usize] as char);
            }
            if i + 2 < data.len() {
                result.push(CHARSET[(triple & 0x3F) as usize] as char);
            }

            i += 3;
        }
        result
    }

    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    /// Decode a URL-safe Base64 string (with or without padding) into raw bytes.
    pub fn decode(input: &str) -> Result<Vec<u8>, String> {
        let input = input.trim_end_matches('=');
        let bytes = input.as_bytes();
        let mut output = Vec::with_capacity((bytes.len() * 3) / 4);

        let mut i = 0;
        while i < bytes.len() {
            let rem = bytes.len() - i;
            let c0 = decode_char(bytes[i]).ok_or("invalid base64url character")? as u32;
            let c1 = if rem > 1 {
                decode_char(bytes[i + 1]).ok_or("invalid base64url character")? as u32
            } else {
                0
            };
            let c2 = if rem > 2 {
                decode_char(bytes[i + 2]).ok_or("invalid base64url character")? as u32
            } else {
                0
            };
            let c3 = if rem > 3 {
                decode_char(bytes[i + 3]).ok_or("invalid base64url character")? as u32
            } else {
                0
            };

            let chunk = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;

            if rem >= 2 {
                output.push(((chunk >> 16) & 0xFF) as u8);
            }
            if rem >= 3 {
                output.push(((chunk >> 8) & 0xFF) as u8);
            }
            if rem >= 4 {
                output.push((chunk & 0xFF) as u8);
            }

            i += 4;
        }

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// SignetEnvelope
// ---------------------------------------------------------------------------

/// A self-contained, verifiable signed message envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignetEnvelope {
    /// The canonical name of the signature algorithm (e.g., `"ecdsa"`, `"eddsa"`, `"mldsa"`).
    pub algo: String,
    /// The public key bytes of the signer.
    pub public_key: Vec<u8>,
    /// The signed message payload.
    pub message: Vec<u8>,
    /// The digital signature over `message`.
    pub signature: Vec<u8>,
    /// Unix timestamp (seconds) when the envelope was created.
    pub created_at: u64,
}

impl SignetEnvelope {
    /// Create and sign a new envelope using the specified signer.
    pub fn seal(
        signer: &dyn SignetSigner,
        private_key: &[u8],
        public_key: &[u8],
        message: &[u8],
    ) -> Result<Self, String> {
        let signature = signer.sign(private_key, message)?;
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            algo: signer.name().to_string(),
            public_key: public_key.to_vec(),
            message: message.to_vec(),
            signature,
            created_at,
        })
    }

    /// Verify this envelope against its embedded public key and algorithm name.
    pub fn verify(&self) -> Result<bool, String> {
        let signer = Signet::from_name(&self.algo)
            .ok_or_else(|| format!("unknown algorithm in envelope: {:?}", self.algo))?;
        signer.verify(&self.public_key, &self.message, &self.signature)
    }

    /// Serialize the envelope to a clean JSON string with hex-encoded keys and signatures.
    pub fn to_json(&self) -> String {
        format!(
            "{{\n  \"algo\": \"{}\",\n  \"created_at\": {},\n  \"public_key\": \"{}\",\n  \"message\": \"{}\",\n  \"signature\": \"{}\"\n}}",
            self.algo,
            self.created_at,
            hex::encode(&self.public_key),
            hex::encode(&self.message),
            hex::encode(&self.signature)
        )
    }

    /// Parse a JSON-formatted envelope string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let extract = |key: &str| -> Result<String, String> {
            let needle = format!("\"{}\":", key);
            let pos = json
                .find(&needle)
                .ok_or_else(|| format!("missing field {key:?} in envelope JSON"))?;
            let rest = json[pos + needle.len()..].trim_start();
            if let Some(stripped) = rest.strip_prefix('"') {
                let end = stripped.find('"').ok_or("unterminated string in JSON")?;
                Ok(stripped[..end].to_string())
            } else {
                let end = rest
                    .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
                    .unwrap_or(rest.len());
                Ok(rest[..end].to_string())
            }
        };

        let algo = extract("algo")?;
        let created_at = extract("created_at")?
            .parse::<u64>()
            .map_err(|e| format!("invalid created_at timestamp: {e}"))?;
        let public_key = hex::decode(extract("public_key")?)
            .map_err(|e| format!("invalid hex public_key: {e}"))?;
        let message =
            hex::decode(extract("message")?).map_err(|e| format!("invalid hex message: {e}"))?;
        let signature = hex::decode(extract("signature")?)
            .map_err(|e| format!("invalid hex signature: {e}"))?;

        Ok(Self {
            algo,
            public_key,
            message,
            signature,
            created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// JWS Compact Format (RFC 7515)
// ---------------------------------------------------------------------------

/// JSON Web Signature (JWS) compact token generator and validator (RFC 7515).
pub struct JwsCompact;

impl JwsCompact {
    /// Sign a payload into a URL-safe compact JWS string (`<header>.<payload>.<signature>`).
    pub fn sign(algo: &str, private_key: &[u8], payload: &[u8]) -> Result<String, String> {
        let signer =
            Signet::from_name(algo).ok_or_else(|| format!("unknown algorithm {algo:?}"))?;

        let header = format!("{{\"alg\":\"{}\",\"typ\":\"JWS\"}}", signer.name());
        let encoded_header = base64url::encode(header.as_bytes());
        let encoded_payload = base64url::encode(payload);

        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let signature = signer.sign(private_key, signing_input.as_bytes())?;
        let encoded_signature = base64url::encode(&signature);

        Ok(format!("{signing_input}.{encoded_signature}"))
    }

    /// Verify a compact JWS token against `public_key` and return the decoded payload.
    pub fn verify(token: &str, public_key: &[u8]) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(
                "invalid JWS compact format: expected 3 dot-separated segments".to_string(),
            );
        }

        let encoded_header = parts[0];
        let encoded_payload = parts[1];
        let encoded_signature = parts[2];

        let header_bytes = base64url::decode(encoded_header)?;
        let header_str = std::str::from_utf8(&header_bytes)
            .map_err(|e| format!("invalid UTF-8 in JWS header: {e}"))?;

        // Extract algorithm name from header
        let algo = extract_alg_from_header(header_str)?;
        let signer = Signet::from_name(&algo)
            .ok_or_else(|| format!("unsupported algorithm in JWS header: {algo:?}"))?;

        let signing_input = format!("{encoded_header}.{encoded_payload}");
        let signature = base64url::decode(encoded_signature)?;

        let is_valid = signer.verify(public_key, signing_input.as_bytes(), &signature)?;
        if !is_valid {
            return Err("JWS verification failed: signature invalid".to_string());
        }

        base64url::decode(encoded_payload)
    }
}

fn extract_alg_from_header(header: &str) -> Result<String, String> {
    let needle = "\"alg\":";
    let pos = header
        .find(needle)
        .ok_or("missing \"alg\" field in JWS header")?;
    let rest = header[pos + needle.len()..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped
            .find('"')
            .ok_or("unterminated string in JWS header")?;
        Ok(stripped[..end].to_string())
    } else {
        Err("malformed \"alg\" value in JWS header".to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"\x00\xFF\xAA\x55?hello world",
        ];

        for case in cases {
            let enc = base64url::encode(case);
            assert!(!enc.contains('+') && !enc.contains('/') && !enc.contains('='));
            let dec = base64url::decode(&enc).expect("decode failed");
            assert_eq!(&dec, case);
        }
    }

    #[test]
    fn envelope_seal_verify_and_json_roundtrip() {
        for &algo in Signet::available() {
            let signer = Signet::from_name(algo).unwrap();
            let (sk, pk) = signer.generate_keys();
            let msg = b"Envelope test payload";

            let envelope = SignetEnvelope::seal(signer.as_ref(), &sk, &pk, msg)
                .unwrap_or_else(|e| panic!("{algo}: seal failed: {e}"));

            assert!(
                envelope.verify().unwrap(),
                "{algo}: fresh envelope should verify"
            );

            let json = envelope.to_json();
            let parsed = SignetEnvelope::from_json(&json)
                .unwrap_or_else(|e| panic!("{algo}: parse failed: {e}"));

            assert_eq!(envelope, parsed);
            assert!(
                parsed.verify().unwrap(),
                "{algo}: parsed envelope should verify"
            );
        }
    }

    #[test]
    fn envelope_tampered_fails() {
        let signer = Signet::from_name("eddsa").unwrap();
        let (sk, pk) = signer.generate_keys();
        let mut envelope = SignetEnvelope::seal(signer.as_ref(), &sk, &pk, b"hello").unwrap();

        envelope.message = b"tampered message".to_vec();
        let result = envelope.verify();
        assert!(result.is_err() || result == Ok(false));
    }

    #[test]
    fn jws_compact_sign_and_verify() {
        let test_algos = ["eddsa", "ecdsa", "ecdsa-p384", "schnorr", "rsa-pss"];
        for algo in test_algos {
            let signer = Signet::from_name(algo).unwrap();
            let (sk, pk) = signer.generate_keys();
            let payload = b"user=alice&action=read";

            let token = JwsCompact::sign(algo, &sk, payload)
                .unwrap_or_else(|e| panic!("{algo}: JWS sign failed: {e}"));

            assert_eq!(token.split('.').count(), 3);

            let verified = JwsCompact::verify(&token, &pk)
                .unwrap_or_else(|e| panic!("{algo}: JWS verify failed: {e}"));

            assert_eq!(verified, payload, "{algo}: JWS payload mismatch");
        }
    }

    #[test]
    fn jws_compact_tampered_token_rejected() {
        let signer = Signet::from_name("eddsa").unwrap();
        let (sk, pk) = signer.generate_keys();
        let token = JwsCompact::sign("eddsa", &sk, b"secret data").unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_payload = base64url::encode(b"attacker data");
        parts[1] = &tampered_payload;
        let tampered_token = parts.join(".");

        let result = JwsCompact::verify(&tampered_token, &pk);
        assert!(result.is_err(), "tampered JWS token must fail verification");
    }
}
