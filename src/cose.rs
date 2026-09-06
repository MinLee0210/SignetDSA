//! CBOR Object Signing and Encryption (COSE, RFC 9052 / RFC 8152) `COSE_Sign1` binary envelopes.
//!
//! Provides compact binary signing and verification without JSON or Base64URL string overhead,
//! standard in IoT, FIDO2/WebAuthn passkeys, and constrained environments.

use crate::Signet;

/// COSE Algorithm Identifiers (IANA COSE Algorithms Registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseAlgorithm {
    /// EdDSA (Ed25519) = -8
    EdDsa = -8,
    /// ECDSA with SHA-256 on P-256 = -7
    Es256 = -7,
    /// ECDSA with SHA-384 on P-384 = -35
    Es384 = -35,
    /// ECDSA with SHA-256 on secp256k1 = -47
    Es256k = -47,
    /// RSASSA-PSS with SHA-256 = -37
    Ps256 = -37,
    /// RSASSA-PKCS1-v1_5 with SHA-256 = -257
    Rs256 = -257,
}

impl CoseAlgorithm {
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.to_lowercase().as_str() {
            "eddsa" | "ed25519" => Ok(Self::EdDsa),
            "ecdsa" | "p256" => Ok(Self::Es256),
            "ecdsa-p384" | "p384" | "secp384r1" => Ok(Self::Es384),
            "ecdsa-secp256k1" | "secp256k1" => Ok(Self::Es256k),
            "rsa-pss" | "pss" => Ok(Self::Ps256),
            "rsa" => Ok(Self::Rs256),
            other => Err(format!("unsupported COSE algorithm {other:?}")),
        }
    }

    pub fn to_signet_name(self) -> &'static str {
        match self {
            Self::EdDsa => "eddsa",
            Self::Es256 => "ecdsa",
            Self::Es384 => "ecdsa-p384",
            Self::Es256k => "ecdsa-secp256k1",
            Self::Ps256 => "rsa-pss",
            Self::Rs256 => "rsa",
        }
    }

    pub fn to_id(self) -> i64 {
        self as i64
    }

    pub fn from_id(id: i64) -> Result<Self, String> {
        match id {
            -8 => Ok(Self::EdDsa),
            -7 => Ok(Self::Es256),
            -35 => Ok(Self::Es384),
            -47 => Ok(Self::Es256k),
            -37 => Ok(Self::Ps256),
            -257 => Ok(Self::Rs256),
            other => Err(format!("unknown COSE algorithm ID {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal robust CBOR primitives for COSE structures
// ---------------------------------------------------------------------------
mod cbor {
    pub fn encode_uint(val: u64, buf: &mut Vec<u8>) {
        if val < 24 {
            buf.push(val as u8);
        } else if val <= 0xff {
            buf.push(0x18);
            buf.push(val as u8);
        } else if val <= 0xffff {
            buf.push(0x19);
            buf.extend_from_slice(&(val as u16).to_be_bytes());
        } else if val <= 0xffff_ffff {
            buf.push(0x1a);
            buf.extend_from_slice(&(val as u32).to_be_bytes());
        } else {
            buf.push(0x1b);
            buf.extend_from_slice(&val.to_be_bytes());
        }
    }

    pub fn encode_int(val: i64, buf: &mut Vec<u8>) {
        if val >= 0 {
            encode_uint(val as u64, buf);
        } else {
            let neg_val = (-1 - val) as u64;
            if neg_val < 24 {
                buf.push(0x20 | (neg_val as u8));
            } else if neg_val <= 0xff {
                buf.push(0x38);
                buf.push(neg_val as u8);
            } else if neg_val <= 0xffff {
                buf.push(0x39);
                buf.extend_from_slice(&(neg_val as u16).to_be_bytes());
            } else {
                buf.push(0x3a);
                buf.extend_from_slice(&(neg_val as u32).to_be_bytes());
            }
        }
    }

    pub fn encode_bstr(bytes: &[u8], buf: &mut Vec<u8>) {
        let len = bytes.len() as u64;
        if len < 24 {
            buf.push(0x40 | (len as u8));
        } else if len <= 0xff {
            buf.push(0x58);
            buf.push(len as u8);
        } else if len <= 0xffff {
            buf.push(0x59);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            buf.push(0x5a);
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        }
        buf.extend_from_slice(bytes);
    }

    pub fn encode_tstr(s: &str, buf: &mut Vec<u8>) {
        let bytes = s.as_bytes();
        let len = bytes.len() as u64;
        if len < 24 {
            buf.push(0x60 | (len as u8));
        } else if len <= 0xff {
            buf.push(0x78);
            buf.push(len as u8);
        } else {
            buf.push(0x79);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        }
        buf.extend_from_slice(bytes);
    }

    pub fn encode_array_header(len: usize, buf: &mut Vec<u8>) {
        if len < 24 {
            buf.push(0x80 | (len as u8));
        } else {
            buf.push(0x98);
            buf.push(len as u8);
        }
    }

    pub fn encode_map_header(len: usize, buf: &mut Vec<u8>) {
        if len < 24 {
            buf.push(0xa0 | (len as u8));
        } else {
            buf.push(0xb8);
            buf.push(len as u8);
        }
    }

    pub fn decode_header(bytes: &[u8], offset: &mut usize) -> Result<(u8, u64), String> {
        if *offset >= bytes.len() {
            return Err("unexpected end of CBOR payload".to_string());
        }
        let initial = bytes[*offset];
        *offset += 1;
        let major = initial >> 5;
        let info = initial & 0x1f;

        let val = if info < 24 {
            info as u64
        } else if info == 24 {
            if *offset >= bytes.len() {
                return Err("truncated CBOR uint8".to_string());
            }
            let v = bytes[*offset] as u64;
            *offset += 1;
            v
        } else if info == 25 {
            if *offset + 2 > bytes.len() {
                return Err("truncated CBOR uint16".to_string());
            }
            let v = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]) as u64;
            *offset += 2;
            v
        } else if info == 26 {
            if *offset + 4 > bytes.len() {
                return Err("truncated CBOR uint32".to_string());
            }
            let v = u32::from_be_bytes([
                bytes[*offset],
                bytes[*offset + 1],
                bytes[*offset + 2],
                bytes[*offset + 3],
            ]) as u64;
            *offset += 4;
            v
        } else {
            return Err(format!("unsupported CBOR additional info {info}"));
        };

        Ok((major, val))
    }

    pub fn decode_bstr<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
        let (major, len) = decode_header(bytes, offset)?;
        if major != 2 {
            return Err(format!("expected CBOR byte string (major 2), got {major}"));
        }
        let len = len as usize;
        if *offset + len > bytes.len() {
            return Err("truncated CBOR byte string data".to_string());
        }
        let slice = &bytes[*offset..*offset + len];
        *offset += len;
        Ok(slice)
    }
}

/// CBOR Object Signing and Encryption `COSE_Sign1` envelope (RFC 9052 §4.2).
pub struct CoseSign1;

impl CoseSign1 {
    /// Sign `payload` into a tagged `COSE_Sign1` CBOR byte vector (Tag 18).
    pub fn sign(algo_name: &str, private_key: &[u8], payload: &[u8]) -> Result<Vec<u8>, String> {
        let algo = CoseAlgorithm::from_name(algo_name)?;
        let signer = Signet::from_name(algo.to_signet_name())
            .ok_or_else(|| format!("unknown algorithm {algo_name:?}"))?;

        // 1. Construct protected header map: { 1 (alg): algo_id }
        let mut protected_map = Vec::new();
        cbor::encode_map_header(1, &mut protected_map);
        cbor::encode_uint(1, &mut protected_map); // label 1: alg
        cbor::encode_int(algo.to_id(), &mut protected_map);

        // 2. Build Sig_structure: ["Signature1", protected_bytes, external_aad (b""), payload]
        let mut sig_structure = Vec::new();
        cbor::encode_array_header(4, &mut sig_structure);
        cbor::encode_tstr("Signature1", &mut sig_structure);
        cbor::encode_bstr(&protected_map, &mut sig_structure);
        cbor::encode_bstr(&[], &mut sig_structure); // empty external_aad
        cbor::encode_bstr(payload, &mut sig_structure);

        // 3. Sign the Sig_structure
        let signature = signer.sign(private_key, &sig_structure)?;

        // 4. Construct final COSE_Sign1 array: [protected_bytes, {}, payload, signature]
        let mut cose_array = Vec::new();
        cbor::encode_array_header(4, &mut cose_array);
        cbor::encode_bstr(&protected_map, &mut cose_array);
        cbor::encode_map_header(0, &mut cose_array); // empty unprotected header map
        cbor::encode_bstr(payload, &mut cose_array);
        cbor::encode_bstr(&signature, &mut cose_array);

        // Prefix with Tag 18 (0xd2)
        let mut tagged = Vec::with_capacity(1 + cose_array.len());
        tagged.push(0xd2); // Tag 18
        tagged.extend_from_slice(&cose_array);

        Ok(tagged)
    }

    /// Verify a `COSE_Sign1` message against `public_key` and return the authentic payload.
    pub fn verify(cose_bytes: &[u8], public_key: &[u8]) -> Result<Vec<u8>, String> {
        if cose_bytes.is_empty() {
            return Err("empty COSE message".to_string());
        }

        let mut offset = 0;
        if cose_bytes[offset] == 0xd2 {
            // Tag 18
            offset += 1;
        }

        let (major, arr_len) = cbor::decode_header(cose_bytes, &mut offset)?;
        if major != 4 || arr_len != 4 {
            return Err(format!(
                "invalid COSE_Sign1 structure: expected 4-element array, got major {major} len {arr_len}"
            ));
        }

        // 1. Protected headers
        let protected_bytes = cbor::decode_bstr(cose_bytes, &mut offset)?;

        // Decode algorithm ID from protected header map
        let mut p_offset = 0;
        let (p_major, p_map_len) = cbor::decode_header(protected_bytes, &mut p_offset)?;
        if p_major != 5 || p_map_len == 0 {
            return Err("invalid protected header map in COSE".to_string());
        }

        // Search for key 1 (alg)
        let (k_major, k_val) = cbor::decode_header(protected_bytes, &mut p_offset)?;
        if k_major != 0 || k_val != 1 {
            return Err("missing 'alg' (1) parameter in protected header".to_string());
        }
        let (v_major, v_val) = cbor::decode_header(protected_bytes, &mut p_offset)?;
        let alg_id = if v_major == 0 {
            v_val as i64
        } else if v_major == 1 {
            -1 - (v_val as i64)
        } else {
            return Err("invalid algorithm ID in COSE protected header".to_string());
        };

        let algo = CoseAlgorithm::from_id(alg_id)?;
        let signer = Signet::from_name(algo.to_signet_name())
            .ok_or_else(|| format!("algorithm {} not available", algo.to_signet_name()))?;

        // 2. Unprotected headers (skip empty map)
        let (unprot_major, _) = cbor::decode_header(cose_bytes, &mut offset)?;
        if unprot_major != 5 {
            return Err("expected unprotected header map".to_string());
        }

        // 3. Payload
        let payload = cbor::decode_bstr(cose_bytes, &mut offset)?;

        // 4. Signature
        let signature = cbor::decode_bstr(cose_bytes, &mut offset)?;

        // Reconstruct Sig_structure for verification
        let mut sig_structure = Vec::new();
        cbor::encode_array_header(4, &mut sig_structure);
        cbor::encode_tstr("Signature1", &mut sig_structure);
        cbor::encode_bstr(protected_bytes, &mut sig_structure);
        cbor::encode_bstr(&[], &mut sig_structure);
        cbor::encode_bstr(payload, &mut sig_structure);

        let valid = signer.verify(public_key, &sig_structure, signature)?;
        if !valid {
            return Err("COSE signature verification failed".to_string());
        }

        Ok(payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_sign1_eddsa_roundtrip() {
        let signer = Signet::from_name("eddsa").unwrap();
        let (sk, pk) = signer.generate_keys();
        let payload = b"COSE compact binary payload for IoT / FIDO2";

        let cose_bytes = CoseSign1::sign("eddsa", &sk, payload).unwrap();
        assert_eq!(cose_bytes[0], 0xd2); // Tag 18

        let verified = CoseSign1::verify(&cose_bytes, &pk).unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn cose_sign1_p256_roundtrip() {
        let signer = Signet::from_name("ecdsa").unwrap();
        let (sk, pk) = signer.generate_keys();
        let payload = b"WebAuthn Passkey Assertion Payload";

        let cose_bytes = CoseSign1::sign("ecdsa", &sk, payload).unwrap();
        let verified = CoseSign1::verify(&cose_bytes, &pk).unwrap();
        assert_eq!(verified, payload);
    }

    #[test]
    fn cose_sign1_tampered_fails() {
        let signer = Signet::from_name("eddsa").unwrap();
        let (sk, pk) = signer.generate_keys();
        let payload = b"Valid sensor telemetry";

        let mut cose_bytes = CoseSign1::sign("eddsa", &sk, payload).unwrap();
        let last_idx = cose_bytes.len() - 1;
        cose_bytes[last_idx] ^= 0xff; // corrupt signature

        let res = CoseSign1::verify(&cose_bytes, &pk);
        assert!(res.is_err());
    }
}
