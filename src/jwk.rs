//! JSON Web Key (JWK, RFC 7517) and JSON Web Key Set (JWKS) support.
//!
//! Provides import, export, and thumbprint computation (RFC 7638) for public and private
//! keys across elliptic curve (`EC`), octet key pair (`OKP`), and `RSA` algorithms.

use crate::envelope::base64url;
use sha2::{Digest, Sha256};

/// A JSON Web Key (JWK, RFC 7517).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwk {
    /// Key Type: `"OKP"`, `"EC"`, or `"RSA"`.
    pub kty: String,
    /// Intended Use: usually `"sig"`.
    pub use_: Option<String>,
    /// Algorithm: e.g. `"EdDSA"`, `"ES256"`, `"ES384"`, `"ES256K"`, `"PS256"`, `"RS256"`.
    pub alg: Option<String>,
    /// Key ID.
    pub kid: Option<String>,
    /// Curve name: `"Ed25519"`, `"Ed448"`, `"P-256"`, `"P-384"`, `"secp256k1"`.
    pub crv: Option<String>,
    /// Public key / X coordinate (Base64URL encoded).
    pub x: Option<String>,
    /// Y coordinate for uncompressed EC curves (Base64URL encoded).
    pub y: Option<String>,
    /// Private key scalar / seed (Base64URL encoded, optional).
    pub d: Option<String>,
    /// RSA Modulus (Base64URL encoded).
    pub n: Option<String>,
    /// RSA Exponent (Base64URL encoded).
    pub e: Option<String>,
}

impl Jwk {
    /// Create a public JWK from algorithm name and raw public key bytes.
    pub fn from_public_key(algo: &str, public_key: &[u8]) -> Result<Self, String> {
        match algo.to_lowercase().as_str() {
            "eddsa" | "ed25519" => {
                if public_key.len() != 32 {
                    return Err("Ed25519 public key must be 32 bytes".to_string());
                }
                let x = base64url::encode(public_key);
                let mut jwk = Self {
                    kty: "OKP".to_string(),
                    use_: Some("sig".to_string()),
                    alg: Some("EdDSA".to_string()),
                    kid: None,
                    crv: Some("Ed25519".to_string()),
                    x: Some(x),
                    y: None,
                    d: None,
                    n: None,
                    e: None,
                };
                jwk.kid = Some(jwk.thumbprint());
                Ok(jwk)
            }
            "ed448" | "ed448-goldilocks" => {
                if public_key.len() != 57 {
                    return Err("Ed448 public key must be 57 bytes".to_string());
                }
                let x = base64url::encode(public_key);
                let mut jwk = Self {
                    kty: "OKP".to_string(),
                    use_: Some("sig".to_string()),
                    alg: Some("EdDSA".to_string()),
                    kid: None,
                    crv: Some("Ed448".to_string()),
                    x: Some(x),
                    y: None,
                    d: None,
                    n: None,
                    e: None,
                };
                jwk.kid = Some(jwk.thumbprint());
                Ok(jwk)
            }
            "ecdsa" | "p256" => {
                use p256::ecdsa::VerifyingKey;
                use p256::elliptic_curve::sec1::EncodedPoint;
                let point = EncodedPoint::<p256::NistP256>::from_bytes(public_key)
                    .map_err(|e| format!("invalid P-256 public key: {e}"))?;
                let vk = VerifyingKey::from_encoded_point(&point)
                    .map_err(|e| format!("invalid P-256 key: {e}"))?;
                let uncompressed = vk.to_encoded_point(false);
                let x = uncompressed.x().ok_or("missing x")?.to_vec();
                let y = uncompressed.y().ok_or("missing y")?.to_vec();

                let mut jwk = Self {
                    kty: "EC".to_string(),
                    use_: Some("sig".to_string()),
                    alg: Some("ES256".to_string()),
                    kid: None,
                    crv: Some("P-256".to_string()),
                    x: Some(base64url::encode(&x)),
                    y: Some(base64url::encode(&y)),
                    d: None,
                    n: None,
                    e: None,
                };
                jwk.kid = Some(jwk.thumbprint());
                Ok(jwk)
            }
            "ecdsa-p384" | "p384" | "secp384r1" => {
                use p384::ecdsa::VerifyingKey;
                use p384::elliptic_curve::sec1::EncodedPoint;
                let point = EncodedPoint::<p384::NistP384>::from_bytes(public_key)
                    .map_err(|e| format!("invalid P-384 public key: {e}"))?;
                let vk = VerifyingKey::from_encoded_point(&point)
                    .map_err(|e| format!("invalid P-384 key: {e}"))?;
                let uncompressed = vk.to_encoded_point(false);
                let x = uncompressed.x().ok_or("missing x")?.to_vec();
                let y = uncompressed.y().ok_or("missing y")?.to_vec();

                let mut jwk = Self {
                    kty: "EC".to_string(),
                    use_: Some("sig".to_string()),
                    alg: Some("ES384".to_string()),
                    kid: None,
                    crv: Some("P-384".to_string()),
                    x: Some(base64url::encode(&x)),
                    y: Some(base64url::encode(&y)),
                    d: None,
                    n: None,
                    e: None,
                };
                jwk.kid = Some(jwk.thumbprint());
                Ok(jwk)
            }
            "ecdsa-secp256k1" | "secp256k1" => {
                use k256::ecdsa::VerifyingKey;
                use k256::elliptic_curve::sec1::EncodedPoint;
                let point = EncodedPoint::<k256::Secp256k1>::from_bytes(public_key)
                    .map_err(|e| format!("invalid secp256k1 public key: {e}"))?;
                let vk = VerifyingKey::from_encoded_point(&point)
                    .map_err(|e| format!("invalid secp256k1 key: {e}"))?;
                let uncompressed = vk.to_encoded_point(false);
                let x = uncompressed.x().ok_or("missing x")?.to_vec();
                let y = uncompressed.y().ok_or("missing y")?.to_vec();

                let mut jwk = Self {
                    kty: "EC".to_string(),
                    use_: Some("sig".to_string()),
                    alg: Some("ES256K".to_string()),
                    kid: None,
                    crv: Some("secp256k1".to_string()),
                    x: Some(base64url::encode(&x)),
                    y: Some(base64url::encode(&y)),
                    d: None,
                    n: None,
                    e: None,
                };
                jwk.kid = Some(jwk.thumbprint());
                Ok(jwk)
            }
            "schnorr" | "bip340" => {
                if public_key.len() != 32 {
                    return Err("Schnorr BIP340 public key must be 32 bytes".to_string());
                }
                let mut jwk = Self {
                    kty: "OKP".to_string(),
                    use_: Some("sig".to_string()),
                    alg: Some("SCHNORR".to_string()),
                    kid: None,
                    crv: Some("secp256k1".to_string()),
                    x: Some(base64url::encode(public_key)),
                    y: None,
                    d: None,
                    n: None,
                    e: None,
                };
                jwk.kid = Some(jwk.thumbprint());
                Ok(jwk)
            }
            "rsa" | "rsa-pss" => {
                use rsa::RsaPublicKey;
                use rsa::pkcs1::DecodeRsaPublicKey;
                use rsa::traits::PublicKeyParts;

                let pk = RsaPublicKey::from_pkcs1_der(public_key)
                    .map_err(|e| format!("RSA PKCS#1 DER decode failed: {e}"))?;
                let n_bytes = pk.n().to_bytes_be();
                let e_bytes = pk.e().to_bytes_be();

                let alg = if algo.to_lowercase().contains("pss") {
                    "PS256"
                } else {
                    "RS256"
                };

                let mut jwk = Self {
                    kty: "RSA".to_string(),
                    use_: Some("sig".to_string()),
                    alg: Some(alg.to_string()),
                    kid: None,
                    crv: None,
                    x: None,
                    y: None,
                    d: None,
                    n: Some(base64url::encode(&n_bytes)),
                    e: Some(base64url::encode(&e_bytes)),
                };
                jwk.kid = Some(jwk.thumbprint());
                Ok(jwk)
            }
            other => Err(format!(
                "JWK conversion not currently supported for algorithm {other:?}"
            )),
        }
    }

    /// Extract the raw public key bytes from this JWK according to SignetDSA encoding.
    pub fn to_public_key(&self) -> Result<Vec<u8>, String> {
        match self.kty.as_str() {
            "OKP" => {
                let x_str = self.x.as_ref().ok_or("missing x coordinate in OKP JWK")?;
                base64url::decode(x_str)
            }
            "EC" => {
                let x_str = self.x.as_ref().ok_or("missing x coordinate in EC JWK")?;
                let y_str = self.y.as_ref().ok_or("missing y coordinate in EC JWK")?;
                let x_bytes = base64url::decode(x_str)?;
                let y_bytes = base64url::decode(y_str)?;

                // Reconstruct SEC1 uncompressed point: 0x04 || X || Y
                let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
                point.push(0x04);
                point.extend_from_slice(&x_bytes);
                point.extend_from_slice(&y_bytes);

                // Convert to compressed representation if P-256 / P-384 / secp256k1
                match self.crv.as_deref() {
                    Some("P-256") => {
                        use p256::elliptic_curve::sec1::EncodedPoint;
                        let pt = EncodedPoint::<p256::NistP256>::from_bytes(&point)
                            .map_err(|e| format!("invalid P-256 point: {e}"))?;
                        Ok(pt.compress().as_bytes().to_vec())
                    }
                    Some("P-384") => {
                        use p384::elliptic_curve::sec1::EncodedPoint;
                        let pt = EncodedPoint::<p384::NistP384>::from_bytes(&point)
                            .map_err(|e| format!("invalid P-384 point: {e}"))?;
                        Ok(pt.compress().as_bytes().to_vec())
                    }
                    Some("secp256k1") => {
                        use k256::elliptic_curve::sec1::EncodedPoint;
                        let pt = EncodedPoint::<k256::Secp256k1>::from_bytes(&point)
                            .map_err(|e| format!("invalid secp256k1 point: {e}"))?;
                        Ok(pt.compress().as_bytes().to_vec())
                    }
                    _ => Ok(point),
                }
            }
            "RSA" => {
                use rsa::pkcs1::EncodeRsaPublicKey;
                use rsa::{BigUint, RsaPublicKey};

                let n_str = self.n.as_ref().ok_or("missing n in RSA JWK")?;
                let e_str = self.e.as_ref().ok_or("missing e in RSA JWK")?;
                let n_bytes = base64url::decode(n_str)?;
                let e_bytes = base64url::decode(e_str)?;

                let n = BigUint::from_bytes_be(&n_bytes);
                let e = BigUint::from_bytes_be(&e_bytes);

                let pk = RsaPublicKey::new(n, e)
                    .map_err(|err| format!("invalid RSA public key components: {err}"))?;
                Ok(pk
                    .to_pkcs1_der()
                    .map_err(|err| format!("RSA PKCS#1 DER encode failed: {err}"))?
                    .as_bytes()
                    .to_vec())
            }
            other => Err(format!("unsupported JWK kty {other:?}")),
        }
    }

    /// Compute RFC 7638 SHA-256 JWK thumbprint in Base64URL encoding.
    pub fn thumbprint(&self) -> String {
        let canonical_json = match self.kty.as_str() {
            "OKP" => format!(
                "{{\"crv\":\"{}\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
                self.crv.as_deref().unwrap_or(""),
                self.x.as_deref().unwrap_or("")
            ),
            "EC" => format!(
                "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                self.crv.as_deref().unwrap_or(""),
                self.x.as_deref().unwrap_or(""),
                self.y.as_deref().unwrap_or("")
            ),
            "RSA" => format!(
                "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
                self.e.as_deref().unwrap_or(""),
                self.n.as_deref().unwrap_or("")
            ),
            _ => format!("{{\"kty\":\"{}\"}}", self.kty),
        };

        let mut hasher = Sha256::new();
        hasher.update(canonical_json.as_bytes());
        let digest = hasher.finalize();
        base64url::encode(&digest)
    }

    /// Serialize JWK to JSON string.
    pub fn to_json(&self) -> String {
        let mut fields = Vec::new();
        fields.push(format!("\"kty\":\"{}\"", self.kty));

        if let Some(ref u) = self.use_ {
            fields.push(format!("\"use\":\"{u}\""));
        }
        if let Some(ref a) = self.alg {
            fields.push(format!("\"alg\":\"{a}\""));
        }
        if let Some(ref k) = self.kid {
            fields.push(format!("\"kid\":\"{k}\""));
        }
        if let Some(ref c) = self.crv {
            fields.push(format!("\"crv\":\"{c}\""));
        }
        if let Some(ref x) = self.x {
            fields.push(format!("\"x\":\"{x}\""));
        }
        if let Some(ref y) = self.y {
            fields.push(format!("\"y\":\"{y}\""));
        }
        if let Some(ref d) = self.d {
            fields.push(format!("\"d\":\"{d}\""));
        }
        if let Some(ref n) = self.n {
            fields.push(format!("\"n\":\"{n}\""));
        }
        if let Some(ref e) = self.e {
            fields.push(format!("\"e\":\"{e}\""));
        }

        format!("{{{}}}", fields.join(","))
    }

    /// Parse a JSON string into a JWK.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let extract = |key: &str| -> Option<String> {
            let needle = format!("\"{}\":", key);
            let pos = json.find(&needle)?;
            let rest = json[pos + needle.len()..].trim_start();
            if let Some(stripped) = rest.strip_prefix('"') {
                let end = stripped.find('"')?;
                Some(stripped[..end].to_string())
            } else {
                let end = rest
                    .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
                    .unwrap_or(rest.len());
                Some(rest[..end].to_string())
            }
        };

        let kty = extract("kty").ok_or_else(|| "missing required 'kty' in JWK JSON".to_string())?;
        let use_ = extract("use");
        let alg = extract("alg");
        let kid = extract("kid");
        let crv = extract("crv");
        let x = extract("x");
        let y = extract("y");
        let d = extract("d");
        let n = extract("n");
        let e = extract("e");

        Ok(Self {
            kty,
            use_,
            alg,
            kid,
            crv,
            x,
            y,
            d,
            n,
            e,
        })
    }
}

/// JSON Web Key Set (JWKS, RFC 7517 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwks {
    /// Array of JSON Web Keys.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Create a new JWKS from a list of JWKs.
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }

    /// Format as standard JWKS JSON (`{"keys": [...]}`).
    pub fn to_json(&self) -> String {
        let key_jsons: Vec<String> = self.keys.iter().map(|k| k.to_json()).collect();
        format!("{{\"keys\":[{}]}}", key_jsons.join(","))
    }

    /// Parse a standard JWKS JSON string.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let keys_pos = json
            .find("\"keys\":")
            .ok_or_else(|| "missing 'keys' array in JWKS JSON".to_string())?;
        let rest = json[keys_pos + 7..].trim_start();
        let open_bracket = rest
            .find('[')
            .ok_or_else(|| "invalid 'keys' array syntax".to_string())?;
        let close_bracket = rest
            .rfind(']')
            .ok_or_else(|| "unclosed 'keys' array".to_string())?;
        let array_body = rest[open_bracket + 1..close_bracket].trim();

        if array_body.is_empty() {
            return Ok(Self { keys: Vec::new() });
        }

        // Split top-level objects
        let mut keys = Vec::new();
        let mut depth = 0;
        let mut start = 0;
        for (i, c) in array_body.char_indices() {
            if c == '{' {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            } else if c == '}' {
                depth -= 1;
                if depth == 0 {
                    let obj_str = &array_body[start..=i];
                    keys.push(Jwk::from_json(obj_str)?);
                }
            }
        }

        Ok(Self { keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signet;

    #[test]
    fn jwk_roundtrip_eddsa() {
        let signer = Signet::from_name("eddsa").unwrap();
        let (_sk, pk) = signer.generate_keys();

        let jwk = Jwk::from_public_key("eddsa", &pk).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.kid.is_some());

        let json = jwk.to_json();
        let parsed = Jwk::from_json(&json).unwrap();
        assert_eq!(jwk, parsed);

        let recovered_pk = parsed.to_public_key().unwrap();
        assert_eq!(recovered_pk, pk);
    }

    #[test]
    fn jwk_roundtrip_ecdsa_p256() {
        let signer = Signet::from_name("ecdsa").unwrap();
        let (_sk, pk) = signer.generate_keys();

        let jwk = Jwk::from_public_key("ecdsa", &pk).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert_eq!(jwk.alg.as_deref(), Some("ES256"));

        let recovered_pk = jwk.to_public_key().unwrap();
        assert_eq!(recovered_pk, pk);
    }

    #[test]
    fn jwks_serialization_roundtrip() {
        let signer1 = Signet::from_name("eddsa").unwrap();
        let (_sk1, pk1) = signer1.generate_keys();
        let signer2 = Signet::from_name("ecdsa").unwrap();
        let (_sk2, pk2) = signer2.generate_keys();

        let jwk1 = Jwk::from_public_key("eddsa", &pk1).unwrap();
        let jwk2 = Jwk::from_public_key("ecdsa", &pk2).unwrap();

        let jwks = Jwks::new(vec![jwk1, jwk2]);
        let json = jwks.to_json();
        assert!(json.contains("\"keys\":["));

        let parsed_jwks = Jwks::from_json(&json).unwrap();
        assert_eq!(parsed_jwks.keys.len(), 2);
        assert_eq!(parsed_jwks, jwks);
    }
}
