//! Known-answer tests for Ed25519 against the official RFC 8032 §7.1 test vectors.
//!
//! These prove interoperability with the specification, not just internal
//! sign/verify round-trip consistency. Vectors 1-3 are transcribed verbatim
//! from <https://www.rfc-editor.org/rfc/rfc8032#section-7.1>.

use ed25519_dalek::{Signature, VerifyingKey};

struct Vector {
    public_key: &'static str,
    message: &'static str,
    signature: &'static str,
}

const VECTORS: &[Vector] = &[
    // RFC 8032 TEST 1 — empty message.
    Vector {
        public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        message: "",
        signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    // RFC 8032 TEST 2 — 1-byte message.
    Vector {
        public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        message: "72",
        signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    // RFC 8032 TEST 3 — 2-byte message.
    Vector {
        public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        message: "af82",
        signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
];

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn ed25519_matches_rfc8032_test_vectors() {
    for (i, vector) in VECTORS.iter().enumerate() {
        let pk_bytes: [u8; 32] = from_hex(vector.public_key).try_into().unwrap();
        let sig_bytes: [u8; 64] = from_hex(vector.signature).try_into().unwrap();
        let message = from_hex(vector.message);

        let verifying_key =
            VerifyingKey::from_bytes(&pk_bytes).expect("RFC 8032 public key must be valid");
        let signature = Signature::from_bytes(&sig_bytes);

        assert!(
            verifying_key.verify_strict(&message, &signature).is_ok(),
            "RFC 8032 TEST {} failed to verify",
            i + 1
        );
    }
}
