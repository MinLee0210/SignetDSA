//! Known-answer tests for Ed448 against the official RFC 8032 §7.4 test
//! vectors (the context-free "Ed448"/PureEdDSA vectors, matching this
//! crate's `sign_raw`/`verify_raw` usage in `src/algo/ed448.rs`).

use ed448_goldilocks_plus::{Signature, VerifyingKey};

struct Vector {
    public_key: &'static str,
    message: &'static str,
    signature: &'static str,
}

const VECTORS: &[Vector] = &[
    // RFC 8032 §7.4 "-----Blank" — empty message.
    Vector {
        public_key: "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
        message: "",
        signature: "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600",
    },
    // RFC 8032 §7.4 "-----1 octet" — 1-byte message.
    Vector {
        public_key: "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
        message: "03",
        signature: "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
    },
];

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn ed448_matches_rfc8032_test_vectors() {
    for (i, vector) in VECTORS.iter().enumerate() {
        let pk_bytes: [u8; 57] = from_hex(vector.public_key).try_into().unwrap();
        let message = from_hex(vector.message);
        let sig_bytes = from_hex(vector.signature);

        let verifying_key =
            VerifyingKey::from_bytes(&pk_bytes).expect("RFC 8032 Ed448 public key must be valid");
        let signature =
            Signature::from_slice(&sig_bytes).expect("RFC 8032 Ed448 signature must be valid");

        assert!(
            verifying_key.verify_raw(&signature, &message).is_ok(),
            "RFC 8032 Ed448 vector {i} failed to verify"
        );
    }
}
