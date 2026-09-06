//! Known-answer tests for deterministic ECDSA over NIST P-384 against RFC 6979 §A.2.6.

use p384::ecdsa::{
    Signature, SigningKey,
    signature::{Signer, Verifier},
};

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc6979_p384_test_vectors() {
    // RFC 6979 A.2.6 — Curve P-384 with SHA-384
    let priv_hex = "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740257B0C2664B3F71D83DFF88BEA322F226BA9B724";
    let message = b"sample";

    // RFC 6979 r value and low-s normalized signature for "sample" with SHA-384
    let expected_r_hex = "B64A2EC08B4B2EB0C99EB2FEA748C7064CA2F641CC68B8507DABC17E22F3F51CAB1C16B4D4A290EA1646D13C310A46A6";
    let expected_s_hex = "4B152BFC1DDE5B997E32DD71AF4A7407D9ECEE9233DA6DDF1FC9701E16EA03E372A65CB92208418C8A6AAA22F6182071";

    let priv_bytes = from_hex(priv_hex);
    let sk = SigningKey::from_bytes(priv_bytes.as_slice().into()).expect("valid P-384 private key");
    let vk = *sk.verifying_key();

    // Verify signing produces exact deterministic RFC 6979 signature
    let sig: Signature = sk.sign(message);
    let (r, s) = sig.split_bytes();

    assert_eq!(hex::encode(r).to_uppercase(), expected_r_hex);
    assert_eq!(hex::encode(s).to_uppercase(), expected_s_hex);

    // Verify verifying key validates the produced signature
    assert!(vk.verify(message, &sig).is_ok());

    // Verify tampered message fails
    assert!(vk.verify(b"tampered message", &sig).is_err());
}
