//! # SignetDSA
//!
//! `SignetDSA` is a Rust library providing a unified, object-safe factory API for
//! digital signature algorithms. It supports classical, threshold, and post-quantum
//! signature schemes under a single easy-to-use interface.
//!
//! Inspired by HuggingFace's `AutoTokenizer.from_pretrained()` pattern, `SignetDSA`
//! allows selecting algorithms at runtime via string identifiers (e.g., `"ecdsa"`, `"mldsa"`).
//!
//! ## Features
//!
//! * **Classical Algorithms:** RSA (PKCS#1 v1.5 & RSA-PSS), DSA, ECDSA (NIST P-256 & P-384),
//!   ECDSA/secp256k1 (with `ecrecover`-style public-key recovery), EdDSA (Ed25519), Ed448,
//!   Schnorr (BIP340).
//! * **Threshold Signatures:** FROST (Schnorr 2-of-3 threshold signatures).
//! * **Aggregatable Signatures:** BLS (BLS12-381) — many signatures collapse
//!   into one.
//! * **Post-Quantum:** ML-DSA (CRYSTALS-Dilithium, FIPS 204).
//! * **Self-Contained Envelopes & JWS:** Portable signed envelopes and RFC 7515 JWS compact tokens.
//! * **Performance Benchmarking:** Built-in micro-benchmarking across all schemes.
//!
//! ## Quick Start
//!
//! ```rust
//! use SignetDSA::{Signet, SignetSigner};
//!
//! // Instantiate the signer dynamically by name
//! let signer = Signet::from_name("ecdsa").expect("Unknown algorithm");
//!
//! // Generate a new keypair
//! let (sk, pk) = signer.generate_keys();
//!
//! // Sign a message
//! let message = b"Hello, SignetDSA!";
//! let signature = signer.sign(&sk, message).unwrap();
//!
//! // Verify the signature
//! let is_valid = signer.verify(&pk, message, &signature).unwrap();
//! assert!(is_valid);
//! ```
#![allow(non_snake_case)] // package name `SignetDSA` is an intentional brand name, not an identifier

pub mod algo;
pub mod bench;
pub mod envelope;
pub mod signature;
pub mod signet;

pub use envelope::{JwsCompact, SignetEnvelope};
pub use signature::Signature;
pub use signet::{Signet, SignetSigner};
