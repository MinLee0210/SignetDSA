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
//! * **Classical Algorithms:** RSA, DSA, ECDSA (NIST P-256), EdDSA (Ed25519), Schnorr (BIP340).
//! * **Threshold Signatures:** FROST (Schnorr 2-of-3 threshold signatures).
//! * **Post-Quantum:** ML-DSA (CRYSTALS-Dilithium, FIPS 204).
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
pub mod signature;
pub mod signet;

pub use signature::Signature;
pub use signet::{Signet, SignetSigner};
