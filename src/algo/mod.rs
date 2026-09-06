//! Individual implementations of digital signature algorithms.
//!
//! This module contains underlying structs implementing the core [`crate::Signature`] trait.
//! These implementations are wrapped by the adapter layer internally used in [`crate::SignetSigner`].

pub mod bls;
pub mod dsa;
pub mod ecdsa;
pub mod ecdsa_p384;
pub mod ecdsa_secp256k1;
pub mod ed448;
pub mod eddsa;
pub mod frost;
pub mod mldsa;
pub mod rsa;
pub mod rsa_pss;
pub mod schnorr;
pub mod slhdsa;
