//! Individual implementations of digital signature algorithms.
//!
//! This module contains underlying structs implementing the core [`crate::Signature`] trait.
//! These implementations are wrapped by the adapter layer internally used in [`crate::SignetSigner`].

pub mod dsa;
pub mod ecdsa;
pub mod eddsa;
pub mod frost;
pub mod mldsa;
pub mod rsa;
pub mod schnorr;
