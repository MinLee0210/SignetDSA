//! FROST (Flexible Round-Optimized Schnorr Threshold) — 2-of-3 threshold signing.
//!
//! FROST allows `t` out of `n` participants to collaboratively produce a Schnorr
//! signature without any single party ever holding the full private key. This is
//! the foundation of modern multi-sig wallets.
//!
//! Because FROST signing is a two-round interactive ceremony (not a single function
//! call), this module does NOT implement the `Signature` trait. Instead it exposes
//! the ceremony directly so the structure is fully transparent.
//!
//! Round 1: each participant generates a nonce commitment and broadcasts it.
//! Round 2: each participant computes a signature share; shares are then aggregated.

use frost_secp256k1 as frost;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

/// FROST 2-of-3 threshold ceremony.
///
/// Returns `Ok(true)` if the aggregated signature is valid over `message`.
pub fn ceremony_2_of_3(message: &[u8]) -> Result<bool, frost::Error> {
    // --- Key generation: Distributed Key Generation (DKG) -------------------------
    // In production each participant would run this locally and exchange commitments
    // over a secure channel. Here we simulate all three participants in one process.

    let max_signers = 3;
    let min_signers = 2; // threshold

    let (shares, public_key_package) =
        frost::keys::generate_with_dealer(max_signers, min_signers, frost::keys::IdentifierList::Default, &mut OsRng)?;

    // Each participant keeps their own key package.
    let key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage> = shares
        .into_iter()
        .map(|(id, share)| {
            let package = frost::keys::KeyPackage::try_from(share)?;
            Ok((id, package))
        })
        .collect::<Result<_, frost::Error>>()?;

    // --- Round 1: Commit ----------------------------------------------------------
    // Each participant generates a (nonce, commitment) pair and broadcasts
    // their commitment. Nonces are kept secret.

    let mut nonces_map: BTreeMap<frost::Identifier, frost::round1::SigningNonces> = BTreeMap::new();
    let mut commitments_map: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> =
        BTreeMap::new();

    // Only participants 1 and 2 sign (satisfying the 2-of-3 threshold).
    for participant_id in key_packages.keys().take(min_signers as usize) {
        let key_package = &key_packages[participant_id];
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut OsRng);
        nonces_map.insert(*participant_id, nonces);
        commitments_map.insert(*participant_id, commitments);
    }

    // --- Round 2: Sign ------------------------------------------------------------
    // Each participant receives the full commitments map, then produces a
    // signature share using their nonce and key package.

    let signing_package = frost::SigningPackage::new(commitments_map, message);

    let mut signature_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> =
        BTreeMap::new();

    for (participant_id, nonces) in &nonces_map {
        let key_package = &key_packages[participant_id];
        let share = frost::round2::sign(&signing_package, nonces, key_package)?;
        signature_shares.insert(*participant_id, share);
    }

    // --- Aggregation --------------------------------------------------------------
    // The coordinator (any trusted party, or even a public aggregator) combines
    // the shares into a single standard Schnorr signature.

    let aggregated_sig = frost::aggregate(&signing_package, &signature_shares, &public_key_package)?;

    // --- Verification -------------------------------------------------------------
    // The result is a normal Schnorr signature verifiable by anyone who has the
    // group public key — they don't need to know it was threshold-signed.

    let is_valid = public_key_package
        .verifying_key()
        .verify(message, &aggregated_sig)
        .is_ok();

    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frost_2_of_3_ceremony() {
        let message = b"Hello, GrimoireDSA!";
        let valid = ceremony_2_of_3(message).expect("FROST ceremony failed");
        assert!(valid, "Aggregated FROST signature should be valid");
    }

    #[test]
    fn frost_2_of_3_tampered_message_fails() {
        // Sign one message, but verify against a different one.
        // We verify manually here to demonstrate the failure path.
        let message = b"Hello, GrimoireDSA!";

        // Run a full ceremony and capture the verifying key + signature.
        let max_signers = 3u16;
        let min_signers = 2u16;

        let (shares, public_key_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut OsRng,
        )
        .expect("DKG failed");

        let key_packages: std::collections::BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, share)| {
                (id, frost::keys::KeyPackage::try_from(share).expect("Invalid share"))
            })
            .collect();

        let mut nonces_map = std::collections::BTreeMap::new();
        let mut commitments_map = std::collections::BTreeMap::new();

        for participant_id in key_packages.keys().take(min_signers as usize) {
            let (nonces, commitments) =
                frost::round1::commit(key_packages[participant_id].signing_share(), &mut OsRng);
            nonces_map.insert(*participant_id, nonces);
            commitments_map.insert(*participant_id, commitments);
        }

        let signing_package = frost::SigningPackage::new(commitments_map, message);
        let mut signature_shares = std::collections::BTreeMap::new();

        for (id, nonces) in &nonces_map {
            let share = frost::round2::sign(&signing_package, nonces, &key_packages[id])
                .expect("Signing share failed");
            signature_shares.insert(*id, share);
        }

        let aggregated_sig =
            frost::aggregate(&signing_package, &signature_shares, &public_key_package)
                .expect("Aggregation failed");

        // Verify against a DIFFERENT message — must fail.
        let tampered = b"Tampered message!";
        let result = public_key_package
            .verifying_key()
            .verify(tampered, &aggregated_sig);

        assert!(result.is_err(), "Tampered message should fail verification");
    }
}
