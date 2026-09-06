"""
SignetDSA Python Bindings
=========================

Enterprise-grade digital signature library in Rust with Python bindings.
Supports classical (ECDSA, Ed25519, Ed448, RSA-PSS, Schnorr), threshold (FROST),
aggregatable (BLS12-381), and post-quantum (ML-DSA FIPS 204) schemes.

Quick Start:
------------
>>> import signetdsa
>>> signer = signetdsa.Signet.from_name("eddsa")
>>> sk, pk = signer.generate_keys()
>>> msg = b"Hello, SignetDSA!"
>>> sig = signer.sign(sk, msg)
>>> assert signer.verify(pk, msg, sig)
"""

from signetdsa._signetdsa import (
    Signet,
    SignetSigner,
    SignetEnvelope,
    JwsCompact,
    BenchmarkResult,
    frost_ceremony,
    frost_ceremony_2_of_3,
    secp256k1_sign_recoverable,
    secp256k1_recover_public_key,
    bls_aggregate_signatures,
    bls_verify_aggregated,
    eddsa_verify_batch,
)

__all__ = [
    "Signet",
    "SignetSigner",
    "SignetEnvelope",
    "JwsCompact",
    "BenchmarkResult",
    "frost_ceremony",
    "frost_ceremony_2_of_3",
    "secp256k1_sign_recoverable",
    "secp256k1_recover_public_key",
    "bls_aggregate_signatures",
    "bls_verify_aggregated",
    "eddsa_verify_batch",
]

__version__ = "0.1.0"
