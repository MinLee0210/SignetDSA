#!/usr/bin/env python3
"""
Ethereum ecrecover / secp256k1 Public Key Recovery in Python.

Demonstrates:
- Signing a 32-byte message hash with recoverable secp256k1 ECDSA
- Extracting the recovery ID (0-3)
- Reconstructing the exact public key from (message, signature, recovery_id)
"""

import hashlib
import signetdsa


def main():
    print("=== SignetDSA Python SDK - Ethereum ecrecover Example ===\n")

    signer = signetdsa.Signet.from_name("ecdsa-secp256k1")
    sk, pk = signer.generate_keys()

    tx_data = b"transfer(0xRecipientAddress, 1000000000000000000)"
    tx_hash = hashlib.sha256(tx_data).digest()

    print(f"Signer Public Key (compressed): {pk.hex()}")
    print(f"Transaction Hash (SHA-256):     {tx_hash.hex()}\n")

    # 1. Sign transaction producing recoverable signature + 1-byte recovery ID
    signature, recovery_id = signetdsa.secp256k1_sign_recoverable(sk, tx_hash)
    print("1. Produced Recoverable Signature:")
    print(f"   Signature (64 bytes): {signature.hex()}")
    print(f"   Recovery ID (0-3):    {recovery_id}\n")

    # 2. Reconstruct public key without knowing it in advance (ecrecover)
    print("2. Reconstructing public key from signature and recovery ID (ecrecover)...")
    recovered_pk = signetdsa.secp256k1_recover_public_key(tx_hash, signature, recovery_id)
    print(f"   Recovered Public Key: {recovered_pk.hex()}")

    assert recovered_pk == pk
    print("   [✓] Recovered key perfectly matches signer public key!\n")

    print("[✓] Ethereum ecrecover example completed successfully!")


if __name__ == "__main__":
    main()
