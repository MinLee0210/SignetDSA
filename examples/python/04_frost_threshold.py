#!/usr/bin/env python3
"""
FROST Threshold Signatures (secp256k1 BIP340 Schnorr) in Python.

Demonstrates:
- 2-of-3 threshold ceremony (e.g. 2 of 3 multi-sig signers)
- Arbitrary t-of-n threshold ceremony (e.g. 3 of 5 board members)
"""

import signetdsa


def main():
    print("=== SignetDSA Python SDK - FROST Threshold Signatures ===\n")

    message = b"APPROVE DISBURSEMENT: $500,000 to Infrastructure Vault"

    # 1. 2-of-3 Ceremony
    print("1. Running 2-of-3 FROST Ceremony...")
    success_2_3 = signetdsa.frost_ceremony_2_of_3(message)
    print(f"   [✓] 2-of-3 Ceremony Success: {success_2_3}\n")
    assert success_2_3 is True

    # 2. 3-of-5 Ceremony
    print("2. Running 3-of-5 FROST Ceremony...")
    success_3_5 = signetdsa.frost_ceremony(min_signers=3, max_signers=5, message=message)
    print(f"   [✓] 3-of-5 Ceremony Success: {success_3_5}\n")
    assert success_3_5 is True

    print("[✓] FROST threshold examples completed successfully!")


if __name__ == "__main__":
    main()
