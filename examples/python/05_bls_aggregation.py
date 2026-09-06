#!/usr/bin/env python3
"""
BLS12-381 Signature Aggregation in Python.

Demonstrates:
- Multi-signer individual signature generation
- Signature aggregation into a single constant 96-byte signature
- Single-pairing batch verification over distinct messages
"""

import signetdsa


def main():
    print("=== SignetDSA Python SDK - BLS12-381 Signature Aggregation ===\n")

    num_signers = 4
    print(f"Simulating {num_signers} independent validators...")

    signers = [signetdsa.Signet.from_name("bls") for _ in range(num_signers)]
    keypairs = [s.generate_keys() for s in signers]
    messages = [f"Validator #{i+1} votes YES on proposal #42".encode("utf-8") for i in range(num_signers)]

    # 1. Sign individual messages
    signatures = [
        s.sign(sk, msg)
        for (sk, pk), msg, s in zip(keypairs, messages, signers)
    ]
    print(f"Generated {len(signatures)} individual 96-byte signatures.")

    # 2. Aggregate signatures into a single 96-byte signature
    print("\n1. Aggregating signatures...")
    aggregated_sig = signetdsa.bls_aggregate_signatures(signatures)
    print(f"   Aggregated Signature Length: {len(aggregated_sig)} bytes (constant size)")
    assert len(aggregated_sig) == 96

    # 3. Verify aggregated signature against all public keys and messages
    print("\n2. Verifying aggregated signature...")
    public_keys = [pk for (sk, pk) in keypairs]
    is_valid = signetdsa.bls_verify_aggregated(aggregated_sig, messages, public_keys)
    print(f"   [✓] Batch Aggregate Verification Result: {is_valid}\n")
    assert is_valid is True

    print("[✓] BLS signature aggregation completed successfully!")


if __name__ == "__main__":
    main()
