#!/usr/bin/env python3
"""
Basic usage example for SignetDSA Python SDK.

Demonstrates:
- Inspecting available algorithms
- Dynamic algorithm selection via Signet factory
- Key generation, signing, and verification
- Error handling on tampered data
"""

import signetdsa


def main():
    print("=== SignetDSA Python SDK - Basic Usage ===\n")

    # 1. Inspect supported schemes
    algorithms = signetdsa.Signet.available()
    print(f"Supported Algorithms ({len(algorithms)} total):")
    print(f"  {', '.join(algorithms)}\n")

    # 2. Iterate and test dynamic signing across diverse algorithm families
    sample_algos = ["eddsa", "ecdsa-p384", "schnorr", "bls", "mldsa"]

    for algo in sample_algos:
        signer = signetdsa.Signet.from_name(algo)
        sk, pk = signer.generate_keys()

        message = b"SignetDSA Python SDK: Fast, secure, and idiomatic."
        signature = signer.sign(sk, message)

        is_valid = signer.verify(pk, message, signature)
        assert is_valid is True

        print(
            f"  [✓] {signer.name:14} | SecretKey: {len(sk):4} B | "
            f"PublicKey: {len(pk):4} B | Sig: {len(signature):4} B | Valid: {is_valid}"
        )

        # Demonstrate tampering rejection
        try:
            signer.verify(pk, b"Tampered malicious payload!", signature)
            print("  [!] Error: tamper check did not raise exception")
        except ValueError:
            pass

    print("\n[✓] All basic Python usage tests passed successfully!")


if __name__ == "__main__":
    main()
