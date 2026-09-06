#!/usr/bin/env python3
"""
JSON Web Signature (JWS RFC 7515) compact tokens example in Python.

Demonstrates:
- Creating compact URL-safe JWS tokens (<header>.<payload>.<signature>)
- Verifying JWS tokens and decoding original payload
- Detecting token tampering and corrupted signatures
"""

import json
import signetdsa


def main():
    print("=== SignetDSA Python SDK - JWS Compact Tokens (RFC 7515) ===\n")

    test_algos = ["eddsa", "ecdsa-p384", "schnorr", "rsa-pss"]
    payload_dict = {
        "sub": "user_29384",
        "iss": "auth.signetdsa.io",
        "scope": ["read:profile", "write:orders"],
        "iat": 1788685000,
    }
    raw_payload = json.dumps(payload_dict).encode("utf-8")

    for algo in test_algos:
        signer = signetdsa.Signet.from_name(algo)
        sk, pk = signer.generate_keys()

        # 1. Sign payload into JWS compact token string
        token = signetdsa.JwsCompact.sign(algo, sk, raw_payload)
        parts = token.split(".")

        print(f"Algorithm: {algo}")
        print(f"  Header:    {parts[0]}")
        print(f"  Payload:   {parts[1]}")
        print(f"  Signature: {parts[2][:20]}... ({len(parts[2])} chars)")

        # 2. Verify token and decode original payload
        recovered_bytes = signetdsa.JwsCompact.verify(token, pk)
        recovered_dict = json.loads(recovered_bytes.decode("utf-8"))
        assert recovered_dict == payload_dict
        print("  [✓] Successfully verified & decoded payload.")

        # 3. Test tampering detection
        tampered_token = f"{parts[0]}.dGFtcGVyZWQ.{parts[2]}"
        try:
            signetdsa.JwsCompact.verify(tampered_token, pk)
            print("  [!] Error: Tampered token accepted!")
        except ValueError:
            print("  [✓] Tampered token successfully rejected.\n")

    print("[✓] All JWS token examples completed successfully!")


if __name__ == "__main__":
    main()
