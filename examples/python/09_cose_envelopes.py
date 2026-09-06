#!/usr/bin/env python3
"""
COSE Compact Binary Envelopes (RFC 9052) example in Python.

Demonstrates:
- Signing payloads into compact CBOR COSE_Sign1 binary envelopes (Tag 18)
- Zero string/base64 overhead for Passkeys / IoT
- Verifying envelopes against public keys
"""

import signetdsa


def main():
    print("=== SignetDSA Python SDK - COSE Binary Envelopes (RFC 9052) ===\n")

    algos = ["eddsa", "ecdsa", "ecdsa-p384", "ecdsa-secp256k1"]
    payload = b"WEBAUTHN_ASSERTION_AUTHENTICATOR_DATA_CBOR_PAYLOAD"

    for algo in algos:
        signer = signetdsa.Signet.from_name(algo)
        sk, pk = signer.generate_keys()

        # 1. Sign into binary COSE_Sign1 envelope
        cose_bytes = signetdsa.CoseSign1.sign(algo, sk, payload)
        print(f"Algorithm: {algo}")
        print(f"  Raw Payload:     {len(payload)} bytes")
        print(f"  COSE_Sign1 Size: {len(cose_bytes)} bytes (Tag 18 prefix: 0x{cose_bytes[0]:02x})")

        # 2. Verify and recover authentic payload
        verified_payload = signetdsa.CoseSign1.verify(cose_bytes, pk)
        assert verified_payload == payload
        print("  [✓] Verified payload successfully.\n")

        # 3. Tamper detection
        tampered = bytearray(cose_bytes)
        tampered[-1] ^= 0xff
        try:
            signetdsa.CoseSign1.verify(bytes(tampered), pk)
            print("  [!] Error: Tampered COSE envelope accepted!")
        except ValueError:
            print("  [✓] Tampered COSE envelope rejected as expected.\n")

    print("[✓] All COSE binary envelope operations completed successfully!")


if __name__ == "__main__":
    main()
