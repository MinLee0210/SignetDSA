#!/usr/bin/env python3
"""
Self-Contained Signed Envelopes example in Python.

Demonstrates:
- Sealing messages into self-verifying JSON envelopes (SignetEnvelope)
- Exporting to and parsing from JSON format
- Autonomous verification on the recipient side
"""

import signetdsa


def main():
    print("=== SignetDSA Python SDK - Signed Envelopes ===\n")

    signer = signetdsa.Signet.from_name("schnorr")
    sk, pk = signer.generate_keys()

    message = b"AUDIT_RECORD: User #489 authorized wire transfer of $12,500.00"

    # 1. Seal message into envelope
    print("1. Sealing message into SignetEnvelope...")
    envelope = signetdsa.SignetEnvelope.seal(signer, sk, pk, message)

    print(f"   Algo:       {envelope.algo}")
    print(f"   Created At: {envelope.created_at}")
    print(f"   Message:    {envelope.message.decode('utf-8')}")

    # 2. Export to JSON string for network transport
    json_string = envelope.to_json()
    print(f"\n2. Exported JSON Envelope:\n{json_string}\n")

    # 3. Deserialize and verify at destination
    print("3. Parsing and verifying at receiver...")
    parsed_envelope = signetdsa.SignetEnvelope.from_json(json_string)
    is_valid = parsed_envelope.verify()
    assert is_valid is True
    print("   [✓] Envelope autonomously verified!\n")

    print("[✓] Signed envelope example completed successfully!")


if __name__ == "__main__":
    main()
