#!/usr/bin/env python3
"""
W3C did:key Decentralized Identifiers example in Python.

Demonstrates:
- Deriving W3C did:key:z... URIs across multicodecs
- Resolving did:key URIs into algorithm names and public key bytes
"""

import signetdsa


def main():
    print("=== SignetDSA Python SDK - W3C did:key Identifiers ===\n")

    schemes = ["eddsa", "ecdsa-secp256k1", "ecdsa", "ecdsa-p384"]

    for algo in schemes:
        signer = signetdsa.Signet.from_name(algo)
        _, pk = signer.generate_keys()

        # 1. Derive DID
        did = signetdsa.DidKey.to_did(algo, pk)
        print(f"Algorithm: {algo}")
        print(f"  Derived DID: {did}")

        # 2. Resolve DID
        doc = signetdsa.DidKey.resolve(did)
        print(f"  Resolved:    algo={doc.algo}, pk_len={len(doc.public_key)} bytes")
        assert doc.did == did
        assert doc.algo == signer.name
        assert doc.public_key == pk
        print("  [✓] Verified round-trip resolution.\n")

    print("[✓] All W3C did:key operations completed successfully!")


if __name__ == "__main__":
    main()
