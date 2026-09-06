#!/usr/bin/env python3
"""
JSON Web Key (JWK, RFC 7517) & JWKS example in Python.

Demonstrates:
- Exporting public keys to JWK format (OKP, EC, RSA)
- Computing RFC 7638 SHA-256 JWK thumbprints
- Building and parsing JWKS sets (.well-known/jwks.json)
- Converting JWKs back into raw public keys
"""

import signetdsa


def main():
    print("=== SignetDSA Python SDK - JWK & JWKS (RFC 7517) ===\n")

    algos = ["eddsa", "ecdsa", "ecdsa-secp256k1", "ecdsa-p384"]
    jwk_list = []

    for algo in algos:
        signer = signetdsa.Signet.from_name(algo)
        sk, pk = signer.generate_keys()

        # 1. Export to JWK
        jwk = signetdsa.Jwk.from_public_key(algo, pk)
        print(f"Algorithm: {algo}")
        print(f"  Key Type:   {jwk.kty}")
        print(f"  Curve:      {jwk.crv}")
        print(f"  Thumbprint: {jwk.thumbprint()}")
        print(f"  JSON:       {jwk.to_json()}\n")

        # 2. Reconstruct public key
        recovered_pk = jwk.to_public_key()
        assert recovered_pk == pk

        jwk_list.append(jwk)

    # 3. Create JWKS Key Set
    jwks = signetdsa.Jwks(jwk_list)
    jwks_json = jwks.to_json()
    print("Exported JWKS Set:")
    print(f"  {jwks_json}\n")

    # 4. Parse JWKS
    parsed_jwks = signetdsa.Jwks.from_json(jwks_json)
    assert len(parsed_jwks.keys) == len(algos)

    print("[✓] All JWK & JWKS operations completed successfully!")


if __name__ == "__main__":
    main()
