# JSON Web Keys (JWK, RFC 7517) & JWKS

**SignetDSA** supports standard [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) **JSON Web Keys (JWK)** and **JSON Web Key Sets (JWKS)**, enabling seamless integration with OAuth 2.0 / OpenID Connect IDPs, browser `window.crypto.subtle`, and `.well-known/jwks.json` endpoints.

---

## Supported Key Types & Curves

| SignetDSA Algorithm | JWK Key Type (`kty`) | Curve (`crv`) | Algorithm (`alg`) | RFC Standard |
|---|---|---|---|---|
| **Ed25519 (`eddsa`)** | `OKP` | `Ed25519` | `EdDSA` | RFC 8037 §2 |
| **Ed448 (`ed448`)** | `OKP` | `Ed448` | `EdDSA` | RFC 8037 §2 |
| **ECDSA P-256 (`ecdsa`)** | `EC` | `P-256` | `ES256` | RFC 7518 §6.2.1 |
| **ECDSA P-384 (`ecdsa-p384`)** | `EC` | `P-384` | `ES384` | RFC 7518 §6.2.1 |
| **ECDSA secp256k1** | `EC` | `secp256k1` | `ES256K` | RFC 8812 §2 |
| **Schnorr BIP340** | `OKP` | `secp256k1` | `SCHNORR` | BIP340 |
| **RSA / RSA-PSS** | `RSA` | — | `RS256` / `PS256` | RFC 7518 §6.3 |

---

## Rust Usage

```rust
use SignetDSA::{Signet, Jwk, Jwks};

// 1. Generate keypair
let signer = Signet::from_name("eddsa").unwrap();
let (sk, pk) = signer.generate_keys();

// 2. Export to JWK
let jwk = Jwk::from_public_key("eddsa", &pk).unwrap();
println!("JWK Thumbprint (RFC 7638): {}", jwk.thumbprint());
println!("JWK JSON:\n{}", jwk.to_json());

// 3. Export to JWKS Set (.well-known/jwks.json)
let jwks = Jwks::new(vec![jwk]);
println!("JWKS JSON:\n{}", jwks.to_json());

// 4. Parse from JWK JSON and recover public key
let parsed = Jwk::from_json(&jwks.keys[0].to_json()).unwrap();
let recovered_pk = parsed.to_public_key().unwrap();
assert_eq!(recovered_pk, pk);
```

---

## Python Usage

```python
import signetdsa

signer = signetdsa.Signet.from_name("ecdsa")
sk, pk = signer.generate_keys()

# 1. Create JWK
jwk = signetdsa.Jwk.from_public_key("ecdsa", pk)
print("Key ID / Thumbprint:", jwk.thumbprint())
print("JWK JSON:", jwk.to_json())

# 2. Reconstruct public key from JWK
recovered_pk = jwk.to_public_key()
assert recovered_pk == pk

# 3. Create JWKS key set
jwks = signetdsa.Jwks([jwk])
print("JWKS:", jwks.to_json())
```
