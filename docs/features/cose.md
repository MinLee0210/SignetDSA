# COSE Compact Binary Envelopes (RFC 9052)

**SignetDSA** provides support for [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) / [RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152) **CBOR Object Signing and Encryption (`COSE_Sign1`)**.

COSE is the compact binary counterpart to JOSE/JWS. It replaces JSON and Base64URL string encodings with native CBOR binary data, making it the standard for **WebAuthn / FIDO2 Passkeys**, **IoT devices**, and **constrained networks**.

---

## Supported COSE Algorithms

| Algorithm | COSE Algorithm Identifier | SignetDSA Name | Standard |
|---|---|---|---|
| **EdDSA (Ed25519)** | `-8` | `eddsa` | RFC 9053 §2.2 |
| **ECDSA on P-256 (ES256)** | `-7` | `ecdsa` | RFC 9053 §2.1 |
| **ECDSA on P-384 (ES384)** | `-35` | `ecdsa-p384` | RFC 9053 §2.1 |
| **ECDSA on secp256k1 (ES256K)** | `-47` | `ecdsa-secp256k1` | RFC 8812 §3 |
| **RSASSA-PSS (PS256)** | `-37` | `rsa-pss` | RFC 8812 §4 |
| **RSASSA-PKCS1-v1_5 (RS256)** | `-257` | `rsa` | RFC 8812 §4 |

---

## Rust Usage

```rust
use SignetDSA::{Signet, CoseSign1};

let signer = Signet::from_name("eddsa").unwrap();
let (sk, pk) = signer.generate_keys();
let payload = b"Binary sensor telemetry: temp=23.4C";

// 1. Sign into CBOR COSE_Sign1 structure (Tag 18)
let cose_bytes = CoseSign1::sign("eddsa", &sk, payload).unwrap();
assert_eq!(cose_bytes[0], 0xd2); // CBOR Tag 18 prefix

// 2. Verify and extract payload
let verified_payload = CoseSign1::verify(&cose_bytes, &pk).unwrap();
assert_eq!(verified_payload, payload);
```

---

## Python Usage

```python
import signetdsa

signer = signetdsa.Signet.from_name("ecdsa")
sk, pk = signer.generate_keys()
payload = b"WebAuthn passkey assertion auth payload"

# 1. Sign into binary COSE_Sign1 envelope
cose_bytes = signetdsa.CoseSign1.sign("ecdsa", sk, payload)

# 2. Verify signature and extract authentic payload
verified_payload = signetdsa.CoseSign1.verify(cose_bytes, pk)
assert verified_payload == payload
```
