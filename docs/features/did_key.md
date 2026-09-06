# W3C Decentralized Identifiers (`did:key`)

**SignetDSA** supports the [W3C `did:key` method specification](https://w3c-ccg.github.io/did-method-key/), mapping cryptographic public keys to and from deterministic, self-describing decentralized identifiers using **multicodec** headers and **Base58BTC** encoding.

---

## Supported Multicodecs

| Curve / Algorithm | Multicodec Prefix | Output DID Prefix | Key Size |
|---|---|---|---|
| **Ed25519 (`eddsa`)** | `0xed01` (`[0xed, 0x01]`) | `did:key:z6Mk...` | 32 B |
| **secp256k1 (`ecdsa-secp256k1`)** | `0xe701` (`[0xe7, 0x01]`) | `did:key:zQ3s...` | 33 B |
| **NIST P-256 (`ecdsa`)** | `0x1200` (`[0x80, 0x24]`) | `did:key:zDna...` | 33 B |
| **NIST P-384 (`ecdsa-p384`)** | `0x1201` (`[0x81, 0x24]`) | `did:key:z82L...` | 49 B |

---

## Rust Usage

```rust
use SignetDSA::{Signet, DidKey};

let signer = Signet::from_name("eddsa").unwrap();
let (_sk, pk) = signer.generate_keys();

// 1. Derive DID URI from public key
let did = DidKey::to_did("eddsa", &pk).unwrap();
println!("Derived DID: {}", did);
// did:key:z6Mku...

// 2. Resolve DID URI back to algorithm and public key bytes
let doc = DidKey::resolve(&did).unwrap();
assert_eq!(doc.algo, "eddsa");
assert_eq!(doc.public_key, pk);
```

---

## Python Usage

```python
import signetdsa

signer = signetdsa.Signet.from_name("ecdsa-secp256k1")
_, pk = signer.generate_keys()

# 1. Derive DID URI
did = signetdsa.DidKey.to_did("ecdsa-secp256k1", pk)
print("DID URI:", did)
# did:key:zQ3sh...

# 2. Resolve DID
doc = signetdsa.DidKey.resolve(did)
print(f"Algorithm: {doc.algo}, Public Key Length: {len(doc.public_key)} bytes")
assert doc.public_key == pk
```
