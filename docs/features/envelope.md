# Signed Envelopes & JWS Tokens

SignetDSA provides high-level abstractions for bundling messages, signatures, public keys, and cryptographic metadata into portable, self-verifying containers.

## 1. SignetEnvelope (Self-Contained Signed Messages)

In distributed architectures, managing disconnected tuples of `(algo, public_key, signature, message)` leads to repetitive parsing logic. [`SignetEnvelope`](file:///home/octoopt/workspace/projects/personal/LightDSA/src/envelope.rs) encapsulates all elements in a single verifiable structure with standard JSON serialization.

### Sealing and Verifying

```rust
use SignetDSA::{Signet, SignetEnvelope};

let signer = Signet::from_name("eddsa").unwrap();
let (sk, pk) = signer.generate_keys();
let message = b"Authorize payment transfer: $500 to Bob";

// Seal message into envelope
let envelope = SignetEnvelope::seal(signer.as_ref(), &sk, &pk, message).unwrap();

// Serialize to JSON (ideal for network APIs or disk storage)
let json = envelope.to_json();

// Parse from JSON and verify autonomously
let parsed = SignetEnvelope::from_json(&json).unwrap();
assert!(parsed.verify().unwrap());
```

### JSON Format

```json
{
  "algo": "eddsa",
  "created_at": 1788685354,
  "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "message": "417574686f72697a65207061796d656e74207472616e736665723a202435303020746f20426f62",
  "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
}
```

---

## 2. JwsCompact (RFC 7515 JSON Web Signatures)

[`JwsCompact`](file:///home/octoopt/workspace/projects/personal/LightDSA/src/envelope.rs) generates standard URL-safe compact tokens composed of three Base64URL dot-separated segments:

$$\text{Token} = \text{BASE64URL}(\text{Header}) \,.\, \text{BASE64URL}(\text{Payload}) \,.\, \text{BASE64URL}(\text{Signature})$$

### Creating and Verifying Compact Tokens

```rust
use SignetDSA::{Signet, envelope::JwsCompact};

let signer = Signet::from_name("ecdsa-p384").unwrap();
let (sk, pk) = signer.generate_keys();
let payload = b"sub=1234567890&name=Alice&admin=true";

// Sign into compact JWS string
let token = JwsCompact::sign("ecdsa-p384", &sk, payload).unwrap();
println!("Compact Token: {token}");

// Verify token signature and extract original payload
let verified_payload = JwsCompact::verify(&token, &pk).unwrap();
assert_eq!(verified_payload, payload);
```

### Supported Token Algorithms

Any signature algorithm supported by [`Signet::from_name`](file:///home/octoopt/workspace/projects/personal/LightDSA/src/signet.rs) works automatically with `JwsCompact` (including `"eddsa"`, `"ecdsa"`, `"ecdsa-p384"`, `"schnorr"`, `"rsa-pss"`).
