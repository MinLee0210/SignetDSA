# Python SDK (`signetdsa`)

**SignetDSA** provides first-class, high-performance Python bindings powered by [PyO3](https://pyo3.rs) and [Maturin](https://www.maturin.rs). It brings Rust's memory safety, automatic secret zeroization, and all 11 cryptographic algorithms directly to Python with zero unnecessary memory copies and full [PEP 561](https://peps.python.org/pep-0561/) typing stubs (`.pyi`).

---

## Installation

### From Source / Repository

To build and install `signetdsa` in your Python environment:

```bash
# Clone the repository
git clone https://github.com/MinLee0210/SignetDSA.git
cd SignetDSA

# Option 1: Standard pip install
pip install .

# Option 2: Using maturin for development / editable build
pip install maturin
maturin develop --release
```

---

## Quickstart: Dynamic Factory API

The `Signet` factory provides runtime algorithm selection matching Rust's `Signet::from_name()`:

```python
import signetdsa

# 1. Inspect supported algorithms
print(signetdsa.Signet.available())
# ['rsa', 'rsa-pss', 'dsa', 'ecdsa', 'ecdsa-p384', 'ecdsa-secp256k1', 'eddsa', 'ed448', 'schnorr', 'mldsa', 'bls']

# 2. Instantiate a signer
signer = signetdsa.Signet.from_name("eddsa")

# 3. Generate keypair (bytes)
private_key, public_key = signer.generate_keys()

# 4. Sign a message
message = b"Securing payments with SignetDSA"
signature = signer.sign(private_key, message)

# 5. Verify the signature
is_valid = signer.verify(public_key, message, signature)
assert is_valid is True
```

---

## JSON Web Signatures (JWS RFC 7515)

Create and verify standard compact JWS tokens (`<header>.<payload>.<signature>`):

```python
import signetdsa

signer = signetdsa.Signet.from_name("ecdsa-p384")
sk, pk = signer.generate_keys()

claims = b'{"sub": "user_42", "role": "admin", "iat": 1788685000}'

# Produce compact JWS token string
token = signetdsa.JwsCompact.sign("ecdsa-p384", sk, claims)
print(token)
# eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXUyJ9.eyJzdWIiOiAidXNlc...

# Verify and extract the authentic payload
payload = signetdsa.JwsCompact.verify(token, pk)
assert payload == claims
```

---

## Self-Contained Signed Envelopes

Seal arbitrary payloads into self-describing, verifiable JSON envelopes:

```python
import signetdsa

signer = signetdsa.Signet.from_name("schnorr")
sk, pk = signer.generate_keys()

# Seal message into an envelope
envelope = signetdsa.SignetEnvelope.seal(signer, sk, pk, b"Audit Log Entry #9812")

# Export to JSON
json_data = envelope.to_json()

# Inspect envelope properties
print(envelope.algo)        # "schnorr"
print(envelope.created_at)  # 1788685020

# Deserialize and verify anywhere
parsed = signetdsa.SignetEnvelope.from_json(json_data)
assert parsed.verify() is True
```

---

## Specialized Cryptographic Protocols

### 1. FROST (t-of-n Threshold Schnorr)

Simulate or execute a full FROST ceremony where $t$ out of $n$ participants jointly construct a valid standard Schnorr signature without any party ever reconstructing the aggregate private key:

```python
import signetdsa

message = b"Multi-party transaction approval"

# Standard 2-of-3 threshold ceremony
assert signetdsa.frost_ceremony_2_of_3(message) is True

# Arbitrary t-of-n threshold ceremony (e.g. 3-of-5)
assert signetdsa.frost_ceremony(min_signers=3, max_signers=5, message=message) is True
```

---

### 2. Ethereum `ecrecover` (Public-Key Recovery)

Produce recoverable secp256k1 signatures and extract the signer's public key from the signature and 1-byte recovery ID:

```python
import signetdsa

signer = signetdsa.Signet.from_name("ecdsa-secp256k1")
sk, pk = signer.generate_keys()

tx_hash = b"\x01" * 32

# Sign with recovery ID
signature, recovery_id = signetdsa.secp256k1_sign_recoverable(sk, tx_hash)

# Reconstruct public key (ecrecover)
recovered_pk = signetdsa.secp256k1_recover_public_key(tx_hash, signature, recovery_id)
assert recovered_pk == pk
```

---

### 3. BLS12-381 Signature Aggregation

Aggregate multiple independent signatures over distinct messages into a single 96-byte aggregate signature:

```python
import signetdsa

signers = [signetdsa.Signet.from_name("bls") for _ in range(3)]
keypairs = [s.generate_keys() for s in signers]
messages = [b"TX_01", b"TX_02", b"TX_03"]

# Generate individual signatures
signatures = [s.sign(sk, msg) for (sk, pk), msg, s in zip(keypairs, messages, signers)]

# Aggregate signatures into one 96-byte signature
aggregated_sig = signetdsa.bls_aggregate_signatures(signatures)

# Verify all distinct messages in a single pairing equation
public_keys = [pk for (sk, pk) in keypairs]
is_valid = signetdsa.bls_verify_aggregated(public_keys, messages, aggregated_sig)
assert is_valid is True
```

---

### 4. Ed25519 Batch Verification

Verify $N$ signatures in parallel with high cryptographic efficiency:

```python
import signetdsa

signer = signetdsa.Signet.from_name("eddsa")
pairs = [signer.generate_keys() for _ in range(5)]
messages = [f"Batch item {i}".encode() for i in range(5)]
signatures = [signer.sign(sk, msg) for (sk, pk), msg in zip(pairs, messages)]

public_keys = [pk for (sk, pk) in pairs]

assert signetdsa.eddsa_verify_batch(public_keys, messages, signatures) is True
```

---

## In-Process Benchmarking

Benchmark all 11 algorithms directly from Python:

```python
import signetdsa

results = signetdsa.benchmark_all(iterations=20)
for res in results:
    print(f"Algorithm: {res.algo_name:18} | Sign: {res.sign_ops_per_sec:10.1f} ops/s | Verify: {res.verify_ops_per_sec:10.1f} ops/s")
```

---

## Type Safety and IDE Autocomplete

`signetdsa` ships with complete type stubs (`signetdsa/__init__.pyi`) and a `py.typed` marker. Modern IDEs (VS Code Pylance, PyCharm, MyPy, Pyright) provide instant autocomplete, argument type validation, and docstrings.
