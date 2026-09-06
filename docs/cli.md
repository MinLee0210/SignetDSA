# CLI

The `signetdsa` binary ([`src/bin/signetdsa.rs`](https://github.com/MinLee0210/SignetDSA/blob/main/src/bin/signetdsa.rs))
exposes the [factory API](features/factory.md) from the shell — generate
keys, sign, and verify, for any algorithm `Signet::available()` knows about,
without writing any Rust. Keys and signatures are stored as hex-encoded text
files, so they're easy to inspect, diff, or paste elsewhere.

## Commands

### `list`

```console
$ cargo run --bin signetdsa -- list
rsa
dsa
ecdsa
ecdsa-secp256k1
eddsa
ed448
schnorr
mldsa
bls
```

### `keygen`

```console
$ cargo run --bin signetdsa -- keygen \
    --algo ed25519 \
    --priv-out alice.key \
    --pub-out alice.pub
Generated ed25519 keypair -> private: alice.key, public: alice.pub
```

### `sign`

```console
$ cargo run --bin signetdsa -- sign \
    --algo ed25519 \
    --key alice.key \
    --message "hello" \
    --sig-out hello.sig
Signature written to hello.sig
```

`--message` takes the message directly on the command line; `--message-file
<path>` reads it from a file instead (the two are mutually exclusive). If
`--sig-out` is omitted, the hex-encoded signature is printed to stdout
instead of written to a file.

### `verify`

```console
$ cargo run --bin signetdsa -- verify \
    --algo ed25519 \
    --pubkey alice.pub \
    --message "hello" \
    --sig hello.sig
VALID
```

```console
$ cargo run --bin signetdsa -- verify \
    --algo ed25519 \
    --pubkey alice.pub \
    --message "tampered" \
    --sig hello.sig
error: INVALID (signature error: Verification equation was not satisfied)
```

`verify` exits `0` and prints `VALID` on success; it exits non-zero on an
invalid signature or a parse error, so it's safe to use directly in a
script's exit-code check.

## Full Example: All Nine Algorithms

```console
$ for algo in rsa dsa ecdsa ecdsa-secp256k1 eddsa ed448 schnorr mldsa bls; do
    cargo run --bin signetdsa -- keygen --algo $algo --priv-out $algo.key --pub-out $algo.pub
    cargo run --bin signetdsa -- sign --algo $algo --key $algo.key --message "hi" --sig-out $algo.sig
    cargo run --bin signetdsa -- verify --algo $algo --pubkey $algo.pub --message "hi" --sig $algo.sig
  done
```

### `recover`

Recover an ECDSA secp256k1 public key from a signature and recovery ID:

```console
$ cargo run --bin signetdsa -- recover \
    --message "ecrecover me" \
    --sig eth.sig \
    --recid 1 \
    --pub-out recovered.pub
Recovered public key written to recovered.pub
```

### `aggregate` & `verify-aggregate` (BLS)

Combine multiple BLS signatures into an aggregate signature, and verify over distinct messages:

```console
# Aggregate individual signatures
$ cargo run --bin signetdsa -- aggregate \
    --sigs sig1.sig sig2.sig sig3.sig \
    --out agg.sig
Aggregate signature written to agg.sig

# Verify aggregate signature over distinct messages and public keys
$ cargo run --bin signetdsa -- verify-aggregate \
    --sig agg.sig \
    --messages "msg1" "msg2" "msg3" \
    --pubkeys pk1.pub pk2.pub pk3.pub
VALID AGGREGATE SIGNATURE
```

### `envelope-sign` & `envelope-verify`

Create and verify self-contained signed envelopes:

```console
# Seal envelope into JSON
$ cargo run --bin signetdsa -- envelope-sign \
    --algo ed25519 \
    --key alice.key \
    --pubkey alice.pub \
    --message "payload" \
    --out envelope.json
Signed envelope saved to envelope.json

# Verify envelope autonomously
$ cargo run --bin signetdsa -- envelope-verify --envelope envelope.json
VALID ENVELOPE [algo: eddsa, created_at: 1788685354]
```

### `bench`

Benchmark performance (keygen, sign, verify timings, and key/sig sizes):

```console
$ cargo run --release --bin signetdsa -- bench --iterations 50
```
