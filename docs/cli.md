# CLI

The `signetdsa` binary ([`src/bin/signetdsa.rs`](https://github.com/MinLee0210/LightDSA/blob/main/src/bin/signetdsa.rs))
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

## What the CLI Doesn't Cover

The CLI only reaches the ordinary sign/verify shape every algorithm shares
through `SignetSigner` — it doesn't expose
[FROST](algorithms/frost.md) ceremonies,
[BLS aggregation](features/aggregation.md),
[Ed25519 batch verification](features/batch_verification.md),
[ECDSA/secp256k1 public-key recovery](features/recovery.md), or
[PEM import/export](features/pem.md). Those need the typed Rust API
directly (see each feature's own page) — the CLI is a thin, generic wrapper
over what the [factory](features/factory.md) covers, nothing more.
