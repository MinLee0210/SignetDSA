import pytest
import signetdsa

def test_available_algorithms():
    algos = signetdsa.Signet.available()
    expected = [
        "rsa",
        "rsa-pss",
        "dsa",
        "ecdsa",
        "ecdsa-p384",
        "ecdsa-secp256k1",
        "eddsa",
        "ed448",
        "schnorr",
        "mldsa",
        "bls",
    ]
    assert sorted(algos) == sorted(expected)

def test_all_algorithms_roundtrip():
    message = b"Testing SignetDSA Python bindings!"
    for algo in signetdsa.Signet.available():
        signer = signetdsa.Signet.from_name(algo)
        assert signer.name == algo
        sk, pk = signer.generate_keys()

        sig = signer.sign(sk, message)
        assert len(sig) > 0

        is_valid = signer.verify(pk, message, sig)
        assert is_valid is True, f"{algo} verification failed"

        # Tampered message must fail
        with pytest.raises(ValueError):
            signer.verify(pk, b"Tampered message", sig)

def test_signed_envelope():
    signer = signetdsa.Signet.from_name("eddsa")
    sk, pk = signer.generate_keys()
    message = b"Payment instruction: transfer $100 to Alice"

    envelope = signetdsa.SignetEnvelope.seal(signer, sk, pk, message)
    assert envelope.algo == "eddsa"
    assert envelope.message == message
    assert envelope.verify() is True

    # JSON roundtrip
    json_str = envelope.to_json()
    assert '"algo": "eddsa"' in json_str

    parsed = signetdsa.SignetEnvelope.from_json(json_str)
    assert parsed.algo == envelope.algo
    assert parsed.verify() is True

def test_jws_compact():
    test_algos = ["eddsa", "ecdsa", "ecdsa-p384", "schnorr", "rsa-pss"]
    payload = b"user=alice&role=admin"

    for algo in test_algos:
        signer = signetdsa.Signet.from_name(algo)
        sk, pk = signer.generate_keys()

        token = signetdsa.JwsCompact.sign(algo, sk, payload)
        assert len(token.split(".")) == 3

        verified_payload = signetdsa.JwsCompact.verify(token, pk)
        assert verified_payload == payload

def test_jws_compact_tampered():
    signer = signetdsa.Signet.from_name("eddsa")
    sk, pk = signer.generate_keys()

    token = signetdsa.JwsCompact.sign("eddsa", sk, b"valid payload")
    parts = token.split(".")
    parts[1] = "dGFtcGVyZWQ"  # "tampered" in base64
    tampered_token = ".".join(parts)

    with pytest.raises(ValueError):
        signetdsa.JwsCompact.verify(tampered_token, pk)

def test_frost_threshold():
    message = b"Threshold multi-sig approval"
    assert signetdsa.frost_ceremony_2_of_3(message) is True
    assert signetdsa.frost_ceremony(3, 5, message) is True

def test_secp256k1_recovery():
    signer = signetdsa.Signet.from_name("ecdsa-secp256k1")
    sk, pk = signer.generate_keys()
    message = b"ecrecover transaction"

    sig, recid = signetdsa.secp256k1_sign_recoverable(sk, message)
    recovered_pk = signetdsa.secp256k1_recover_public_key(message, sig, recid)

    assert recovered_pk == pk

def test_bls_aggregation():
    signers = [signetdsa.Signet.from_name("bls") for _ in range(3)]
    keypairs = [s.generate_keys() for s in signers]
    messages = [b"msg_alice", b"msg_bob", b"msg_carol"]

    signatures = [s.sign(sk, msg) for s, (sk, _), msg in zip(signers, keypairs, messages)]
    public_keys = [pk for _, pk in keypairs]

    agg_sig = signetdsa.bls_aggregate_signatures(signatures)
    assert len(agg_sig) == 96  # BLS12-381 G2 signature is 96 bytes

    is_valid = signetdsa.bls_verify_aggregated(agg_sig, messages, public_keys)
    assert is_valid is True

def test_eddsa_batch_verification():
    signer = signetdsa.Signet.from_name("eddsa")
    keypairs = [signer.generate_keys() for _ in range(5)]
    messages = [f"batch_message_{i}".encode() for i in range(5)]
    signatures = [signer.sign(sk, msg) for (sk, _), msg in zip(keypairs, messages)]
    public_keys = [pk for _, pk in keypairs]

    is_valid = signetdsa.eddsa_verify_batch(messages, signatures, public_keys)
    assert is_valid is True

def test_benchmark():
    result = signetdsa.Signet.benchmark("eddsa", iterations=5)
    assert result.algo == "eddsa"
    assert result.sign_ops_per_sec > 0
    assert result.priv_key_bytes == 32
    assert result.pub_key_bytes == 32
    assert result.sig_bytes == 64
