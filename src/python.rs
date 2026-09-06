#![allow(unsafe_op_in_unsafe_fn, unused_unsafe, clippy::all)]
//! Python C-Extension bindings for SignetDSA via PyO3.

use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::algo::bls::Bls;
use crate::algo::ecdsa_secp256k1::EcdsaSecp256k1;
use crate::algo::eddsa::EdDsa;
use crate::algo::frost;
use crate::bench::{benchmark_algo, benchmark_all};
use crate::envelope::{JwsCompact, SignetEnvelope};
use crate::signet::{Signet, SignetSigner};

/// Object-safe dynamic signature algorithm instance.
#[pyclass(name = "SignetSigner")]
pub struct PySignetSigner {
    inner: Box<dyn SignetSigner>,
}

#[pymethods]
impl PySignetSigner {
    /// Canonical name of the signature algorithm.
    #[getter]
    pub fn name(&self) -> &'static str {
        self.inner.name()
    }

    /// Generate a fresh (private_key, public_key) pair as bytes.
    pub fn generate_keys<'py>(
        &self,
        py: Python<'py>,
    ) -> (Bound<'py, PyBytes>, Bound<'py, PyBytes>) {
        let (sk, pk) = self.inner.generate_keys();
        (PyBytes::new_bound(py, &sk), PyBytes::new_bound(py, &pk))
    }

    /// Sign a message using the serialized private key bytes.
    pub fn sign<'py>(
        &self,
        py: Python<'py>,
        private_key: &[u8],
        message: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self
            .inner
            .sign(private_key, message)
            .map_err(PyValueError::new_err)?;
        Ok(PyBytes::new_bound(py, &sig))
    }

    /// Verify that signature was produced over message by the holder of public_key.
    pub fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
        self.inner
            .verify(public_key, message, signature)
            .map_err(PyValueError::new_err)
    }

    fn __repr__(&self) -> String {
        format!("<SignetSigner name='{}'>", self.inner.name())
    }
}

/// Factory that instantiates signature algorithm implementations by name.
#[pyclass(name = "Signet")]
pub struct PySignet;

#[pymethods]
impl PySignet {
    /// Return a SignetSigner instance for the given algorithm name (case-insensitive).
    #[staticmethod]
    pub fn from_name(name: &str) -> PyResult<PySignetSigner> {
        let signer = Signet::from_name(name)
            .ok_or_else(|| PyKeyError::new_err(format!("unknown algorithm name '{name}'")))?;
        Ok(PySignetSigner { inner: signer })
    }

    /// Return all canonical algorithm names supported by SignetDSA.
    #[staticmethod]
    pub fn available() -> Vec<&'static str> {
        Signet::available().to_vec()
    }

    /// Micro-benchmark a single algorithm by name over N iterations.
    #[staticmethod]
    #[pyo3(signature = (name, iterations=10))]
    pub fn benchmark(name: &str, iterations: usize) -> PyResult<PyBenchmarkResult> {
        let res = benchmark_algo(name, iterations).map_err(PyValueError::new_err)?;
        Ok(PyBenchmarkResult::from(res))
    }

    /// Micro-benchmark all 11 algorithms over N iterations.
    #[staticmethod]
    #[pyo3(signature = (iterations=10))]
    pub fn benchmark_all(iterations: usize) -> Vec<PyBenchmarkResult> {
        benchmark_all(iterations)
            .into_iter()
            .map(PyBenchmarkResult::from)
            .collect()
    }
}

/// Performance benchmark result for an algorithm.
#[pyclass(name = "BenchmarkResult")]
#[derive(Clone)]
pub struct PyBenchmarkResult {
    #[pyo3(get)]
    pub algo: String,
    #[pyo3(get)]
    pub keygen_ms: f64,
    #[pyo3(get)]
    pub sign_ms: f64,
    #[pyo3(get)]
    pub verify_ms: f64,
    #[pyo3(get)]
    pub sign_ops_per_sec: f64,
    #[pyo3(get)]
    pub priv_key_bytes: usize,
    #[pyo3(get)]
    pub pub_key_bytes: usize,
    #[pyo3(get)]
    pub sig_bytes: usize,
    #[pyo3(get)]
    pub iterations: usize,
}

impl From<crate::bench::BenchmarkResult> for PyBenchmarkResult {
    fn from(r: crate::bench::BenchmarkResult) -> Self {
        Self {
            algo: r.algo.to_string(),
            keygen_ms: r.keygen_avg.as_secs_f64() * 1000.0,
            sign_ms: r.sign_avg.as_secs_f64() * 1000.0,
            verify_ms: r.verify_avg.as_secs_f64() * 1000.0,
            sign_ops_per_sec: r.sign_ops_per_sec(),
            priv_key_bytes: r.priv_key_bytes,
            pub_key_bytes: r.pub_key_bytes,
            sig_bytes: r.sig_bytes,
            iterations: r.iterations,
        }
    }
}

#[pymethods]
impl PyBenchmarkResult {
    fn __repr__(&self) -> String {
        format!(
            "<BenchmarkResult algo='{}' sign_ops_sec={:.0} keygen={:.2}ms sign={:.2}ms verify={:.2}ms>",
            self.algo, self.sign_ops_per_sec, self.keygen_ms, self.sign_ms, self.verify_ms
        )
    }
}

/// Self-contained, verifiable signed message envelope.
#[pyclass(name = "SignetEnvelope")]
#[derive(Clone)]
pub struct PySignetEnvelope {
    inner: SignetEnvelope,
}

#[pymethods]
impl PySignetEnvelope {
    #[getter]
    pub fn algo(&self) -> String {
        self.inner.algo.clone()
    }

    #[getter]
    pub fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.public_key)
    }

    #[getter]
    pub fn message<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.message)
    }

    #[getter]
    pub fn signature<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.signature)
    }

    #[getter]
    pub fn created_at(&self) -> u64 {
        self.inner.created_at
    }

    /// Seal message into a signed envelope using signer and keypair.
    #[staticmethod]
    pub fn seal(
        signer: &PySignetSigner,
        private_key: &[u8],
        public_key: &[u8],
        message: &[u8],
    ) -> PyResult<Self> {
        let envelope =
            SignetEnvelope::seal(signer.inner.as_ref(), private_key, public_key, message)
                .map_err(PyValueError::new_err)?;
        Ok(Self { inner: envelope })
    }

    /// Verify this envelope against its embedded public key and algorithm name.
    pub fn verify(&self) -> PyResult<bool> {
        self.inner.verify().map_err(PyValueError::new_err)
    }

    /// Serialize envelope to a JSON string.
    pub fn to_json(&self) -> String {
        self.inner.to_json()
    }

    /// Parse envelope from JSON string.
    #[staticmethod]
    pub fn from_json(json_str: &str) -> PyResult<Self> {
        let envelope = SignetEnvelope::from_json(json_str).map_err(PyValueError::new_err)?;
        Ok(Self { inner: envelope })
    }

    fn __repr__(&self) -> String {
        format!(
            "<SignetEnvelope algo='{}' created_at={}>",
            self.inner.algo, self.inner.created_at
        )
    }
}

/// JSON Web Signature (JWS) compact token serialization (RFC 7515).
#[pyclass(name = "JwsCompact")]
pub struct PyJwsCompact;

#[pymethods]
impl PyJwsCompact {
    /// Sign a payload into a URL-safe compact JWS token (`<header>.<payload>.<signature>`).
    #[staticmethod]
    pub fn sign(algo: &str, private_key: &[u8], payload: &[u8]) -> PyResult<String> {
        JwsCompact::sign(algo, private_key, payload).map_err(PyValueError::new_err)
    }

    /// Verify a compact JWS token against public_key and return the verified payload.
    #[staticmethod]
    pub fn verify<'py>(
        py: Python<'py>,
        token: &str,
        public_key: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let payload = JwsCompact::verify(token, public_key).map_err(PyValueError::new_err)?;
        Ok(PyBytes::new_bound(py, &payload))
    }
}

// ---------------------------------------------------------------------------
// Specialized Free Functions
// ---------------------------------------------------------------------------

/// Simulate a FROST min_signers-of-max_signers threshold ceremony on secp256k1.
#[pyfunction]
#[pyo3(signature = (min_signers, max_signers, message))]
pub fn frost_ceremony(min_signers: u16, max_signers: u16, message: &[u8]) -> PyResult<bool> {
    frost::ceremony(min_signers, max_signers, message)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Convenience FROST 2-of-3 threshold ceremony.
#[pyfunction]
#[pyo3(signature = (message))]
pub fn frost_ceremony_2_of_3(message: &[u8]) -> PyResult<bool> {
    frost::ceremony_2_of_3(message).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// ECDSA/secp256k1 recoverable signing, returning (signature_bytes, recovery_id).
#[pyfunction]
#[pyo3(signature = (private_key, message))]
pub fn secp256k1_sign_recoverable<'py>(
    py: Python<'py>,
    private_key: &[u8],
    message: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, u8)> {
    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_bytes(private_key.into())
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let (sig, recid) = EcdsaSecp256k1::sign_recoverable(&sk, message)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok((PyBytes::new_bound(py, &sig), recid))
}

/// Recover an ECDSA/secp256k1 public key from a message, signature, and recovery id.
#[pyfunction]
#[pyo3(signature = (message, signature, recid))]
pub fn secp256k1_recover_public_key<'py>(
    py: Python<'py>,
    message: &[u8],
    signature: &[u8],
    recid: u8,
) -> PyResult<Bound<'py, PyBytes>> {
    let vk = EcdsaSecp256k1::recover_public_key(message, signature, recid)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let point = vk.to_encoded_point(true);
    Ok(PyBytes::new_bound(py, point.as_bytes()))
}

/// Combine multiple BLS12-381 signatures into a single aggregate signature.
#[pyfunction]
#[pyo3(signature = (signatures))]
pub fn bls_aggregate_signatures<'py>(
    py: Python<'py>,
    signatures: Vec<Vec<u8>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let agg =
        Bls::aggregate_signatures(&signatures).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new_bound(py, &agg))
}

/// Verify an aggregate BLS12-381 signature over distinct messages and public keys.
#[pyfunction]
#[pyo3(signature = (aggregate_signature, messages, public_keys))]
pub fn bls_verify_aggregated(
    aggregate_signature: &[u8],
    messages: Vec<Vec<u8>>,
    public_keys: Vec<Vec<u8>>,
) -> PyResult<bool> {
    let msg_refs: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();
    Bls::verify_aggregated(aggregate_signature, &msg_refs, &public_keys)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Verify a batch of Ed25519 (message, public_key, signature) triples simultaneously.
#[pyfunction]
#[pyo3(signature = (messages, signatures, public_keys))]
pub fn eddsa_verify_batch(
    messages: Vec<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
    public_keys: Vec<Vec<u8>>,
) -> PyResult<bool> {
    use ed25519_dalek::VerifyingKey;
    let msg_refs: Vec<&[u8]> = messages.iter().map(|v| v.as_slice()).collect();
    let mut keys = Vec::with_capacity(public_keys.len());
    for pk in public_keys {
        let slice: [u8; 32] = pk
            .as_slice()
            .try_into()
            .map_err(|_| PyValueError::new_err("Ed25519 public key must be 32 bytes"))?;
        keys.push(
            VerifyingKey::from_bytes(&slice).map_err(|e| PyValueError::new_err(e.to_string()))?,
        );
    }
    EdDsa::verify_batch(&msg_refs, &signatures, &keys)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// C-extension initialization module.
#[pymodule]
fn _signetdsa(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySignet>()?;
    m.add_class::<PySignetSigner>()?;
    m.add_class::<PySignetEnvelope>()?;
    m.add_class::<PyJwsCompact>()?;
    m.add_class::<PyBenchmarkResult>()?;

    m.add_function(wrap_pyfunction!(frost_ceremony, m)?)?;
    m.add_function(wrap_pyfunction!(frost_ceremony_2_of_3, m)?)?;
    m.add_function(wrap_pyfunction!(secp256k1_sign_recoverable, m)?)?;
    m.add_function(wrap_pyfunction!(secp256k1_recover_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(bls_aggregate_signatures, m)?)?;
    m.add_function(wrap_pyfunction!(bls_verify_aggregated, m)?)?;
    m.add_function(wrap_pyfunction!(eddsa_verify_batch, m)?)?;

    Ok(())
}
