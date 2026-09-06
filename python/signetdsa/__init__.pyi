from typing import List, Tuple, Optional

__version__: str

class SignetSigner:
    """An instantiated digital signature scheme."""
    @property
    def name(self) -> str: ...
    def generate_keys(self) -> Tuple[bytes, bytes]:
        """Generate a fresh (private_key, public_key) pair as bytes."""
        ...
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign a message using the private key bytes."""
        ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify that signature was produced over message by public_key."""
        ...

class BenchmarkResult:
    algo: str
    keygen_ms: float
    sign_ms: float
    verify_ms: float
    sign_ops_per_sec: float
    priv_key_bytes: int
    pub_key_bytes: int
    sig_bytes: int
    iterations: int

class Signet:
    """Factory that instantiates signature algorithm implementations by name."""
    @staticmethod
    def from_name(name: str) -> SignetSigner:
        """Instantiate a signature scheme by name (e.g. 'ecdsa', 'eddsa', 'mldsa')."""
        ...
    @staticmethod
    def available() -> List[str]:
        """Return a list of all 11 canonical algorithm names."""
        ...
    @staticmethod
    def benchmark(name: str, iterations: int = 10) -> BenchmarkResult:
        """Micro-benchmark a single algorithm."""
        ...
    @staticmethod
    def benchmark_all(iterations: int = 10) -> List[BenchmarkResult]:
        """Micro-benchmark all 11 algorithms."""
        ...

class SignetEnvelope:
    """Self-contained, verifiable signed message envelope."""
    algo: str
    public_key: bytes
    message: bytes
    signature: bytes
    created_at: int

    @staticmethod
    def seal(signer: SignetSigner, private_key: bytes, public_key: bytes, message: bytes) -> SignetEnvelope:
        """Create and sign a new envelope."""
        ...
    def verify(self) -> bool:
        """Verify the envelope against its embedded public key and algorithm name."""
        ...
    def to_json(self) -> str:
        """Serialize envelope to JSON."""
        ...
    @staticmethod
    def from_json(json_str: str) -> SignetEnvelope:
        """Parse envelope from JSON."""
        ...

class JwsCompact:
    """JSON Web Signature (JWS) compact token serializer (RFC 7515)."""
    @staticmethod
    def sign(algo: str, private_key: bytes, payload: bytes) -> str:
        """Sign payload into a compact JWS token (header.payload.signature)."""
        ...
    @staticmethod
    def verify(token: str, public_key: bytes) -> bytes:
        """Verify compact JWS token and return original payload."""
        ...

def frost_ceremony(min_signers: int, max_signers: int, message: bytes) -> bool: ...
def frost_ceremony_2_of_3(message: bytes) -> bool: ...
def secp256k1_sign_recoverable(private_key: bytes, message: bytes) -> Tuple[bytes, int]: ...
def secp256k1_recover_public_key(message: bytes, signature: bytes, recid: int) -> bytes: ...
def bls_aggregate_signatures(signatures: List[bytes]) -> bytes: ...
def bls_verify_aggregated(aggregate_signature: bytes, messages: List[bytes], public_keys: List[bytes]) -> bool: ...
def eddsa_verify_batch(messages: List[bytes], signatures: List[bytes], public_keys: List[bytes]) -> bool: ...
