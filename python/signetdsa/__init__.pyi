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
        """Instantiate a signature scheme by name (e.g. 'ecdsa', 'eddsa', 'mldsa', 'slhdsa')."""
        ...
    @staticmethod
    def available() -> List[str]:
        """Return a list of all 12 canonical algorithm names."""
        ...
    @staticmethod
    def benchmark(name: str, iterations: int = 10) -> BenchmarkResult:
        """Micro-benchmark a single algorithm."""
        ...
    @staticmethod
    def benchmark_all(iterations: int = 10) -> List[BenchmarkResult]:
        """Micro-benchmark all 12 algorithms."""
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

class Jwk:
    """JSON Web Key (JWK, RFC 7517)."""
    kty: str
    use_: Optional[str]
    alg: Optional[str]
    kid: Optional[str]
    crv: Optional[str]
    x: Optional[str]
    y: Optional[str]
    n: Optional[str]
    e: Optional[str]

    @staticmethod
    def from_public_key(algo: str, public_key: bytes) -> Jwk:
        """Create a JWK from an algorithm name and public key bytes."""
        ...
    def to_public_key(self) -> bytes:
        """Extract public key bytes from this JWK."""
        ...
    def thumbprint(self) -> str:
        """Compute RFC 7638 SHA-256 JWK thumbprint."""
        ...
    def to_json(self) -> str:
        """Serialize JWK to JSON."""
        ...
    @staticmethod
    def from_json(json_str: str) -> Jwk:
        """Parse JWK from JSON."""
        ...

class Jwks:
    """JSON Web Key Set (JWKS, RFC 7517 §5)."""
    keys: List[Jwk]

    def __init__(self, keys: List[Jwk]) -> None: ...
    def to_json(self) -> str: ...
    @staticmethod
    def from_json(json_str: str) -> Jwks: ...

class CoseSign1:
    """CBOR Object Signing and Encryption (COSE_Sign1, RFC 9052)."""
    @staticmethod
    def sign(algo: str, private_key: bytes, payload: bytes) -> bytes:
        """Sign payload into a binary COSE_Sign1 envelope (CBOR Tag 18)."""
        ...
    @staticmethod
    def verify(cose_bytes: bytes, public_key: bytes) -> bytes:
        """Verify a binary COSE_Sign1 envelope and extract payload."""
        ...

class DidKeyDocument:
    """Resolved W3C did:key document."""
    did: str
    algo: str
    @property
    def public_key(self) -> bytes: ...

class DidKey:
    """W3C did:key decentralized identifier utility."""
    @staticmethod
    def to_did(algo: str, public_key: bytes) -> str:
        """Derive standard W3C did:key URI from algorithm and public key bytes."""
        ...
    @staticmethod
    def resolve(did: str) -> DidKeyDocument:
        """Resolve a did:key URI to algorithm and public key bytes."""
        ...

def frost_ceremony(min_signers: int, max_signers: int, message: bytes) -> bool: ...
def frost_ceremony_2_of_3(message: bytes) -> bool: ...
def secp256k1_sign_recoverable(private_key: bytes, message: bytes) -> Tuple[bytes, int]: ...
def secp256k1_recover_public_key(message: bytes, signature: bytes, recid: int) -> bytes: ...
def bls_aggregate_signatures(signatures: List[bytes]) -> bytes: ...
def bls_verify_aggregated(aggregate_signature: bytes, messages: List[bytes], public_keys: List[bytes]) -> bool: ...
def eddsa_verify_batch(messages: List[bytes], signatures: List[bytes], public_keys: List[bytes]) -> bool: ...
