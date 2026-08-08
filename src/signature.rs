/// Core trait that every digital signature algorithm must implement.
///
/// Each implementor defines its own `PrivateKey`, `PublicKey`, and `Error` types.
/// All methods are static — keys are explicit parameters, not embedded state.
pub trait Signature {
    type PrivateKey;
    type PublicKey;
    type Error;

    /// Generate a fresh (private_key, public_key) pair.
    fn generate_keys() -> (Self::PrivateKey, Self::PublicKey);

    /// Sign `message` with the given private key.
    fn sign(private_key: &Self::PrivateKey, message: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verify that `signature` was produced over `message` by the holder of `public_key`.
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error>;
}
