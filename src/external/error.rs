#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum ProofError {
    /// This error occurs when a proof failed to verify.
    #[cfg_attr(feature = "std", error("Proof verification failed."))]
    VerificationError,
    /// This error occurs when the proof encoding is malformed.
    #[cfg_attr(feature = "std", error("Proof data could not be parsed."))]
    FormatError,
}