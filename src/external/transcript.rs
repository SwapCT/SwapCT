use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use super::error::ProofError;


pub trait TranscriptProtocol {
    /// Append a domain separator for an `n`-bit, `m`-party range proof of different languages.
    fn vsigma_domain_sep(&mut self, n: u64);
    fn innerproduct_domain_sep(&mut self, n: u64);
    fn ringsig_domain_sep(&mut self, n: u64);
    fn sealsig_domain_sep(&mut self, n: u64, m: u64);

    /// Append a `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);

    /// Append a `point` with the given `label`.
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ProofError>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
    fn challenge_point(&mut self, label: &'static [u8]) -> RistrettoPoint;
}

impl TranscriptProtocol for Transcript {
    fn vsigma_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"vecsigma v1");
        self.append_u64(b"n", n);
    }

    fn innerproduct_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"ipp v1");
        self.append_u64(b"n", n);
    }

    fn ringsig_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"ringsig v1");
        self.append_u64(b"n", n);
    }

    fn sealsig_domain_sep(&mut self, n: u64, m: u64) {
        self.append_message(b"dom-sep", b"sealsig v1");
        self.append_u64(b"n", n);
        self.append_u64(b"m", m);
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ProofError> {
        use curve25519_dalek::traits::IsIdentity;

        if point.is_identity() {
            Err(ProofError::VerificationError)
        } else {
            Ok(self.append_message(label, point.as_bytes()))
        }
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn challenge_point(&mut self, label: &'static [u8]) -> RistrettoPoint {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        RistrettoPoint::from_uniform_bytes(&buf)
    }
}