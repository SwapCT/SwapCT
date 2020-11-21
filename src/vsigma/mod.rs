use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use rand::thread_rng;
use serde::{Serialize, Deserialize};

use crate::external::transcript::TranscriptProtocol;


#[derive(Debug, Hash, Clone, Serialize, Deserialize)]
pub struct VSigmaProof{
    cprime: CompressedRistretto,
    z: Vec<Scalar>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum VSigmaError{
    InvalidGeneratorsLength,
    VerificationError
}

impl VSigmaProof {
    pub fn prove(transcript: &mut Transcript,
                 exponents: &[Scalar],
                 bases: &[RistrettoPoint]) -> Result<(VSigmaProof, RistrettoPoint),VSigmaError> {
        if exponents.len() != bases.len() {
            return Err(VSigmaError::InvalidGeneratorsLength)
        }
        transcript.vsigma_domain_sep(bases.len() as u64);

        let original_point = RistrettoPoint::multiscalar_mul(exponents, bases);
        transcript.append_point(b"Commitment", &original_point.compress());

        let mut csprng = thread_rng();
        let random_exponents: Vec<Scalar> = bases.iter().map(|_| {
            Scalar::random(&mut csprng)
        }).collect();

        let cprime = RistrettoPoint::multiscalar_mul(&random_exponents, bases).compress();
        transcript.append_point(b"Point",&cprime);

        let chl = transcript.challenge_scalar(b"challenge");

        let mut proof = VSigmaProof{ cprime, z: Vec::new()};

        for (&exp,rand_exp) in exponents.iter().zip(random_exponents) {
            proof.z.push(rand_exp-chl*exp);
        }
        Ok((proof, original_point))
    }

    pub fn verify(&self, transcript: &mut Transcript, bases: &[RistrettoPoint], com: &RistrettoPoint) -> Result<(),VSigmaError> {
        if self.z.len() != bases.len(){
            return Err(VSigmaError::InvalidGeneratorsLength)
        }

        transcript.vsigma_domain_sep(bases.len() as u64);

        transcript.append_point(b"Commitment", &com.compress());
        transcript.append_point(b"Point", &self.cprime);

        let chl = transcript.challenge_scalar(b"challenge");

        let expect_cprime = (chl*com+RistrettoPoint::multiscalar_mul(self.z.iter(), bases)).compress();
        if expect_cprime == self.cprime {
            Ok(())
        } else {
            Err(VSigmaError::VerificationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;

    use super::VSigmaProof;
    use crate::constants::PEDERSEN_H;

    #[test]
    fn create_vsigma() {

        let mut prover_transcript = Transcript::new(b"test example");

        let val1 = Scalar::from(37264829u64);
        let val2 = Scalar::from(372614829u64);

        let (proof, commitment) = VSigmaProof::prove(&mut prover_transcript,
                                                     &vec![val1,val2],
                                                     &vec![RISTRETTO_BASEPOINT_POINT, PEDERSEN_H()]
        ).expect("valid proof inputs");
        //print!("{:#?}", tr);
        let mut verifier_transcript = Transcript::new(b"test example");
        assert!(proof.verify(&mut verifier_transcript, &vec![RISTRETTO_BASEPOINT_POINT, PEDERSEN_H()], &commitment).is_ok());
    }

}