use bytes::Bytes;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use std::ops::Add;
use rand::thread_rng;
use merlin::Transcript;
use sha3::{Digest, Sha3_512};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::traits::IsIdentity;
use serde::{Serialize, Deserialize};
use rayon::prelude::*;

use crate::{constants, vsigma};
use crate::ringsig::TaggedRingSig;
use crate::account::OTAccount;
use crate::commitment::TypeCommitment;
use crate::vsigma::VSigmaProof;


#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum AAError{
    ArgumentNumberError,
    VerificationSigRemaining,
    VerificationOutputProof,
    VerificationMsgNotFound,
    VerificationMsgRemaining,
    VerificationError,
    VerificationInputProof,
    VerificationInputMatching,
    VerificationInputSignature,
}

pub trait AAMsg: Eq + Default + Clone {
    fn to_byte_vec(&self) -> Vec<u8>;
    fn publish(&self) -> Self;
}

impl AAMsg for Bytes {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_vec()
    }
    fn publish(&self) -> Bytes { self.clone() }
}

#[derive(Default, Hash, Debug, Clone, Serialize, Deserialize)]
pub struct AASig<Algo: TaggedRingSig, Msg: AAMsg> {
    pub(crate) input_proofs: Vec<(vsigma::VSigmaProof, CompressedRistretto, Algo, CompressedRistretto)>,
    output_proofs: Vec<(vsigma::VSigmaProof, CompressedRistretto, Msg)>,
    randomness: Scalar,
}

impl<Algo: TaggedRingSig + Default + Send + Sync + Clone, Msg: AAMsg + Send + Sync> AASig<Algo, Msg> {
    pub fn sign(signers: &Vec<(&Vec<OTAccount>, &usize, &TypeCommitment)>, msgs: &Vec<Msg>) -> Result<AASig<Algo, Msg>, AAError> {
        let mut sig = AASig::<Algo, Msg>::default();

        if signers.len() < 1 {
            return Err(AAError::ArgumentNumberError)
        }
        if msgs.len() < 1 {
            return Err(AAError::ArgumentNumberError)
        }

        let mut csprng = thread_rng();
        let sr_exp:Vec<(Scalar,Scalar)> = msgs.iter().map(|_|(Scalar::random(&mut csprng),Scalar::random(&mut csprng))).collect();

        let outside: Vec<(Scalar, Scalar, (VSigmaProof, CompressedRistretto, Msg))> = msgs.par_iter().zip(sr_exp).map(|(msg,(s_exp,r_exp))|{
            let mut transcript = Transcript::new(b"output knowledge");
            let (proof, tmpcom) = vsigma::VSigmaProof::prove(&mut transcript, &vec![s_exp, r_exp], &vec![RISTRETTO_BASEPOINT_POINT, constants::PEDERSEN_H()]
            ).expect("something went very wrong");

            let mut hasher = Sha3_512::new();
            hasher.update(&tmpcom.compress().as_bytes());
            hasher.update(&msg.to_byte_vec());

            let output_hash = Scalar::from_hash(hasher);
            (s_exp + output_hash, r_exp, (proof, tmpcom.compress(), (*msg).clone()) )
        }).collect();

        let cum_s: Scalar = outside.iter().map(|(s,_,_)|s).sum();
        sig.randomness = outside.iter().map(|(_,r,_)|r).sum();
        sig.output_proofs = outside.iter().map(|(_,_,p)|p.clone()).collect();


        let mut random_exponents: Vec<Scalar> = signers.iter().map(|_| Scalar::random(&mut csprng) ).collect();
        let mut rsum: Scalar = random_exponents.iter().sum();
        rsum -= random_exponents[0];
        random_exponents[0] = cum_s - rsum;

        let sigs: Vec<Result<(VSigmaProof, CompressedRistretto, Algo, CompressedRistretto ),AAError>> = signers.par_iter().zip(random_exponents).map(|((accts,index, com),random_exponent)| {
            let mut transcript = Transcript::new(b"input knowledge");
            let (proof, tmpcom) = vsigma::VSigmaProof::prove(&mut transcript, &vec![random_exponent], &vec![RISTRETTO_BASEPOINT_POINT]
            ).expect("something went wrong in the input");

            let tmpcomcompressed = tmpcom.compress();

            let setsig = match Algo::sign(&mut transcript, accts, *index.clone(), com, &Bytes::from(tmpcomcompressed.to_bytes().to_vec())){
                Ok(x) => x,
                Err(_e) => return Err(AAError::ArgumentNumberError)
            };
            Ok((proof, tmpcom.compress(), setsig, com.com.compress()))
        }).collect();

        match sigs.iter().find(|res| res.is_err()) {
            Some(_) => return Err(AAError::ArgumentNumberError),
            _ => {}
        }
        sig.input_proofs = sigs.iter().map(|res| res.as_ref().unwrap().clone()).collect();

        sig.normalize();
        Ok(sig)
    }

    pub fn verify(&self, signers: &Vec<(&Vec<OTAccount>, &TypeCommitment)>, msgs: &Vec<Msg>) -> Result<(), AAError> {

        let mut cum_elem = (-self.randomness) * constants::PEDERSEN_H();
        let vers: Vec<Result<(usize,Scalar, RistrettoPoint),AAError>> = self.output_proofs.par_iter().map(|(proof, com, msg)| {
            // check that msg is in in cmp msgs
            let idx = match msgs.iter().position(|x| x == msg) {
                Some(idx) =>idx,
                None => return Err(AAError::VerificationMsgNotFound)
            };

            let mut transcript = Transcript::new(b"output knowledge");
            if proof.verify(&mut transcript, &vec![RISTRETTO_BASEPOINT_POINT, constants::PEDERSEN_H()], &com.decompress().unwrap()).is_err() {
                return Err(AAError::VerificationOutputProof)
            }

            let mut hasher = Sha3_512::new();
            hasher.update(&com.as_bytes());
            hasher.update(&msg.to_byte_vec());

            let output_hash = Scalar::from_hash(hasher);
            Ok((idx,output_hash, com.decompress().unwrap()))
        }).collect();

        match vers.iter().find(|res| res.is_err()) {
            Some(e) => return Err(e.clone().unwrap_err()),
            _ => {}
        }

        let mut idices = vers.iter().map(|r| r.clone().unwrap().0).collect::<Vec<usize>>();
        idices.sort();
        idices.dedup();
        if idices.len() != msgs.len() {
            return Err(AAError::VerificationMsgRemaining)
        }
        cum_elem += vers.iter().map(|r| r.clone().unwrap().2).sum::<RistrettoPoint>();
        cum_elem += vers.iter().map(|r| r.clone().unwrap().1).sum::<Scalar>() * RISTRETTO_BASEPOINT_POINT;

        let verout: Vec<Result<(usize,RistrettoPoint),AAError>> = self.input_proofs.par_iter().map( |(proof, com, signature, intcom)| {
            let mut transcript = Transcript::new(b"input knowledge");
            if proof.verify(&mut transcript, &vec![RISTRETTO_BASEPOINT_POINT], &com.decompress().unwrap()).is_err() {
                return Err(AAError::VerificationInputProof)
            }
            let sigmsg = com.to_bytes().to_vec();

            let mut index =Option::default();
            for (i, (_,itercom)) in signers.iter().enumerate() {
                if itercom.com == intcom.decompress().unwrap()  {
                    index = Some(i);
                }
            }
            let index = match index {
                Some(i) => i,
                None => return Err(AAError::VerificationInputMatching)
            };
            if signature.verify(&mut transcript, &signers[index].0, &signers[index].1, &Bytes::from(sigmsg)).is_err() {
                return Err(AAError::VerificationInputSignature)
            }
            Ok((index,com.decompress().unwrap()))
        }).collect();

        match verout.iter().find(|res| res.is_err()) {
            Some(e) => return Err(e.clone().unwrap_err()),
            _ => {}
        }

        let mut idices = verout.iter().map(|r| r.clone().unwrap().0).collect::<Vec<usize>>();
        idices.sort();
        idices.dedup();
        if idices.len() != signers.len() {
            return Err(AAError::VerificationSigRemaining)
        }

        cum_elem = cum_elem - verout.iter().map(|r| r.clone().unwrap().1).sum::<RistrettoPoint>();

        if cum_elem.is_identity() {
            Ok(())
        } else {
            Err(AAError::VerificationError)
        }
    }

    pub fn publish(self) -> AASig<Algo, Msg> {
        let output_proofs = self.output_proofs.iter().map(|(sigma,com, msg)|(sigma.clone(), com.clone(),msg.publish())).collect();
        AASig::<Algo, Msg> {
            input_proofs: self.input_proofs,
            output_proofs,
            randomness: self.randomness,
        }
    }

    pub fn normalize(&mut self) {
        self.input_proofs.sort_unstable_by(|a,b|a.1.as_bytes().cmp(b.1.as_bytes()));
        self.output_proofs.sort_unstable_by(|a,b|a.1.as_bytes().cmp(b.1.as_bytes()));
    }
}

impl<Algo: TaggedRingSig + Default + Send + Sync + Clone, Msg: AAMsg + Send + Sync> Add for AASig<Algo, Msg> {
    type Output = AASig<Algo, Msg>;
    fn add(self, other: AASig<Algo, Msg>) -> AASig<Algo, Msg> {
        let mut ips = Vec::from(self.input_proofs);
        ips.extend(other.input_proofs);
        let mut ops = Vec::from(self.output_proofs);
        ops.extend(other.output_proofs);
        let mut a = AASig::<Algo, Msg>{
            input_proofs: ips,
            output_proofs: ops,
            randomness: self.randomness+other.randomness
        };
        a.normalize();
        a
    }
}

#[cfg(test)]
mod tests {
    use crate::account::{OTAccount, Account};
    use crate::commitment::TypeCommitment;
    use rand::thread_rng;
    use curve25519_dalek::scalar::Scalar;
    use bytes::Bytes;
    use super::AASig;
    use crate::ringsig;

    fn create_signer() -> (Vec<OTAccount>, usize, TypeCommitment) {
        let mut accounts = vec![OTAccount::default(); 11];
        let acct = Account::new();
        let typ = TypeCommitment::type_gen(&String::from("testtype"));
        accounts[3] = acct.derive_ot(&typ, &Scalar::from(5u64));

        let mut csrng = thread_rng();
        let rand = Scalar::random(&mut csrng);
        let typ_rand = Scalar::random(&mut csrng);
        let com = TypeCommitment::commit(&typ, &Scalar::from(5u64), &typ_rand, &rand);

        (accounts, 3, com)
    }

    #[test]
    fn create_aasig() {
        let msgs = vec![Bytes::from("Huey"), Bytes::from("Dewey"),Bytes::from("Louie")];
        let mut signers = Vec::<(Vec<OTAccount>,usize,TypeCommitment)>::new();

        for _ in 0..6 {
            let (accts,index, com) = create_signer();
            signers.push((accts.clone(), index.clone(), com.clone()) );
        }

        let sigref = signers.iter().map(|(acct,index,com)|(acct, index,com)).collect();
        let asig = AASig::<ringsig::BPRingSig, Bytes>::sign(&sigref, &msgs).expect("broke");

        let sigver = signers.iter().map(|(acct,_,com)|(acct,com)).collect();

        assert!(asig.verify(&sigver, &msgs).is_ok());
    }

    #[test]
    fn merge_sig() {
        let mut msgs = vec![Bytes::from("Huey"), Bytes::from("Dewey"),Bytes::from("Louie")];
        let mut signers = Vec::<(Vec<OTAccount>,usize,TypeCommitment)>::new();
        for _ in 0..2 {
            let (accts,index, com) = create_signer();
            signers.push((accts,index, com));
        }

        let sigref = signers.iter().map(|(acct,index,com)|(acct,index,com)).collect();
        let asig = AASig::<ringsig::BPRingSig, Bytes>::sign(&sigref, &msgs).expect("broke");
        let mut sigver = signers.iter().map(|(acct,_,com)|(acct,com)).collect();
        assert!(asig.clone().verify(&sigver, &msgs).is_ok());

        let msgs2 = vec![Bytes::from("Donald"), Bytes::from("Daisy")];
        let mut signers2 = Vec::<(Vec<OTAccount>, usize,TypeCommitment)>::new();
        for _ in 0..2 {
            let (accts, index, com) = create_signer();
            signers2.push((accts, index, com));
        }

        let sigref2 = signers2.iter().map(|(acct, index,com)|(acct, index,com)).collect();
        let asig2 = AASig::<ringsig::BPRingSig, Bytes>::sign(&sigref2, &msgs2).expect("broke");

        let sigver2 = signers2.iter().map(|(acct,_,com)|(acct,com)).collect();
        assert!(asig2.verify(&sigver2, &msgs2).is_ok());

        sigver.extend(sigver2);
        msgs.extend(msgs2);

        let sigsum = asig+asig2;
        assert!(sigsum.verify(&sigver, &msgs).is_ok());
        msgs[4] = Bytes::from("Scrooge");
        assert!(sigsum.verify(&sigver, &msgs).is_err());
    }

}
