#![allow(non_snake_case)]
use merlin::Transcript;
use bytes::Bytes;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};
use core::iter;
use serde::{Serialize, Deserialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rayon::prelude::*;

use crate::account::{OTAccount, Tag};
use crate::commitment::TypeCommitment;
use crate::external::inner_product_proof::{InnerProductProof, inner_product};
use crate::constants::PEDERSEN_H;
use crate::external::util::{exp_iter, add_vec, smul_vec, inv_vec, mul_vec, sum_of_powers, sub_vec, VecPoly1};
use crate::external::transcript::TranscriptProtocol;
use crate::external::inner_product_proof;


#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum RingError{
    VerificationError
}

pub trait TaggedRingSig: Sized{
    fn sign(transcript: &mut Transcript, accounts: &Vec<OTAccount>, index: usize, com: &TypeCommitment, msg: &Bytes) -> Result<Self, RingError>;
    fn verify(&self, transcript: &mut Transcript, accounts: &Vec<OTAccount>, com: &TypeCommitment, msg: &Bytes) -> Result<(), RingError>;
    fn get_tag(&self) -> Tag;
}

#[derive(Debug, Default, Hash, Clone, Serialize, Deserialize)]
pub struct BPRingSig{
    tag: Tag,
    A: CompressedRistretto,
    S: CompressedRistretto,
    T1: CompressedRistretto,
    T2: CompressedRistretto,
    tau: Scalar,
    r: Scalar,
    ipp_proof: InnerProductProof,
    t: Scalar
}

impl BPRingSig {
    fn get_G(u: &Scalar, tag: &Tag,accounts: &[OTAccount], com: &TypeCommitment, w: &Scalar, P: &Vec<RistrettoPoint>, Gprime: &Vec<RistrettoPoint>) -> Vec<RistrettoPoint>{
        let uu = u*u;
        let rightG: Vec<RistrettoPoint> = accounts.par_iter().map(|acct| {
            RistrettoPoint::multiscalar_mul(vec![&Scalar::one(), &u, &uu],
                                            vec![acct.get_pk(),acct.com.etype.unwrap()- com.etype.unwrap(),
                                                 acct.com.com-com.com] ) }).collect();
        let innerG: Vec<RistrettoPoint> = iter::once(RISTRETTO_BASEPOINT_POINT)
            .chain(iter::once(PEDERSEN_H())).chain(iter::once((u*u*u)*tag.decompress().unwrap()))
            .chain(rightG.iter().cloned()).collect();

        let mut Gw: Vec<RistrettoPoint> = innerG.par_iter().zip(P).map(|(gP,iP)|w*gP + iP).collect();
        Gw.extend(Gprime);
        Gw
    }

    fn get_constraints(len: usize, u: &Scalar, y: &Scalar, z: &Scalar) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Scalar) {

        let mut v0 = vec![Scalar::zero(), Scalar::zero(), Scalar::zero()];
        let yexps: Vec<Scalar> = exp_iter(*y).take(len).collect();
        v0.extend(yexps);
        v0.push(Scalar::zero());
        v0.push(Scalar::zero());

        let mut v1 = vec![Scalar::zero()];
        v1.push(*y);
        let remv1: Vec<Scalar> = (0..len+3).map(|_|Scalar::zero()).collect();
        v1.extend(remv1);

        let mut v2 = vec![Scalar::zero(),Scalar::zero()];
        v2.push(y*y);
        let remv2: Vec<Scalar> = vec![*y; len];
        v2.extend(remv2);
        v2.push(Scalar::zero());
        v2.push(Scalar::zero());

        let mut v3 = vec![Scalar::one()];
        let remv3: Vec<Scalar> = (0..len+2).map(|_|Scalar::zero()).collect();
        v3.extend(remv3);
        v3.push(*u);
        v3.push(u*u);

        let mut u3 = vec![Scalar::zero()];
        u3.push(-u*u*u);
        let remu3: Vec<Scalar> = (0..len+3).map(|_|Scalar::zero()).collect();
        u3.extend(remu3);

        let theta = add_vec(&v0,&smul_vec(&z,&v1));
        let inv_theta = inv_vec(&theta);
        let mu = add_vec( &add_vec(&smul_vec(&(z*z),&v2) , &smul_vec(&(z*z*z),&v3) ),  &smul_vec(&(z*z*z*z),&v0) );
        let nu = smul_vec(&(z*z*z*z),&v0);
        let omega = smul_vec(&(z*z*z),&u3);
        let alpha = mul_vec(&inv_theta, &sub_vec(&omega, &nu));
        let beta = mul_vec(&inv_theta, &mu);
        let delta = z*y+z*z*(y+y*y)+inner_product(&alpha, &mu)+(z*z*z*z)*sum_of_powers(y, len);

        (theta, inv_theta, mu, nu, omega, alpha, beta, delta)
    }
}

impl TaggedRingSig for BPRingSig {

    fn get_tag(&self) -> Tag {
        self.tag
    }
    fn sign(transcript: &mut Transcript, accounts: &Vec<OTAccount>, index: usize, com: &TypeCommitment, msg: &Bytes) -> Result<BPRingSig, RingError> {
        assert!( (accounts.len()+5).is_power_of_two() );

        transcript.ringsig_domain_sep(accounts.len() as u64);

        transcript.append_message(b"siging-message",&msg);

        for (_, acct) in accounts.iter().enumerate() {
            transcript.append_point(b"Account", &acct.get_pk().compress());
            transcript.append_point(b"EType", &acct.com.etype.unwrap().compress());
            transcript.append_point(b"Com", &acct.com.com.compress());
        }

        transcript.append_point(b"EQ-EType", &com.etype.unwrap().compress());
        transcript.append_point(b"EQ-Com", &com.com.compress());

        let tag = accounts[index].get_tag().unwrap();

        let u = transcript.challenge_scalar(b"u for exponents");
        let F = transcript.challenge_point(b"F for vec-com");
        let mut P = vec![transcript.challenge_point(b"blinding G"), transcript.challenge_point(b"blinding H"), transcript.challenge_point(b"blinding T")];
        let dynP: Vec<RistrettoPoint> = (0..accounts.len()).map(|_| transcript.challenge_point(b"blinding Ps")).collect();
        P.extend(dynP);
        let Gprime = vec![transcript.challenge_point(b"Gtype"), transcript.challenge_point(b"Gcom")];
        let H: Vec<RistrettoPoint> = (0..accounts.len()+5).map(|_| transcript.challenge_point(b"blinding Ps")).collect();

        let G0 = BPRingSig::get_G(&u, &tag,accounts, com, &Scalar::zero(), &P, &Gprime );

        let mut csrng = rand::thread_rng();
        let rA = Scalar::random(&mut csrng);

        let e: Vec<Scalar> = (0..accounts.len()).map(|i| { match i==index {
            true => Scalar::one(),
            false => Scalar::zero()
        }}).collect();
        let eminus1: Vec<Scalar> = (0..accounts.len()).map(|i| { match i==index {
            true => Scalar::zero(),
            false => -Scalar::one()
        }}).collect();

        let rt = accounts[index].com.type_randomness.unwrap() - com.type_randomness.unwrap();
        let rv =accounts[index].com.type_randomness.unwrap()*accounts[index].com.amount.unwrap() + accounts[index].com.randomness.unwrap() - com.type_randomness.unwrap()*com.amount.unwrap() - com.randomness.unwrap();

        let xi = -( u*u*u*accounts[index].get_sk().unwrap().invert() + u*rt + u*u*rv);

        let mut cl = vec![xi,-accounts[index].get_sk().unwrap(),Scalar::one()];
        cl.extend(e);
        cl.push(rt);
        cl.push(rv);

        let mut cr = vec![Scalar::zero(),-accounts[index].get_sk().unwrap().invert(),Scalar::zero()];
        cr.extend(eminus1);
        cr.push(Scalar::zero());
        cr.push(Scalar::zero());

        let A = rA*F + RistrettoPoint::multiscalar_mul(&cl, &G0) + RistrettoPoint::multiscalar_mul(&cr, &H);

        transcript.append_point(b"A commitment", &A.compress());

        let w = transcript.challenge_scalar(b"w");

        let rS = Scalar::random(&mut csrng);
        let Gw = BPRingSig::get_G(&u, &tag,accounts, com, &w, &P, &Gprime );
        let sl: Vec<Scalar> = (0..Gw.len()).map(|_| Scalar::random(&mut csrng)).collect();
        let sr: Vec<Scalar> = cr.iter().map(|c| { match *c == Scalar::zero() {
            true => Scalar::zero(),
            false => Scalar::random(&mut csrng)
        }}).collect();

        let S = rS*F + RistrettoPoint::multiscalar_mul(&sl, &Gw) + RistrettoPoint::multiscalar_mul(&sr, &H);

        transcript.append_point(b"S commitment", &S.compress());

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        let (theta, inv_theta, mu, _nu, _omega, alpha, _beta, _delta) = BPRingSig::get_constraints(accounts.len(), &u, &y, &z);

        let l_x = VecPoly1(add_vec(&cl,&alpha),sl.clone());
        let r_x = VecPoly1(add_vec(&mul_vec(&theta, &cr),&mu),mul_vec(&theta,&sr));

        let t_x = l_x.inner_product(&r_x);

        let tau_1 = Scalar::random(&mut csrng);
        let tau_2 = Scalar::random(&mut csrng);

        let T1 = t_x.1*RISTRETTO_BASEPOINT_POINT + tau_1*F;
        let T2 = t_x.2*RISTRETTO_BASEPOINT_POINT + tau_2*F;

        transcript.append_point(b"T1 commitment", &T1.compress());
        transcript.append_point(b"T2 commitment", &T2.compress());

        let x = transcript.challenge_scalar(b"x");

        let tau = tau_1*x+tau_2*x*x;
        let r = rA + x*rS;
        let lvec = l_x.eval(x);
        let rvec = r_x.eval(x);
        let t = t_x.eval(x);

        transcript.append_scalar(b"tau", &tau);
        transcript.append_scalar(b"r", &r);
        transcript.append_scalar(b"t", &t);

        /*let lhs = r*F + RistrettoPoint::multiscalar_mul(&lvec, &Gw) + RistrettoPoint::multiscalar_mul(&mul_vec(&inv_vec(&theta), &rvec), &H);
        let rhs = A + x*S + RistrettoPoint::multiscalar_mul(&alpha, &Gw) + RistrettoPoint::multiscalar_mul(&beta, &H);
        assert_eq!(lhs.compress(), rhs.compress(), "verification eq should hold");

        assert_eq!(t_x.0, delta, "offset should be delta");
        assert_eq!(t, t_x.0 + x*t_x.1 + x*x*t_x.2, "polynomial holds");
        */

        // Get a challenge value to combine statements for the IPP
        let ippw = transcript.challenge_scalar(b"ippw");
        let Q = ippw * RISTRETTO_BASEPOINT_POINT;

        let G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(Gw.len()).collect();
        let H_factors: Vec<Scalar> = inv_theta;

        let ipp_proof = inner_product_proof::InnerProductProof::create(
            transcript,
            &Q,
            &G_factors,
            &H_factors,
            Gw.clone(),
            H.clone(),
            lvec.clone(),
            rvec.clone(),
        );

        Ok(BPRingSig{
            tag,
            A: A.compress(),
            S: S.compress(),
            T1: T1.compress(),
            T2: T2.compress(),
            tau,
            r,
            ipp_proof,
            t,
        })
    }

    fn verify(&self, transcript: &mut Transcript, accounts: &Vec<OTAccount>, com: &TypeCommitment, msg: &Bytes) -> Result<(), RingError> {
        transcript.ringsig_domain_sep(accounts.len() as u64);

        transcript.append_message(b"siging-message",&msg);

        for acct in accounts {
            transcript.append_point(b"Account", &acct.get_pk().compress());
            transcript.append_point(b"EType", &acct.com.etype.unwrap().compress());
            transcript.append_point(b"Com", &acct.com.com.compress());
        }
        transcript.append_point(b"EQ-EType", &com.etype.unwrap().compress());
        transcript.append_point(b"EQ-Com", &com.com.compress());

        let u = transcript.challenge_scalar(b"u for exponents");
        let F = transcript.challenge_point(b"F for vec-com");
        let mut P = vec![transcript.challenge_point(b"blinding G"), transcript.challenge_point(b"blinding H"), transcript.challenge_point(b"blinding T")];
        let dynP: Vec<RistrettoPoint> = (0..accounts.len()).map(|_| transcript.challenge_point(b"blinding Ps")).collect();
        P.extend(dynP);
        let Gprime = vec![transcript.challenge_point(b"Gtype"), transcript.challenge_point(b"Gcom")];
        let H: Vec<RistrettoPoint> = (0..accounts.len()+5).map(|_| transcript.challenge_point(b"blinding Ps")).collect();

        transcript.append_point(b"A commitment", &self.A);

        let w = transcript.challenge_scalar(b"w");

        transcript.append_point(b"S commitment", &self.S);

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        transcript.append_point(b"T1 commitment", &self.T1);
        transcript.append_point(b"T2 commitment", &self.T2);

        let x = transcript.challenge_scalar(b"x");

        let Gw = BPRingSig::get_G(&u, &self.tag,accounts, com, &w, &P, &Gprime );

        transcript.append_scalar(b"tau", &self.tau);
        transcript.append_scalar(b"r", &self.r);
        transcript.append_scalar(b"t", &self.t);

        let (theta,inv_theta, _mu, _nu, _omega, alpha, beta, delta) = BPRingSig::get_constraints(accounts.len(), &u, &y, &z);

        let ippw = transcript.challenge_scalar(b"ippw");
        let Q = ippw * RISTRETTO_BASEPOINT_POINT;

        let ipPmQ = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(&Scalar::one())
                .chain(iter::once(&x))
                .chain(iter::once(&-self.r))
                .chain(iter::once(&self.t))
                .chain(alpha.iter())
                .chain(beta.iter()),
            iter::once(&self.A.decompress().unwrap())
                .chain(iter::once(&self.S.decompress().unwrap()))
                .chain(iter::once(&F))
                .chain(iter::once(&Q))
                .chain(Gw.iter())
                .chain(H.iter()));

        let G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(Gw.len()).collect();
        let H_factors: Vec<Scalar> = inv_theta;

        if self.ipp_proof.verify(Gw.len(), transcript, G_factors, H_factors, &ipPmQ, &Q, &Gw, &H).is_err() {
            return Err(RingError::VerificationError)
        }

        let lnd = self.t*RISTRETTO_BASEPOINT_POINT + self.tau*F;
        let rnd = delta*RISTRETTO_BASEPOINT_POINT + x*self.T1.decompress().unwrap() + x*x*self.T2.decompress().unwrap();

        if lnd != rnd {
            return Err(RingError::VerificationError)
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use crate::account::Account;
    use crate::aasig::AAMsg;

    #[test]
    fn bpsetsig_create() {
        let mut prover_transcript = Transcript::new(b"test example");

        let mut accounts = vec![OTAccount::default(); 11];
        let acct = Account::new();
        let typ = TypeCommitment::type_gen(&String::from("testtype"));
        accounts[3] = acct.derive_ot(&typ, &Scalar::from(5u64));

        let mut csrng = thread_rng();
        let rand = Scalar::random(&mut csrng);
        let typ_rand = Scalar::random(&mut csrng);
        let com = TypeCommitment::commit(&typ, &Scalar::from(5u64), &typ_rand, &rand);
        let msg = Bytes::from("nonsense");

        let sigma = BPRingSig::sign(&mut prover_transcript, &accounts, 3, &com, &msg).expect("work not");

        accounts[3] = accounts[3].publish();

        let mut verifier_transcript = Transcript::new(b"test example");

        let s = sigma.verify(&mut verifier_transcript, &accounts, &com, &msg);
        assert!(s.is_ok());
    }
}