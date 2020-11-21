#![allow(non_snake_case)]
use core::iter;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{VartimeMultiscalarMul, MultiscalarMul};
use merlin::Transcript;
use rayon::prelude::*;
use serde::{Serialize, Deserialize};

use crate::commitment::TypeCommitment;
use crate::constants::NATIVE;
use crate::external::inner_product_proof::{InnerProductProof, inner_product};
use crate::external::transcript::TranscriptProtocol;
use crate::external::inner_product_proof;
use crate::external::util::{sub_vec, mul_vec, sum_of_powers, exp_iter, smul_vec, kron_vec, add_vec, inv_vec, VecPoly1};


#[derive(Debug, Default, Hash, Clone, Serialize, Deserialize)]
pub struct SealSig {
    A: CompressedRistretto,
    S: CompressedRistretto,
    T1: CompressedRistretto,
    T2: CompressedRistretto,
    tau: Scalar,
    r: Scalar,
    ipp_proof: InnerProductProof,
    t: Scalar
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum SealError{
    InvalidGeneratorsLength,
    VerificationErrorIPP,
    VerificationError
}

trait BinRep {
    fn to_binary(&self) -> Vec<Scalar>;
}

impl BinRep for Scalar {
    fn to_binary(&self) -> Vec<Scalar> {
        let bytes = self.to_bytes();
        let mut o = Vec::<Scalar>::new();
        for byte in bytes.iter().take(8) {
            for i in 0..8 {
                o.push(Scalar::from(((byte >> i) & 1) as u8))
            }
        }
        o
    }
}

impl SealSig{
    fn get_G(u: &Scalar, v: &Scalar, inputs: &[&TypeCommitment], outputs: &[&TypeCommitment], fee: &Scalar, w: &Scalar, P: &Vec<RistrettoPoint>, Gprime: &Vec<RistrettoPoint> ) -> Vec<RistrettoPoint> {

        let fee_point = fee*NATIVE();

        let V_hat = RistrettoPoint::vartime_multiscalar_mul(
            exp_iter(*v).take(outputs.len()).map(|vexp|-u*vexp)
                .chain(vec![u*u;inputs.len()])
                .chain(exp_iter(*v).take(outputs.len()).map(|vexp|-(u*u) - u*u*u*vexp )),
            outputs.iter().map(|com| com.etype.unwrap())
                .chain(inputs.iter().map(|com|com.com))
                .chain(outputs.iter().map(|com| com.com))
        ) + (-(u*u) * fee_point);

        let mut innerG = vec![RISTRETTO_BASEPOINT_POINT, V_hat];
        for (out,vexp) in outputs.iter().zip(exp_iter(*v).take(outputs.len())){
            innerG.push((u*u*u*vexp)*out.etype.unwrap())
        }
        for inp in inputs{
            innerG.push(u*inp.etype.unwrap())
        }

        let mut Gw: Vec<RistrettoPoint> = innerG.par_iter().zip(P).map(|(gP,iP)|w*gP + iP).collect();
        Gw.extend(Gprime);
        Gw
    }

    fn get_constraints(ilen: usize, olen: usize, _u: &Scalar, v: &Scalar, y: &Scalar, z: &Scalar) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Scalar) {

        let m = 2+ilen+olen+(olen*ilen + olen*64);

        let mut v0 = vec![Scalar::zero(); 2+ilen+olen];
        let yexps: Vec<Scalar> = exp_iter(*y).take(ilen*olen+64*olen).collect();
        v0.extend(yexps);

        let mut v1 = vec![Scalar::zero(); 2+ilen+olen];
        let yexps: Vec<Scalar> = exp_iter(*y).take(olen+1).collect();
        let yexpstart: Vec<Scalar> = exp_iter(*y).take(olen).collect();
        v1.extend( kron_vec(&yexpstart, &vec![Scalar::one(); ilen]) );
        v1.extend(vec![Scalar::zero(); 64*olen]);
        v1[1] = yexps[yexps.len()-1];

        let mut v2 = vec![Scalar::zero(); 2];
        let yexps: Vec<Scalar> = exp_iter(*y).take(olen).collect();
        v2.extend( smul_vec(&(-Scalar::one()),&yexps) );
        v2.extend(vec![Scalar::zero(); ilen+ilen*olen]);
        let twoexp: Vec<Scalar> = exp_iter(Scalar::from(2u8)).take(64).collect();
        v2.extend( kron_vec(&yexps, &twoexp)  );

        let mut v3 = vec![Scalar::zero(); 2+olen];
        let yexps: Vec<Scalar> = exp_iter(*y).take(ilen).collect();
        let vexps: Vec<Scalar> = exp_iter(*v).take(olen).collect();
        v3.extend(smul_vec(&(-Scalar::one()),&yexps));
        v3.extend( kron_vec(&vexps, &yexps ) );
        v3.extend(vec![Scalar::zero(); olen*64]);

        let theta = v0.clone();
        let mu = add_vec(&add_vec( &smul_vec(z, &v1), &smul_vec(&(z * z), &v2) ), &add_vec(&smul_vec(&(z * z * z), &v3), &smul_vec(&(z * z * z * z), &v0)) );
        let nu = smul_vec(&(z * z * z * z), &v0);
        let alpha = mul_vec(&inv_vec(&theta), &smul_vec(&(-Scalar::one()),&nu));
        let beta = mul_vec(&inv_vec(&theta), &mu);
        let delta = z * sum_of_powers(y, olen+1) + inner_product(&alpha, &mu) + inner_product(&vec![Scalar::one(); m], &nu);

        (theta, mu, nu, alpha, beta, delta)
    }

    pub fn sign(transcript: &mut Transcript, inputs: &[&TypeCommitment], outputs: &[&TypeCommitment], fee: &Scalar) -> Result<SealSig, SealError> {

        let m = 2+inputs.len()+outputs.len()+(outputs.len()*inputs.len() + outputs.len()*64);

        transcript.sealsig_domain_sep(inputs.len() as u64, outputs.len() as u64);

        for (_i,com) in inputs.iter().enumerate() {
            transcript.append_point(b"in EType", &com.etype.unwrap().compress());
            transcript.append_point(b"in Com", &com.com.compress());
        }
        for (_i,com) in outputs.iter().enumerate() {
            transcript.append_point(b"out EType", &com.etype.unwrap().compress());
            transcript.append_point(b"out Com", &com.com.compress());
        }

        let u = transcript.challenge_scalar(b"u for exponents");
        let v = transcript.challenge_scalar(b"v for exponents");
        let F = transcript.challenge_point(b"F for vec-com");
        let mut P = vec![transcript.challenge_point(b"blinding G"),
                                         transcript.challenge_point(b"blinding V")];
        for _ in 0..(inputs.len()+outputs.len()) {
            P.push(transcript.challenge_point(b"blinding Ps"));
        }
        let Gprime = vec![transcript.challenge_point(b"Gprime"); outputs.len()*inputs.len() + outputs.len()*64];
        let H: Vec<RistrettoPoint> = (0..m).map(|_| transcript.challenge_point(b"H")).collect();

        let G0 = SealSig::get_G(&u, &v, &inputs,&outputs, &fee, &Scalar::zero(), &P, &Gprime );

        let mut csrng = rand::thread_rng();
        let rA = Scalar::random(&mut csrng);

        let mut xi = Scalar::zero();

        let mut E = Vec::<Vec<Scalar>>::new();
        let mut Eminus1 = Vec::<Vec<Scalar>>::new();
        let mut ehat = vec![Scalar::zero(); inputs.len()];
        let mut B = Vec::<Vec<Scalar>>::new();
        let mut Bminus1 = Vec::<Vec<Scalar>>::new();
        for (out, vexp) in outputs.iter().zip(exp_iter(v).take(outputs.len())) {
            let mut ei = vec![Scalar::zero(); inputs.len()];
            for (i, inp) in inputs.iter().enumerate() {
                if inp.typ == out.typ {
                    ei[i] = Scalar::one();
                    ehat[i] += vexp;
                    xi += -u * vexp  * ( - out.type_randomness.unwrap() + inp.type_randomness.unwrap());
                    break;
                }
            }
            Eminus1.push(sub_vec(&ei,&vec![Scalar::one(); inputs.len()]));
            E.push(ei);
            xi += u*u*u * (vexp*out.randomness.unwrap());
            xi += u*u * (out.randomness.unwrap()+out.type_randomness.unwrap()*out.amount.unwrap());
            let bin = out.amount.unwrap().to_binary();
            Bminus1.push(sub_vec(&bin,&vec![Scalar::one(); 64]));
            B.push(bin);
        }

        xi += inputs.iter().map(|out|u*u*( -out.randomness.unwrap() -out.type_randomness.unwrap()*out.amount.unwrap()  ) ).sum::<Scalar>();

        let mut cr = vec![Scalar::zero(); inputs.len()+outputs.len()+2];

        let mut cl: Vec<Scalar> = iter::once(xi).chain(iter::once(Scalar::one()))
            .chain(outputs.iter().map(|out|out.amount.unwrap()))
            .chain(ehat.iter().cloned()).collect();
        for (e,em) in E.iter().zip(Eminus1) {
            cl.extend(e);
            cr.extend(em);
        }
        for (b,bm) in B.iter().zip(Bminus1) {
            cl.extend(b);
            cr.extend(bm);
        }

        let A = rA*F
            + RistrettoPoint::multiscalar_mul(&cl, &G0)
            + RistrettoPoint::multiscalar_mul(&cr, &H);

        transcript.append_point(b"A commitment", &A.compress());

        let w = transcript.challenge_scalar(b"w");

        let rS = Scalar::random(&mut csrng);
        let Gw = SealSig::get_G(&u, &v, &inputs, &outputs, &fee,&w, &P, &Gprime );
        let sl: Vec<Scalar> = (0..Gw.len()).map(|_| Scalar::random(&mut csrng)).collect();
        let sr: Vec<Scalar> = cr.iter().map(|c| { match *c == Scalar::zero() {
            true => Scalar::zero(),
            false => Scalar::random(&mut csrng)
        }}).collect();

        let S = rS*F + RistrettoPoint::multiscalar_mul(&sl, &Gw) + RistrettoPoint::multiscalar_mul(&sr, &H);

        transcript.append_point(b"S commitment", &S.compress());

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        let (theta, mu, _nu, alpha, _beta, _delta) = SealSig::get_constraints(inputs.len(), outputs.len(), &u, &v, &y, &z);

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

        let padlen = m.next_power_of_two() -m;

        let mut G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(m).collect();
        G_factors.extend(vec![Scalar::zero(); padlen]);
        let mut H_factors: Vec<Scalar> = inv_vec(&theta);
        H_factors.extend(vec![Scalar::zero(); padlen]);

        let mut lpad = lvec.clone();
        let mut rpad = rvec.clone();
        lpad.extend(vec![Scalar::zero(); padlen]);
        rpad.extend(vec![Scalar::zero(); padlen]);

        let mut Gpad = Gw;
        let mut Hpad = H;
        for _ in 0..padlen {
            Gpad.push(transcript.challenge_point(b"padding G"));
            Hpad.push(transcript.challenge_point(b"padding H"));
        }

        let ipp_proof = inner_product_proof::InnerProductProof::create(
            transcript,
            &Q,
            &G_factors,
            &H_factors,
            Gpad,
            Hpad,
            lpad.clone(),
            rpad.clone(),
        );

        Ok(SealSig{
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

    pub fn verify(&self, transcript: &mut Transcript, inputs: &Vec<&TypeCommitment>, outputs: &Vec<&TypeCommitment>, fee: &Scalar) -> Result<(), SealError> {
        let m = 2+inputs.len()+outputs.len()+(outputs.len()*inputs.len() + outputs.len()*64);

        transcript.sealsig_domain_sep(inputs.len() as u64, outputs.len() as u64);

        for (_,com) in inputs.iter().enumerate() {
            transcript.append_point(b"in EType", &com.etype.unwrap().compress());
            transcript.append_point(b"in Com", &com.com.compress());
        }
        for (_,com) in outputs.iter().enumerate() {
            transcript.append_point(b"out EType", &com.etype.unwrap().compress());
            transcript.append_point(b"out Com", &com.com.compress());
        }

        let u = transcript.challenge_scalar(b"u for exponents");
        let v = transcript.challenge_scalar(b"v for exponents");
        let F = transcript.challenge_point(b"F for vec-com");
        let mut P = vec![transcript.challenge_point(b"blinding G"),
                                         transcript.challenge_point(b"blinding V")];
        for _ in 0..(inputs.len()+outputs.len()) {
            P.push(transcript.challenge_point(b"blinding Ps"));
        }
        let Gprime = vec![transcript.challenge_point(b"Gprime"); outputs.len()*inputs.len() + outputs.len()*64];
        let H: Vec<RistrettoPoint> = (0..m).map(|_| transcript.challenge_point(b"H")).collect();

        transcript.append_point(b"A commitment", &self.A);
        let w = transcript.challenge_scalar(b"w");
        transcript.append_point(b"S commitment", &self.S);

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        transcript.append_point(b"T1 commitment", &self.T1);
        transcript.append_point(b"T2 commitment", &self.T2);

        let x = transcript.challenge_scalar(b"x");

        let Gw = SealSig::get_G(&u, &v, &inputs, &outputs, fee, &w, &P, &Gprime );

        transcript.append_scalar(b"tau", &self.tau);
        transcript.append_scalar(b"r", &self.r);
        transcript.append_scalar(b"t", &self.t);

        let (theta, _mu, _nu, alpha, beta, delta) = SealSig::get_constraints(inputs.len(), outputs.len(), &u, &v, &y, &z);

        let rhs = self.A.decompress().unwrap() + x*self.S.decompress().unwrap() + RistrettoPoint::multiscalar_mul(&alpha, &Gw) + RistrettoPoint::multiscalar_mul(&beta, &H);

        let ippw = transcript.challenge_scalar(b"ippw");

        let Q = ippw * RISTRETTO_BASEPOINT_POINT;

        let ipPmQ = rhs - (self.r*F) + self.t*Q;

        let padlen = m.next_power_of_two() -m;

        let mut G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(m).collect();
        G_factors.extend(vec![Scalar::zero(); padlen]);
        let mut H_factors: Vec<Scalar> = inv_vec(&theta);
        H_factors.extend(vec![Scalar::zero(); padlen]);

        let mut Gpad = Gw.clone();
        let mut Hpad = H.clone();
        for _ in 0..padlen {
            Gpad.push(transcript.challenge_point(b"padding G"));
            Hpad.push(transcript.challenge_point(b"padding H"));
        }

        if self.ipp_proof.verify(Gpad.len(), transcript, G_factors, H_factors, &ipPmQ, &Q, &Gpad, &Hpad).is_err() {
            return Err(SealError::VerificationErrorIPP)
        }

        let lnd = self.t*RISTRETTO_BASEPOINT_POINT + self.tau*F;
        let rnd = delta*RISTRETTO_BASEPOINT_POINT + x*self.T1.decompress().unwrap() + x*x*self.T2.decompress().unwrap();

        if lnd != rnd {
            return Err(SealError::VerificationError)
        }
        //assert_eq!(lnd.compress(), rnd.compress(), "second stuff too");

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealsig_create() {
        let mut prover_transcript = Transcript::new(b"test example");

        let t1 = TypeCommitment::type_gen(&String::from("first"));
        let t2 = TypeCommitment::type_gen(&String::from("second"));

        let inputs = vec![TypeCommitment::commit(&t1,&Scalar::from(5u64), &Scalar::from(4u8), &Scalar::from(10u8)).randomize(),
                          TypeCommitment::commit(&t2,&Scalar::from(7u64), &Scalar::from(4u8), &Scalar::from(10u8)).randomize(),
                          TypeCommitment::commit(&t2,&Scalar::from(3u64), &Scalar::from(4u8), &Scalar::from(10u8)).randomize(),
                          TypeCommitment::commit(&NATIVE(),&Scalar::from(1u64), &Scalar::from(4u8), &Scalar::from(10u8)).randomize()];

        let outputs = vec![TypeCommitment::commit(&t1,&Scalar::from(5u64), &Scalar::from(4u8), &Scalar::from(10u8)).randomize(),
                           TypeCommitment::commit(&t2,&Scalar::from(8u64), &Scalar::from(4u8), &Scalar::from(10u8)).randomize(),
                           TypeCommitment::commit(&t2,&Scalar::from(2u64), &Scalar::from(4u8), &Scalar::from(10u8)).randomize()];

        let outputs: Vec<&TypeCommitment> = outputs.iter().map(|x|x).collect();
        let inputs: Vec<&TypeCommitment> = inputs.iter().map(|x|x).collect();
        let sigma = SealSig::sign(&mut prover_transcript, &inputs, &outputs, &Scalar::one()).expect("work not");

        let mut verifier_transcript = Transcript::new(b"test example");

        let s = sigma.verify(&mut verifier_transcript, &inputs, &outputs, &Scalar::one());
        assert!(s.is_ok());
    }
}