#![allow(non_snake_case)]
#![allow(dead_code)]
use core::iter;
use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_COMPRESSED};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{VartimeMultiscalarMul, MultiscalarMul};
use merlin::Transcript;
use rayon::prelude::*;
use serde::{Serialize, Deserialize};

use crate::commitment::Commitment;
use crate::constants::{NATIVE, PEDERSEN_H};
use crate::external::inner_product_proof::{InnerProductProof, inner_product};
use crate::external::transcript::TranscriptProtocol;
use crate::external::inner_product_proof;
use crate::external::util::{sub_vec, mul_vec, sum_of_powers, exp_iter, smul_vec, kron_vec, add_vec, inv_vec, VecPoly1};
use crate::account::{OTAccount, Tag};
use bytes::buf::BufExt;


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
    fn get_G(u: &Scalar, v: &Scalar, ring: &[&OTAccount], tags: &[&Tag], outputs: &[&OTAccount], fee: &Scalar, w: &Scalar, P: &Vec<RistrettoPoint>, Gprime: &Vec<RistrettoPoint> ) -> Vec<RistrettoPoint> {

        let T_hat = RistrettoPoint::vartime_multiscalar_mul(
            exp_iter(*v).take(tags.len()).map(|vexp|u*u*vexp),
            tags.iter().map(|tag| tag.decompress().unwrap()));

        let mut innerG = vec![RISTRETTO_BASEPOINT_POINT, PEDERSEN_H(), T_hat];
        for inp in ring{
            innerG.push(inp.pk + u*inp.com.com)
        }

        let mut Gw: Vec<RistrettoPoint> = innerG.par_iter().zip(P).map(|(gP,iP)|w*gP + iP).collect();
        Gw.extend(Gprime);
        Gw
    }

    fn get_constraints(rlen: usize, ilen: usize, olen: usize, u: &Scalar, v: &Scalar, y: &Scalar, z: &Scalar) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Scalar) {

        let m = 3 + rlen + rlen*ilen + olen*64 + 3 * ilen;

        let mut v0 = vec![Scalar::zero(); 3+rlen];
        let yexps: Vec<Scalar> = exp_iter(*y).take(rlen*ilen+64*olen).collect();
        v0.extend(yexps);
        v0.extend(vec![Scalar::zero(); 3*ilen]);

        let mut v1 = vec![Scalar::zero();  3 + rlen + rlen*ilen + olen*64 + 2*ilen];
        let yexps: Vec<Scalar> = exp_iter(*y).take(ilen).collect();
        v1.extend(yexps);

        let mut v2 = vec![Scalar::zero();  3 + rlen + rlen*ilen];
        let yexps: Vec<Scalar> = exp_iter(*y).take(olen).collect();
        let twoexp: Vec<Scalar> = exp_iter(Scalar::from(2u8)).take(64).collect();
        v2.extend( kron_vec(&yexps, &twoexp)  );
        v2.extend(vec![Scalar::zero(); 3*ilen]);

        let mut v3 = vec![Scalar::zero();  3 + rlen ];
        let yexps: Vec<Scalar> = exp_iter(*y).take(ilen+1).collect();
        let yexpstart: Vec<Scalar> = exp_iter(*y).take(ilen).collect();
        v3.extend( kron_vec(&yexpstart, &vec![Scalar::one(); rlen]) );
        v3.extend(vec![Scalar::zero(); 64*olen + 3 * ilen]);
        v3[2] = yexps[yexps.len()-1];

        let mut v4 = vec![Scalar::one()];
        v4.extend(vec![Scalar::zero(); 2+rlen+ rlen*ilen+ 64*olen]);
        let vexps: Vec<Scalar> = exp_iter(*v).take(ilen).map(|vexp| u*vexp).collect();
        v4.extend( vexps);
        v4.extend(vec![Scalar::zero(); 2 * ilen]);

        let mut v5 = vec![Scalar::zero(); 3+rlen+ rlen*ilen+ 64*olen + ilen];
        let uvexps: Vec<Scalar> = exp_iter(*v).take(ilen).map(|vexp| u*vexp).collect();
        v5.extend( uvexps);
        let vexps: Vec<Scalar> = exp_iter(*v).take(ilen).collect();
        v5.extend( vexps);
        v5[1] = Scalar::one();

        let mut v6 = vec![Scalar::zero(); 3];
        let yexps: Vec<Scalar> = exp_iter(*y).take(rlen).collect();
        v6.extend( smul_vec(&(-Scalar::one()),&yexps) );
        let vexp: Vec<Scalar> = exp_iter(*v).take(ilen).collect();
        v6.extend( kron_vec(&vexp, &yexps)  );
        v6.extend(vec![Scalar::zero(); olen*64 + 3 * ilen]);

        let mut v7 = vec![Scalar::zero(); 3 + rlen + rlen*ilen];
        let twoexp: Vec<Scalar> = exp_iter(Scalar::from(2u8)).take(64).collect();
        v7.extend( kron_vec(&vec![Scalar::one(); olen], &twoexp)  );
        v7.extend(vec![-Scalar::one(); ilen]);
        v7.extend(vec![Scalar::zero(); 2 * ilen]);

        let v8 = v0.clone();

        let mut u4 = vec![Scalar::zero(); 3 + rlen + rlen*ilen + olen*64 + 2 * ilen];
        let vexps: Vec<Scalar> = exp_iter(*v).take(ilen).map(|vexp|u*u*vexp).collect();
        u4.extend( vexps  );

        let theta = add_vec( &v0.clone(), &smul_vec(z, &v1));
        let theta_inv = inv_vec(&theta);
        let mut zexp = z*z;
        let mut mu = smul_vec(&zexp, &v2);
        for iterv in vec![v3,v4,v5,v6,v7,v8.clone()] {
            zexp = zexp*z;
            mu = add_vec( &mu, &smul_vec(&zexp, &iterv) )
        }
        let nu = smul_vec(&(z * z * z * z  *  z * z * z * z), &v8);
        let omega = smul_vec(&(z * z * z * z ), &u4);
        let alpha = mul_vec(&theta_inv, &add_vec( &omega, &smul_vec(&(-Scalar::one()),&nu) ) );
        let beta = mul_vec(&theta_inv, &mu);
        let delta = z * sum_of_powers(y, ilen) + z*z*z*sum_of_powers(y, ilen+1)  + inner_product(&alpha, &mu) + inner_product(&vec![Scalar::one(); m], &nu);

        (theta, theta_inv, mu, nu, omega, alpha, beta, delta)

    }

    pub fn sign(transcript: &mut Transcript, ring: &[&OTAccount], tags: &[&Tag], positions: &[usize], outputs: &[&OTAccount], fee: &Scalar) -> Result<SealSig, SealError> {

        let m = 3 + ring.len() + ring.len()*tags.len() + outputs.len()*64 + 3 * tags.len();

        transcript.sealsig_domain_sep(ring.len() as u64, outputs.len() as u64);

        for (_i,acct) in ring.iter().enumerate() {
            transcript.append_point(b"in pk", &acct.pk.compress());
            transcript.append_point(b"in Com", &acct.com.com.compress());
        }
        for (_i,acct) in outputs.iter().enumerate() {
            transcript.append_point(b"out pk", &acct.pk.compress());
            transcript.append_point(b"out Com", &acct.com.com.compress());
        }

        let u = transcript.challenge_scalar(b"u for exponents");
        let v = transcript.challenge_scalar(b"v for exponents");
        let F = transcript.challenge_point(b"F for vec-com");
        let mut P = vec![transcript.challenge_point(b"blinding G"),
                         transcript.challenge_point(b"blinding H"),
                         transcript.challenge_point(b"blinding Tag")];
        for _ in 0..(ring.len()) {
            P.push(transcript.challenge_point(b"blinding Vs"));
        }
        let Gprime: Vec<RistrettoPoint> = (0..(ring.len()*tags.len() + outputs.len()*64 + 3*tags.len())).map(|_| transcript.challenge_point(b"Gprime")).collect();
        let H: Vec<RistrettoPoint> = (0..m).map(|_| transcript.challenge_point(b"H")).collect();

        let G0 = SealSig::get_G(&u, &v, &ring, &tags,&outputs, &fee, &Scalar::zero(), &P, &Gprime );

        let mut csrng = rand::thread_rng();
        let rA = Scalar::random(&mut csrng);

        let inputs: Vec<&OTAccount> = positions.iter().map(|pos| ring[*pos]).collect();

        let mut E = Vec::<Vec<Scalar>>::new();
        let mut Eminus1 = Vec::<Vec<Scalar>>::new();
        let mut ehat = vec![Scalar::zero(); ring.len()];
        let mut B = Vec::<Vec<Scalar>>::new();
        let mut Bminus1 = Vec::<Vec<Scalar>>::new();
        for (acct, vexp) in inputs.iter().zip(exp_iter(v).take(inputs.len())) {
            let mut ei = vec![Scalar::zero(); ring.len()];
            for (i, racct) in ring.iter().enumerate() {
                if racct == acct {
                    ei[i] = Scalar::one();
                    ehat[i] += vexp;
                    break;
                }
            }
            Eminus1.push(sub_vec(&ei, &vec![Scalar::one(); ring.len()]));
            E.push(ei);
        }
        for acct in outputs {
            let bin = acct.com.amount.unwrap().to_binary();
            Bminus1.push(sub_vec(&bin,&vec![Scalar::one(); 64]));
            B.push(bin);
        }

        let xi = -exp_iter(v).take(tags.len()).zip(&inputs).map(|(vexp, acct)| vexp*( u*acct.com.amount.unwrap() + u*u*acct.get_sk().unwrap().invert()  ) ).sum::<Scalar>();
        let eta = -exp_iter(v).take(tags.len()).zip(&inputs).map(|(vexp, acct)| vexp*( u*acct.com.randomness.unwrap() + acct.get_sk().unwrap()  ) ).sum::<Scalar>();

        let mut cr = vec![Scalar::zero(); ring.len()+3];

        let mut cl: Vec<Scalar> = iter::once(xi).chain(iter::once(eta))
            .chain(iter::once(Scalar::one()))
            .chain(ehat.iter().cloned()).collect();
        for (e,em) in E.iter().zip(Eminus1) {
            cl.extend(e);
            cr.extend(em);
        }
        for (b,bm) in B.iter().zip(Bminus1) {
            cl.extend(b);
            cr.extend(bm);
        }

        for inp in &inputs {
            cl.extend(inp.com.amount);
            cr.extend(iter::once(Scalar::zero()));
        }
        for inp in &inputs {
            cl.extend(inp.com.randomness);
            cr.extend(iter::once(Scalar::zero()));
        }
        for inp in &inputs {
            cl.extend(iter::once(inp.get_sk().unwrap()));
            cr.extend(iter::once(inp.get_sk().unwrap().invert()));
        }

        let A = rA*F
            + RistrettoPoint::multiscalar_mul(&cl, &G0)
            + RistrettoPoint::multiscalar_mul(&cr, &H);

        transcript.append_point(b"A commitment", &A.compress());

        let w = transcript.challenge_scalar(b"w");

        let rS = Scalar::random(&mut csrng);
        let Gw = SealSig::get_G(&u, &v, &ring, &tags, &outputs, &fee,&w, &P, &Gprime );
        let sl: Vec<Scalar> = (0..Gw.len()).map(|_| Scalar::random(&mut csrng)).collect();
        let sr: Vec<Scalar> = cr.iter().map(|c| { match *c == Scalar::zero() {
            true => Scalar::zero(),
            false => Scalar::random(&mut csrng)
        }}).collect();

        let S = rS*F + RistrettoPoint::multiscalar_mul(&sl, &Gw) + RistrettoPoint::multiscalar_mul(&sr, &H);

        transcript.append_point(b"S commitment", &S.compress());

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        let (theta, theta_inv, mu, _nu, omega, alpha, beta, delta) = SealSig::get_constraints(ring.len(), inputs.len(), outputs.len(), &u, &v, &y, &z);

        let l_x = VecPoly1(add_vec(&cl,&alpha),sl.clone());
        let r_x = VecPoly1(add_vec(&mul_vec(&theta, &cr),&mu),mul_vec(&theta,&sr));

        let t_x = l_x.inner_product(&r_x);

        let tau_1 = Scalar::random(&mut csrng);
        let tau_2 = Scalar::random(&mut csrng);

        let T1 = t_x.1*RISTRETTO_BASEPOINT_POINT + tau_1*PEDERSEN_H();
        let T2 = t_x.2*RISTRETTO_BASEPOINT_POINT + tau_2*PEDERSEN_H();

        transcript.append_point(b"T1 commitment", &T1.compress());
        transcript.append_point(b"T2 commitment", &T2.compress());

        let x = transcript.challenge_scalar(b"x");

        let outrand: Vec<Scalar> = outputs.iter().map(|acct| acct.com.randomness.unwrap()).collect();
        let outyexp: Vec<Scalar> = exp_iter(y).take(outputs.len()).collect();
        let tau = z*z*inner_product(&outrand, &outyexp) +tau_1*x+tau_2*x*x;
        let r = rA + x*rS;
        let lvec = l_x.eval(x);
        let rvec = r_x.eval(x);
        let t = t_x.eval(x);

        transcript.append_scalar(b"tau", &tau);
        transcript.append_scalar(b"r", &r);
        transcript.append_scalar(b"t", &t);

        // Get a challenge value to combine statements for the IPP
        let ippw = transcript.challenge_scalar(b"ippw");

        let Q = ippw * RISTRETTO_BASEPOINT_POINT;

        let padlen = m.next_power_of_two() -m;

        let mut G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(m).collect();
        G_factors.extend(vec![Scalar::zero(); padlen]);
        let mut H_factors: Vec<Scalar> = theta_inv;
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

    pub fn verify(&self, transcript: &mut Transcript, ring: &[&OTAccount], tags: &[&Tag], outputs: &[&OTAccount], fee: &Scalar) -> Result<(), SealError> {

        let m = 3 + ring.len() + ring.len()*tags.len() + outputs.len()*64 + 3 * tags.len();

        transcript.sealsig_domain_sep(ring.len() as u64, outputs.len() as u64);

        for (_i,acct) in ring.iter().enumerate() {
            transcript.append_point(b"in pk", &acct.pk.compress());
            transcript.append_point(b"in Com", &acct.com.com.compress());
        }
        for (_i,acct) in outputs.iter().enumerate() {
            transcript.append_point(b"out pk", &acct.pk.compress());
            transcript.append_point(b"out Com", &acct.com.com.compress());
        }

        let u = transcript.challenge_scalar(b"u for exponents");
        let v = transcript.challenge_scalar(b"v for exponents");
        let F = transcript.challenge_point(b"F for vec-com");
        let mut P = vec![transcript.challenge_point(b"blinding G"),
                         transcript.challenge_point(b"blinding H"),
                         transcript.challenge_point(b"blinding Tag")];
        for _ in 0..(ring.len()) {
            P.push(transcript.challenge_point(b"blinding Vs"));
        }
        let Gprime: Vec<RistrettoPoint> = (0..(ring.len()*tags.len() + outputs.len()*64 + 3*tags.len())).map(|_| transcript.challenge_point(b"Gprime")).collect();
        let H: Vec<RistrettoPoint> = (0..m).map(|_| transcript.challenge_point(b"H")).collect();

        transcript.append_point(b"A commitment", &self.A);
        let w = transcript.challenge_scalar(b"w");
        transcript.append_point(b"S commitment", &self.S);

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        transcript.append_point(b"T1 commitment", &self.T1);
        transcript.append_point(b"T2 commitment", &self.T2);

        let x = transcript.challenge_scalar(b"x");

        let Gw = SealSig::get_G(&u, &v, &ring, &tags, &outputs, fee, &w, &P, &Gprime );

        transcript.append_scalar(b"tau", &self.tau);
        transcript.append_scalar(b"r", &self.r);
        transcript.append_scalar(b"t", &self.t);

        let (theta, theta_inv, _mu, _nu, _omega, alpha, beta, delta) = SealSig::get_constraints(ring.len(), tags.len(), outputs.len(), &u, &v, &y, &z);

        let ippw = transcript.challenge_scalar(b"ippw");

        let Q = ippw * RISTRETTO_BASEPOINT_POINT;

        let ipPmQ = RistrettoPoint::vartime_multiscalar_mul(iter::once(Scalar::one())
                                                                .chain(iter::once(x))
                                                                .chain(alpha)
                                                                .chain(beta)
                                                                .chain(iter::once(-self.r))
                                                                .chain(iter::once(self.t)),
                                                            iter::once(self.A.decompress().unwrap())
                                                                .chain(iter::once(self.S.decompress().unwrap()))
                                                                .chain(Gw.clone()).chain(H.clone())
                                                                .chain(iter::once(F))
                                                                .chain(iter::once(Q)));


        let padlen = m.next_power_of_two() -m;

        let mut G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(m).collect();
        G_factors.extend(vec![Scalar::zero(); padlen]);
        let mut H_factors: Vec<Scalar> = theta_inv;
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


        let lnd = self.t*RISTRETTO_BASEPOINT_POINT + self.tau*PEDERSEN_H();
        let comsum = exp_iter(y).take(outputs.len()).zip(outputs).map(|(yexp,acct)| (z*z*yexp)*acct.com.com).sum::<RistrettoPoint>();
        let rnd = delta*RISTRETTO_BASEPOINT_POINT + comsum + x*self.T1.decompress().unwrap() + x*x*self.T2.decompress().unwrap();

        if lnd != rnd {
            return Err(SealError::VerificationError)
        }
        assert_eq!(lnd.compress(), rnd.compress(), "second stuff too");

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;
    use crate::transaction::get_test_ring;
    use crate::account::Account;

    #[test]
    fn sealsig_create() {
        let mut prover_transcript = Transcript::new(b"test example");
        let mut poss = Vec::<usize>::new();
        let mut ring = get_test_ring(123);

        let acct = Account::new();
        let accts = vec![acct.derive_ot(&Scalar::from(6u64)), acct.derive_ot(&Scalar::from(10u64))];

        for acct in accts.iter(){
            let mut pos = random::<usize>() % ring.len();
            while poss.contains(&pos) {
                pos = random::<usize>() % ring.len();
            }
            ring[pos] = acct.clone();
            poss.push(pos);
        }
        let mut outputs = Vec::<OTAccount>::new();
        let recipients = vec![(&acct,Scalar::from(6u64)),(&acct,Scalar::from(10u64))];
        for (rcpt, amout) in recipients {
            outputs.push(rcpt.derive_ot(&amout));
        }

        let tagelem: Vec<Tag> = poss.iter().map(|pos| ring[*pos].clone()).map(|acct| acct.get_tag().unwrap().clone()).collect();
        let tags: Vec<&Tag> = tagelem.iter().map(|t|t).collect();

        let inputs:Vec<OTAccount> = ring.iter().map(|acct|(acct.clone())).collect();
        let sigin:Vec<&OTAccount> = ring.iter().map(|acct|acct).collect();
        let sigout:Vec<&OTAccount> = outputs.iter().map(|acct|acct).collect();

        let sigma = SealSig::sign(&mut prover_transcript, &sigin, &tags, &poss, &sigout, &Scalar::zero()).expect("work not");

        let mut verifier_transcript = Transcript::new(b"test example");

        let s = sigma.verify(&mut verifier_transcript, &sigin, &tags, &sigout, &Scalar::zero());
        assert!(s.is_ok());
    }
}
