use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::thread_rng;
use serde::{Serialize, Deserialize};
use sha3::Sha3_512;
use std::ops::Add;
use crate::constants::PEDERSEN_H;


#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Commitment{
    pub com: RistrettoPoint,
    pub amount: Option<Scalar>,
    pub randomness: Option<Scalar>,
}

impl Default for Commitment{
    fn default() -> Self {
        let mut csrng = thread_rng();
        Commitment{
            com: RistrettoPoint::random(&mut csrng),
            amount: None,
            randomness: None
        }
    }
}

impl Commitment {
    pub fn commit( amount: &Scalar, randomness: &Scalar) -> Commitment {
        let com = amount*RISTRETTO_BASEPOINT_POINT+randomness*PEDERSEN_H();
        //let com = RistrettoPoint::multiscalar_mul(&[amount,randomness], &[PEDERSEN_H(), RISTRETTO_BASEPOINT_POINT]);
        Commitment{com,  amount: Some(*amount), randomness: Some(*randomness), ..Default::default()}
    }

    pub fn randomize(&self) -> Commitment {
        let mut csrng = thread_rng();
        let randomness = Scalar::random(&mut csrng);
        Commitment::commit(&self.amount.unwrap(), &randomness)
    }

    pub fn publish(&self) -> Commitment {
        Commitment{com: self.com, ..Default::default()}
    }

}


impl Add for Commitment {
    type Output = Commitment;
    fn add(self, other: Commitment) -> Commitment{

        match {
            (self.amount.unwrap() + other.amount.unwrap()) == Scalar::zero()
        } {
            true => Commitment{
                com: self.com + other.com,
                amount: Some(Scalar::zero()),
                randomness: {Some(self.randomness.unwrap()+other.randomness.unwrap())},
                ..Default::default()
            },
            false => Commitment {
                com: self.com+other.com,
                amount: {
                    Some(self.amount.unwrap()+other.amount.unwrap())
                },
                randomness: {
                    Some(self.randomness.unwrap()+other.randomness.unwrap())
                },
            },
        }


    }
}

impl PartialEq for Commitment {
    fn eq(&self, other: &Self) -> bool {
        if self.com != other.com {
            return false;
        }

        true
    }
}


#[cfg(test)]
mod tests{
    use curve25519_dalek::scalar::Scalar;
    use rand::thread_rng;

    use super::Commitment;

    #[test]
    fn homomorphic_commitments() {
        let b = Scalar::from(37264829u64);
        let mut csprng = thread_rng();
        let r: Scalar = Scalar::random(&mut csprng);

        let value = Scalar::from(5u64);
        let two = Scalar::from(2u64);

        let com = Commitment::commit(&value,&r);

        let com2 = Commitment::commit(&two,&b);
        let sum_com = Commitment::commit(&(two+value),&(r+b));

        assert_eq!((com+com2).com.compress(), sum_com.com.compress());
    }
}