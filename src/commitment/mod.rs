use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use rand::thread_rng;
use serde::{Serialize, Deserialize};
use sha3::Sha3_512;
use std::ops::Add;


pub type Type = RistrettoPoint;
pub type EphemeralType = RistrettoPoint;
pub type Commitment = RistrettoPoint;


#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct TypeCommitment{
    pub com: Commitment,
    pub etype: Option<EphemeralType>,
    pub typ: Option<Type>,
    pub amount: Option<Scalar>,
    pub type_randomness: Option<Scalar>,
    pub randomness: Option<Scalar>,
}

impl Default for TypeCommitment{
    fn default() -> Self {
        let mut csrng = thread_rng();
        TypeCommitment{
            com: RistrettoPoint::random(&mut csrng),
            etype: Some(RistrettoPoint::random(&mut csrng)),
            typ: None,
            amount: None,
            type_randomness: None,
            randomness: None
        }
    }
}

impl TypeCommitment {
    pub fn type_gen(name: &String) -> Type {
        RistrettoPoint::hash_from_bytes::<Sha3_512>(name.as_bytes())
    }
    pub fn commit(typ: &Type, amount: &Scalar, type_randomness: &Scalar, randomness: &Scalar) -> TypeCommitment {
        let et = typ + type_randomness*RISTRETTO_BASEPOINT_POINT;
        let mut tc = TypeCommitment::commit_ephemeral(et, *amount, *randomness);
        tc.type_randomness = Some(*type_randomness);
        tc.typ = Some(*typ);
        tc
    }

    pub fn randomize(&self) -> TypeCommitment {
        let mut csrng = thread_rng();
        let randomness = Scalar::random(&mut csrng);
        let type_randomness = Scalar::random(&mut csrng);
        TypeCommitment::commit(&self.typ.unwrap(), &self.amount.unwrap(), &type_randomness, &randomness)
    }

    pub fn commit_ephemeral(et: EphemeralType, amount: Scalar, randomness: Scalar) -> TypeCommitment {
        let com = RistrettoPoint::multiscalar_mul(&[amount,randomness], &[et, RISTRETTO_BASEPOINT_POINT]);
        TypeCommitment{com, etype: Some(et), amount: Some(amount), randomness: Some(randomness), ..Default::default()}
    }
    pub fn publish(&self) -> TypeCommitment {
        TypeCommitment{etype: self.etype, com: self.com, ..Default::default()}
    }

    pub fn is_consistent(&self) -> bool {
        match self.typ {
            Some(typ) => match self.amount {
                Some(amt) => match self.type_randomness {
                    Some(typ_r) => match self.randomness {
                        Some(r) => &TypeCommitment::commit(&typ,&amt,&typ_r, &r) == self,
                        _ => false
                    },
                    _ => false
                },
                _ => false
            },
            _ => false
        }
    }
}


impl Add for TypeCommitment {
    type Output = TypeCommitment;
    fn add(self, other: TypeCommitment) -> TypeCommitment{
        match self.typ {
            None => match self.etype == other.etype {
                true => TypeCommitment{etype: self.etype, com: self.com+other.com,..Default::default()},
                false => TypeCommitment{com: self.com+other.com,..Default::default()}
            }
            Some(typ) => match Some(typ) == other.typ {
                true => match {
                    (self.amount.unwrap() + other.amount.unwrap()) == Scalar::zero()
                } {
                    true => TypeCommitment{
                        com: self.com + other.com,
                        amount: Some(Scalar::zero()),
                        randomness: {Some(self.randomness.unwrap()+other.randomness.unwrap())},
                        ..Default::default()
                    },
                    false => TypeCommitment {
                        com: self.com+other.com,
                        etype: {
                            Some(self.etype.unwrap()+other.etype.unwrap())
                        },
                        amount: {
                            Some(self.amount.unwrap()+other.amount.unwrap())
                        },
                        typ: self.typ,
                        type_randomness: {
                            let sr = self.type_randomness.unwrap();
                            let sa = self.amount.unwrap();
                            let or = other.type_randomness.unwrap();
                            let oa = other.amount.unwrap();
                            let valsum = sa+oa;
                            Some((sr*sa+or*oa) * (valsum.invert()))
                        },
                        randomness: {
                            Some(self.randomness.unwrap()+other.randomness.unwrap())
                        },
                    },
                }
                false => TypeCommitment{com: self.com+other.com,..Default::default()}
            }
        }
    }
}

impl PartialEq for TypeCommitment {
    fn eq(&self, other: &Self) -> bool {
        if self.com != other.com {
            return false;
        }
        match self.etype {
            Some(etype) => match other.etype {
                Some(otype) => if etype != otype {
                    return false;
                }
                None => ()
            }
            None => ()
        }
        true
    }
}


#[cfg(test)]
mod tests{
    use curve25519_dalek::scalar::Scalar;
    use rand::thread_rng;

    use super::TypeCommitment;

    #[test]
    fn homomorphic_commitments() {
        let b = Scalar::from(37264829u64);
        let mut csprng = thread_rng();
        let etr: Scalar = Scalar::random(&mut csprng);
        let r: Scalar = Scalar::random(&mut csprng);

        let value = Scalar::from(5u64);
        let two = Scalar::from(2u64);

        let typ = TypeCommitment::type_gen(&String::from("test"));

        let com = TypeCommitment::commit(&typ,&value,&etr,&r);

        let com2 = TypeCommitment::commit(&typ,&two,&etr,&b);
        let sum_com = TypeCommitment::commit_ephemeral(com2.etype.unwrap(),two+value,r+b);

        assert_eq!((com+com2).com.compress(), sum_com.com.compress());
    }
}