use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use std::hash::{Hash, Hasher};
use sha3::{Digest, Sha3_512};
use rand::{thread_rng, Rng};
use serde::{Serialize, Deserialize};

use crate::commitment::{TypeCommitment, Type};
use crate::lpke::Ciphertext;
use crate::constants::PEDERSEN_H;
use crate::aasig;


#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum AccountError{
    NotOurAccount,
    NotPrivateAccount
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Account{
    sk: Scalar,
    pk: RistrettoPoint,
    ask: Scalar,
    apk: RistrettoPoint,
    vsk: Scalar,
    vpk: RistrettoPoint,
}

pub type Tag = CompressedRistretto;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OTAccount{
    pk: RistrettoPoint,
    pub com: TypeCommitment,
    account: Option<Account>,
    eek: Option<Ciphertext>,
    eck: Option<Ciphertext>,
    ek: Option<Vec<u8>>,
    s: Option<Scalar>,
    sk: Option<Scalar>,
    tag: Option<Tag>,
}

impl Eq for OTAccount {}
impl PartialEq for OTAccount{
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk && self.com.com == other.com.com && self.com.etype.unwrap() == other.com.etype.unwrap()
    }
}

impl Default for OTAccount{
    fn default() -> Self {
        let mut csrng = thread_rng();

        OTAccount {
            pk: RistrettoPoint::random(&mut csrng),
            com: TypeCommitment::default(),
            account: None,
            eek: None,
            eck: None,
            ek: None,
            s: None,
            sk: None,
            tag: None,
        }
    }
}

impl aasig::AAMsg for OTAccount {
    fn to_byte_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(self.pk.compress().as_bytes());
        buf.extend_from_slice(self.com.com.compress().as_bytes());
        buf.extend_from_slice(self.com.etype.unwrap().compress().as_bytes());
        buf
    }

    fn publish(&self) -> OTAccount {
        OTAccount{
            pk: self.pk,
            com: self.com.publish(),
            ..Default::default()
        }
    }
}

impl Account {

    fn tag_k_gen(x: Scalar) -> RistrettoPoint {
        x*PEDERSEN_H()
    }

    fn tag_eval(x: Scalar) -> RistrettoPoint {
        x.invert() * RISTRETTO_BASEPOINT_POINT
    }

    pub fn new() -> Account {
        let mut csprng = thread_rng();
        let sk = Scalar::random(&mut csprng);
        let ask = Scalar::random(&mut csprng);
        let vsk = Scalar::random(&mut csprng);
        Account{
            sk,
            pk: Account::tag_k_gen(sk),
            ask,
            apk: ask*RISTRETTO_BASEPOINT_POINT,
            vsk,
            vpk: vsk*RISTRETTO_BASEPOINT_POINT,
        }
    }

    pub fn derive_ot(&self, typ: &Type, amount: &Scalar) -> OTAccount{
        let mut csprng = thread_rng();
        let randomness = Scalar::random(&mut csprng);
        let type_randomness = Scalar::random(&mut csprng);
        let com = TypeCommitment::commit(typ, amount, &type_randomness, &randomness);
        let contains = (*typ, *amount, type_randomness, randomness);
        let serialized = serde_cbor::to_vec(&contains).unwrap();
        let ek = thread_rng().gen::<[u8; 32]>();
        let mut hasher = Sha3_512::new();
        hasher.update(&self.pk.compress().as_bytes());
        hasher.update(&ek);
        let s = Scalar::from_hash(hasher);
        let pk = self.pk + Account::tag_k_gen(s);

        let mut label = pk.compress().as_bytes().to_vec();
        label.extend( com.com.compress().as_bytes().to_vec());
        let eek = Ciphertext::encrypt(&self.apk, &label, &ek.to_vec());
        let eck = Ciphertext::encrypt(&self.vpk, &label, &serialized);

        OTAccount{
            pk,
            com,
            account: Some(*self),
            ek: Some(ek.to_vec()),
            eek: Some(eek),
            eck: Some(eck),
            ..Default::default()
        }
    }

    pub fn receive_ot(&self, acc: &OTAccount) -> Result<OTAccount, AccountError> {
        let mut label = acc.pk.compress().as_bytes().to_vec();
        label.extend( acc.com.com.compress().as_bytes().to_vec());
        let ek = match acc.eek.as_ref().unwrap().decrypt(&self.ask, &label) {
            Ok(ek) => ek,
            Err(_) => return Err(AccountError::NotOurAccount)
        };
        let ck = match acc.eck.as_ref().unwrap().decrypt(&self.vsk, &label) {
            Ok(ek) => ek,
            Err(_) => return Err(AccountError::NotOurAccount)
        };
        let (typ, amount, type_randomness, randomness): (Type, Scalar, Scalar, Scalar) = serde_cbor::from_slice(&ck).unwrap();

        let mut hasher = Sha3_512::new();
        hasher.update(&self.pk.compress().as_bytes());
        hasher.update(&ek);
        let s = Scalar::from_hash(hasher);
        let sk = self.sk + s;

        if Account::tag_k_gen(sk) != acc.pk {
            return Err(AccountError::NotOurAccount)
        }
        let trcom = TypeCommitment::commit(&typ, &amount, &type_randomness, &randomness);
        if trcom != acc.com {
            return Err(AccountError::NotOurAccount)
        }

        Ok(OTAccount{
            pk: acc.pk,
            com: trcom,
            account: Some(*self),
            ek: Some(ek),
            eek: acc.eek.clone(),
            eck: acc.eck.clone(),
            s: Some(s),
            sk: Some(sk),
            tag: Some(Account::tag_eval(sk).compress()),
        })
    }
}


impl OTAccount {

    pub fn get_s(&self) -> Result<Scalar, AccountError> {
        match &self.ek {
            Some(ek) => {
                let mut hasher = Sha3_512::new();
                hasher.update(&self.account.as_ref().unwrap().pk.compress().as_bytes());
                hasher.update(ek);
                Ok(Scalar::from_hash(hasher))
            }
            None => Err(AccountError::NotPrivateAccount)
        }

    }

    pub fn get_sk(&self) -> Result<Scalar, AccountError> {
        match self.sk {
            Some(sk) => Ok(sk),
            None => match self.s {
                Some(s) => Ok(self.account.as_ref().unwrap().sk + s),
                None => match self.get_s() {
                    Ok(s) => Ok(self.account.as_ref().unwrap().sk + s),
                    Err(e) => Err(e)
                }
            }
        }
    }

    pub fn get_tag(&self) -> Result<Tag, AccountError> {
        match self.tag {
            Some(tag) => Ok(tag),
            None => match self.sk {
                Some(sk) => Ok(Account::tag_eval(sk).compress()),
                None => match self.get_sk() {
                    Ok(sk) => Ok(Account::tag_eval(sk).compress()),
                    Err(e) => Err(e)
                }
            }
        }
    }
    pub fn get_pk(&self) -> RistrettoPoint {
        self.pk
    }

    pub fn publish_offer(&self) -> OTAccount {
        OTAccount{
            pk: self.pk,
            com: self.com,
            eek: self.eek.clone(),
            eck: self.eck.clone(),
            ..Default::default()
        }
    }
}

impl Hash for OTAccount {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pk.compress().hash(state);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_account() {
        let acct = Account::new();
        let typ = RistrettoPoint::default();
        let ota = acct.derive_ot(&typ, &Scalar::from(6u64));

        let rcv = acct.receive_ot(&ota);

        assert_eq!(rcv.unwrap().com.amount.unwrap(),Scalar::from(6u64));

    }
}