use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use std::collections::HashSet;
use core::iter;
use serde::{Serialize, Deserialize};

use crate::account::{OTAccount, Account};
use crate::offer::Offer;
use crate::seal::SealSig;


#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum TransactionError{
    InvalidTransaction,
    InvalidOffer
}


#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct Transaction{
    pub(crate) offer: Offer,
    pub(crate) seal: SealSig,
    pub(crate) fee: Scalar,
    pub(crate) new_type: Option<(OTAccount, String)>,
}


impl Transaction {
    pub fn verify(&self) -> Result<(), TransactionError> {
        if self.offer.verify_in_tx().is_err(){
            return Err(TransactionError::InvalidOffer)
        }
        self.verify_seal()
    }

    pub fn verify_seal(&self) -> Result<(), TransactionError> {
        let mut tr = Transcript::new(b"seal tx");
        let b = self.seal.verify(&mut tr,&self.offer.inputs.iter().map(|(_,com)|com).collect(), &self.offer.outputs.iter().map(|acc|&acc.com).collect(), &self.fee);
        match b {
            Ok(()) => Ok(()),
            Err(_) => Err(TransactionError::InvalidTransaction)
        }
    }

    pub fn get_outputs(&self) -> HashSet<OTAccount> {
        let mut it = self.offer.outputs
            .iter().map(|ota|ota.clone()).collect::<HashSet<OTAccount>>();

        if self.new_type.is_some() {
            let elem = self.new_type.clone().unwrap().0;
            it.extend(iter::once(elem));
        }
        it
    }

    pub fn get_new_type(&self) -> Option<String> {
        if self.new_type.is_some() {
            let elem = self.new_type.clone().unwrap().1;
            Some(elem)
        }
        else {
            None
        }

    }

    pub fn add_new_type(&mut self, ota: &OTAccount, name: &String) {
        self.new_type=Some((ota.clone(), name.clone()));
    }

    pub fn try_receive(&self, acc: &Account) -> Vec<OTAccount> {
        let mut accts = Vec::<OTAccount>::new();
        if self.new_type.is_some() {
            match acc.receive_ot(&self.new_type.as_ref().unwrap().0) {
                Ok(a) => accts.extend(iter::once(a)),
                Err(_) => ()
            }

        }
        accts.extend(self.offer.try_receive(acc));
        accts
    }

    pub fn publish(&self) -> Transaction {
        let new_type = match &self.new_type {
            Some((a,s)) => Some((a.publish_offer(), s.clone())),
            None => None
        };
        Transaction{
            offer: self.offer.publish_in_tx(),
            seal: self.seal.clone(),
            fee: self.fee.clone(),
            new_type
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::TypeCommitment;
    use crate::offer::get_test_ring;

    #[test]
    fn create_offer() {

        let acct = Account::new();
        let typ=TypeCommitment::type_gen(&String::from("mytype"));
        let ota = acct.derive_ot(&typ, &Scalar::from(6u64));

        let off = Offer::offer(&vec![ota], &vec![(&acct,&typ,&Scalar::from(6u64))], &vec![get_test_ring(3)]);
        assert!(off.verify().is_ok());
        let tx = off.seal(None);
        assert!(tx.verify().is_ok());
    }

    #[test]
    fn ser_tx() {
        let acct = Account::new();
        let typ=TypeCommitment::type_gen(&String::from("mytype"));
        let ota = acct.derive_ot(&typ, &Scalar::from(6u64));

        let off = Offer::offer(&vec![ota], &vec![(&acct,&typ,&Scalar::from(6u64))], &vec![get_test_ring(3)]);
        let tx = off.seal(None);
        let serialized = serde_json::to_string(&tx.publish()).unwrap();
        assert!(tx.publish().verify().is_ok());

        let deserialized: Transaction = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.verify().is_ok());
    }

    #[test]
    fn ser_cbor() {
        let acct = Account::new();
        let typ=TypeCommitment::type_gen(&String::from("bla"));
        let ota = acct.derive_ot(&typ, &Scalar::from(6u64));


        let off = Offer::offer(&vec![ota], &vec![(&acct,&typ,&Scalar::from(6u64))], &vec![get_test_ring(3)]);
        let tx = off.seal(None);
        let serialized = serde_cbor::to_vec(&tx.publish()).unwrap();
        assert!(tx.publish().verify().is_ok());

        //println!("serialized = {:?}", serialized);
        //println!("serialized = {:?}", serialized.len());

        let deserialized: Transaction = serde_cbor::from_slice(&serialized).unwrap();
        assert!(deserialized.verify().is_ok());
    }
}
