#![allow(dead_code)]
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use serde::{Serialize, Deserialize};
use rand::random;

use crate::account::{OTAccount, Account, Tag};
use crate::seal::SealSig;


#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum TransactionError{
    InvalidTransaction,
    InvalidOffer
}


#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct Transaction{
    pub(crate) inputs: Vec<OTAccount>,
    pub(crate) outputs: Vec<OTAccount>,
    pub(crate) tags: Vec<Tag>,
    pub(crate) seal: SealSig,
    pub(crate) fee: Scalar,
}


impl Transaction {

    pub fn spend(accts: &Vec<OTAccount>, recipients: &Vec<(&Account, &Scalar)>, inring: &Vec<OTAccount>) -> Transaction{
        let mut poss = Vec::<usize>::new();
        let mut ring = inring.clone();
        for acct in accts.iter(){
            let mut pos = random::<usize>() % ring.len();
            while poss.contains(&pos) {
                pos = random::<usize>() % ring.len();
            }
            ring[pos] = acct.clone();
            poss.push(pos);
        }
        let mut outputs = Vec::<OTAccount>::new();
        for (rcpt, amout) in recipients {
            outputs.push(rcpt.derive_ot(amout));
        }

        let inputs:Vec<OTAccount> = ring.iter().map(|acct|(acct.clone())).collect();
        let sigin:Vec<&OTAccount> = ring.iter().map(|acct|acct).collect();
        let sigout:Vec<&OTAccount> = outputs.iter().map(|acct|acct).collect();
        let mut tr = Transcript::new(b"seal tx");

        let tagelem: Vec<Tag> = poss.iter().map(|pos| ring[*pos].clone()).map(|acct| acct.get_tag().unwrap().clone()).collect();
        let tags: Vec<&Tag> = tagelem.iter().map(|t|t).collect();

        let seal = SealSig::sign(&mut tr, &sigin, &tags,&poss, &sigout, &Scalar::zero()).expect("Not able sign tx");

        Transaction{
            inputs ,
            outputs,
            tags: tagelem,
            seal,
            fee: Scalar::zero(),
        }
    }

    pub fn verify(&self) -> Result<(), TransactionError> {
        let mut tr = Transcript::new(b"seal tx");
        let inputs: Vec<&OTAccount> = self.inputs.iter().map(|a|a).collect();
        let tags: Vec<&Tag> = self.tags.iter().map(|a|a).collect();
        let outputs: Vec<&OTAccount> = self.outputs.iter().map(|a|a).collect();
        let b = self.seal.verify(&mut tr,&inputs, &tags, &outputs, &self.fee);
        match b {
            Ok(()) => Ok(()),
            Err(_) => Err(TransactionError::InvalidTransaction)
        }
    }

    pub fn try_receive(&self, acc: &Account) -> Vec<OTAccount> {
        let mut accts = Vec::<OTAccount>::new();
        accts
    }

    pub fn bytes(&self) -> Vec<u8> {
        serde_cbor::to_vec(self).unwrap()
    }
}

pub fn get_test_ring(n: usize) -> Vec<OTAccount> {
    let accounts = vec![OTAccount::default(); n];
    accounts
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]
    use super::*;
    use crate::commitment::Commitment;

    #[test]
    fn create_tx() {

        let acct = Account::new();
        let ota1 = acct.derive_ot(&Scalar::from(6u64));
        let ota2 = acct.derive_ot(&Scalar::from(10u64));
        let ota3 = acct.derive_ot(&Scalar::from(5u64));

        let tx = Transaction::spend(&vec![ota1,ota2,ota3], &vec![(&acct,&Scalar::from(6u64)),(&acct,&Scalar::from(3u64)),(&acct,&Scalar::from(12u64))], &get_test_ring(123));
        assert!(tx.verify().is_ok());
    }
}
