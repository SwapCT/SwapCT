use curve25519_dalek::scalar::Scalar;
use std::collections::HashSet;
use rand::random;
use core::iter;
use merlin::Transcript;
use serde::{Serialize, Deserialize};

use crate::aasig::{AASig, AAMsg};
use crate::ringsig::{BPRingSig, TaggedRingSig};
use crate::account::{OTAccount, Account, Tag};
use crate::commitment::{TypeCommitment, Type};
use crate::seal::SealSig;
use crate::transaction::Transaction;
use std::ops::Add;


#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum OfferError{
    InvalidOffer,
    InvalidCommitment
}

#[derive(Default, Clone, Serialize, Deserialize, Debug)]
pub struct Offer{
    aasig: AASig<BPRingSig, OTAccount>,
    pub(crate) inputs: Vec<(Vec<OTAccount>, TypeCommitment)>,
    pub(crate) outputs: Vec<OTAccount>
}


impl Offer {
    pub fn offer(accts: &Vec<OTAccount>, recipients: &Vec<(&Account, &Type, &Scalar)>, rings: &Vec<Vec<OTAccount>>) -> Offer{
        let mut inp = Vec::<(Vec<OTAccount>, usize, TypeCommitment)>::new();
        for (acct, ring) in accts.iter().zip(rings){
            let mut ring = ring.clone(); // Offer::get_ring(*ring_size);
            let pos = random::<usize>() % ring.len();
            ring[pos] = acct.clone();
            inp.push((ring, pos, acct.com.randomize()));
        }
        let mut outputs = Vec::<OTAccount>::new();
        for (rcpt, typ, amout) in recipients {
            outputs.push(rcpt.derive_ot(typ, amout));
        }

        let sigref:Vec<(&Vec<OTAccount>, &usize, &TypeCommitment)> = inp.iter().map(|(acct,index ,com)|(acct, index,com)).collect();
        let inputs:Vec<(Vec<OTAccount>, TypeCommitment)> = inp.iter().map(|(acct,_ ,com)|(acct.clone(),com.clone())).collect();
        let aasig = AASig::sign(&sigref, &outputs).expect("Not able sign offer");
        Offer{
            inputs,
            outputs,
            aasig
        }
    }

    pub fn verify(&self) -> Result<(),OfferError> {
        for (_,com) in &self.inputs {
            if !com.is_consistent() {
                return Err(OfferError::InvalidCommitment)
            }
        }
        for acct in &self.outputs {
            if !acct.com.is_consistent() {
                return Err(OfferError::InvalidCommitment)
            }
        }
        self.verify_in_tx()
    }

    pub fn verify_in_tx(&self) -> Result<(),OfferError> {
        let sigref:Vec<(&Vec<OTAccount>, &TypeCommitment)> = self.inputs.iter().map(|(acct,com)|(acct,com)).collect();
        match self.aasig.verify(&sigref, &self.outputs) {
            Ok(()) => Ok(()),
            Err(_) => Err(OfferError::InvalidOffer)
        }
    }

    pub fn publish(self) -> Offer {
        let outputs: Vec<OTAccount> =  self.outputs.iter().map(|o| o.publish_offer()).collect();
        let inputs:  Vec<(Vec<OTAccount>, TypeCommitment)> = self.inputs.iter().map(|(acvec,com)| ( acvec.iter().map(|a|a.publish()).collect() ,com.clone())).collect();
        Offer {
            inputs,
            outputs,
            aasig: self.aasig.publish()
        }
    }

    pub fn get_tags(&self) -> HashSet<Tag> {
        let mut tags = HashSet::new();
        for (_,_,setsig,_) in &self.aasig.input_proofs {
            tags.insert(setsig.get_tag());
        }
        tags
    }

    pub fn publish_in_tx(&self) -> Offer {
        let outputs: Vec<OTAccount> =  self.outputs.iter().map(|o| o.publish_offer()).collect();
        let inputs:  Vec<(Vec<OTAccount>, TypeCommitment)> = self.inputs.iter().map(|(acvec,com)| ( acvec.iter().map(|a|a.publish()).collect() ,com.publish())).collect();
        Offer {
            inputs,
            outputs,
            aasig: self.aasig.clone().publish()
        }
    }

    pub fn try_receive(&self, acc: &Account) -> Vec<OTAccount> {
        let mut accts = Vec::<OTAccount>::new();
        for o in &self.outputs {
            match acc.receive_ot(o) {
                Ok(a) => accts.extend(iter::once(a)),
                Err(_) => ()
            }
        }
        accts
    }

    fn get_fee(&self) -> Scalar {
        Scalar::zero()
    }

    pub fn seal(&self, new_type: Option<(OTAccount, String)>) -> Transaction {
        let mut tr = Transcript::new(b"seal tx");
        let fee = self.get_fee();
        let seal = SealSig::sign(&mut tr, &self.inputs.iter().map(|(_,com)|com).collect::<Vec<&TypeCommitment>>().as_slice(), &self.outputs.iter().map(|acc|&acc.com).collect::<Vec<&TypeCommitment>>().as_slice(), &fee).expect("valid seal");
        Transaction{
            offer: self.clone(),
            seal,
            fee,
            new_type,
        }
    }
}

pub fn get_test_ring(n: usize) -> Vec<OTAccount> {
    let accounts = vec![OTAccount::default(); n];
    accounts
}

impl Add for Offer{
    type Output = Offer;

    fn add(self, rhs: Self) -> Self::Output {

        let mut inputs = self.inputs;
        inputs.extend(rhs.inputs);
        let mut outputs = self.outputs;
        outputs.extend(rhs.outputs);
        Offer{
            aasig: self.aasig+rhs.aasig,
            inputs,
            outputs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_offer() {
        let acct = Account::new();
        let typ = TypeCommitment::type_gen(&String::from("mytype"));
        let ota = acct.derive_ot(&typ, &Scalar::from(6u64));

        let off = Offer::offer(&vec![ota], &vec![(&acct, &typ, &Scalar::from(6u64))], &vec![get_test_ring(3)]);
        assert!(off.verify().is_ok());
    }

    #[test]
    fn ser_offer() {
        let acct = Account::new();
        let typ = TypeCommitment::type_gen(&String::from("mytype"));
        let ota = acct.derive_ot(&typ, &Scalar::from(6u64));

        let off = Offer::offer(&vec![ota], &vec![(&acct, &typ, &Scalar::from(6u64))], &vec![get_test_ring(3)]);

        let puboff = off.publish();
        let serialized = serde_json::to_string(&puboff).unwrap();
        //println!("serialized = {}", serialized);
        let deserialized: Offer = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.verify().is_ok());
    }

    #[test]
    fn merge_offer() {
        let acct = Account::new();
        let typ = TypeCommitment::type_gen(&String::from("mytype"));
        let ota = acct.derive_ot(&typ, &Scalar::from(6u64));

        let off = Offer::offer(&vec![ota], &vec![(&acct, &typ, &Scalar::from(6u64))], &vec![get_test_ring(3)]);
        let puboff = off.publish();

        let ota2 = acct.derive_ot(&typ, &Scalar::from(8u64));
        let off2 = Offer::offer(&vec![ota2], &vec![(&acct, &typ, &Scalar::from(6u64))], &vec![get_test_ring(3)]);
        let puboff2 = off2.publish();

        assert!((puboff+puboff2).verify().is_ok());
    }
}
