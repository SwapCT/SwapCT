#![allow(non_snake_case)]
use serde::{Serialize, Deserialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::{thread_rng, Rng};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use bytes::buf::BufExt;
use bytes::Buf;
use aes_gcm_siv::aead::generic_array::GenericArray;
use sha3::{Sha3_512, Digest};
use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::aead::{Aead, NewAead};
use hmac::{Hmac, Mac, NewMac};


#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(Error))]
pub enum LpkeError{
    DecryptionError
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Ciphertext {
    R: RistrettoPoint,
    e: Vec<u8>,
    nonce: [u8; 12],
    mac: Vec<u8>,
}

impl Ciphertext{
    pub fn encrypt(pk: &RistrettoPoint, label: &[u8], message: &[u8]) -> Ciphertext {
        let mut csrng = thread_rng();
        let r = Scalar::random(&mut csrng);
        let R = r*RISTRETTO_BASEPOINT_POINT;
        let P = r*pk;

        let mut hasher = Sha3_512::new();
        hasher.update(P.compress().as_bytes());
        hasher.update(label);

        let hash = hasher.finalize();
        let enckey = hash.take(32).to_bytes();
        let macvec = hash.as_slice().to_vec();
        let mackey =  macvec.iter().skip(32).collect::<Vec<&u8>>() ;

        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&enckey));
        let nonce = thread_rng().gen::<[u8; 12]>();
        let nce = GenericArray::from_slice(&nonce);

        let e = cipher.encrypt(&nce, message)
            .expect("encryption failure!");  // NOTE: handle this error to avoid panics!

        let mm = mackey.iter().map(|e| *e.clone()).collect::<Vec<u8>>();
        let mut mac = Hmac::<Sha3_512>::new_varkey(mm.as_slice()).expect("HMAC can take key of any size");

        mac.update(e.as_slice());

        let result = mac.finalize().into_bytes().to_vec();

        Ciphertext{
            R,
            e,
            nonce,
            mac: result
        }
    }

    pub fn decrypt(&self, sk: &Scalar, label: &[u8]) -> Result<Vec<u8>,LpkeError>{
        let P = sk*self.R;
        let mut hasher = Sha3_512::new();
        hasher.update(P.compress().as_bytes());
        hasher.update(label);

        let hash = hasher.finalize();
        let enckey = hash.take(32).to_bytes();
        let macvec = hash.as_slice().to_vec();
        let mackey =  macvec.iter().skip(32).collect::<Vec<&u8>>() ;

        let mm = mackey.iter().map(|e| *e.clone()).collect::<Vec<u8>>();
        let mut mac = Hmac::<Sha3_512>::new_varkey(mm.as_slice()).expect("HMAC can take key of any size");

        mac.update(self.e.as_slice());

        match mac.verify(&self.mac) {
            Ok(a) => a,
            Err(_) => return Err(LpkeError::DecryptionError)
        }

        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&enckey));

        let nce = GenericArray::from_slice(&self.nonce);
        let plaintext = cipher.decrypt(&nce, self.e.as_ref())
            .expect("decryption failure!");
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::Ciphertext;
    use rand::{thread_rng, Rng};
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;

    #[test]
    fn test_enc() {
        let mut csrng = thread_rng();
        let sk = Scalar::random(&mut csrng);
        let pk= sk*RISTRETTO_BASEPOINT_POINT;

        let label = RistrettoPoint::random(&mut csrng);
        let ek = thread_rng().gen::<[u8; 32]>();
        let lvec = Vec::from(*label.compress().as_bytes());
        let ekvec = Vec::from(ek);
        let c = Ciphertext::encrypt(&pk, &lvec, &ekvec);

        let msg = c.decrypt(&sk, &lvec);

        assert_eq!(ek.to_vec(),msg.unwrap());
    }
}