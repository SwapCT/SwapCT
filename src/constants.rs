#![allow(non_snake_case)]

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use sha3::{Sha3_512};

pub const COMPRESSED_PEDERSEN_H: CompressedRistretto = CompressedRistretto([140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95, 148, 160, 140, 219, 127, 68, 203, 205, 123, 70, 243, 64, 72, 135, 17, 52]);
pub const COMPRESSED_NATIVE: CompressedRistretto = CompressedRistretto([72, 2, 95, 153, 203, 254, 246, 104, 19, 19, 203, 9, 150, 245, 105, 42, 71, 184, 185, 77, 228, 204, 239, 66, 196, 171, 214, 194, 232, 253, 206, 21]);

pub fn PEDERSEN_H() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha3_512>(
        RISTRETTO_BASEPOINT_COMPRESSED.as_bytes())
}
pub fn NATIVE() -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha3_512>(
        b"swapct_native".as_ref())
}

#[cfg(test)]
mod tests {
    use super::{PEDERSEN_H, COMPRESSED_PEDERSEN_H, NATIVE, COMPRESSED_NATIVE};

    #[test]
    fn test_pedersen() {
        assert_eq!(PEDERSEN_H().compress(), COMPRESSED_PEDERSEN_H);
    }

    #[test]
    fn test_native() {
        assert_eq!(NATIVE().compress(), COMPRESSED_NATIVE);
    }

}