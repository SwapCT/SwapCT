#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha3::{Sha3XofReader, Shake256};
use sha3::digest::{Update, ExtendableOutputDirty, XofReader};

/// The `GeneratorsChain` creates an arbitrary-long sequence of
/// orthogonal generators.  The sequence can be deterministically
/// produced starting with an arbitrary point.
struct GeneratorsChain {
    reader: Sha3XofReader,
}

impl GeneratorsChain {
    /// Creates a chain of generators, determined by the hash of `label`.
    fn new(label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);

        GeneratorsChain {
            reader: shake.finalize_xof_dirty(),
        }
    }

    /// Advances the reader n times, squeezing and discarding
    /// the result.
    fn fast_forward(mut self, n: usize) -> Self {
        for _ in 0..n {
            let mut buf = [0u8; 64];
            self.reader.read(&mut buf);
        }
        self
    }
}

impl Default for GeneratorsChain {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl Iterator for GeneratorsChain {
    type Item = RistrettoPoint;

    fn next(&mut self) -> Option<Self::Item> {
        let mut uniform_bytes = [0u8; 64];
        self.reader.read(&mut uniform_bytes);

        Some(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}


/// The `BulletproofGens` struct contains all the generators needed
/// for aggregating up to `m` range proofs of up to `n` bits each.
///
/// # Extensible Generator Generation
///
/// Instead of constructing a single vector of size `m*n`, as
/// described in the Bulletproofs paper, we construct each party's
/// generators separately.
///
/// To construct an arbitrary-length chain of generators, we apply
/// SHAKE256 to a domain separator label, and feed each 64 bytes of
/// XOF output into the `ristretto255` hash-to-group function.
/// Each of the `m` parties' generators are constructed using a
/// different domain separation label, and proving and verification
/// uses the first `n` elements of the arbitrary-length chain.
///
/// This means that the aggregation size (number of
/// parties) is orthogonal to the rangeproof size (number of bits),
/// and allows using the same `BulletproofGens` object for different
/// proving parameters.
///
/// This construction is also forward-compatible with constraint
/// system proofs, which use a much larger slice of the generator
/// chain, and even forward-compatible to multiparty aggregation of
/// constraint system proofs, since the generators are namespaced by
/// their party index.
#[derive(Clone)]
pub struct BulletproofGens {
    /// The maximum number of usable generators for each party.
    pub gens_capacity: usize,
    /// Number of values or parties
    pub party_capacity: usize,
    /// Precomputed \\(\mathbf G\\) generators for each party.
    G_vec: Vec<Vec<RistrettoPoint>>,
    /// Precomputed \\(\mathbf H\\) generators for each party.
    H_vec: Vec<Vec<RistrettoPoint>>,
}

impl BulletproofGens {
    /// Create a new `BulletproofGens` object.
    ///
    /// # Inputs
    ///
    /// * `gens_capacity` is the number of generators to precompute
    ///    for each party.  For rangeproofs, it is sufficient to pass
    ///    `64`, the maximum bitsize of the rangeproofs.  For circuit
    ///    proofs, the capacity must be greater than the number of
    ///    multipliers, rounded up to the next power of two.
    ///
    /// * `party_capacity` is the maximum number of parties that can
    ///    produce an aggregated proof.
    pub fn new(gens_capacity: usize, party_capacity: usize) -> Self {
        let mut gens = BulletproofGens {
            gens_capacity: 0,
            party_capacity,
            G_vec: (0..party_capacity).map(|_| Vec::new()).collect(),
            H_vec: (0..party_capacity).map(|_| Vec::new()).collect(),
        };
        gens.increase_capacity(gens_capacity);
        gens
    }

    /// Returns j-th share of generators, with an appropriate
    /// slice of vectors G and H for the j-th range proof.
    pub fn share(&self, j: usize) -> BulletproofGensShare<'_> {
        BulletproofGensShare {
            gens: &self,
            share: j,
        }
    }

    /// Increases the generators' capacity to the amount specified.
    /// If less than or equal to the current capacity, does nothing.
    pub fn increase_capacity(&mut self, new_capacity: usize) {
        use byteorder::{ByteOrder, LittleEndian};

        if self.gens_capacity >= new_capacity {
            return;
        }

        for i in 0..self.party_capacity {
            let party_index = i as u32;
            let mut label = [b'G', 0, 0, 0, 0];
            LittleEndian::write_u32(&mut label[1..5], party_index);
            self.G_vec[i].extend(
                &mut GeneratorsChain::new(&label)
                    .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity),
            );

            label[0] = b'H';
            self.H_vec[i].extend(
                &mut GeneratorsChain::new(&label)
                    .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity),
            );
        }
        self.gens_capacity = new_capacity;
    }

    /// Return an iterator over the aggregation of the parties' G generators with given size `n`.
    pub(crate) fn G(&self, n: usize, m: usize) -> impl Iterator<Item = &RistrettoPoint> {
        AggregatedGensIter {
            n,
            m,
            array: &self.G_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }

    /// Return an iterator over the aggregation of the parties' H generators with given size `n`.
    pub(crate) fn H(&self, n: usize, m: usize) -> impl Iterator<Item = &RistrettoPoint> {
        AggregatedGensIter {
            n,
            m,
            array: &self.H_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }
}


struct AggregatedGensIter<'a> {
    array: &'a Vec<Vec<RistrettoPoint>>,
    n: usize,
    m: usize,
    party_idx: usize,
    gen_idx: usize,
}

impl<'a> Iterator for AggregatedGensIter<'a> {
    type Item = &'a RistrettoPoint;

    fn next(&mut self) -> Option<Self::Item> {
        if self.gen_idx >= self.n {
            self.gen_idx = 0;
            self.party_idx += 1;
        }

        if self.party_idx >= self.m {
            None
        } else {
            let cur_gen = self.gen_idx;
            self.gen_idx += 1;
            Some(&self.array[self.party_idx][cur_gen])
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.n * (self.m - self.party_idx) - self.gen_idx;
        (size, Some(size))
    }
}


/// Represents a view of the generators used by a specific party in an
/// aggregated proof.
///
/// The `BulletproofGens` struct represents generators for an aggregated
/// range proof `m` proofs of `n` bits each; the `BulletproofGensShare`
/// provides a view of the generators for one of the `m` parties' shares.
///
/// The `BulletproofGensShare` is produced by [`BulletproofGens::share()`].
#[derive(Copy, Clone)]
pub struct BulletproofGensShare<'a> {
    /// The parent object that this is a view into
    gens: &'a BulletproofGens,
    /// Which share we are
    share: usize,
}

impl<'a> BulletproofGensShare<'a> {
    /// Return an iterator over this party's G generators with given size `n`.
    pub(crate) fn G(&self, n: usize) -> impl Iterator<Item = &'a RistrettoPoint> {
        self.gens.G_vec[self.share].iter().take(n)
    }

    /// Return an iterator over this party's H generators with given size `n`.
    pub(crate) fn H(&self, n: usize) -> impl Iterator<Item = &'a RistrettoPoint> {
        self.gens.H_vec[self.share].iter().take(n)
    }
}