// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Precomputation for one-round signing.

#[cfg(all(feature = "std", not(feature = "force-alloc")))]
use std::boxed::Box;

#[cfg(any(feature = "alloc", feature = "force-alloc"))]
use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand_core::{CryptoRng, RngCore};

use subtle::Choice;
use subtle::ConstantTimeEq;

use zeroize::Zeroize;

#[derive(Debug)]
pub(crate) struct NoncePair(pub(crate) Scalar, pub(crate) Scalar);

impl NoncePair {
    pub fn new(mut csprng: impl CryptoRng + RngCore) -> Self {
        let mut bytes1 = [0u8; 64];
        let mut bytes2 = [0u8; 64];
        csprng.fill_bytes(&mut bytes1);
        csprng.fill_bytes(&mut bytes2);
        NoncePair(
            Scalar::from_bytes_mod_order_wide(&bytes1),
            Scalar::from_bytes_mod_order_wide(&bytes2),
        )
    }
}

impl Drop for NoncePair {
    fn drop(&mut self) {
        self.0 = Scalar::ZERO;
        self.1 = Scalar::ZERO;
    }
}

impl From<NoncePair> for CommitmentShare {
    fn from(other: NoncePair) -> CommitmentShare {
        let x = &other.0 * RISTRETTO_BASEPOINT_TABLE;
        let y = &other.1 * RISTRETTO_BASEPOINT_TABLE;

        CommitmentShare {
            hiding: Commitment {
                nonce: other.0,
                sealed: x,
            },
            binding: Commitment {
                nonce: other.1,
                sealed: y,
            },
        }
    }
}

/// A pair of a nonce and a commitment to it.
#[derive(Clone, Debug)]
pub(crate) struct Commitment {
    /// The nonce.
    pub(crate) nonce: Scalar,
    /// The commitment.
    pub(crate) sealed: RistrettoPoint,
}

impl Drop for Commitment {
    fn drop(&mut self) {
        self.nonce = Scalar::ZERO;
        self.sealed = RistrettoPoint::identity();
    }
}

/// Test equality in constant-time.
impl ConstantTimeEq for Commitment {
    fn ct_eq(&self, other: &Commitment) -> Choice {
        self.nonce.ct_eq(&other.nonce) & self.sealed.compress().ct_eq(&other.sealed.compress())
    }
}

/// A precomputed commitment share.
#[derive(Clone, Debug)]
pub struct CommitmentShare {
    /// The hiding commitment.
    ///
    /// This is \\((d\_{ij}, D\_{ij})\\) in the paper.
    pub(crate) hiding: Commitment,
    /// The binding commitment.
    ///
    /// This is \\((e\_{ij}, E\_{ij})\\) in the paper.
    pub(crate) binding: Commitment,
}

/// Test equality in constant-time.
impl ConstantTimeEq for CommitmentShare {
    fn ct_eq(&self, other: &CommitmentShare) -> Choice {
        self.hiding.ct_eq(&other.hiding) & self.binding.ct_eq(&other.binding)
    }
}

impl CommitmentShare {
    /// Publish the public commitments in this [`CommitmentShare`].
    pub fn publish(&self) -> (RistrettoPoint, RistrettoPoint) {
        (self.hiding.sealed, self.binding.sealed)
    }
}

/// A secret commitment share list, containing the revealed nonces for the
/// hiding and binding commitments.
#[derive(Debug)]
pub struct SecretCommitmentShareList {
    /// The secret commitment shares.
    pub commitments: Vec<CommitmentShare>,
}

/// A public commitment share list, containing only the hiding and binding
/// commitments, *not* their committed-to nonce values.
///
/// This should be published somewhere before the signing protocol takes place
/// for the other signing participants to obtain.
#[derive(Debug)]
pub struct PublicCommitmentShareList {
    /// The participant's index.
    pub participant_index: u32,
    /// The published commitments.
    pub commitments: Vec<(RistrettoPoint, RistrettoPoint)>,
}

/// Pre-compute a list of [`CommitmentShare`]s for single-round threshold signing.
///
/// # Inputs
///
/// * `participant_index` is the index of the threshold signing
///   participant who is publishing this share.
/// * `number_of_shares` denotes the number of commitments published at a time.
///
/// # Returns
///
/// A tuple of ([`PublicCommitmentShareList`], [`SecretCommitmentShareList`]).
pub fn generate_commitment_share_lists(
    mut csprng: impl CryptoRng + RngCore,
    participant_index: u32,
    number_of_shares: usize,
) -> (PublicCommitmentShareList, SecretCommitmentShareList) {
    let mut commitments: Vec<CommitmentShare> = Vec::with_capacity(number_of_shares);

    for _ in 0..number_of_shares {
        commitments.push(CommitmentShare::from(NoncePair::new(&mut csprng)));
    }

    let mut published: Vec<(RistrettoPoint, RistrettoPoint)> = Vec::with_capacity(number_of_shares);

    for commitment in commitments.iter() {
        published.push(commitment.publish());
    }

    (
        PublicCommitmentShareList {
            participant_index,
            commitments: published,
        },
        SecretCommitmentShareList { commitments },
    )
}

// XXX TODO This should maybe be a field on SecretKey with some sort of
// regeneration API for generating new share, or warning that there are no
// ununsed shares.
impl SecretCommitmentShareList {
    /// Drop a used [`CommitmentShare`] from our secret commitment share list
    /// and ensure that it is wiped from memory.
    pub fn drop_share(&mut self, share: CommitmentShare) {
        let mut index = -1;

        // This is not constant-time in that the number of commitment shares in
        // the list may be discovered via side channel, as well as the index of
        // share to be deleted, as well as whether or not the share was in the
        // list, but none of this gives any adversary that I can think of any
        // advantage.
        for (i, s) in self.commitments.iter().enumerate() {
            if s.ct_eq(&share).into() {
                index = i as isize;
            }
        }
        if index >= 0 {
            drop(self.commitments.remove(index as usize));
        }
        drop(share);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::rngs::OsRng;

    #[test]
    fn nonce_pair() {
        let _nonce_pair = NoncePair::new(&mut OsRng);
    }

    #[test]
    fn nonce_pair_into_commitment_share() {
        let _commitment_share: CommitmentShare = NoncePair::new(&mut OsRng).into();
    }

    #[test]
    fn commitment_share_list_generate() {
        let (public_share_list, secret_share_list) =
            generate_commitment_share_lists(&mut OsRng, 0, 5);

        assert_eq!(
            public_share_list.commitments[0].0.compress(),
            (&secret_share_list.commitments[0].hiding.nonce * RISTRETTO_BASEPOINT_TABLE).compress()
        );
    }

    #[test]
    fn drop_used_commitment_shares() {
        let (_public_share_list, mut secret_share_list) =
            generate_commitment_share_lists(&mut OsRng, 3, 8);

        assert!(secret_share_list.commitments.len() == 8);

        let used_share = secret_share_list.commitments[0].clone();

        secret_share_list.drop_share(used_share);

        assert!(secret_share_list.commitments.len() == 7);
    }
}
