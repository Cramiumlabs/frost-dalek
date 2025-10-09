#[cfg(not(any(feature = "std", feature = "alloc", feature = "force-alloc")))]
compile_error!("This module requires heap. Enable one of: `std`, `alloc`, or `force-alloc`.");

#[cfg(any(feature = "alloc", feature = "force-alloc"))]
use alloc::vec::Vec;
#[cfg(all(feature = "std", not(feature = "force-alloc")))]
use std::vec::Vec;

#[cfg(any(feature = "alloc", feature = "force-alloc"))]
use hashbrown::HashMap;
#[cfg(all(feature = "std", not(feature = "force-alloc")))]
use std::collections::HashMap;

use rand_core::{CryptoRng, RngCore};

use crate::keygen;
use crate::parameters;
use crate::precomputation;
use crate::signature;

#[derive(Clone, Default, Debug)]
pub struct Party {
    index: u32,
    parameters: parameters::Parameters,
    is_presigning: bool,

    // Keygen state data
    participant: keygen::Participant,
    coefficients: keygen::Coefficients,
    dkg_state_r1: keygen::DistributedKeyGeneration<keygen::RoundOne>,
    dkg_state_r2: keygen::DistributedKeyGeneration<keygen::RoundTwo>,
    secret_share: keygen::SecretKey,
    group_key: keygen::GroupKey,

    // Signing state data
    signer: Vec<signature::Signer>,
    aggregator: signature::SignatureAggregator<signature::Finalized>,
}

pub trait MetaData {
    fn get_index(&self) -> u32;
    fn get_params(&self) -> &parameters::Parameters;
}

pub trait Keygen {
    fn generate_keygen_message1<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Message1;
    fn handle_keygen_message1(
        &mut self,
        messages: Vec<Message1>,
    ) -> Result<Vec<keygen::SecretShare>, parameters::FrostError>;
    fn handle_keygen_message2(
        &mut self,
        shares: Vec<keygen::SecretShare>,
    ) -> Result<(), parameters::FrostError>;
}

pub trait PreSigning {
    fn generate_presigning_data() -> (
        precomputation::PublicCommitmentShareList,
        precomputation::SecretCommitmentShareList,
    );
}

pub trait Signing {
    fn generate_commitment_data(
        &self,
        rng: impl CryptoRng + RngCore,
    ) -> (
        precomputation::PublicCommitmentShareList,
        precomputation::SecretCommitmentShareList,
    );

    fn sign(
        &mut self,
        message: &[u8],
        group_key: &keygen::GroupKey,
        my_secret_commitment_share_list: &mut precomputation::SecretCommitmentShareList,
        my_commitment_share_index: usize,
        signers: &[signature::Signer],
    ) -> Result<signature::PartialThresholdSignature, &'static str>;

    /// Combine partial signatures and verify the final result.
    /// Returns Ok((ThresholdSignature, verified_bool)) if success.
    fn combine_partial_signatures(
        &self,
        group_key: &keygen::GroupKey,
        message: &[u8],
        partial_signatures: Vec<signature::PartialThresholdSignature>,
    ) -> Result<(signature::ThresholdSignature, bool), HashMap<u32, &'static str>>;
}


// Commitments and ZK Proofs
pub type Message1 = keygen::Participant;

impl Party {
    pub fn new(index: u32, t: u32, n: u32) -> Self {
        Self {
            index,
            parameters: parameters::Parameters { t, n },
            is_presigning: true,
            participant: Default::default(),
            coefficients: Default::default(),
            dkg_state_r1: Default::default(),
            dkg_state_r2: Default::default(),
            secret_share: Default::default(),
            group_key: Default::default(),
            signer: Default::default(),
            aggregator: Default::default(),
        }
    }
}

impl Keygen for Party {
    fn generate_keygen_message1<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Message1 {
        let (p, c) = keygen::Participant::new(&self.parameters, self.index, rng);
        self.participant = p.clone();
        self.coefficients = c;
        p
    }

    // handle recieved commitments and ZK Proofs
    // generate partners shares for broadcasting
    fn handle_keygen_message1(
        &mut self,
        mut messages: Vec<Message1>,
    ) -> Result<Vec<keygen::SecretShare>, parameters::FrostError> {
        let result = keygen::DistributedKeyGeneration::<_>::new(
            &self.parameters,
            &self.index,
            &self.coefficients,
            &mut messages,
        );
        match result {
            Ok(state) => {
                self.dkg_state_r1 = state;
            }
            Err(_) => {
                return Err(parameters::FrostError::DkgInvalidPartners);
            }
        }

        let shares_result = self.dkg_state_r1.their_secret_shares();
        match shares_result {
            Ok(shares) => {
                return Ok((*shares).clone());
            }
            Err(_) => {
                return Err(parameters::FrostError::Unknown);
            }
        }
    }

    // handle received shares
    fn handle_keygen_message2(
        &mut self,
        shares: Vec<keygen::SecretShare>,
    ) -> Result<(), parameters::FrostError> {
        let state2_result = self.dkg_state_r1.clone().to_round_two(shares);
        match state2_result {
            Ok(state2) => {
                self.dkg_state_r2 = state2;
            }
            Err(_) => return Err(parameters::FrostError::DkgInvalidShares),
        }
        let dkg_result = self
            .dkg_state_r2
            .clone()
            .finish(self.participant.public_key().unwrap());
        match dkg_result {
            Ok((group_key, sk)) => {
                self.secret_share = sk;
                self.group_key = group_key;
            }
            Err(_) => return Err(parameters::FrostError::DkgInvalidSecretShares),
        }
        return Ok(());
    }
}

impl Signing for Party {
    fn generate_commitment_data(
        &self,
        rng: impl CryptoRng + RngCore,
    ) -> (
        precomputation::PublicCommitmentShareList,
        precomputation::SecretCommitmentShareList,
    ) {
        if !self.is_presigning {
            return precomputation::generate_commitment_share_lists(
                rng,
                (self.index + 1) as u32,
                1,
            );
        } else {
            return precomputation::generate_commitment_share_lists(
                rng,
                (self.index + 1) as u32,
                0,
            );
        }
    }

    fn sign(
        &mut self,
        message: &[u8],
        group_key: &keygen::GroupKey,
        my_secret_commitment_share_list: &mut precomputation::SecretCommitmentShareList,
        my_commitment_share_index: usize,
        signers: &[signature::Signer],
    ) -> Result<signature::PartialThresholdSignature, &'static str> {
        let message_hash = &signature::compute_message_hash(&[], &message[..]);

        self.secret_share.sign(
            message_hash,
            group_key,
            my_secret_commitment_share_list,
            my_commitment_share_index,
            &signers,
        )
    }

    fn combine_partial_signatures(
        &self,
        group_key: &keygen::GroupKey,
        message: &[u8],
        partial_signatures: Vec<signature::PartialThresholdSignature>,
    ) -> Result<(signature::ThresholdSignature, bool), HashMap<u32, &'static str>> {
        let mut aggregator: signature::SignatureAggregator<signature::Initial<'_>> =
            signature::SignatureAggregator::new(
                self.parameters,
                group_key.clone(),
                &[],
                &message[..],
            );

        for signer in self.signer.iter() {
            aggregator.include_signer(
                signer.participant_index,
                signer.published_commitment_share,
                signer.public_key,
            );
        }

        for partial in partial_signatures {
            aggregator.include_partial_signature(partial);
        }

        match aggregator.finalize() {
            Ok(finalized_aggregator) => {
                match finalized_aggregator.aggregate() {
                    Ok(threshold_signature) => {
                        let message_hash = signature::compute_message_hash(&[], &message[..]);
                        let verify_result = threshold_signature.verify(group_key, &message_hash);
                        Ok((threshold_signature, verify_result.is_ok()))
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}


impl MetaData for Party {
    fn get_index(&self) -> u32 {
        return self.index;
    }

    fn get_params(&self) -> &parameters::Parameters {
        return &self.parameters;
    }
}
