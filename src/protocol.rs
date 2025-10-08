#[cfg(not(any(feature = "std", feature = "alloc", feature = "force-alloc")))]
compile_error!("This module requires heap. Enable one of: `std`, `alloc`, or `force-alloc`.");

#[cfg(any(feature = "alloc", feature = "force-alloc"))]
use alloc::vec::Vec;
#[cfg(all(feature = "std", not(feature = "force-alloc")))]
use std::vec::Vec;

use rand_core::{CryptoRng, RngCore};

use crate::keygen;
use crate::parameters;

#[derive(Clone, Default, Debug)]
pub struct Party {
    index: u32,
    parameters: parameters::Parameters,
    participant: keygen::Participant,
    coefficients: keygen::Coefficients,
    dkg_state_r1: keygen::DistributedKeyGeneration<keygen::RoundOne>,
    dkg_state_r2: keygen::DistributedKeyGeneration<keygen::RoundTwo>,
    secret_share: keygen::SecretKey,
    group_key: keygen::GroupKey,
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

pub trait Signing {}

// Commitments and ZK Proofs
pub type Message1 = keygen::Participant;

impl Party {
    pub fn new(index: u32, t: u32, n: u32) -> Self {
        Self {
            index,
            parameters: parameters::Parameters { t, n },
            participant: Default::default(),
            coefficients: Default::default(),
            dkg_state_r1: Default::default(),
            dkg_state_r2: Default::default(),
            secret_share: Default::default(),
            group_key: Default::default(),
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

impl MetaData for Party {
    fn get_index(&self) -> u32 {
        return self.index;
    }

    fn get_params(&self) -> &parameters::Parameters {
        return &self.parameters;
    }
}
