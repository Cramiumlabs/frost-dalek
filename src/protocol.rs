#[cfg(not(any(feature = "std", feature = "alloc", feature = "force-alloc")))]
compile_error!("This module requires heap. Enable one of: `std`, `alloc`, or `force-alloc`.");

#[cfg(any(feature = "alloc", feature = "force-alloc"))]
use alloc::vec::Vec;
#[cfg(all(feature = "std", not(feature = "force-alloc")))]
use std::vec::Vec;

use rand_core::{CryptoRng, RngCore};

use crate::keygen;
use crate::parameters;
use crate::precomputation;
use crate::signature;

use zeroize::Zeroize;


#[derive(Clone, Debug)]
pub struct Party {
    index: u32,
    parameters: parameters::Parameters,
    is_presigning: bool,

    // Keygen state data
    participant: Option<keygen::Participant>,
    coefficients: Option<keygen::Coefficients>,
    dkg_state_r1: Option<keygen::DistributedKeyGeneration<keygen::RoundOne>>,
    dkg_state_r2: Option<keygen::DistributedKeyGeneration<keygen::RoundTwo>>,
    secret_share: Option<keygen::SecretKey>,
    group_key: Option<keygen::GroupKey>,

    // Signing state data
    signer: Vec<signature::Signer>,
    aggregator: Option<signature::SignatureAggregator<signature::Finalized>>,
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
    fn is_keygen_complete(&self) -> bool;
    fn clear_keygen_state(&mut self);
    fn import_secret_share(
        &mut self,
        secret_share: keygen::SecretKey,
        group_key: keygen::GroupKey,
    ) -> Result<(), parameters::FrostError>;
    fn get_secret_share(&self) -> Option<&keygen::SecretKey>;
    fn get_group_key(&self) -> Option<&keygen::GroupKey>;
}

pub trait PreSigning {
    fn generate_presigning_data(
        &self,
        num_shares: usize,
        rng: impl CryptoRng + RngCore,
    ) -> Result<
        (
            precomputation::PublicCommitmentShareList,
            precomputation::SecretCommitmentShareList,
        ),
        parameters::FrostError,
    >;
}

pub trait Signing {
    fn generate_commitment_data(
        &self,
        rng: impl CryptoRng + RngCore,
    ) -> Result<
        (
            precomputation::PublicCommitmentShareList,
            precomputation::SecretCommitmentShareList,
        ),
        parameters::FrostError,
    >;

    fn sign(
        &mut self,
        message: &[u8],
        my_secret_commitment_share_list: &mut precomputation::SecretCommitmentShareList,
        my_commitment_share_index: usize,
        signers: &[signature::Signer],
    ) -> Result<signature::PartialThresholdSignature, parameters::FrostError>;

    /// Combine partial signatures and verify the final result.
    /// Returns Ok((ThresholdSignature, verified_bool)) if success.
    fn combine_partial_signatures(
        &self,
        message: &[u8],
        partial_signatures: Vec<signature::PartialThresholdSignature>,
    ) -> Result<(signature::ThresholdSignature, bool), parameters::FrostError>;

    fn clear_signing_state(&mut self);
    fn get_signers(&self) -> &[signature::Signer];
}

// Commitments and ZK Proofs
pub type Message1 = keygen::Participant;

impl Party {
    pub fn new(index: u32, t: u32, n: u32) -> Result<Self, parameters::FrostError> {
        if index == 0 || index > n {
            return Err(parameters::FrostError::InvalidParameters);
        }
        if t == 0 || t > n {
            return Err(parameters::FrostError::InvalidParameters);
        }

        Ok(Self {
            index,
            parameters: parameters::Parameters { t, n },
            is_presigning: true,
            participant: None,
            coefficients: None,
            dkg_state_r1: None,
            dkg_state_r2: None,
            secret_share: None,
            group_key: None,
            signer: Vec::new(),
            aggregator: None,
        })
    }
}

impl Keygen for Party {
    fn generate_keygen_message1<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Message1 {
        let (p, c) = keygen::Participant::new(&self.parameters, self.index, rng);
        self.participant = Some(p.clone());
        self.coefficients = Some(c);
        p
    }

    // handle received commitments and ZK Proofs
    // generate partners shares for broadcasting
    fn handle_keygen_message1(
        &mut self,
        mut messages: Vec<Message1>,
    ) -> Result<Vec<keygen::SecretShare>, parameters::FrostError> {
        // Validate we have participant and coefficients
        let coefficients = self
            .coefficients
            .as_ref()
            .ok_or(parameters::FrostError::InvalidParameters)?;

        // Validate message count (should be n-1)
        if messages.len() != (self.parameters.n - 1) as usize {
            return Err(parameters::FrostError::DkgInvalidPartners);
        }

        let state = keygen::DistributedKeyGeneration::<_>::new(
            &self.parameters,
            &self.index,
            coefficients,
            &mut messages,
        )
        .map_err(|_| parameters::FrostError::DkgInvalidPartners)?;

        let shares = state
            .their_secret_shares()
            .map_err(|_| parameters::FrostError::Unknown)?
            .clone();

        self.dkg_state_r1 = Some(state);
        Ok(shares)
    }

    // handle received shares
    fn handle_keygen_message2(
        &mut self,
        shares: Vec<keygen::SecretShare>,
    ) -> Result<(), parameters::FrostError> {
        // Validate we have dkg_state_r1
        let dkg_state_r1 = self
            .dkg_state_r1
            .take()
            .ok_or(parameters::FrostError::InvalidParameters)?;

        // Validate share count (should be n-1)
        if shares.len() != (self.parameters.n - 1) as usize {
            return Err(parameters::FrostError::DkgInvalidShares);
        }

        let state2 = dkg_state_r1
            .to_round_two(shares)
            .map_err(|_| parameters::FrostError::DkgInvalidShares)?;

        let participant = self
            .participant
            .as_ref()
            .ok_or(parameters::FrostError::InvalidParameters)?;

        let public_key = participant
            .public_key()
            .ok_or(parameters::FrostError::InvalidParameters)?;

        let (group_key, sk) = state2
            .clone()
            .finish(public_key)
            .map_err(|_| parameters::FrostError::DkgInvalidSecretShares)?;

        self.secret_share = Some(sk);
        self.group_key = Some(group_key);
        self.dkg_state_r2 = Some(state2);

        // Clear intermediate keygen state
        self.participant = None;
        self.coefficients = None;
        self.dkg_state_r1 = None;

        Ok(())
    }

    fn is_keygen_complete(&self) -> bool {
        self.secret_share.is_some() && self.group_key.is_some()
    }

    fn clear_keygen_state(&mut self) {
        if let Some(sk) = self.secret_share.as_mut() {
            sk.zeroize();
        }
        if let Some(coeffs) = self.coefficients.as_mut() {
            coeffs.zeroize();
        }
        if let Some(r1) = self.dkg_state_r1.as_mut() {
            r1.zeroize();
        }
        if let Some(r2) = self.dkg_state_r2.as_mut() {
            r2.zeroize();
        }

        // Then drop all references
        self.participant = None;
        self.coefficients = None;
        self.dkg_state_r1 = None;
        self.dkg_state_r2 = None;
        self.secret_share = None;
        self.group_key = None;
    }

    fn import_secret_share(
        &mut self,
        secret_share: keygen::SecretKey,
        group_key: keygen::GroupKey,
    ) -> Result<(), parameters::FrostError> {
        // Validate that the secret share index matches party index
        if secret_share.index != self.index {
            return Err(parameters::FrostError::InvalidParameters);
        }

        // Clear any existing keygen state
        self.clear_keygen_state();

        // Import the keys
        self.secret_share = Some(secret_share);
        self.group_key = Some(group_key);

        Ok(())
    }

    fn get_secret_share(&self) -> Option<&keygen::SecretKey> {
        self.secret_share.as_ref()
    }

    fn get_group_key(&self) -> Option<&keygen::GroupKey> {
        self.group_key.as_ref()
    }
}

impl PreSigning for Party {
    fn generate_presigning_data(
        &self,
        num_shares: usize,
        rng: impl CryptoRng + RngCore,
    ) -> Result<
        (
            precomputation::PublicCommitmentShareList,
            precomputation::SecretCommitmentShareList,
        ),
        parameters::FrostError,
    > {
        Ok(precomputation::generate_commitment_share_lists(
            rng, self.index, num_shares,
        ))
    }
}

impl Signing for Party {
    fn generate_commitment_data(
        &self,
        rng: impl CryptoRng + RngCore,
    ) -> Result<
        (
            precomputation::PublicCommitmentShareList,
            precomputation::SecretCommitmentShareList,
        ),
        parameters::FrostError,
    > {
        // Validate keygen is complete
        if !self.is_keygen_complete() {
            return Err(parameters::FrostError::InvalidParameters);
        }

        let number_of_shares = if !self.is_presigning { 1 } else { 0 };

        Ok(precomputation::generate_commitment_share_lists(
            rng,
            self.index,
            number_of_shares,
        ))
    }

    fn sign(
        &mut self,
        message: &[u8],
        my_secret_commitment_share_list: &mut precomputation::SecretCommitmentShareList,
        my_commitment_share_index: usize,
        signers: &[signature::Signer],
    ) -> Result<signature::PartialThresholdSignature, parameters::FrostError> {
        // Validate keygen is complete
        let secret_share = self
            .secret_share
            .as_ref()
            .ok_or(parameters::FrostError::InvalidParameters)?;
        let group_key = self
            .group_key
            .as_ref()
            .ok_or(parameters::FrostError::InvalidParameters)?;

        // Validate we have enough signers (at least t)
        if signers.len() < self.parameters.t as usize {
            return Err(parameters::FrostError::InvalidParameters);
        }

        for signer in signers.iter() {
            self.signer.push((*signer).clone());
        }

        // Validate message is not empty
        if message.is_empty() {
            return Err(parameters::FrostError::InvalidParameters);
        }

        let message_hash = &signature::compute_message_hash(&[], &message[..]);

        secret_share
            .sign(
                message_hash,
                group_key,
                my_secret_commitment_share_list,
                my_commitment_share_index,
                signers,
            )
            .map_err(|_| parameters::FrostError::SigningError)
    }

    fn combine_partial_signatures(
        &self,
        message: &[u8],
        partial_signatures: Vec<signature::PartialThresholdSignature>,
    ) -> Result<(signature::ThresholdSignature, bool), parameters::FrostError> {
        // Validate keygen is complete
        let group_key = self
            .group_key
            .as_ref()
            .ok_or(parameters::FrostError::InvalidParameters)?;

        // Validate we have enough partial signatures (at least t)
        if partial_signatures.len() < self.parameters.t as usize {
            return Err(parameters::FrostError::InvalidParameters);
        }

        // Validate we have signers
        if self.signer.is_empty() {
            return Err(parameters::FrostError::InvalidParameters);
        }

        // Validate message is not empty
        if message.is_empty() {
            return Err(parameters::FrostError::InvalidParameters);
        }

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

        let finalized_aggregator = aggregator
            .finalize()
            .map_err(|_| parameters::FrostError::SigningError)?;

        let threshold_signature = finalized_aggregator
            .aggregate()
            .map_err(|_| parameters::FrostError::SigningError)?;

        let message_hash = signature::compute_message_hash(&[], &message[..]);
        let verify_result = threshold_signature.verify(group_key, &message_hash);

        Ok((threshold_signature, verify_result.is_ok()))
    }

    fn clear_signing_state(&mut self) {
        self.signer.clear();
        self.aggregator = None;
    }

    fn get_signers(&self) -> &[signature::Signer] {
        &self.signer
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Test full keygen and signing flow with 3 parties, threshold 2
    #[test]
    fn test_full_protocol_flow_3_2() {
        let mut rng = OsRng;
        let n = 3;
        let t = 2;

        // Step 1: Create parties
        let mut parties = Vec::new();
        for i in 1..=n {
            let party = Party::new(i, t, n).expect("Failed to create party");
            assert_eq!(party.get_index(), i);
            assert!(!party.is_keygen_complete());
            parties.push(party);
        }

        // Step 2: Keygen Round 1 - Generate commitments
        let mut messages = vec![Vec::new(); n as usize];
        for (i, party) in parties.iter_mut().enumerate() {
            let message1 = party.generate_keygen_message1(&mut rng);
            // Broadcast to all other parties
            for j in 0..n as usize {
                if i != j {
                    messages[j].push(message1.clone());
                }
            }
        }

        // Step 3: Keygen Round 2 - Process commitments and generate shares
        let mut all_shares = Vec::new();
        for (i, party) in parties.iter_mut().enumerate() {
            let shares = party
                .handle_keygen_message1(messages[i].clone())
                .expect("Failed to handle keygen message 1");
            assert_eq!(shares.len(), (n - 1) as usize);
            all_shares.push(shares);
        }

        // Step 4: Keygen Round 3 - Distribute and process shares
        for i in 0..n as usize {
            let mut my_shares = Vec::new();
            for j in 0..n as usize {
                if i == j {
                    continue;
                }
                let share_index = if i < j { i } else { i - 1 };
                my_shares.push(all_shares[j][share_index].clone());
            }
            parties[i]
                .handle_keygen_message2(my_shares)
                .expect("Failed to handle keygen message 2");
        }

        // Step 5: Verify keygen completion
        for party in &parties {
            assert!(party.is_keygen_complete());
            assert!(party.get_secret_share().is_some());
            assert!(party.get_group_key().is_some());
        }

        // Verify all parties have the same group key
        let group_key = parties[0].get_group_key().unwrap();
        for party in &parties {
            assert_eq!(party.get_group_key().unwrap(), group_key);
        }

        // Step 6: Signing Phase - Generate commitment data
        let message = b"Test message";
        let mut commitment_lists = Vec::new();
        for i in 0..t as usize {
            let (pub_coms, sec_coms) = parties[i]
                .generate_presigning_data(10, &mut rng)
                .expect("Failed to generate commitment data");
            commitment_lists.push((i, pub_coms, sec_coms));
        }

        // Step 7: Add signers to all signing parties
        let mut signers: Vec<signature::Signer> = Vec::new();
        for (i, pub_coms, _) in &commitment_lists {
            let signer = signature::Signer {
                participant_index: (*i + 1) as u32,
                published_commitment_share: pub_coms.commitments[0],
                public_key: parties[*i].get_secret_share().unwrap().into(),
            };
            signers.push(signer);
        }

        // Step 8: Generate partial signatures
        let mut partial_signatures = Vec::new();
        for (i, _, mut sec_coms) in commitment_lists {
            let partial = parties[i]
                .sign(message, &mut sec_coms, 0, &signers)
                .expect("Failed to sign");
            partial_signatures.push(partial);
        }

        // Step 9: Combine and verify signature
        let (_threshold_sig, verified) = parties[0]
            .combine_partial_signatures(message, partial_signatures)
            .expect("Failed to combine signatures");
        assert!(verified, "Signature verification failed");
    }

    /// Test full protocol flow with 5 parties, threshold 3
    #[test]
    fn test_full_protocol_flow_5_3() {
        let mut rng = OsRng;
        let n = 5;
        let t = 3;

        // Create parties
        let mut parties = Vec::new();
        for i in 1..=n {
            parties.push(Party::new(i, t, n).unwrap());
        }

        // Keygen Round 1
        let mut messages = vec![Vec::new(); n as usize];
        for (i, party) in parties.iter_mut().enumerate() {
            let msg = party.generate_keygen_message1(&mut rng);
            for j in 0..n as usize {
                if i != j {
                    messages[j].push(msg.clone());
                }
            }
        }

        // Keygen Round 2
        let mut all_shares = Vec::new();
        for (i, party) in parties.iter_mut().enumerate() {
            let shares = party.handle_keygen_message1(messages[i].clone()).unwrap();
            all_shares.push(shares);
        }

        // Keygen Round 3
        for i in 0..n as usize {
            let mut my_shares = Vec::new();
            for j in 0..n as usize {
                if i != j {
                    let share_index = if i < j { i } else { i - 1 };
                    my_shares.push(all_shares[j][share_index].clone());
                }
            }
            parties[i].handle_keygen_message2(my_shares).unwrap();
        }

        // Verify all parties completed keygen
        for party in &parties {
            assert!(party.is_keygen_complete());
        }

        // Signing with t parties
        let message = b"Another test message";
        let mut commitment_lists = Vec::new();
        for i in 0..t as usize {
            let (pub_coms, sec_coms) = parties[i].generate_presigning_data(10, &mut rng).unwrap();
            commitment_lists.push((i, pub_coms, sec_coms));
        }

        let mut signers: Vec<signature::Signer> = Vec::new();
        for (i, pub_coms, _) in &commitment_lists {
            let signer = signature::Signer {
                participant_index: (*i + 1) as u32,
                published_commitment_share: pub_coms.commitments[0],
                public_key: parties[*i].get_secret_share().unwrap().into(),
            };
            signers.push(signer);
        }

        let mut partial_signatures = Vec::new();
        for (i, _, mut sec_coms) in commitment_lists {
            let partial = parties[i]
                .sign(message, &mut sec_coms, 0, &signers)
                .unwrap();
            partial_signatures.push(partial);
        }

        let (_sig, verified) = parties[0]
            .combine_partial_signatures(message, partial_signatures)
            .unwrap();
        assert!(verified);
    }

    /// Test invalid party creation parameters
    #[test]
    fn test_invalid_party_creation() {
        // Index 0 is invalid
        assert!(Party::new(0, 2, 3).is_err());

        // Index > n is invalid
        assert!(Party::new(4, 2, 3).is_err());

        // t = 0 is invalid
        assert!(Party::new(1, 0, 3).is_err());

        // t > n is invalid
        assert!(Party::new(1, 4, 3).is_err());

        // Valid parameters
        assert!(Party::new(1, 2, 3).is_ok());
    }

    /// Test keygen state management
    #[test]
    fn test_keygen_state_management() {
        let mut rng = OsRng;
        let mut party = Party::new(1, 2, 3).unwrap();

        // Initially keygen is not complete
        assert!(!party.is_keygen_complete());
        assert!(party.get_secret_share().is_none());
        assert!(party.get_group_key().is_none());

        // Generate message1
        let _msg1 = party.generate_keygen_message1(&mut rng);

        // Still not complete
        assert!(!party.is_keygen_complete());

        // Clear state
        party.clear_keygen_state();
        assert!(!party.is_keygen_complete());
        assert!(party.get_secret_share().is_none());
        assert!(party.get_group_key().is_none());
    }

    /// Test signing before keygen completion: presigning phase
    #[test]
    fn test_signing_before_keygen() {
        let mut rng = OsRng;
        let mut party = Party::new(1, 2, 3).unwrap();

        // Try to generate commitment data before keygen
        let result = party.generate_presigning_data(10, &mut rng);
        assert!(result.is_ok());
    }

    /// Test invalid message count in keygen round 1
    #[test]
    fn test_invalid_message_count() {
        let mut rng = OsRng;
        let mut party = Party::new(1, 2, 3).unwrap();
        party.generate_keygen_message1(&mut rng);

        // Should expect 2 messages (n-1), but provide only 1
        let mut other_party = Party::new(2, 2, 3).unwrap();
        let other_msg = other_party.generate_keygen_message1(&mut rng);
        let other_messages = vec![other_msg];

        let result = party.handle_keygen_message1(other_messages);
        assert!(result.is_err());
    }

    /// Test invalid share count in keygen round 2
    #[test]
    fn test_invalid_share_count() {
        let mut rng = OsRng;
        let n = 3;
        let t = 2;

        let mut party1 = Party::new(1, t, n).unwrap();
        let mut party2 = Party::new(2, t, n).unwrap();

        party1.generate_keygen_message1(&mut rng);
        party2.generate_keygen_message1(&mut rng);

        // This should fail because we're not providing the correct number of shares
        let result = party1.handle_keygen_message2(Vec::new());
        assert!(result.is_err());
    }

    /// Test signing with empty message
    #[test]
    fn test_signing_empty_message() {
        let mut rng = OsRng;
        let n = 3;
        let t = 2;

        // Complete keygen
        let mut parties = Vec::new();
        for i in 1..=n {
            parties.push(Party::new(i, t, n).unwrap());
        }

        let mut messages = vec![Vec::new(); n as usize];
        for (i, party) in parties.iter_mut().enumerate() {
            let msg = party.generate_keygen_message1(&mut rng);
            for j in 0..n as usize {
                if i != j {
                    messages[j].push(msg.clone());
                }
            }
        }

        let mut all_shares = Vec::new();
        for (i, party) in parties.iter_mut().enumerate() {
            let shares = party.handle_keygen_message1(messages[i].clone()).unwrap();
            all_shares.push(shares);
        }

        for i in 0..n as usize {
            let mut my_shares = Vec::new();
            for j in 0..n as usize {
                if i != j {
                    let share_index = if i < j { i } else { i - 1 };
                    my_shares.push(all_shares[j][share_index].clone());
                }
            }
            parties[i].handle_keygen_message2(my_shares).unwrap();
        }

        // Try to sign empty message
        let empty_message = b"";
        let (pub_coms, mut sec_coms) = parties[0].generate_presigning_data(10, &mut rng).unwrap();

        let signer = signature::Signer {
            participant_index: 1,
            published_commitment_share: pub_coms.commitments[0],
            public_key: parties[0].get_secret_share().unwrap().into(),
        };

        let result = parties[0].sign(empty_message, &mut sec_coms, 0, &[signer]);
        assert!(result.is_err());
    }

    /// Test getting metadata
    #[test]
    fn test_metadata() {
        let party = Party::new(2, 3, 5).unwrap();
        assert_eq!(party.get_index(), 2);
        assert_eq!(party.get_params().t, 3);
        assert_eq!(party.get_params().n, 5);
    }
}
