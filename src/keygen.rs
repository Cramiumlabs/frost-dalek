use core::cmp::Ordering;

#[cfg(all(feature = "std", not(feature = "force-alloc")))]
use std::boxed::Box;
#[cfg(all(feature = "std", not(feature = "force-alloc")))]
use std::vec::Vec;

#[cfg(any(feature = "alloc", feature = "force-alloc"))]
use alloc::boxed::Box;
#[cfg(any(feature = "alloc", feature = "force-alloc"))]
use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::nizk::NizkOfSecretKey;
use crate::parameters::Parameters;

/// A struct for holding a shard of the shared secret, in order to ensure that
/// the shard is overwritten with zeroes when it falls out of scope.
pub struct Coefficients(pub(crate) Vec<Scalar>);

impl Drop for Coefficients {
    fn drop(&mut self) {
        for scalar in self.0.iter_mut() {
            *scalar = Scalar::ZERO;
        }
    }
}

/// A commitment to the dealer's secret polynomial coefficients for Feldman's
/// verifiable secret sharing scheme.
#[derive(Clone, Debug)]
pub struct VerifiableSecretSharingCommitment(pub(crate) Vec<RistrettoPoint>);

/// A participant created by a trusted dealer.
///
/// This can be used to create the participants' keys and secret shares without
/// having to do secret sharing or zero-knowledge proofs.  It's mostly provided
/// for testing and debugging purposes, but there is nothing wrong with using it
/// if you have trust in the dealer to not forge rogue signatures.
#[derive(Clone, Debug)]
pub struct DealtParticipant {
    pub(crate) secret_share: SecretShare,
    pub(crate) public_key: IndividualPublicKey,
    pub(crate) group_key: RistrettoPoint,
}

/// A participant in a threshold signing.
#[derive(Clone, Debug)]
pub struct Participant {
    /// The index of this participant, to keep the participants in order.
    pub index: u32,
    /// A vector of Pedersen commitments to the coefficients of this
    /// participant's private polynomial.
    pub commitments: Vec<RistrettoPoint>,
    /// The zero-knowledge proof of knowledge of the secret key (a.k.a. the
    /// first coefficient in the private polynomial).  It is constructed as a
    /// Schnorr signature using \\( a_{i0} \\) as the signing key.
    pub proof_of_secret_key: NizkOfSecretKey,
}

impl Participant {
    /// Have a trusted dealer generate all participants' key material and
    /// associated commitments for distribution to the participants.
    ///
    /// # Warning
    ///use rand_core::{CryptoRng, RngCore};
    /// Each participant MUST verify with all other n-1 participants that the
    /// [`VerifiableSecretSharingCommitment`] given to them by the dealer is
    /// identical.  Otherwise, the participants' secret shares could be formed
    /// with respect to different polynomials and they will fail to create
    /// threshold signatures which validate.
    pub fn dealer<R: RngCore + CryptoRng>(
        parameters: &Parameters,
        rng: &mut R,
    ) -> (Vec<DealtParticipant>, VerifiableSecretSharingCommitment) {
        let mut secret_bytes = [0u8; 64];
        rng.fill_bytes(&mut secret_bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);

        generate_shares(parameters, secret, rng)
    }

    /// Construct a new participant for the distributed key generation protocol.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`Parameters`], and
    /// * This participant's `index`.
    ///
    /// # Usage
    ///
    /// After a new participant is constructed, the `participant.index`,
    /// `participant.commitments`, and `participant.proof_of_secret_key` should
    /// be sent to every other participant in the protocol.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`] and that
    /// participant's secret polynomial `Coefficients` which must be kept
    /// private.
    pub fn new<R: RngCore + CryptoRng>(
        parameters: &Parameters,
        index: u32,
        rng: &mut R,
    ) -> (Self, Coefficients) {
        // Step 1: Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)})
        //         uniformly in ZZ_q, and uses these values as coefficients to define a
        //         polynomial f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^{j} of degree t-1 over
        //         ZZ_q.
        let t: usize = parameters.t as usize;
        let mut coefficients: Vec<Scalar> = Vec::with_capacity(t);
        let mut commitments: Vec<RistrettoPoint> = Vec::with_capacity(t);

        for _ in 0..t {
            let mut bytes = [0u8; 64];
            rng.fill_bytes(&mut bytes);
            coefficients.push(Scalar::from_bytes_mod_order_wide(&bytes));
        }

        let coefficients = Coefficients(coefficients);

        // Step 3: Every participant P_i computes a public commitment
        //         C_i = [\phi_{i0}, ..., \phi_{i(t-1)}], where \phi_{ij} = g^{a_{ij}},
        //         0 ≤ j ≤ t-1.
        for j in 0..t {
            commitments.push(&coefficients.0[j] * RISTRETTO_BASEPOINT_TABLE);
        }

        // Yes, I know the steps are out of order.  It saves one scalar multiplication.

        // Step 2: Every P_i computes a proof of knowledge to the corresponding secret
        //         a_{i0} by calculating a Schnorr signature \alpha_i = (s, R).  (In
        //         the FROST paper: \alpha_i = (\mu_i, c_i), but we stick with Schnorr's
        //         original notation here.)
        let proof: NizkOfSecretKey =
            NizkOfSecretKey::prove(&index, &coefficients.0[0], &commitments[0], rng);

        // Step 4: Every participant P_i broadcasts C_i, \alpha_i to all other participants.
        (
            Participant {
                index,
                commitments,
                proof_of_secret_key: proof,
            },
            coefficients,
        )
    }

    /// Retrieve \\( \alpha_{i0} * B \\), where \\( B \\) is the Ristretto basepoint.
    ///
    /// This is used to pass into the final call to `DistributedKeyGeneration::<RoundTwo>.finish()`.
    pub fn public_key(&self) -> Option<&RistrettoPoint> {
        if !self.commitments.is_empty() {
            return Some(&self.commitments[0]);
        }
        None
    }
}

fn generate_shares<R: RngCore + CryptoRng>(
    parameters: &Parameters,
    secret: Scalar,
    rng: &mut R,
) -> (Vec<DealtParticipant>, VerifiableSecretSharingCommitment) {
    let mut participants: Vec<DealtParticipant> = Vec::with_capacity(parameters.n as usize);

    // STEP 1: Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)})
    //         uniformly in ZZ_q, and uses these values as coefficients to define a
    //         polynomial f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^{j} of degree t-1 over
    //         ZZ_q.
    let t: usize = parameters.t as usize;
    let mut coefficients: Vec<Scalar> = Vec::with_capacity(t as usize);
    let mut commitment = VerifiableSecretSharingCommitment(Vec::with_capacity(t as usize));

    coefficients.push(secret);
    for _ in 0..t - 1 {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        coefficients.push(Scalar::from_bytes_mod_order_wide(&bytes));
    }

    let coefficients = Coefficients(coefficients);

    // Step 3: Every participant P_i computes a public commitment
    //         C_i = [\phi_{i0}, ..., \phi_{i(t-1)}], where \phi_{ij} = g^{a_{ij}},
    //         0 ≤ j ≤ t-1.
    for j in 0..t {
        commitment
            .0
            .push(&coefficients.0[j] * RISTRETTO_BASEPOINT_TABLE);
    }

    // Generate secret shares here
    let group_key = &coefficients.0[0] * RISTRETTO_BASEPOINT_TABLE;

    // Only one polynomial because dealer, then secret shards are dependent upon index.
    for i in 1..parameters.n + 1 {
        let secret_share = SecretShare::evaluate_polynomial(&i, &coefficients);
        let public_key = IndividualPublicKey {
            index: i,
            share: &secret_share.polynomial_evaluation * RISTRETTO_BASEPOINT_TABLE,
        };

        participants.push(DealtParticipant {
            secret_share,
            public_key,
            group_key,
        });
    }
    (participants, commitment)
}

impl PartialOrd for Participant {
    fn partial_cmp(&self, other: &Participant) -> Option<Ordering> {
        match self.index.cmp(&other.index) {
            Ordering::Less => Some(Ordering::Less),
            Ordering::Equal => None, // Participants cannot have the same index.
            Ordering::Greater => Some(Ordering::Greater),
        }
    }
}

impl PartialEq for Participant {
    fn eq(&self, other: &Participant) -> bool {
        self.index == other.index
    }
}

/// Module to implement trait sealing so that `DkgState` cannot be
/// implemented for externally declared types.
mod private {
    pub trait Sealed {}

    impl Sealed for super::RoundOne {}
    impl Sealed for super::RoundTwo {}
}

/// State machine structures for holding intermediate values during a
/// distributed key generation protocol run, to prevent misuse.
#[derive(Clone, Debug)]
pub struct DistributedKeyGeneration<S: DkgState> {
    state: Box<ActualState>,
    data: S,
}

/// Shared state which occurs across all rounds of a threshold signing protocol run.
#[derive(Clone, Debug)]
struct ActualState {
    /// The parameters for this instantiation of a threshold signature.
    parameters: Parameters,
    /// A vector of tuples containing the index of each participant and that
    /// respective participant's commitments to their private polynomial
    /// coefficients.
    their_commitments: Vec<(u32, VerifiableSecretSharingCommitment)>,
    /// A secret share for this participant.
    my_secret_share: SecretShare,
    /// The secret shares this participant has calculated for all the other participants.
    their_secret_shares: Option<Vec<SecretShare>>,
    /// The secret shares this participant has received from all the other participants.
    my_secret_shares: Option<Vec<SecretShare>>,
}

/// Marker trait to designate valid rounds in the distributed key generation
/// protocol's state machine.  It is implemented using the [sealed trait design
/// pattern][sealed] pattern to prevent external types from implementing further
/// valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait DkgState: private::Sealed {}

impl DkgState for RoundOne {}
impl DkgState for RoundTwo {}

/// Marker trait to designate valid variants of [`RoundOne`] in the distributed
/// key generation protocol's state machine.  It is implemented using the
/// [sealed trait design pattern][sealed] pattern to prevent external types from
/// implementing further valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Round1: private::Sealed {}

/// Marker trait to designate valid variants of [`RoundTwo`] in the distributed
/// key generation protocol's state machine.  It is implemented using the
/// [sealed trait design pattern][sealed] pattern to prevent external types from
/// implementing further valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Round2: private::Sealed {}

impl Round1 for RoundOne {}
impl Round2 for RoundTwo {}

/// Every participant in the distributed key generation has sent a vector of
/// commitments and a zero-knowledge proof of a secret key to every other
/// participant in the protocol.  During round one, each participant checks the
/// zero-knowledge proofs of secret keys of all other participants.
#[derive(Clone, Debug)]
pub struct RoundOne {}

impl DistributedKeyGeneration<RoundOne> {
    /// Check the zero-knowledge proofs of knowledge of secret keys of all the
    /// other participants.
    ///
    /// # Note
    ///
    /// The `participants` will be sorted by their indices.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new(
        parameters: &Parameters,
        my_index: &u32,
        my_coefficients: &Coefficients,
        other_participants: &mut Vec<Participant>,
    ) -> Result<Self, Vec<u32>> {
        let mut their_commitments: Vec<(u32, VerifiableSecretSharingCommitment)> =
            Vec::with_capacity(parameters.t as usize);
        let mut misbehaving_participants: Vec<u32> = Vec::new();

        // Bail if we didn't get enough participants.
        if other_participants.len() != parameters.n as usize - 1 {
            return Err(misbehaving_participants);
        }

        // Step 5: Upon receiving C_l, \sigma_l from participants 1 \le l \le n, l \ne i,
        //         participant P_i verifies \sigma_l = (s_l, r_l), by checking:
        //
        //         s_l ?= H(l, \Phi, \phi_{l0}, g^{r_l} \mdot \phi_{l0}^{-s_i})
        for p in other_participants.iter() {
            let public_key = match p.commitments.get(0) {
                Some(key) => key,
                None => {
                    misbehaving_participants.push(p.index);
                    continue;
                }
            };
            match p.proof_of_secret_key.verify(&p.index, &public_key) {
                Ok(_) => their_commitments.push((
                    p.index,
                    VerifiableSecretSharingCommitment(p.commitments.clone()),
                )),
                Err(_) => misbehaving_participants.push(p.index),
            }
        }

        // [DIFFERENT_TO_PAPER] If any participant was misbehaving, return their indices.
        if !misbehaving_participants.is_empty() {
            return Err(misbehaving_participants);
        }

        // [DIFFERENT_TO_PAPER] We pre-calculate the secret shares from Round 2
        // Step 1 here since it doesn't require additional online activity.
        //
        // Round 2
        // Step 1: Each P_i securely sends to each other participant P_l a secret share
        //         (l, f_i(l)) and keeps (i, f_i(i)) for themselves.
        let mut their_secret_shares: Vec<SecretShare> =
            Vec::with_capacity(parameters.n as usize - 1);

        // XXX need a way to index their_secret_shares
        for p in other_participants.iter() {
            their_secret_shares.push(SecretShare::evaluate_polynomial(&p.index, my_coefficients));
        }

        let my_secret_share = SecretShare::evaluate_polynomial(my_index, my_coefficients);
        let state = ActualState {
            parameters: *parameters,
            their_commitments,
            my_secret_share,
            their_secret_shares: Some(their_secret_shares),
            my_secret_shares: None,
        };

        Ok(DistributedKeyGeneration::<RoundOne> {
            state: Box::new(state),
            data: RoundOne {},
        })
    }

    /// Retrieve a secret share for each other participant, to be given to them
    /// at the end of `DistributedKeyGeneration::<RoundOne>`.
    pub fn their_secret_shares(&self) -> Result<&Vec<SecretShare>, ()> {
        self.state.their_secret_shares.as_ref().ok_or(())
    }

    /// Progress to round two of the DKG protocol once we have sent each share
    /// from `DistributedKeyGeneration::<RoundOne>.their_secret_shares()` to its
    /// respective other participant, and collected our shares from the other
    /// participants in turn.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_round_two(
        mut self,
        my_secret_shares: Vec<SecretShare>,
    ) -> Result<DistributedKeyGeneration<RoundTwo>, ()> {
        // Zero out the other participants secret shares from memory.
        if let Some(mut shares) = self.state.their_secret_shares.take() {
            for share in shares.iter_mut() {
                share.polynomial_evaluation = Scalar::ZERO;
            }
        }

        if my_secret_shares.len() != self.state.parameters.n as usize - 1 {
            return Err(());
        }

        // Step 2: Each P_i verifies their shares by calculating:
        //         g^{f_l(i)} ?= \Prod_{k=0}^{t-1} \phi_{lk}^{i^{k} mod q},
        //         aborting if the check fails.
        for share in my_secret_shares.iter() {
            // XXX TODO implement sorting for SecretShare and also for a new Commitment type
            for (index, commitment) in self.state.their_commitments.iter() {
                if index == &share.index {
                    share.verify(commitment)?;
                }
            }
        }
        self.state.my_secret_shares = Some(my_secret_shares);

        Ok(DistributedKeyGeneration::<RoundTwo> {
            state: self.state,
            data: RoundTwo {},
        })
    }
}

/// A secret share calculated by evaluating a polynomial with secret
/// coefficients for some indeterminant.
#[derive(Clone, Debug)]
pub struct SecretShare {
    /// The participant index that this secret share was calculated for.
    pub index: u32,
    /// The final evaluation of the polynomial for the participant-respective
    /// indeterminant.
    pub(crate) polynomial_evaluation: Scalar,
}

impl SecretShare {
    /// Evaluate the polynomial, `f(x)` for the secret coefficients at the value of `x`.
    //
    // XXX [PAPER] [CFRG] The participant index CANNOT be 0, or the secret share ends up being Scalar::zero().
    pub(crate) fn evaluate_polynomial(index: &u32, coefficients: &Coefficients) -> SecretShare {
        let term: Scalar = Scalar::from(*index);
        let mut sum: Scalar = Scalar::ZERO;

        // Evaluate using Horner's method.
        for (idx, coefficient) in coefficients.0.iter().rev().enumerate() {
            // The secret is the constant term in the polynomial
            sum += coefficient;

            if idx != (coefficients.0.len() - 1) {
                sum *= term;
            }
        }
        SecretShare {
            index: *index,
            polynomial_evaluation: sum,
        }
    }

    /// Verify that this secret share was correctly computed w.r.t. some secret
    /// polynomial coefficients attested to by some `commitment`.
    pub(crate) fn verify(&self, commitment: &VerifiableSecretSharingCommitment) -> Result<(), ()> {
        let lhs = &self.polynomial_evaluation * RISTRETTO_BASEPOINT_TABLE;
        let term: Scalar = Scalar::from(self.index);
        let mut rhs: RistrettoPoint = RistrettoPoint::identity();

        for (index, com) in commitment.0.iter().rev().enumerate() {
            rhs += com;

            if index != (commitment.0.len() - 1) {
                rhs *= term;
            }
        }

        match lhs.compress() == rhs.compress() {
            true => Ok(()),
            false => Err(()),
        }
    }
}

/// During round two each participant verifies their secret shares they received
/// from each other participant.
#[derive(Clone, Debug)]
pub struct RoundTwo {}

impl DistributedKeyGeneration<RoundTwo> {
    /// Calculate this threshold signing protocol participant's long-lived
    /// secret signing keyshare and the group's public verification key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (group_key, secret_key) = state.finish(participant.public_key()?)?;
    /// ```
    pub fn finish(mut self, my_commitment: &RistrettoPoint) -> Result<(GroupKey, SecretKey), ()> {
        let secret_key = self.calculate_signing_key()?;
        let group_key = self.calculate_group_key(my_commitment)?;

        // Zero out secret shares from memory
        self.state.my_secret_share.polynomial_evaluation = Scalar::ZERO;
        if let Some(ref mut shares) = self.state.my_secret_shares {
            for share in shares.iter_mut() {
                share.polynomial_evaluation = Scalar::ZERO;
            }
        }

        Ok((group_key, secret_key))
    }

    /// Calculate this threshold signing participant's long-lived secret signing
    /// key by summing all of the polynomial evaluations from the other
    /// participants.
    pub(crate) fn calculate_signing_key(&self) -> Result<SecretKey, ()> {
        let my_secret_shares = self.state.my_secret_shares.as_ref().ok_or(())?;
        let mut key = my_secret_shares
            .iter()
            .map(|x| x.polynomial_evaluation)
            .sum();

        key += self.state.my_secret_share.polynomial_evaluation;

        Ok(SecretKey {
            index: self.state.my_secret_share.index,
            key,
        })
    }

    /// Calculate the group public key used for verifying threshold signatures.
    ///
    /// # Returns
    ///
    /// A [`GroupKey`] for the set of participants.
    pub(crate) fn calculate_group_key(
        &self,
        my_commitment: &RistrettoPoint,
    ) -> Result<GroupKey, ()> {
        let mut keys: Vec<RistrettoPoint> = Vec::with_capacity(self.state.parameters.n as usize);

        for commitment in self.state.their_commitments.iter() {
            match commitment.1 .0.get(0) {
                Some(key) => keys.push(*key),
                None => return Err(()),
            }
        }
        keys.push(*my_commitment);

        Ok(GroupKey(keys.iter().sum()))
    }
}

/// A public verification share for a participant.
///
/// Any participant can recalculate the public verification share, which is the
/// public half of a [`SecretKey`], of any other participant in the protocol.
#[derive(Clone, Debug)]
pub struct IndividualPublicKey {
    /// The participant index to which this key belongs.
    pub index: u32,
    /// The public verification share.
    pub share: RistrettoPoint,
}

impl IndividualPublicKey {
    /// Any participant can compute the public verification share of any other participant.
    ///
    /// This is done by re-computing each [`IndividualPublicKey`] as \\(Y\_i\\) s.t.:
    ///
    /// \\[
    /// Y\_i = \prod\_{j=1}^{n} \prod\_{k=0}^{t-1} \phi\_{jk}^{i^{k} \mod q}
    /// \\]
    ///
    /// for each [`Participant`] index \\(i\\).
    ///
    /// # Inputs
    ///
    /// * The [`Parameters`] of this threshold signing instance, and
    /// * A vector of `commitments` regarding the secret polynomial
    ///   [`Coefficients`] that this [`IndividualPublicKey`] was generated with.
    ///
    /// # Returns
    ///
    /// A `Result` with either an empty `Ok` or `Err` value, depending on
    /// whether or not the verification was successful.
    #[allow(unused)]
    pub fn verify(
        &self,
        parameters: &Parameters,
        commitments: &[RistrettoPoint],
    ) -> Result<(), ()> {
        let rhs = RistrettoPoint::identity();

        for j in 1..parameters.n {
            for k in 0..parameters.t {
                // XXX ah shit we need the incoming commitments to be sorted or have indices
            }
        }
        unimplemented!()
    }
}

/// A secret key, used by one participant in a threshold signature scheme, to sign a message.
#[derive(Debug)]
pub struct SecretKey {
    /// The participant index to which this key belongs.
    pub(crate) index: u32,
    /// The participant's long-lived secret share of the group signing key.
    pub(crate) key: Scalar,
}

impl SecretKey {
    /// Derive the corresponding public key for this secret key.
    pub fn to_public(&self) -> IndividualPublicKey {
        let share = &self.key * RISTRETTO_BASEPOINT_TABLE;

        IndividualPublicKey {
            index: self.index,
            share,
        }
    }
}

impl From<&SecretKey> for IndividualPublicKey {
    fn from(source: &SecretKey) -> IndividualPublicKey {
        source.to_public()
    }
}

/// A public key, used to verify a signature made by a threshold of a group of participants.
#[derive(Clone, Copy, Debug, Eq)]
pub struct GroupKey(pub(crate) RistrettoPoint);

impl PartialEq for GroupKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.compress() == other.0.compress()
    }
}

impl GroupKey {
    /// Serialise this group public key to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Deserialise this group public key from an array of bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<GroupKey, ()> {
        let point = CompressedRistretto(bytes).decompress().ok_or(())?;

        Ok(GroupKey(point))
    }
}

/// Calculate using Lagrange's method the interpolation of a polynomial.
///
/// # Note
///
/// isis stole this from Chelsea and Ian but they stole it from Lagrange, so who
/// can really say.
pub(crate) fn calculate_lagrange_coefficients(
    participant_index: &u32,
    all_participant_indices: &[u32],
) -> Result<Scalar, &'static str> {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    let mine = Scalar::from(*participant_index);

    for j in all_participant_indices.iter() {
        if j == participant_index {
            continue;
        }
        let s = Scalar::from(*j);

        num *= s;
        den *= s - mine; // Check to ensure that one person isn't trying to sign twice.
    }

    if den == Scalar::ZERO {
        return Err("Duplicate shares provided");
    }
    Ok(num * den.invert())
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;

    use crate::keygen::calculate_lagrange_coefficients;

    #[cfg(feature = "std")]
    use crate::precomputation::generate_commitment_share_lists;
    #[cfg(feature = "std")]
    use rand::rngs::OsRng;

    #[cfg(feature = "std")]
    use crate::signature::compute_message_hash;
    #[cfg(feature = "std")]
    use crate::signature::SignatureAggregator;

    /// Reconstruct the secret from enough (at least the threshold) already-verified shares.
    fn reconstruct_secret(participants: &Vec<&DealtParticipant>) -> Result<Scalar, &'static str> {
        let all_participant_indices: Vec<u32> =
            participants.iter().map(|p| p.public_key.index).collect();
        let mut secret = Scalar::ZERO;

        for this_participant in participants {
            let my_coeff = crate::keygen::calculate_lagrange_coefficients(
                &this_participant.public_key.index,
                &all_participant_indices,
            )?;

            secret += my_coeff * this_participant.secret_share.polynomial_evaluation;
        }
        Ok(secret)
    }

    #[test]
    fn nizk_of_secret_key() {
        let mut rng: OsRng = OsRng;
        let params = Parameters { n: 3, t: 2 };
        let (p, _) = Participant::new(&params, 0, &mut rng);
        let result = p.proof_of_secret_key.verify(&p.index, &p.commitments[0]);

        assert!(result.is_ok());
    }

    #[test]
    fn verify_secret_sharing_from_dealer() {
        let params = Parameters { n: 3, t: 2 };
        let mut rng: OsRng = OsRng;
        let mut secret_bytes = [0u8; 64];
        rng.fill_bytes(&mut secret_bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);
        let (participants, _commitment) = generate_shares(&params, secret, &mut rng);

        let mut subset_participants = Vec::new();
        for i in 0..params.t {
            subset_participants.push(&participants[i as usize]);
        }
        let supposed_secret = reconstruct_secret(&subset_participants);
        assert!(secret == supposed_secret.unwrap());
    }

    #[test]
    fn dkg_with_dealer() {
        let mut rng: OsRng = OsRng;
        let params = Parameters { t: 1, n: 2 };
        let (participants, commitment) = Participant::dealer(&params, &mut rng);
        let (_, commitment2) = Participant::dealer(&params, &mut rng);

        // Verify each of the participants' secret shares.
        for p in participants.iter() {
            let result = p.secret_share.verify(&commitment);

            assert!(
                result.is_ok(),
                "participant {} failed to receive a valid secret share",
                p.public_key.index
            );

            let result = p.secret_share.verify(&commitment2);

            assert!(
                !result.is_ok(),
                "Should not validate with invalid commitment"
            );
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn dkg_with_dealer_and_signing() {
        let mut rng: OsRng = OsRng;
        let params = Parameters { t: 1, n: 2 };
        let (participants, commitment) = Participant::dealer(&params, &mut rng);

        // Verify each of the participants' secret shares.
        for p in participants.iter() {
            let result = p.secret_share.verify(&commitment);

            assert!(
                result.is_ok(),
                "participant {} failed to receive a valid secret share",
                p.public_key.index
            );
        }

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, mut p2_secret_comshares) =
            generate_commitment_share_lists(&mut OsRng, 2, 1);

        let p1_sk = SecretKey {
            index: participants[0].secret_share.index,
            key: participants[0].secret_share.polynomial_evaluation,
        };
        let p2_sk = SecretKey {
            index: participants[1].secret_share.index,
            key: participants[1].secret_share.polynomial_evaluation,
        };

        let group_key = GroupKey(participants[0].group_key);

        let mut aggregator =
            SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p1_secret_comshares,
                0,
                signers,
            )
            .unwrap();
        let p2_partial = p2_sk
            .sign(
                &message_hash,
                &group_key,
                &mut p2_secret_comshares,
                0,
                signers,
            )
            .unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();

        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn secret_share_from_one_coefficients() {
        let mut coeffs: Vec<Scalar> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Scalar::ONE);
        }

        let coefficients = Coefficients(coeffs);
        let share = SecretShare::evaluate_polynomial(&1, &coefficients);

        assert!(share.polynomial_evaluation == Scalar::from(5u32));

        let mut commitments = VerifiableSecretSharingCommitment(Vec::new());

        for i in 0..5 {
            commitments
                .0
                .push(&coefficients.0[i] * RISTRETTO_BASEPOINT_TABLE);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn secret_share_participant_index_zero() {
        let mut coeffs: Vec<Scalar> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Scalar::ONE);
        }

        let coefficients = Coefficients(coeffs);
        let share = SecretShare::evaluate_polynomial(&0, &coefficients);

        assert!(share.polynomial_evaluation == Scalar::ONE);

        let mut commitments = VerifiableSecretSharingCommitment(Vec::new());

        for i in 0..5 {
            commitments
                .0
                .push(&coefficients.0[i] * RISTRETTO_BASEPOINT_TABLE);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn single_party_keygen() {
        let mut rng: OsRng = OsRng;
        let params = Parameters { n: 1, t: 1 };
        let (p1, p1coeffs) = Participant::new(&params, 1, &mut rng);

        p1.proof_of_secret_key
            .verify(&p1.index, &p1.commitments[0])
            .unwrap();

        let mut p1_other_participants: Vec<Participant> = Vec::new();
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(
            &params,
            &p1.index,
            &p1coeffs,
            &mut p1_other_participants,
        )
        .unwrap();
        let p1_my_secret_shares = Vec::new();
        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let result = p1_state.finish(p1.public_key().unwrap());

        assert!(result.is_ok());

        let (p1_group_key, p1_secret_key) = result.unwrap();

        assert!(
            p1_group_key.0.compress()
                == (&p1_secret_key.key * RISTRETTO_BASEPOINT_TABLE).compress()
        );
    }

    #[test]
    fn keygen_3_out_of_5() {
        let mut rng: OsRng = OsRng;
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1, &mut rng);
        let (p2, p2coeffs) = Participant::new(&params, 2, &mut rng);
        let (p3, p3coeffs) = Participant::new(&params, 3, &mut rng);
        let (p4, p4coeffs) = Participant::new(&params, 4, &mut rng);
        let (p5, p5coeffs) = Participant::new(&params, 5, &mut rng);

        p1.proof_of_secret_key
            .verify(&p1.index, &p1.public_key().unwrap())
            .unwrap();
        p2.proof_of_secret_key
            .verify(&p2.index, &p2.public_key().unwrap())
            .unwrap();
        p3.proof_of_secret_key
            .verify(&p3.index, &p3.public_key().unwrap())
            .unwrap();
        p4.proof_of_secret_key
            .verify(&p4.index, &p4.public_key().unwrap())
            .unwrap();
        p5.proof_of_secret_key
            .verify(&p5.index, &p5.public_key().unwrap())
            .unwrap();

        let mut p1_other_participants: Vec<Participant> =
            vec![p2.clone(), p3.clone(), p4.clone(), p5.clone()];
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(
            &params,
            &p1.index,
            &p1coeffs,
            &mut p1_other_participants,
        )
        .unwrap();
        let p1_their_secret_shares = p1_state.their_secret_shares().unwrap();

        let mut p2_other_participants: Vec<Participant> =
            vec![p1.clone(), p3.clone(), p4.clone(), p5.clone()];
        let p2_state = DistributedKeyGeneration::<RoundOne>::new(
            &params,
            &p2.index,
            &p2coeffs,
            &mut p2_other_participants,
        )
        .unwrap();
        let p2_their_secret_shares = p2_state.their_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> =
            vec![p1.clone(), p2.clone(), p4.clone(), p5.clone()];
        let p3_state = DistributedKeyGeneration::<RoundOne>::new(
            &params,
            &p3.index,
            &p3coeffs,
            &mut p3_other_participants,
        )
        .unwrap();
        let p3_their_secret_shares = p3_state.their_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> =
            vec![p1.clone(), p2.clone(), p3.clone(), p5.clone()];
        let p4_state = DistributedKeyGeneration::<RoundOne>::new(
            &params,
            &p4.index,
            &p4coeffs,
            &mut p4_other_participants,
        )
        .unwrap();
        let p4_their_secret_shares = p4_state.their_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> =
            vec![p1.clone(), p2.clone(), p3.clone(), p4.clone()];
        let p5_state = DistributedKeyGeneration::<RoundOne>::new(
            &params,
            &p5.index,
            &p5coeffs,
            &mut p5_other_participants,
        )
        .unwrap();
        let p5_their_secret_shares = p5_state.their_secret_shares().unwrap();

        let p1_my_secret_shares = vec![
            p2_their_secret_shares[0].clone(), // XXX FIXME indexing
            p3_their_secret_shares[0].clone(),
            p4_their_secret_shares[0].clone(),
            p5_their_secret_shares[0].clone(),
        ];

        let p2_my_secret_shares = vec![
            p1_their_secret_shares[0].clone(),
            p3_their_secret_shares[1].clone(),
            p4_their_secret_shares[1].clone(),
            p5_their_secret_shares[1].clone(),
        ];

        let p3_my_secret_shares = vec![
            p1_their_secret_shares[1].clone(),
            p2_their_secret_shares[1].clone(),
            p4_their_secret_shares[2].clone(),
            p5_their_secret_shares[2].clone(),
        ];

        let p4_my_secret_shares = vec![
            p1_their_secret_shares[2].clone(),
            p2_their_secret_shares[2].clone(),
            p3_their_secret_shares[2].clone(),
            p5_their_secret_shares[3].clone(),
        ];

        let p5_my_secret_shares = vec![
            p1_their_secret_shares[3].clone(),
            p2_their_secret_shares[3].clone(),
            p3_their_secret_shares[3].clone(),
            p4_their_secret_shares[3].clone(),
        ];

        let p1_state = p1_state.to_round_two(p1_my_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_secret_shares).unwrap();

        let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.public_key().unwrap()).unwrap();
        let (p2_group_key, _p2_secret_key) = p2_state.finish(p2.public_key().unwrap()).unwrap();
        let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.public_key().unwrap()).unwrap();
        let (p4_group_key, _p4_secret_key) = p4_state.finish(p4.public_key().unwrap()).unwrap();
        let (p5_group_key, _p5_secret_key) = p5_state.finish(p5.public_key().unwrap()).unwrap();

        assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
        assert!(p2_group_key.0.compress() == p3_group_key.0.compress());
        assert!(p3_group_key.0.compress() == p4_group_key.0.compress());
        assert!(p4_group_key.0.compress() == p5_group_key.0.compress());

        assert!(
            p5_group_key.0.compress()
                == (p1.public_key().unwrap()
                    + p2.public_key().unwrap()
                    + p3.public_key().unwrap()
                    + p4.public_key().unwrap()
                    + p5.public_key().unwrap())
                .compress()
        );
    }

    #[test]
    fn keygen_2_out_of_3() {
        fn do_test() -> Result<(), ()> {
            let mut rng: OsRng = OsRng;
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs) = Participant::new(&params, 1, &mut rng);
            let (p2, p2coeffs) = Participant::new(&params, 2, &mut rng);
            let (p3, p3coeffs) = Participant::new(&params, 3, &mut rng);

            p1.proof_of_secret_key
                .verify(&p1.index, &p1.public_key().unwrap())?;
            p2.proof_of_secret_key
                .verify(&p2.index, &p2.public_key().unwrap())?;
            p3.proof_of_secret_key
                .verify(&p3.index, &p3.public_key().unwrap())?;

            let mut p1_other_participants: Vec<Participant> = vec![p2.clone(), p3.clone()];
            let p1_state = DistributedKeyGeneration::<RoundOne>::new(
                &params,
                &p1.index,
                &p1coeffs,
                &mut p1_other_participants,
            )
            .or(Err(()))?;
            let p1_their_secret_shares = p1_state.their_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec![p1.clone(), p3.clone()];
            let p2_state = DistributedKeyGeneration::<RoundOne>::new(
                &params,
                &p2.index,
                &p2coeffs,
                &mut p2_other_participants,
            )
            .or(Err(()))?;
            let p2_their_secret_shares = p2_state.their_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec![p1.clone(), p2.clone()];
            let p3_state = DistributedKeyGeneration::<RoundOne>::new(
                &params,
                &p3.index,
                &p3coeffs,
                &mut p3_other_participants,
            )
            .or(Err(()))?;
            let p3_their_secret_shares = p3_state.their_secret_shares()?;

            let p1_my_secret_shares = vec![
                p2_their_secret_shares[0].clone(), // XXX FIXME indexing
                p3_their_secret_shares[0].clone(),
            ];
            let p2_my_secret_shares = vec![
                p1_their_secret_shares[0].clone(),
                p3_their_secret_shares[1].clone(),
            ];
            let p3_my_secret_shares = vec![
                p1_their_secret_shares[1].clone(),
                p2_their_secret_shares[1].clone(),
            ];

            let p1_state = p1_state.to_round_two(p1_my_secret_shares)?;
            let p2_state = p2_state.to_round_two(p2_my_secret_shares)?;
            let p3_state = p3_state.to_round_two(p3_my_secret_shares)?;

            let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.public_key().unwrap())?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish(p2.public_key().unwrap())?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.public_key().unwrap())?;

            assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
            assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

            Ok(())
        }
        assert!(do_test().is_ok());
    }
}
