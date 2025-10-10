// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Zero-knowledge proofs.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_core::CryptoRng;
use rand_core::RngCore;

use sha2::Digest;
use sha2::Sha512;

/// A proof of knowledge of a secret key, created by making a Schnorr signature
/// with the secret key.
///
/// This proof is created by making a pseudo-Schnorr signature,
/// \\( \sigma\_i = (s\_i, r\_i) \\) using \\( a\_{i0} \\) (from
/// `frost_dalek::keygen::DistributedKeyGeneration::<RoundOne>::compute_share`)
/// as the secret key, such that \\( k \stackrel{\\$}{\leftarrow} \mathbb{Z}\_q \\),
/// \\( M\_i = g^k \\), \\( s\_i = \mathcal{H}(i, \phi, g^{a\_{i0}}, M\_i) \\),
/// \\( r\_i = k + a\_{i0} \cdot s\_i \\).
///
/// Verification is done by calculating \\(M'\_i = g^r + A\_i^{-s}\\),
/// where \\(A\_i = g^{a_i}\\), and using it to compute
/// \\(s'\_i = \mathcal{H}(i, \phi, A\_i, M'\_i)\\), then finally
/// \\(s\_i \stackrel{?}{=} s'\_i\\).
#[derive(Clone, Debug, Default)]
pub struct NizkOfSecretKey {
    /// The scalar portion of the Schnorr signature encoding the context.
    s: Scalar,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    r: Scalar,
}

impl NizkOfSecretKey {
    /// Prove knowledge of a secret key.
    pub fn prove<R: RngCore + CryptoRng>(
        index: &u32,
        secret_key: &Scalar,
        public_key: &RistrettoPoint,
        rng: &mut R,
    ) -> Self {
        let mut k_bytes = [0u8; 64];
        rng.fill_bytes(&mut k_bytes);
        let k: Scalar = Scalar::from_bytes_mod_order_wide(&k_bytes);
        let M: RistrettoPoint = &k * RISTRETTO_BASEPOINT_TABLE;

        let mut hram = Sha512::new();

        hram.update(index.to_be_bytes());
        hram.update("Φ");
        hram.update(public_key.compress().as_bytes());
        hram.update(M.compress().as_bytes());

        let hash_output = hram.finalize();
        let mut s_bytes = [0u8; 64];
        s_bytes.copy_from_slice(&hash_output);
        let s = Scalar::from_bytes_mod_order_wide(&s_bytes);
        let r = k + (secret_key * s);

        NizkOfSecretKey { s, r }
    }

    /// Verify that the prover does indeed know the secret key.
    pub fn verify(&self, index: &u32, public_key: &RistrettoPoint) -> Result<(), ()> {
        let M_prime: RistrettoPoint =
            (&self.r * RISTRETTO_BASEPOINT_TABLE) + (public_key * -&self.s);

        let mut hram = Sha512::new();

        hram.update(index.to_be_bytes());
        hram.update("Φ");
        hram.update(public_key.compress().as_bytes());
        hram.update(M_prime.compress().as_bytes());

        let hash_output = hram.finalize();
        let mut s_prime_bytes = [0u8; 64];
        s_prime_bytes.copy_from_slice(&hash_output);
        let s_prime = Scalar::from_bytes_mod_order_wide(&s_prime_bytes);

        if self.s == s_prime {
            return Ok(());
        }

        Err(())
    }
}
