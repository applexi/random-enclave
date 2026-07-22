//! Given arithmetic and binary sharings, a [`TryCryptoRng`], and [`DEFAULT_N`] public keys, generates [`DEFAULT_N`] correlated random signed encrypted arithmetic and binary shares
//! 
//! This module contains:
//! - Generate a random and its arithmetic and binary shares, and a random signing keypair
//! - Helper functions to encrypt and then sign those shares given [`DEFAULT_N`] public keys
//! - Tests to check scheme correctness

#[cfg(test)]
mod tests;

use rand::{TryCryptoRng, rand_core::UnwrapErr};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ecies::encrypt;

use crate::{ArithmeticSharing, BinarySharing, RawShare, ArithShare, BitShare, DEFAULT_N};
use crate::random_arith;
use crate::Error;

/// For each call, generates a random signing keypair and secret [`ArithShare`]. From that secret, returns signed correlated arithmetic and binary shares.
pub fn enclave_session<R: TryCryptoRng> (arithmetic: &ArithmeticSharing, binary: &BinarySharing, rng: &mut R, party_pks: &Vec<&[u8]>) -> Result<(VerifyingKey, Vec<Signature>, Vec<Vec<u8>>), Error> {
    // Generate random public and private signing keypair
    let mut infallible_rng = UnwrapErr(rng);
    let enclave_keypair = SigningKey::generate(&mut infallible_rng);
    let enclave_pk = enclave_keypair.verifying_key();

    // Generate random ArithShare and get correlated arithmetic and binary shares
    let shares_raw = generate_randoms(arithmetic, binary, &mut infallible_rng)?;

    // Encrypt shares with each party's public key respectively
    let shares_enc = encrypt_shares(&shares_raw, party_pks)?;

    // Sign each party's share
    let shares_signed = sign_shares(&shares_enc, enclave_keypair)?;
    Ok((enclave_pk, shares_signed, shares_enc))
}

/// Generates a random [`ArithShare`] and returns [`DEFAULT_N`] correlated arithmetic and binary shares in indexed form
fn generate_randoms<R: TryCryptoRng> (arithmetic: &ArithmeticSharing, binary: &BinarySharing, rng: &mut R) -> Result<Vec<RawShare>, Error> {
    let secret = random_arith(rng).map_err(|_| Error::Rng)?;
    let num_bits = ArithShare::BITS;
    let secret_bits: Vec<BitShare> = (0..num_bits).map(|i| (secret >> i) & 1 == 1).collect();
    let arith_shares = arithmetic.share(rng, secret).map_err(|_| Error::Rng)?;
    assert!(arithmetic.reconstruct(&arith_shares) == secret);

    let mut bit_shares = Vec::new();
    for &bit in secret_bits.iter() {
        let bitshares_i = binary.share(rng, bit).map_err(|_| Error::Rng)?;
        bit_shares.push(bitshares_i);
    }
    let shares = (0..DEFAULT_N)
        .map( |i| {
            let ct_i = arith_shares[i];
            let ctbits_i : Vec<BitShare> = bit_shares.iter().map(|bits_j| bits_j[i]).collect();
            RawShare{ pt: ct_i, ptbits: ctbits_i }
        }).collect();
    Ok(shares)
}

fn encrypt_shares(shares_raw: &Vec<RawShare>, party_pks: &Vec<&[u8]>) -> Result<Vec<Vec<u8>>, Error> {
    assert!(shares_raw.len() == party_pks.len() && party_pks.len() == DEFAULT_N);
    let mut enc_shares: Vec<Vec<u8>> = Vec::new();
    for (share_i, pk_i) in std::iter::zip(shares_raw, party_pks) {
        let share_i = serde_cbor::to_vec(share_i)?;
        let share_i = encrypt(*pk_i, &share_i).map_err(|_| Error::Ecies)?;
        enc_shares.push(share_i);
    }
    Ok(enc_shares)
}

fn sign_shares(shares_enc: &Vec<Vec<u8>>, signing_key: SigningKey) -> Result<Vec<Signature>, serde_cbor::Error> {
    let mut shares_signed: Vec<Signature> = Vec::new();
    for share in shares_enc {
        shares_signed.push(signing_key.sign(&share));
    }
    Ok(shares_signed)
}