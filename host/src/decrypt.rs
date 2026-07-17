use std::iter::zip;
use ecies::{PublicKey, SecretKey, decrypt, utils::generate_keypair};
use crate::{RawShare, Error, DEFAULT_N};

/// Generates [`DEFAULT_N`] Ecies keypairs
pub fn generate_n_keys() -> Result<(Vec<SecretKey>, Vec<PublicKey>), Error> {
    let mut party_pks: Vec<PublicKey> = Vec::new();
    let mut party_sks: Vec<SecretKey> = Vec::new();
    for _ in 0..DEFAULT_N {
        let (sk_i, pk_i) = generate_keypair();
        party_sks.push(sk_i);
        party_pks.push(pk_i);
    }
    Ok((party_sks, party_pks))
}

/// Given [`DEFAULT_N`] Ecies encrypted shares and secret keys, returns decrypted [`raw shares`][`RawShare`]
/// 
/// Requires `len(enc_shares) == len(party_sks) == `[`DEFAULT_N`]
pub fn decrypt_shares(enc_shares: &Vec<Vec<u8>>, party_sks: &Vec<&[u8]>) -> Result<Vec<RawShare>, Error> {
    assert!(enc_shares.len() == party_sks.len() && enc_shares.len() == DEFAULT_N);
    let mut raw_shares: Vec<RawShare> = Vec::new();
    for (share_i, sk_i) in zip(enc_shares, party_sks) {
        let share_i = decrypt(*sk_i, share_i).map_err(|_| Error::Ecies)?;
        let share_i: RawShare = serde_cbor::from_slice(&share_i)?;
        raw_shares.push(share_i);
    }
    Ok(raw_shares)
}