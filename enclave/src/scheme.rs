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

#[cfg(test)]
mod tests {
    const TIMES: u64 = 20;
    use std::collections::HashSet;

use super::*;
    use getrandom::SysRng;
    use ed25519_dalek::Verifier;
    use ecies::{PublicKey, SecretKey, decrypt, utils::generate_keypair};

    #[test]
    fn signing_correct_batch() {
        let arithmetic = ArithmeticSharing::new();
        let binary = BinarySharing::new();
        let mut rng = SysRng;
        let mut pk_cache: HashSet<VerifyingKey> = HashSet::new();

        for _ in 0..TIMES {
            let (party_sks, party_pks): (Vec<SecretKey>, Vec<PublicKey>) = (0..DEFAULT_N)
                .map(|_| generate_keypair())
                .unzip();
            let party_pks = party_pks
                .iter()
                .map(|pk| &pk.as_bytes()[..])
                .collect();
            let party_sks: Vec<&[u8]> = party_sks
                .iter()
                .map(|sk| &sk.as_bytes()[..])
                .collect();

            let Ok((enclave_pk, shares_signed, shares_enc)) = enclave_session(&arithmetic, &binary, &mut rng, &party_pks) else {
                panic!("Enclave_session did not return expected output")
            };
            // Enclave's public key should be randomly generated every time, and thus should be unique
            assert!(!pk_cache.contains(&enclave_pk));
            pk_cache.insert(enclave_pk);
            // Length of all shares should be N
            assert!(shares_enc.len() == shares_signed.len() && shares_enc.len() == DEFAULT_N);

            // Tests that all shares have been correctly encrypted and signed 
            for j in 0..DEFAULT_N {
                enclave_pk.verify(&shares_enc[j], &shares_signed[j])
                    .expect("Signing of share failed");

                decrypt(party_sks[j], &shares_enc[j])
                    .expect("Decrypting share failed");
            }
        }
    }

    fn generate_randoms_correct() -> Vec<RawShare>{
        let arithmetic = ArithmeticSharing::new();
        let binary = BinarySharing::new();
        let mut rng = SysRng;
        let shares = generate_randoms(&arithmetic, &binary, &mut rng)
            .expect("Function generate_randoms returned an error");
        // Function generate_randoms should return N shares
        assert!(shares.len() == DEFAULT_N);

        // Test arithmetic reconstruction is correct
        let arith_fold = shares
            .iter()
            .fold(0 as u64, |acc, RawShare{ pt: ct_i, .. }| acc.wrapping_add(*ct_i));
        let arith_shares: Vec<u64>   = shares
            .iter()
            .map(|RawShare{ pt: ct_i, .. }| *ct_i)
            .collect();
        let arith_recon = arithmetic.reconstruct(&arith_shares);
        assert!(arith_fold == arith_recon);

        let num_bits = ArithShare::BITS;
        let mut binary_recon: u64 = 0;
        for j in 0..num_bits {
            // Test each binary reconstruction is correct
            let binary_fold = shares  
                .iter()
                .fold(false, |acc, RawShare{ ptbits: ctbits_i, .. }| acc ^ ctbits_i[j as usize]);
            let binary_shares : Vec<bool> = shares
                .iter()
                .map(|RawShare{ ptbits: ctbits_i, .. }| ctbits_i[j as usize])
                .collect();
            let binary_recon_i = binary.reconstruct(&binary_shares);
            assert!(binary_fold == binary_recon_i);
            binary_recon = binary_recon | ((binary_recon_i as u64) << j);
        }
        
        // Test correlation is correct
        assert!(arith_recon == binary_recon);

        return shares;
    }

    #[test]
    fn generate_randoms_batch() {
        let mut shares_cache: HashSet<Vec<RawShare>> = HashSet::new();
        for _ in 0..TIMES {
            let share = generate_randoms_correct();
            // Shares should be randomly generated every time, and thus should be unique
            assert!(!shares_cache.contains(&share));
            shares_cache.insert(share);
        }
    }
}