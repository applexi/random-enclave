use rand::{TryCryptoRng, rand_core::UnwrapErr};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{ArithmeticSharing, BinarySharing, Share, ArithShare, BitShare, DEFAULT_N};
use crate::random_arith;
use crate::Error;

/// For each call, generates a random signing keypair and secret [`ArithShare`]. From that secret, returns signed correlated arithmetic and binary shares.
pub fn enclave_session<R: TryCryptoRng> (arithmetic: &ArithmeticSharing, binary: &BinarySharing, rng: &mut R) -> Result<(VerifyingKey, Vec<Signature>, Vec<Share>), Error> {
    // Generate random public and private signing keypair
    let mut infallible_rng = UnwrapErr(rng);
    let enclave_keypair = SigningKey::generate(&mut infallible_rng);
    let enclave_pk = enclave_keypair.verifying_key();

    // Generate random ArithShare and get correlated arithmetic and binary shares
    let shares_raw = generate_randoms(arithmetic, binary, &mut infallible_rng)?;

    // TODO: Encrypt shares 

    // Sign each party's share
    let shares_signed = sign_shares(&shares_raw, enclave_keypair)?;
    Ok((enclave_pk, shares_signed, shares_raw))
} 

/// Generates a random [`ArithShare`] and returns [`DEFAULT_N`] correlated arithmetic and binary shares in indexed form
fn generate_randoms<R: TryCryptoRng> (arithmetic: &ArithmeticSharing, binary: &BinarySharing, rng: &mut R) -> Result<Vec<Share>, Error> {
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
            Share{ ct: ct_i, ctbit: ctbits_i }
        }).collect();
    Ok(shares)
}

fn sign_shares(shares_raw: &Vec<Share>, signing_key: SigningKey) -> Result<Vec<Signature>, serde_cbor::Error> {
    let mut shares_signed: Vec<Signature> = Vec::new();
    for share in shares_raw {
        let share = serde_cbor::to_vec(&share)?;
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

    #[test]
    fn signing_correct_batch() {
        let arithmetic = ArithmeticSharing::new();
        let binary = BinarySharing::new();
        let mut rng = SysRng;
        let mut pk_cache: HashSet<VerifyingKey> = HashSet::new();

        for _ in 0..TIMES {
            let Ok((enclave_pk, shares_signed, shares_raw)) = enclave_session(&arithmetic, &binary, &mut rng) else {
                panic!("Enclave_session did not return expected output")
            };
            // Enclave's public key should be randomly generated every time, and thus should be unique
            assert!(!pk_cache.contains(&enclave_pk));
            pk_cache.insert(enclave_pk);
            // Length of all shares should be N
            assert!(shares_raw.len() == shares_signed.len() && shares_raw.len() == DEFAULT_N);

            // Tests that all shares have been correctly signed
            for j in 0..DEFAULT_N {
                let share_raw = serde_cbor::to_vec(&shares_raw[j])
                    .expect("Raw share serialization failed");
                let share_signed = &shares_signed[j];
                enclave_pk.verify(&share_raw, share_signed)
                    .expect("Signing of share failed");
            }
        }
    }

    fn generate_randoms_correct() -> Vec<Share>{
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
            .fold(0 as u64, |acc, Share{ ct: ct_i, .. }| acc.wrapping_add(*ct_i));
        let arith_shares: Vec<u64>   = shares
            .iter()
            .map(|Share{ ct: ct_i, .. }| *ct_i)
            .collect();
        let arith_recon = arithmetic.reconstruct(&arith_shares);
        assert!(arith_fold == arith_recon);

        let num_bits = ArithShare::BITS;
        let mut binary_recon: u64 = 0;
        for j in 0..num_bits {
            // Test each binary reconstruction is correct
            let binary_fold = shares  
                .iter()
                .fold(false, |acc, Share{ ctbit: ctbits_i, .. }| acc ^ ctbits_i[j as usize]);
            let binary_shares : Vec<bool> = shares
                .iter()
                .map(|Share{ ctbit: ctbits_i, .. }| ctbits_i[j as usize])
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
        let mut shares_cache: HashSet<Vec<Share>> = HashSet::new();
        for _ in 0..TIMES {
            let share = generate_randoms_correct();
            // Shares should be randomly generated every time, and thus should be unique
            assert!(!shares_cache.contains(&share));
            shares_cache.insert(share);
        }
    }
}