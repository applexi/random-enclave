use super::*;
use std::collections::HashSet;
use getrandom::SysRng;
use ed25519_dalek::Verifier;
use crate::BenchmarkSelection;
use ecies::{PublicKey, SecretKey, decrypt, utils::generate_keypair};

const TIMES: u64 = 20;

#[test]
fn signing_correct_batch() {
    let mut logger = LogConstructor::new(BenchmarkSelection::None, 0);
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

        let Ok((enclave_pk, shares_signed, shares_enc)) = enclave_session(&arithmetic, &binary, &mut rng, &party_pks, &mut logger) else {
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
        let binary_fold: bool = shares  
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