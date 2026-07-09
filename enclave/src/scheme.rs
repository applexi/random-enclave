use rand::TryCryptoRng;
use crate::{ArithmeticSharing, BinarySharing, DEFAULT_N};
use crate::{ArithShare, BitShare, random_arith};

/// Generates a random [`ArithShare`] and returns [`DEFAULT_N`] correlated arithmetic and binary shares in indexed form
pub fn enclave_session<R: TryCryptoRng> (arithmetic: &ArithmeticSharing, binary: &BinarySharing, rng: &mut R) -> Result<Vec<(ArithShare, Vec<BitShare>)>, R::Error> {
    let secret = random_arith(rng)?;
    let num_bits = ArithShare::BITS;
    println!("secret: {secret}");
    let secret_bits: Vec<BitShare> = (0..num_bits).map(|i| (secret >> i) & 1 == 1).collect();
    let arith_shares = arithmetic.share(rng, secret)?;
    assert!(arithmetic.reconstruct(&arith_shares) == secret);
    println!("arith shares: {arith_shares:?}");
    let mut bit_shares = Vec::new();
    for &bit in secret_bits.iter() {
        let bitshares_i = binary.share(rng, bit)?;
        bit_shares.push(bitshares_i);
    }
    let shares: Vec<(ArithShare, Vec<BitShare>)> = (0..DEFAULT_N)
        .map( |i| {
            let ct_i = arith_shares[i];
            let ctbits_i : Vec<BitShare> = bit_shares.iter().map(|bits_j| bits_j[i]).collect();
            (ct_i, ctbits_i)
        }).collect();
    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::SysRng;

    fn session_correct() {
        let arithmetic = ArithmeticSharing::new();
        let binary = BinarySharing::new();
        let mut rng = SysRng;
        let shares = enclave_session(&arithmetic, &binary, &mut rng)
            .expect("Function enclave_session returned an error");
        // Function enclave_session should return N shares
        assert!(shares.len() == DEFAULT_N);

        // Test arithmetic reconstruction is correct
        let arith_fold = shares
            .iter()
            .fold(0 as u64, |acc, (ct_i, _)| acc.wrapping_add(*ct_i));
        let arith_shares: Vec<u64>   = shares
            .iter()
            .map(|(ct_i, _)| *ct_i)
            .collect();
        let arith_recon = arithmetic.reconstruct(&arith_shares);
        assert!(arith_fold == arith_recon);

        let num_bits = ArithShare::BITS;
        let mut binary_recon: u64 = 0;
        for j in 0..num_bits {
            // Test each binary reconstruction is correct
            let binary_fold = shares  
                .iter()
                .fold(false, |acc, (_, ctbits_i)| acc ^ ctbits_i[j as usize]);
            let binary_shares : Vec<bool> = shares
                .iter()
                .map(|(_, ctbits_i)| ctbits_i[j as usize])
                .collect();
            let binary_recon_i = binary.reconstruct(&binary_shares);
            assert!(binary_fold == binary_recon_i);
            binary_recon = binary_recon | ((binary_recon_i as u64) << j);
        }
        
        // Test correlation is correct
        assert!(arith_recon == binary_recon);
    }

    #[test]
    fn batch_test() {
        for _ in 0..20 {
            session_correct();
        }
    }
}