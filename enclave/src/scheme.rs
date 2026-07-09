use rand::TryCryptoRng;
use crate::{ArithmeticSharing, BinarySharing, DEFAULT_N};
use crate::{ArithShare, BitShare, random_arith};

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