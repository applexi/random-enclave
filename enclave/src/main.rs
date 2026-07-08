use std::{thread, time::Duration};
use rand::TryRng;
use getrandom::SysRng;

fn main() -> std::io::Result<()> {
    let rng_configured = enclave::rng::configure_rng()?;
    if rng_configured {
        println!("")
    }
    let arithmetic = enclave::ArithmeticSharing::new();
    let binary = enclave::BinarySharing::new();
    let mut rng = SysRng;
    loop {
        println!("NEW ROUND");
        let secret = rng.try_next_u64()?;
        println!("secret: {secret}");
        let secret_bits: Vec<bool> = (0..64).map(|i| (secret >> i) & 1 == 1).collect();
        let arith_shares = arithmetic.share(&mut rng, secret)?;
        assert!(arithmetic.reconstruct(&arith_shares) == secret);
        println!("arith shares: {arith_shares:?}");
        let mut bit_shares = Vec::new();
        for i in 0..64 {
            let bit_shares_i = binary.share(&mut rng, secret_bits[i])?;
            assert!(binary.reconstruct(&bit_shares_i) == secret_bits[i]);
            println!("  binary shares {i}: {bit_shares_i:?}");
            bit_shares.push(bit_shares_i);
        }
        let recon_secret = bit_shares
            .iter()
            .enumerate()
            .fold(0, |acc, (i, shares)| {
                let bit = binary.reconstruct(&shares);
                acc | ((bit as u64) << i)
            });
        assert!(secret == recon_secret);
        println!("reconstructed secret is correct");
        println!("===============================");
        thread::sleep(Duration::from_secs(5));
    }
}