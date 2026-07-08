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
        if let Err(e) = run_round(&arithmetic, &binary, &mut rng) {
            println!("ERROR: round failed: {e}");
        }
        println!("===============================");
        thread::sleep(Duration::from_secs(5));
    }
}

fn run_round(
    arithmetic: &enclave::ArithmeticSharing,
    binary: &enclave::BinarySharing,
    rng: &mut SysRng,
) -> std::io::Result<()> {
    let secret = rng.try_next_u64()?;
    println!("secret: {secret}");
    let secret_bits: Vec<bool> = (0..64).map(|i| (secret >> i) & 1 == 1).collect();
    let arith_shares = arithmetic.share(rng, secret)?;
    if arithmetic.reconstruct(&arith_shares) != secret {
        println!("MISMATCH: arithmetic reconstruction does not match secret");
    }
    println!("arith shares: {arith_shares:?}");
    let mut bit_shares = Vec::new();
    for i in 0..64 {
        let bit_shares_i = binary.share(rng, secret_bits[i])?;
        if binary.reconstruct(&bit_shares_i) != secret_bits[i] {
            println!("MISMATCH: binary reconstruction of bit {i} does not match");
        }
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
    if secret == recon_secret {
        println!("reconstructed secret is correct");
    } else {
        println!("MISMATCH: reconstructed secret {recon_secret} != secret {secret}");
    }
    Ok(())
}
