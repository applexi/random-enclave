mod rng;

fn main() -> std::io::Result<()> {
    let rng_configured = rng::configure_rng()?;
    if rng_configured {
        println!("configured rng");
    } else {
        println!("rng already configured");
    }
    Ok(())
}