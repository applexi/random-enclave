mod rng;

use std::{thread, time::Duration};

fn main() -> std::io::Result<()> {
    let rng_configured = rng::configure_rng()?;
    loop {
        if rng_configured {
            println!("configured rng");
        } else {
            println!("rng already configured");
        }
        thread::sleep(Duration::from_secs(5));
    }
    Ok(())
}