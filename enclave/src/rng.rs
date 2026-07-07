use std::fs;
use std::io;
use io::{Error, ErrorKind};

const RNG_CURRENT : &str = "/sys/devices/virtual/misc/hw_random/rng_current";
const RNG_AVAIL : &str = "/sys/class/misc/hw_random/rng_available";
const NSM_RNG : &str = "nsm-hwrng";

pub fn configure_rng() -> io::Result<bool>{
    let current = fs::read_to_string(RNG_CURRENT)?;
    println!("current: {current}");
    if current.trim() == NSM_RNG { return Ok(false); };

    let avail = fs::read_to_string(RNG_AVAIL)?;
    println!("avail: {avail}");
    if ! avail.split_whitespace().any(|rng| rng == NSM_RNG) {
        return Err(Error::new(ErrorKind::NotFound, format!("nsm-hwrng not available, only available rngs = {avail}")));
    }

    fs::write(RNG_CURRENT, NSM_RNG)?;

    let new_current = fs::read_to_string(RNG_CURRENT)?;
    assert!(new_current.trim() == NSM_RNG);

    Ok(true)
}