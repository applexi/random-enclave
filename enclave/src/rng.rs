use std::fs;
use std::io;
use io::{Error, ErrorKind};

const RNG_CURRENT : &str = "/sys/devices/virtual/misc/hw_random/rng_current";
const RNG_AVAIL : &str = "/sys/class/misc/hw_random/rng_available";
const NSM_RNG : &str = "nsm-hwrng";

/// Configures Nitro Enclave's hardware rng to trusted NSM hwrng 
/// 
/// # Returns
/// * `Ok(false)` if NSM hwrng is already configured
/// * `Ok(true)` if configured NSM hwrng
/// 
/// # Errors
/// This function will error if:
/// * The internal `RNG_Current` and `RNG_AVAIL` paths are incorrect
/// * NSM hwrng is not available
pub fn configure_rng() -> Result<bool, Error>{
    let current = fs::read_to_string(RNG_CURRENT)?;
    let avail = fs::read_to_string(RNG_AVAIL)?;
    if current.trim() == NSM_RNG { return Ok(false); };

    if ! avail.split_whitespace().any(|rng| rng == NSM_RNG) {
        return Err(Error::new(ErrorKind::NotFound, format!("{NSM_RNG} not found, only {avail}")))
    }

    fs::write(RNG_CURRENT, NSM_RNG)?;

    let new_current = fs::read_to_string(RNG_CURRENT)?;
    assert!(new_current.trim() == NSM_RNG);

    Ok(true)
}