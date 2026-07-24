use std::fs;
use std::io;
use io::{Error, ErrorKind};

const RNG_CURRENT: &str = "/sys/devices/virtual/misc/hw_random/rng_current";
const RNG_AVAIL: &str = "/sys/class/misc/hw_random/rng_available";
const NSM_RNG: &str = "nsm-hwrng";

// Only used for benchmarking
const CLOCK_CURRENT: &str = "/sys/devices/system/clocksource/clocksource0/current_clocksource";
const CLOCK_AVAIL: &str = "/sys/devices/system/clocksource/clocksource0/available_clocksource";
const KVM_CLOCK: &str = "kvm-clock";

/// Configures Nitro Enclave's hardware rng to trusted NSM hwrng, and clock to KVM clock
pub fn configure_enclave() -> Result<(), Error> {
    configure_rng()?;
    configure_clock()?;
    Ok(())
}

/// Configures Nitro Enclave's hardware rng to trusted NSM hwrng 
/// 
/// # Returns
/// * `Ok(false)` if NSM hwrng is already configured
/// * `Ok(true)` if configured NSM hwrng
/// 
/// # Errors
/// This function will error if:
/// * The internal `RNG_CURRENT` and `RNG_AVAIL` paths are incorrect
/// * NSM hwrng is not available
fn configure_rng() -> Result<bool, Error> {
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

/// Configures Nitro Enclave's clock to trusted KVM clock
/// 
/// # Returns
/// * `Ok(false)` if KVM clock is already configured
/// * `Ok(true)` if configured KVM clock
/// 
/// # Errors
/// This function will error if:
/// * The internal `CLOCK_CURRENT` and `CLOCK_AVAIL` paths are incorrect
/// * KVM clock is not available
fn configure_clock() -> Result<bool, Error> {
    let current = fs::read_to_string(CLOCK_CURRENT)?;
    let avail = fs::read_to_string(CLOCK_AVAIL)?;
    if current.trim() == KVM_CLOCK { return Ok(false); };

    if ! avail.split_whitespace().any(|rng| rng == KVM_CLOCK) {
        return Err(Error::new(ErrorKind::NotFound, format!("{KVM_CLOCK} not found, only {avail}")))
    }

    fs::write(CLOCK_CURRENT, KVM_CLOCK)?;

    let new_current = fs::read_to_string(CLOCK_CURRENT)?;
    assert!(new_current.trim() == KVM_CLOCK);

    Ok(true)
}