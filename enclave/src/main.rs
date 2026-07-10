use getrandom::SysRng;
use pontifex::{SecureModule, Router};

use common::{SharesRequest, SharesResponse, ENCLAVE_PORT};
use enclave::{ArithmeticSharing, BinarySharing, enclave_session};

mod error;
mod attest;

#[tokio::main]
async fn main() -> Result<(), error::Error>{
    // Configure enclave randomness to NSM's trusted entropy pool
    enclave::rng::configure_rng()?;
    // Connect to NSM
    let nsm = SecureModule::try_init_global().await?;
    attest::check_nsm(&nsm)?; // NOTE: maybe best to move into router for lifetime security?
    
    // NOTE: need to do encryption/decryption & signing
    let router = Router::new()
        .route::<SharesRequest, _, _>(|_state, request| async move {
            let nsm = SecureModule::global();
            let arithmetic = ArithmeticSharing::new();
            let binary = BinarySharing::new();
            let mut rng = SysRng;

            // Obtain session parameters
            let session_id = request.session_id;

            // Generate a random and obtain its correlating arithmetic and binary shares
            let shares = enclave_session(&arithmetic, &binary, &mut rng)
                .expect("rng failure");
            // Request an attestation
            let attestation = nsm.raw_attest(Some(session_id.to_be_bytes().to_vec()), None::<Vec<u8>>, None::<Vec<u8>>)
                .expect("attestation failure");

            SharesResponse{ attestation, shares }
        });

    router.serve(ENCLAVE_PORT).await?;
    Ok(())
}