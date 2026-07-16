use getrandom::SysRng;
use pontifex::{SecureModule, Router};
use serde_bytes::{ByteArray, ByteBuf};

use common::{SessionRequest, SessionResponse, ENCLAVE_PORT};
use enclave::{ArithmeticSharing, BinarySharing, enclave_session, Error};

mod nsm_helper;

#[tokio::main]
async fn main() -> Result<(), Error>{
    // Configure enclave randomness to NSM's trusted entropy pool
    enclave::rng::configure_rng()?;
    // Connect to NSM
    let nsm = SecureModule::try_init_global().await?;
    nsm_helper::check_nsm(&nsm)?; // NOTE: maybe best to move into router for lifetime security?
    
    // NOTE: need to do encryption/decryption 
    let router = Router::new()
        .route::<SessionRequest, _, _>(|_state, request| async move {
            let nsm = SecureModule::global();
            let arithmetic = ArithmeticSharing::new();
            let binary = BinarySharing::new();
            let mut rng = SysRng;

            // Obtain session parameters
            let session_id = request.session_id;

            // Generate a random and obtain signed shares
            let (enclave_pk, signed_shares, raw_shares) = enclave_session(&arithmetic, &binary, &mut rng)
                .expect("rng failure");
            let signed_shares: Vec<ByteArray<64>> = signed_shares
                .iter()
                .map(|share| ByteArray::from(share.to_bytes()))
                .collect();

            // Request an attestation with nonce session_id and public_key enclave_pk
            let attestation = nsm.raw_attest(None::<Vec<u8>>, Some(session_id.to_be_bytes().to_vec()), Some(enclave_pk.as_bytes()))
                .expect("attestation failure");
            let attestation = ByteBuf::from(attestation);

            SessionResponse{ attestation, signed_shares, raw_shares }
        });

    router.serve(ENCLAVE_PORT).await?;
    Ok(())
}