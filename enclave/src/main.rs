use getrandom::SysRng;
use pontifex::{SecureModule, Router};
use serde_bytes::{ByteArray, ByteBuf};

use common::{SessionRequest, SessionResponse, ENCLAVE_PORT};
use enclave::{ArithmeticSharing, BenchmarkSelection, BinarySharing, Error, enclave_session};
use enclave::{BenchmarkType, LogConstructor};

mod nsm_helper;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Configure enclave randomness to NSM's trusted entropy pool (and clock for benchmarking)
    enclave::configure::configure_enclave()?;
    // Connect to NSM
    let nsm = SecureModule::try_init_global().await?;
    nsm_helper::check_nsm(&nsm)?; // NOTE: maybe best to move into router for lifetime security?
    
    let router = Router::new()
        .route::<SessionRequest, _, _>(|_state, request| async move {
            let (benchmark_perms, warmup_rounds, num_rounds) = request.benchmark_request
                .map_or((BenchmarkSelection::None, 0, 1), |x| (x.benchmark_selection, x.warmup_rounds, x.num_rounds));
            let mut logger = LogConstructor::new(benchmark_perms, warmup_rounds, num_rounds);

            let nsm = SecureModule::global();
            let arithmetic = ArithmeticSharing::new();
            let binary = BinarySharing::new();
            let mut rng = SysRng;

            // Obtain session parameters
            let session_id = request.session_id;
            let party_pks: Vec<&[u8]> = request.party_pks
                .iter()
                .map(|key| &key[..])
                .collect();

            // Generate a random and obtain signed and encrypted shares
            let (enclave_pk, signed_shares, enc_shares) = enclave_session(&arithmetic, &binary, &mut rng, &party_pks, &mut logger)
                .expect("rng failure");

            let signed_shares = signed_shares
                .iter()
                .map(|share| ByteArray::from(share.to_bytes()))
                .collect();
            
            // Request an attestation with nonce session_id and public_key enclave_pk
            let attestation = logger.benchmark(BenchmarkType::AttestationRequest, || nsm.raw_attest(None::<Vec<u8>>, Some(session_id.to_be_bytes().to_vec()), Some(enclave_pk.as_bytes()))
                .expect("attestation failure"));
            let attestation = ByteBuf::from(attestation);

            let benchmarks = match logger.into_stats() {
                value if value.is_empty() => None,
                value => Some(value),
            };
            SessionResponse{ attestation, signed_shares, enc_shares, benchmarks }
        });

    router.serve(ENCLAVE_PORT).await?;
    Ok(())
}