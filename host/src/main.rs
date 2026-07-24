use host::RequestType::Quit;
use log::{info, warn};
use pontifex::{AttestationDoc, ConnectionDetails, send};
use serde_bytes::{ByteArray, ByteBuf};
use ed25519_dalek::Signature;
use clap::Parser;

use host::{BenchmarkSelection, CliHost, CliInit, RequestType, get_line, init_verbose, shares_from_path};
use host::{Error, SessionInput, generate_n_keys, decrypt_shares, verify_session, verify_aws_attestation, verify_enclave_attestation};
use host::{save_output, attestation_from_path, save_benchmarks};
use common::{SessionRequest, ENCLAVE_PORT, benchmark::{LogConstructor, BenchmarkRequest}};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args_init = CliInit::parse();
    init_verbose(args_init.verbose);
    let connection = ConnectionDetails::new(args_init.enclave_cid, ENCLAVE_PORT);
    println!("Connected to enclave {:?} on port {ENCLAVE_PORT}", args_init.enclave_cid);
    println!("For full commands, please enter \"--help\"");
    loop {

        let line = get_line()?;
        let input = match CliHost::try_parse_from(line.split_whitespace()) {
            Ok(input) => input,
            Err(e) => { println!("{e}"); continue }
        };
        match input.request {
            RequestType::Random => {
                let benchmark_perms = input.benchmark_types;
                let mut benchmark_request = None::<BenchmarkRequest>;
                if benchmark_perms != BenchmarkSelection::None {
                    benchmark_request = Some(BenchmarkRequest{ benchmark_selection: benchmark_perms.clone(), warmup_rounds: input.warmup_rounds, num_rounds: input.num_rounds });
                }
                let mut logger = LogConstructor::new(benchmark_perms, input.num_rounds);

                info!("\nEnclave called with session id: {:?}", input.session_id);
                let session_id = input.session_id;
                let pcrs = input.pcrs;
                let session_input = SessionInput{ session_id, pcrs };

                // Generate N random mock party keypairs
                let Some((party_sks, party_pks)) = generate_n_keys().ok() else {
                    warn!("ERROR: Public keys could not be generated");
                    continue
                };
                let party_pks = party_pks
                    .iter()
                    .map(|key| ByteArray::from(key.to_bytes()))
                    .collect();
                let party_sks: Vec<&[u8]> = party_sks
                    .iter()
                    .map(|key| key.as_bytes().as_slice())
                    .collect();

                // Call the enclave and obtain a response
                let request = SessionRequest{ session_id, party_pks, benchmark_request };
                let response = send(connection, &request).await?;
                info!("\nEnclave response received!");

                let attestation_blob = ByteBuf::into_vec(response.attestation);
                let signed_shares: Vec<Signature> = response.signed_shares 
                    .iter()
                    .map(|share| Signature::from_bytes(&ByteArray::into_array(*share)))
                    .collect();
                let enc_shares = response.enc_shares;
                for i in 0..(input.warmup_rounds + input.num_rounds) {
                    if i == input.warmup_rounds { logger.clear(); }

                    // Verify attestation
                    if let Err(e) = verify_session(&attestation_blob, &signed_shares, &enc_shares, &session_input, &mut logger) {
                        warn!("FAILED: Verification failed with error {e:?}");
                    } else { info!("\nSUCCESS: Verification successful!"); }
                }

                // Decrypt shares
                match decrypt_shares(&enc_shares, &party_sks) {
                    Ok(raw_shares) => { 
                        info!("\nObtained {:?} raw shares: [RawShare{{ pt: {:?}, ptbits: [{:?}, {:?}, {:?}, {:?}, ...] }}, ...",
                        raw_shares.len(), raw_shares[0].pt, raw_shares[0].ptbits[0], raw_shares[0].ptbits[1], raw_shares[0].ptbits[2], raw_shares[0].ptbits[3])
                    },
                    Err(e) => warn!("ERROR: Decrypting shares failed with error {e:?}")
                };

                // If specified, save enclave's output
                if let Some(path) = input.get_output {
                    if let Err(e) = save_output(&attestation_blob, response.signed_shares, &enc_shares, session_id, &path) {
                        warn!("ERROR: Saving enclave outputs failed with error {e:?}");
                        continue
                    }
                }

                // If specified, save the benchmarks
                if let Some(path) = input.benchmark_path && let Some(benchmarks) = response.benchmarks {
                    if let Err(e) = save_benchmarks(benchmarks, &path) {
                        warn!("ERROR: Saving benchmarks failed with error {e:?}");
                        continue
                    }
                }
            }
            RequestType::Verify => {
                let benchmark_perms = input.benchmark_types;
                let mut logger = LogConstructor::new(benchmark_perms, input.num_rounds);

                let Some(attest_path) = input.attest_path else {
                    warn!("\nERROR: Attestation path required for verification");
                    continue
                };
                let Some((attestation_blob, session_id, is_bin)) = attestation_from_path(&attest_path).ok() else {
                    warn!("\nERROR: Attestation path is wrong");
                    continue
                };
                let mut session_id = match session_id {
                    Some(session_id) => session_id,
                    None => input.session_id,
                };
                if input.session_id != 0 { session_id = input.session_id; }
                let pcrs = input.pcrs;
                let session_input = SessionInput{ session_id, pcrs };
                if let Some(signed_path) = input.signed_shares_path && let Some(enc_path) = input.enc_shares_path {
                    let Some((signed_shares, enc_shares)) = shares_from_path(&signed_path, &enc_path).ok() else {
                        warn!("\nERROR: Signed shares path and/or encrypted shares path are wrong");
                        continue
                    };
                    if is_bin {
                        for i in 0..(input.warmup_rounds + input.num_rounds) {
                            if i == input.warmup_rounds { logger.clear(); }
                            if let Err(e) = verify_session(&attestation_blob, &signed_shares, &enc_shares, &session_input, &mut logger) {
                                warn!("\nFAILED: Verification failed with error {e:?}");
                                continue
                            }
                        }
                    } else {
                        info!("\nNote: Attestation path given is (.json) not (.bin). Can only assume attestation was valid, and verify enclave scheme.");
                        let attestation: AttestationDoc = serde_json::from_slice(&attestation_blob)?;
                        for i in 0..(input.warmup_rounds + input.num_rounds) {
                            if i == input.warmup_rounds { logger.clear(); }
                            if let Err(e) = verify_enclave_attestation(&attestation, &signed_shares, &enc_shares, &session_input, &mut logger) {
                                warn!("\nFAILED: Verification failed with error {e:?}");
                                continue
                            }
                        }
                    }
                } else if is_bin {
                    info!("\nNote: Only given an attestation path with no shares paths. Will only verify if attestation is valid.");
                    let attestation = pontifex::SecureModule::parse_raw_attestation_doc(&attestation_blob)?;
                    for i in 0..(input.warmup_rounds + input.num_rounds) {
                        if i == input.warmup_rounds { logger.clear(); }
                        if let Err(e) = verify_aws_attestation(&attestation_blob, &attestation, &mut logger) {
                            warn!("\nFAILED: Verification failed with error {e:?}");
                            continue
                        }
                    }
                } else {
                    warn!("\nWARNING: No verification could be done with the parameters given.");
                    info!("For full verification: --attestation (.bin) and --signed-shares (.cbor) and --enc-shares (.cbor)");
                    info!("For valid AWS attestation: --attestation (.bin)");
                    info!("For just enclave scheme: --attestation (.json) and --signed-shares (.cbor) and --enc-shares (.cbor)")
                }
                info!("\nSUCCESS: Verification successful!");

                // If specified, save the benchmarks
                let benchmarks = logger.into_stats();
                if let Some(path) = input.benchmark_path && benchmarks.len() > 0 {
                    if let Err(e) = save_benchmarks(benchmarks, &path) {
                        warn!("ERROR: Saving benchmarks failed with error {e:?}");
                        continue
                    }
                }
            }
            Quit => break,
        }
    }
    println!("==============================================================================================================");
    info!("\nConnection broken.");
    Ok(())
}