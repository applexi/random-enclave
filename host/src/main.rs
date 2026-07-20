use host::RequestType::Quit;
use pontifex::{AttestationDoc, ConnectionDetails, send};
use serde_bytes::{ByteArray, ByteBuf};
use ed25519_dalek::Signature;
use clap::Parser;

use host::{CliHost, CliInit, RequestType, get_line, shares_from_path};
use host::{Error, SessionInput, generate_n_keys, decrypt_shares, verify_session, verify_aws_attestation, verify_enclave_attestation};
use host::{save_output, attestation_from_path};
use common::{SessionRequest, ENCLAVE_PORT};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args_init = CliInit::parse();
    let connection = ConnectionDetails::new(args_init.enclave_cid, ENCLAVE_PORT);
    println!("Connected to enclave {:?} on port {ENCLAVE_PORT}", args_init.enclave_cid);
    println!("For full commands, please enter \"--help\"");
    println!("===========================================================================================================");
    loop {
        let line = get_line()?;
        let input = match CliHost::try_parse_from(line.split_whitespace()) {
            Ok(input) => input,
            Err(e) => { println!("{e}"); continue }
        };
        match input.request {
            RequestType::Random => {
                println!("\nEnclave called with session id: {:?}", input.session_id);
                let session_id = input.session_id;
                let pcrs = input.pcrs;
                let session_input = SessionInput{ session_id, pcrs };

                // Generate N random mock party keypairs, and sends session ID and party public keys to enclave
                let (party_sks, party_pks) = generate_n_keys()?;
                let party_pks = party_pks
                    .iter()
                    .map(|key| ByteArray::from(key.to_bytes()))
                    .collect();
                let party_sks: Vec<&[u8]> = party_sks
                    .iter()
                    .map(|key| key.as_bytes().as_slice())
                    .collect();
                let request = SessionRequest{ session_id, party_pks };

                let response = send(connection, &request).await?;
                println!("\nEnclave response received!");

                // Verify attestation
                let attestation_blob = &ByteBuf::into_vec(response.attestation);
                let signed_shares: Vec<Signature> = response.signed_shares 
                    .iter()
                    .map(|share| Signature::from_bytes(&ByteArray::into_array(*share)))
                    .collect();
                let enc_shares = response.enc_shares;
                verify_session(attestation_blob, &signed_shares, &enc_shares, &session_input)?;
                println!("\nSUCCESS: Verification successful!");

                // Decrypt shares
                let raw_shares = decrypt_shares(&enc_shares, &party_sks)?;
                println!("\nObtained {:?} raw shares: [RawShare{{ pt: {:?}, ptbits: [{:?}, {:?}, {:?}, {:?}, ...] }}, ...",
                        raw_shares.len(), raw_shares[0].pt, raw_shares[0].ptbits[0], raw_shares[0].ptbits[1], raw_shares[0].ptbits[2], raw_shares[0].ptbits[3]);

                // If specified, save enclave's output
                if let Some(path) = input.get_output {
                    save_output(attestation_blob, response.signed_shares, &enc_shares, session_id, &path)?;
                    println!("\nDownloaded enclave output to {path:?}!")
                }
            }
            RequestType::Verify => {
                let Some(attest_path) = input.attest_path else {
                    println!("ERROR: Attestation path required for verification");
                    continue
                };
                let Some((attestation_blob, session_id, is_bin)) = attestation_from_path(&attest_path).ok() else {
                    println!("ERROR: Attestation path is wrong");
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
                        println!("ERROR: Signed shares path and/or encrypted shares path are wrong");
                        continue
                    };
                    if is_bin && let Err(e) = verify_session(&attestation_blob, &signed_shares, &enc_shares, &session_input) {
                        println!("FAILED: Verification failed with error {e:?}");
                        continue
                    } else {
                        println!("Note: Attestation path given is (.json) not (.bin). Can only assume attestation was valid, and verify enclave scheme.");
                        let attestation: AttestationDoc = serde_json::from_slice(&attestation_blob)?;
                        if let Err(e) = verify_enclave_attestation(&attestation, &signed_shares, &enc_shares, &session_input) {
                            println!("FAILED: Verification failed with error {e:?}");
                            continue
                        }
                    }
                } else if is_bin {
                    println!("Note: Only given an attestation path with no shares paths. Will only verify if attestation is valid.");
                    let attestation = pontifex::SecureModule::parse_raw_attestation_doc(&attestation_blob)?;
                    if let Err(e) = verify_aws_attestation(&attestation_blob, &attestation) {
                        println!("FAILED: Verification failed with error {e:?}");
                        continue
                    }
                } else {
                    println!("No verification could be done with the parameters given.");
                    println!("For full verification: --attestation (.bin) and --signed-shares (.cbor) and --enc-shares (.cbor)");
                    println!("For valid AWS attestation: --attestation (.bin)");
                    println!("For just enclave scheme: --attestation (.json) and --signed-shares (.cbor) and --enc-shares (.cbor)")
                }
                println!("SUCCESS: Verification successful!");
            }
            Quit => break,
        }
        println!("===========================================================================================================");
    }
    println!("Connection broken.");
    Ok(())
}