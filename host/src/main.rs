use host::RequestType::Quit;
use pontifex::{ConnectionDetails, send};
use serde_bytes::{ByteArray, ByteBuf};
use ed25519_dalek::Signature;
use clap::Parser;

use host::{CliHost, CliInit, RequestType, get_line, shares_from_path};
use host::{Error, SessionInput, generate_n_keys, decrypt_shares, verify_session, verify_aws_attestation};
use host::{save_output, attestation_from_path};
use common::{SessionRequest, ENCLAVE_PORT};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args_init = CliInit::parse();
    let connection = ConnectionDetails::new(args_init.enclave_cid, ENCLAVE_PORT);
    println!("Connected to enclave {:?} on port {ENCLAVE_PORT}", args_init.enclave_cid);

    loop {
        let line = get_line()?;
        let input = match CliHost::try_parse_from(line.split_whitespace()) {
            Ok(input) => input,
            Err(e) => { println!("{e}"); continue; }
        };
        match input.request {
            RequestType::Random => {
                println!("====================================================================================================");
                println!("Enclave called with session id: {:?}", input.session_id);
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
                println!("Enclave response received!");

                // Verify attestation
                let attestation_blob = &ByteBuf::into_vec(response.attestation);
                let signed_shares: Vec<Signature> = response.signed_shares 
                    .iter()
                    .map(|share| Signature::from_bytes(&ByteArray::into_array(*share)))
                    .collect();
                let enc_shares = response.enc_shares;
                verify_session(attestation_blob, signed_shares, &enc_shares, session_input)?;
                println!("Verification successful!");

                // Decrypt shares
                let raw_shares = decrypt_shares(&enc_shares, &party_sks)?;
                println!("Obtained {:?} raw shares: [RawShare {{ pt: {:?}, ptbits: [{:?}, {:?}, {:?}, {:?}, ...]}}, ...",
                        raw_shares.len(), raw_shares[0].pt, raw_shares[0].ptbits[0], raw_shares[0].ptbits[1], raw_shares[0].ptbits[2], raw_shares[0].ptbits[3]);

                // If specified, save enclave's output
                if let Some(path) = input.get_output {
                    save_output(attestation_blob, response.signed_shares, &enc_shares, session_id, &path)?;
                    println!("Downloaded enclave output to {path:?}!")
                }
            }
            RequestType::Verify => {
                println!("====================================================================================================");
                let Some(attest_path) = input.attest_path else {
                    println!("Attestation path required for verification");
                    continue;
                };
                let (attestation_blob, session_id) = attestation_from_path(&attest_path)?;
                let session_id = match session_id {
                    Some(session_id) => session_id,
                    None => input.session_id,
                };
                let pcrs = input.pcrs;
                let session_input = SessionInput{ session_id, pcrs };
                if let Some(signed_path) = input.signed_shares_path && let Some(enc_path) = input.enc_shares_path {
                    let (signed_shares, enc_shares) = shares_from_path(&signed_path, &enc_path)?;
                    verify_session(&attestation_blob, signed_shares, &enc_shares, session_input)?;
                } else {
                    let attestation = pontifex::SecureModule::parse_raw_attestation_doc(&attestation_blob)?;
                    verify_aws_attestation(&attestation_blob, &attestation)?;
                }
            }
            Quit => break,
        }
    }
    println!("Connection broken.");
    Ok(())
}