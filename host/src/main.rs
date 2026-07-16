use pontifex::{ConnectionDetails, send};
use serde_bytes::{ByteArray, ByteBuf};
use ed25519_dalek::Signature;
use clap::Parser;

use host::{CliInit, CliHost, SessionInput, Error, verify_session};
use common::{SessionRequest, ENCLAVE_PORT};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args_init = CliInit::parse();
    let connection = ConnectionDetails::new(args_init.enclave_cid, ENCLAVE_PORT);
    println!("Connected to enclave {:?} on port {ENCLAVE_PORT}", args_init.enclave_cid);

    loop {
        let input = CliHost::parse();
        match input.request.to_lowercase().as_str() {
            "random" => {
                println!("=======================================");
                println!("Enclave called with session id: {:?}", input.session_id);
                let session_id = input.session_id;
                let pcr3 = input.pcr3.unwrap_or_default();
                let pcr8 = input.pcr8.unwrap_or_default();

                let session_input = SessionInput{ session_id, pcr3, pcr8 };
                let request = SessionRequest{ session_id };
                let response = send(connection, &request).await?;
                println!("Enclave response received!");

                // Verify attestation
                let attestation_blob = &ByteBuf::into_vec(response.attestation);
                let signed_shares: Vec<Signature> = response.signed_shares 
                    .iter()
                    .map(|share| Signature::from_bytes(&ByteArray::into_array(*share)))
                    .collect();
                let raw_shares = response.raw_shares;

                verify_session(attestation_blob, signed_shares, raw_shares, session_input)
                    .expect("verification gone wrong");
                println!("Verification successful!");
            }
            "quit" => break,
            _ => {
                println!("Please specify a request (-r || --request) with {{\"random\", \"quit\"}}.");
                println!("If \"random\", you may include a session id: u64 (-s || --session-id), or pcr3: String (--pcr3) and pcr8: String (--pcr8)");
            }
        }
    }
    println!("Connection broken");
    Ok(())
}