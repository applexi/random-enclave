use pontifex::{ConnectionDetails, send};
use common::{SessionRequest, ENCLAVE_PORT};
use serde_bytes::{ByteArray, ByteBuf};
use ed25519_dalek::Signature;
use std::{env, io};
mod error;
mod verify_scheme;
use error::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let enclave_cid: u32 = env::args()
        .nth(1)
        .ok_or("Error, need parameter of <enclave_id: String>")?
        .parse()?;
    let connection = ConnectionDetails::new(enclave_cid, ENCLAVE_PORT);
    println!("Connected to enclave {enclave_cid} on port {ENCLAVE_PORT}");

    loop {
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read line");
        input = input.trim().to_lowercase();
        match input.as_str() {
            "random" => {
                let session_id = 5;
                let request = SessionRequest{ session_id };
                let response = send(connection, &request).await?;
                println!("Obtained enclave response: {response}");

                // Verify attestation
                let attestation_blob = &ByteBuf::into_vec(response.attestation);
                let signed_shares: Vec<Signature> = response.signed_shares 
                    .iter()
                    .map(|share| Signature::from_bytes(&ByteArray::into_array(*share)))
                    .collect();
                let raw_shares = response.raw_shares;

                verify_scheme::verify_session(attestation_blob, signed_shares, raw_shares, session_id)
                    .expect("verification gone wrong");
            }
            "quit" => break,
            _ => println!("Please ")
        }
    }
    println!("Connection broken");
    Ok(())
}