use pontifex::{ConnectionDetails, SecureModule, send};
use common::{SharesRequest, ENCLAVE_PORT};
use std::{env, io};
mod error;
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
                let request = SharesRequest{ session_id: 5 };
                let response = send(connection, &request).await?;
                println!("Obtained enclave response: {response}");

                // NOTE: need to add verification process, right now attestation is not verified

                // dummy print parse and print attestation
                let attestation = SecureModule::parse_raw_attestation_doc(&response.attestation)?;
                let Some(user_data_byes) = attestation.user_data else {
                    return Result::Err(Error::Attestation);
                };
                let user_data: [u8; 8] = user_data_byes.as_ref().try_into()?;
                let user_data = u64::from_be_bytes(user_data);
                let pcrs = attestation.pcrs;
                println!("Attestation contains user data {user_data} and pcrs {pcrs:?} ");
            }
            "quit" => break,
            _ => println!("Please ")
        }
    }
    println!("Connection broken");
    Ok(())
}