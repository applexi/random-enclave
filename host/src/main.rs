use pontifex::{ConnectionDetails, send};
use common::{SharesRequest, ENCLAVE_PORT};
use std::{env, io};
mod error;
use error::Error;

#[tokio::main]
async fn main() -> Result<(), Error>{
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
                let request = SharesRequest{};
                let response = send(connection, &request).await?;
                println!("Obtained enclave response: {response}")
            }
            "quit" => break,
            _ => continue
        }
    }
    println!("Connection broken");
    Ok(())
}