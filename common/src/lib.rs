use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use pontifex::Request;

pub const ENCLAVE_PORT: u32 = 1000;
/// Consistent and fixed number of parties
pub const DEFAULT_N : usize = 5;

/// Enclave input sent by host instance
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionRequest {
    pub session_id: u64,
}

impl Request for SessionRequest {
    const ROUTE_ID: &'static str = "shares_request_v1";
    type Response = SessionResponse;
}

/// A share of type [`u64`]
pub type ArithShare = u64;
/// A share of type [`bool`]
pub type BitShare = bool;

/// The raw share structure that has yet to be signed
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct Share {
    pub ct: ArithShare,
    pub ctbit: Vec<BitShare>,
}

/// Enclave output given to host instance
#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResponse {
    pub attestation: ByteBuf,
    pub signed_shares: Vec<ByteArray<64>>,
    pub raw_shares: Vec<Share>,
}

impl std::fmt::Display for SessionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(response: {:?})\n", self.signed_shares)
    }
}

