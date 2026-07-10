use std::fmt;

use serde::{Deserialize, Serialize};
use pontifex::Request;

pub const ENCLAVE_PORT: u32 = 1000;

#[derive(Serialize, Deserialize)]
pub struct SharesRequest {
    pub session_id: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SharesResponse {
    pub attestation: Vec<u8>,
    pub shares: Vec<(u64, Vec<bool>)>,
}

impl Request for SharesRequest {
    const ROUTE_ID: &'static str = "shares_request_v1";
    type Response = SharesResponse;
}

impl fmt::Display for SharesResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(response: {:?})\n", self.shares)
    }
}

