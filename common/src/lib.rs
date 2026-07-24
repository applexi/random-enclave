use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};
use pontifex::Request;
use crate::benchmark::{BenchmarkRequest, BenchmarkResponse};

pub mod benchmark;

pub const ENCLAVE_PORT: u32 = 1000;
/// Consistent and fixed number of parties
pub const DEFAULT_N : usize = 5;

#[derive(Serialize, Deserialize, Debug)]
/// Enclave input sent by host instance
pub struct SessionRequest {
    pub session_id: u64,
    pub party_pks: Vec<ByteArray<32>>,
    /// To get enclave benchmarks
    pub benchmark_request: Option<BenchmarkRequest>,
}

impl Request for SessionRequest {
    const ROUTE_ID: &'static str = "shares_request_v1";
    type Response = SessionResponse;
}

/// A share of type [`u64`]
pub type ArithShare = u64;
/// A share of type [`bool`]
pub type BitShare = bool;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
/// The raw share structure that has yet to be encrypted or signed
pub struct RawShare {
    pub pt: ArithShare,
    pub ptbits: Vec<BitShare>,
}

#[derive(Serialize, Deserialize, Debug)]
/// Enclave output given to host instance
pub struct SessionResponse {
    pub attestation: ByteBuf,
    pub signed_shares: Vec<ByteArray<64>>,
    pub enc_shares: Vec<Vec<u8>>,
    pub benchmarks: Option<BenchmarkResponse>,
}

impl std::fmt::Display for SessionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(response: {:?})\n", self.signed_shares)
    }
}

