use std::{collections::{HashMap, HashSet}, time::{Duration, Instant}};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Hash, PartialEq, Eq, Clone, Copy)]
/// All types of benchmarks for enclave and host
pub enum BenchmarkType {
    // All benchmarks for enclave
    #[serde(rename = "enclave-session")]
    EnclaveSession,
    #[serde(rename = "generate-signing-keypair")]
    GenerateSigningKeypair,
    #[serde(rename = "generate-correlated-randoms")]
    GenerateRandoms,
    #[serde(rename = "encrypt-shares")]
    EncryptShares,
    #[serde(rename = "sign-shares")]
    SignShares,
    #[serde(rename = "attestation-request")]
    AttestationRequest,

    // All benchmarks for host
    #[serde(rename = "verify-aws-attestation")]
    VerifyAWSAttestation,
    #[serde(rename = "verify-enclave-scheme")]
    VerifyEnclaveScheme,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub struct Stats {
    pub mean: u128,
    pub variance: u128,
    pub std: u128,
}

#[derive(Serialize, Deserialize, Debug)]
/// A request sent by host to obtain enclave benchmarks
pub struct BenchmarkRequest {
    pub benchmark_selection: BenchmarkSelection,
    pub warmup_rounds: u32,
    pub num_rounds: u32
}

/// Response received by host containing all enclave's benchmarks
pub type BenchmarkResponse = HashMap<BenchmarkType, Duration>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Default, Clone)]
pub enum BenchmarkSelection {
    All,
    #[default]
    None,
    Some(HashSet<BenchmarkType>),
}

impl BenchmarkSelection {
    pub fn contains(&self, benchmark_type: BenchmarkType) -> bool {
        if *self == BenchmarkSelection::All {
            return true
        } if let BenchmarkSelection::Some(benchmarks) = &self {
            return benchmarks.contains(&benchmark_type)
        }
        false
    }
}

/// A logger with specified permissions that keeps track of all benchmarks
/// 
/// Can be consumed to return all tracked benchmark [stats][`Stats`]
pub struct LogConstructor {
    warmup_count: u32,
    num_count: u32,
    benchmark_perms: BenchmarkSelection,
    logs: HashMap<BenchmarkType, Duration>,
}

impl LogConstructor {
    /// Construct a new logger with specific [benchmark permissions][`LogConstructor::benchmark_perms`] and a target count
    pub fn new(benchmark_perms: BenchmarkSelection, warmup_count: u32, num_count: u32) -> Self {
        LogConstructor{ warmup_count, num_count, benchmark_perms, logs: HashMap::new() }
    }

    /// Benchmark a function
    pub fn benchmark<F: FnMut() -> T, T>(&mut self, benchmark_type: BenchmarkType, mut op: F) -> T {
        if self.num_count == 0 || !self.benchmark_perms.contains(benchmark_type) {
            return op()
        }
        let mut start = Instant::now();
        for i in 0..(self.warmup_count + self.num_count) {
            if i == self.warmup_count { start = Instant::now(); }
            std::hint::black_box(op());
        }
        self.logs.entry(benchmark_type).or_insert(start.elapsed().div_f32(self.num_count as f32));
        op()
    }

    /// Consume the logger to obtain all its lifetime stats
    pub fn into_stats(self) -> HashMap<BenchmarkType, Duration> {
        self.logs
    }
}

impl std::str::FromStr for BenchmarkType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "enclave-session" => Ok(Self::EnclaveSession),
            "get-signing-keypair" => Ok(Self::GenerateSigningKeypair),
            "get-randoms" => Ok(Self::GenerateRandoms),
            "encrypt-shares" => Ok(Self::EncryptShares),
            "sign-shares" => Ok(Self::SignShares),
            "get-attestation" => Ok(Self::AttestationRequest),

            "verify-aws" => Ok(Self::VerifyAWSAttestation),
            "verify-scheme" => Ok(Self::VerifyEnclaveScheme),

            _ => Err("Unknown benchmark type".to_string()),
        }
    }   
}
