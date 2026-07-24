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
    target_count: u32,
    cur_count: u32,
    benchmark_perms: BenchmarkSelection,
    starts: HashMap<BenchmarkType, Instant>,
    logs: HashMap<BenchmarkType, Duration>,
}

impl LogConstructor {
    /// Construct a new logger with specific [benchmark permissions][`LogConstructor::benchmark_perms`] and a target count
    pub fn new(benchmark_perms: BenchmarkSelection, target_count: u32) -> Self {
        LogConstructor{ target_count, cur_count: 0, benchmark_perms, starts: HashMap::new(), logs: HashMap::new() }
    }
    /// Clears logger while keeping the same benchmark permissions and target count
    pub fn clear(&mut self) {
        self.cur_count = 0;
        self.starts.clear();
        self.logs.clear();
    }
    /// Begin a benchmark type's clock 
    /// 
    /// Does nothing if the logger's [benchmark permission][`LogConstructor::benchmark_perms`] doesn't include`benchmark_type`
    /// 
    /// Does nothing if start was already called for that `benchmark_type`
    pub fn start(&mut self, benchmark_type: BenchmarkType) {
        if self.benchmark_perms.contains(benchmark_type) && !self.starts.contains_key(&benchmark_type) {
            let new_start = Instant::now();
            self.starts.insert(benchmark_type, new_start);
        }
    }
    /// Stops a benchmark type's clock and logs time elapsed if current round count is the target count
    /// 
    /// Returns `None` if [start][`LogConstructor::start`] for benchmark type has not been set before
    pub fn stop(&mut self, benchmark_type: BenchmarkType) -> Option<()> {
        let Some(prev_start) = self.starts.get(&benchmark_type) else {
            return None
        };
        self.cur_count += 1;
        if self.cur_count == self.target_count && self.target_count != 0 {
            self.logs.insert(benchmark_type, prev_start.elapsed().div_f32(self.target_count as f32));
        }
        Some(())
    }
    /// Consume the logger to obtain all its lifetime stats
    pub fn into_stats(self) -> HashMap<BenchmarkType, Duration> {
        self.logs
    }
}

/* #[derive(Default)]
/// Uses Welford's online algorithm to calculate running stats
struct LogUpdater {
    cur_count: u128,
    running_mean: f64,
    running_m2: f64,
}

impl LogUpdater {
    pub fn push(&mut self, x: u128) {
        self.cur_count += 1;
        let x = x as f64;
        let delta = x - self.running_mean;
        self.running_mean += delta / self.cur_count as f64;
        let delta2 = x - self.running_mean;
        self.running_m2 += delta * delta2;
    }
    pub fn to_stats(&self) -> Stats {
        let mean = self.running_mean as u128;
        let mut variance = 0u128;
        if self.cur_count > 0 { variance = self.running_m2 as u128/ self.cur_count; }
        let std = variance.isqrt();
        Stats{ mean, variance, std }
    }
} */

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
