pub mod verify_scheme;
pub mod error;
pub mod interface;
pub mod decrypt;

pub use error::Error;
pub use verify_scheme::{verify_session, verify_aws_attestation, verify_enclave_attestation, io::{save_output, attestation_from_path, shares_from_path, save_benchmarks}};
pub use common::{RawShare, DEFAULT_N};
pub use common::benchmark::{BenchmarkType, BenchmarkSelection, LogConstructor};
pub use interface::{CliInit, CliHost, SessionInput, RequestType, get_line, init_verbose};
pub use decrypt::{generate_n_keys, decrypt_shares};