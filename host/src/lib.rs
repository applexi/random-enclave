pub mod verify_scheme;
pub mod error;
pub mod interface;
pub mod decrypt;

pub use error::Error;
pub use verify_scheme::{verify_session, verify_aws_attestation, save_output, attestation_from_path, shares_from_path};
pub use common::{RawShare, DEFAULT_N};
pub use interface::{CliInit, CliHost, SessionInput, RequestType, get_line};
pub use decrypt::{generate_n_keys, decrypt_shares};