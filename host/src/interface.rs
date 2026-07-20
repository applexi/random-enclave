use clap::{ArgAction, Parser, ValueEnum};
use std::{io::{Write, stdin, stdout}, path::PathBuf};
use env_logger::Builder;
use log::LevelFilter;
use crate::Error;

#[derive(Parser, Debug)]
pub struct CliInit {
    #[arg(long = "enclave-cid")]
    pub enclave_cid: u32,
    #[arg(short = 'v', long, action = ArgAction::Count, default_value_t = 3)]
    pub verbose: u8,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum RequestType {
    Random,
    Verify,
    Quit,
}

#[derive(Parser, Debug)]
pub struct CliHost {
    /// The interactive request type
    #[arg(short = 'r', long, value_enum)]
    pub request: RequestType,
    /// A nonce that the enclave attestation must contain
    #[arg(short = 's', long = "session-id", default_value_t = 0)]
    pub session_id: u64,
    /// PCR values the enclave attestation must have
    #[arg(long = "pcr", value_name = "(PCR_INDEX)=(EXPECTED_PCR_VALUE)", value_parser = parse_pcr)]
    pub pcrs: Option<Vec<(usize, String)>>,

    /// Only for random: to download the enclave's output (attestation + shares), with an optional path
    #[arg(long = "get-attest", value_name = "PATH", num_args = 0..=1, default_missing_value = ".")]
    pub get_output: Option<PathBuf>,

    /// Only for verify: specific attestation's path to verify
    #[arg(long = "attestation", value_name = "FILE_PATH (.bin) or (.json)", required_if_eq("request", "verify"))]
    pub attest_path: Option<PathBuf>,
    /// Only for verify: signed shares path. If not included, only checks if attestation is valid AWS
    #[arg(long = "signed-shares", value_name = "FILE_PATH (.cbor)")]
    pub signed_shares_path: Option<PathBuf>,
    /// Only for verify: encrypted shares path. If not included, only checks if attestation is valid AWS
    #[arg(long = "enc-shares", value_name = "FILE_PATH (.cbor)")]
    pub enc_shares_path: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SessionInput {
    pub session_id: u64,
    pub pcrs: Option<Vec<(usize, String)>>,
}

pub fn get_line() -> Result<String, Error> {
    println!("==============================================================================================================");
    print!("> ");
    stdout().flush()?;
    let mut line = String::new();
    stdin().read_line(&mut line)?;
    line.insert_str(0, "host ");
    Ok(line)
}

fn parse_pcr(s: &str) -> Result<(usize, String), String>{
    let Some((index, value)) = s.split_once('=') else {
        return Err("Field 'pcr' requires value of (index)=(value)".to_string())
    };
    let index: usize = index.parse().unwrap();
    if index > 32 {
        return Err("The AWS attestation's max pcr index is 31.".to_string());
    }   
    Ok((index, value.to_string()))
}

pub fn init_logger(verbose: u8) {
    let level = match verbose {
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Trace,
        _ => LevelFilter::Trace,
    };
    return Builder::new()
        .target(env_logger::Target::Stdout)
        .filter_level(level)
        .format_level(false)
        .format_timestamp(None)
        .format_indent(None)
        .format_target(false)
        .init();
}