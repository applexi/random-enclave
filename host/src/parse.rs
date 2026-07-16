use clap::Parser;

#[derive(Parser, Debug)]
pub struct CliInit {
    #[arg(long = "enclave-cid")]
    pub enclave_cid: u32,
}

#[derive(Parser, Debug)]
pub struct CliHost {
    #[arg(short = 'r', long)]
    pub request: String,
    #[arg(short = 's', long = "session-id", default_value_t = 888)]
    pub session_id: u64,
    #[arg(long)]
    pub pcr3: Option<String>,
    #[arg(long)]
    pub pcr8: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SessionInput {
    pub session_id: u64,
    pub pcr3: String,
    pub pcr8: String,
}