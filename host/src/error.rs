
#[derive(Debug)]
pub enum Error {
    IO,
    String,
    Parse,
    Client,
    Attestation,
    AttestParse,
    AttestVerify(String),
    ErrorStack,
    Cose,
    ED25519,
    Serde,
    Hex,
    Ecies,
    Vec,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AttestVerify(msg) => write!(f, "Attestation verification error: {msg}"),
            _ => write!(f, "{self:?}")
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::IO
    }
}

impl From<&str> for Error {
    fn from(_: &str) -> Self {
        Error::String
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(_: std::num::ParseIntError) -> Self {
        Error::Parse
    }
}

impl From<pontifex::client::Error> for Error {
    fn from(_: pontifex::client::Error) -> Self {
        Error::Client
    }
}

impl From<pontifex::AttestationError> for Error {
    fn from(_: pontifex::AttestationError) -> Self {
        Error::Attestation
    }
}

impl From<std::array::TryFromSliceError> for Error {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Error::AttestParse
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(_: openssl::error::ErrorStack) -> Self {
        Error::ErrorStack
    }
}

impl From<aws_nitro_enclaves_cose::error::CoseError> for Error {
    fn from(_: aws_nitro_enclaves_cose::error::CoseError) -> Self {
        Error::Cose
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(_: ed25519_dalek::ed25519::Error) -> Self {
        Error::ED25519
    }
}

impl From<serde_cbor::Error> for Error {
    fn from(_: serde_cbor::Error) -> Self {
        Error::Serde
    }
}

impl From<hex::FromHexError> for Error {
    fn from(_: hex::FromHexError) -> Self {
        Error::Hex
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::Serde
    }
}