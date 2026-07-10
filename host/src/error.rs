use std::array::TryFromSliceError;


#[derive(Debug)]
pub enum Error {
    IO,
    String,
    Parse,
    Client,
    Attestation,
    AttestParse,
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

impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Self {
        Error::AttestParse
    }
}