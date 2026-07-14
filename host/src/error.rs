
#[derive(Debug)]
pub enum Error {
    IO,
    String,
    Parse,
    Client,
    Attestation,
    AttestParse,
    AttestVerify,
    ErrorStack,
    Cose,
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