use std::convert::Infallible;

#[derive(Debug)]
pub enum Error {
    IO,
    SysRng,
    Server,
    String,
    Infallible,
    Rng,
    Serde,
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::IO
    }
}

impl From<getrandom::Error> for Error {
    fn from(_: getrandom::Error) -> Self {
        Error::SysRng
    }
}

impl From<pontifex::server::Error> for Error {
    fn from(_: pontifex::server::Error) -> Self {
        Error::Server
    }
}

impl From<&str> for Error {
    fn from(_: &str) -> Self {
        Error::String
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        Error::Infallible
    }
}

impl From<serde_cbor::Error> for Error {
    fn from(_: serde_cbor::Error) -> Self {
        Error::Serde
    }
}