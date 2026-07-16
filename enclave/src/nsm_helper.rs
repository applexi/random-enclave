use pontifex::{SecureModule, nsm::{Request, Response}};
use std::io::{Error, ErrorKind};

pub fn check_nsm(nsm: &SecureModule) -> Result<(), Error> {
    let nsm_config = nsm.send(Request::DescribeNSM);
    let Response::DescribeNSM { version_major, locked_pcrs, digest, ..} = nsm_config else {
        return Err(Error::new(ErrorKind::NotSeekable, "NSM returned unexpected response"));
    };
    println!("version: {version_major}, locked_pcrs: {locked_pcrs:?}, digest: {digest:?}");
    Ok(())
}