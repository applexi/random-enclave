use pontifex::{SecureModule, nsm::{Request, Response}};
use crate::error::Error;

pub fn check_nsm(nsm: &SecureModule) -> Result<(), Error> {
    let nsm_config = nsm.send(Request::DescribeNSM);
    let Response::DescribeNSM { version_major, locked_pcrs, digest, ..} = nsm_config else {
        return Err(Error::NSM);
    };
    println!("version: {version_major}, locked_pcrs: {locked_pcrs:?}, digest: {digest:?}");
    Ok(())
}