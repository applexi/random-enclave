use getrandom::SysRng;
use enclave::{ArithmeticSharing, BinarySharing, enclave_session};

use pontifex::Router;
use common::{SharesRequest, SharesResponse, ENCLAVE_PORT};
mod error;
use error::Error;

#[tokio::main]
async fn main() -> Result<(), Error>{
    enclave::rng::configure_rng()?;
    
    let router = Router::new()
        .route::<SharesRequest, _, _>(|_state, _req| async {
            let arithmetic = ArithmeticSharing::new();
            let binary = BinarySharing::new();
            let mut rng = SysRng;
            let shares = enclave_session(&arithmetic, &binary, &mut rng)
                .expect("rng failure");
            SharesResponse { shares }
        });

    router.serve(ENCLAVE_PORT).await?;
    Ok(())
}