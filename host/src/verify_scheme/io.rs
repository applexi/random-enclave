use common::benchmark::BenchmarkResponse;

use super::*;


pub fn save_output(attestation_blob: &[u8], signed_shares: Vec<ByteArray<64>>, enc_shares: &Vec<Vec<u8>>, session_id: u64, path: &Path) -> Result<PathBuf, Error> {
    let mut dir_path = path.to_path_buf();
    if !path.ends_with("enclave-output") {
        dir_path = dir_path.join("enclave-output");
    }

    let blob_path = dir_path.join(format!("attestation-{session_id}.bin"));
    let json_path = dir_path.join(format!("attestation-{session_id}.json"));
    let attest_json = SecureModule::parse_raw_attestation_doc(attestation_blob)?;
    let doc_json = serde_json::to_vec_pretty(&attest_json)?;

    let signed_blob_path = dir_path.join(format!("signed-shares-{session_id}.cbor"));
    let enc_blob_path = dir_path.join(format!("encrypted-shares-{session_id}.cbor"));
    let share_json_path = dir_path.join(format!("encrypted-shares-{session_id}.json"));
    let shares_json = serde_json::to_vec_pretty(enc_shares)?;
    let enc_blob = serde_cbor::to_vec(enc_shares)?;
    let signed_blob = serde_cbor::to_vec(&signed_shares)?;

    fs::create_dir_all(&dir_path)?;
    fs::write(&blob_path, attestation_blob)?;
    fs::write(&json_path, doc_json)?;
    fs::write(&signed_blob_path, signed_blob)?;
    fs::write(&enc_blob_path, enc_blob)?;
    fs::write(&share_json_path, shares_json)?;

    info!("\nSaved enclave outputs to {dir_path:?}!");
    trace!("-- Attesation binary: {blob_path:?}");
    trace!("-- Attesation json: {json_path:?}");
    trace!("-- Signed + encrypted shares: {signed_blob_path:?}");
    trace!("-- Encrypted shares: {enc_blob_path:?}");
    Ok(dir_path)
}

/// Returns a binary blob attestation from a given file path and if it is a (.bin). If file name was "attestation-{session id}", also returns the session id
/// 
/// Errors if file path could not be read
pub fn attestation_from_path(path: &Path) -> Result<(Vec<u8>, Option<u64>, bool), Error> {
    let attestation_blob = fs::read(path)?;
    let session_id = path
        .file_stem()
        .and_then(|x| x.to_str())
        .and_then(|x| x.strip_prefix("attestation-"))
        .and_then(|x| x.parse::<u64>().ok());
    let Some(extension) = path.extension() else {
        return Err(Error::AttestParse)
    };
    if extension.to_str() != Some("bin") && extension.to_str() != Some("json") {
        dbg!("here");
        return Err(Error::AttestParse)
    };
    Ok((attestation_blob, session_id, extension.to_str() == Some("bin")))
}

pub fn shares_from_path(signed_path: &Path, enc_path: &Path) -> Result<(Vec<Signature>, Vec<Vec<u8>>), Error> {
    let enc_shares = fs::read(enc_path)?;
    let enc_shares: Vec<Vec<u8>> = serde_cbor::from_slice(&enc_shares)?;

    let signed_shares = fs::read(signed_path)?;
    let signed_shares: Vec<ByteArray<64>> = serde_cbor::from_slice(&signed_shares)?;
    let signed_shares: Vec<Signature> = signed_shares 
        .iter()
        .map(|share| Signature::from_bytes(&ByteArray::into_array(*share)))
        .collect();
    Ok((signed_shares, enc_shares))
}

pub fn save_benchmarks(benchmarks: BenchmarkResponse, num_rounds: u32, warmup_rounds: u32, path: &Path) -> Result<PathBuf, Error> {
    let mut dir_path = path.to_path_buf();
    if !path.ends_with("benchmarks") {
        dir_path = dir_path.join("benchmarks");
    }

    let bench_path = dir_path.join(format!("benchmarks.json"));
    let bench_json = serde_json::json!({"warmup-rounds": warmup_rounds, "num-rounds": num_rounds, "benchmarks": benchmarks});
    let benchmark_blob = serde_json::to_vec_pretty(&bench_json)?;

    fs::create_dir_all(&dir_path)?;
    fs::write(&bench_path, benchmark_blob)?;

    info!("\nSaved benchmarks to {dir_path:?}!");
    Ok(dir_path)
}