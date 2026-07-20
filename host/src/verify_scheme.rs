//! Given an attestation and output from the TEE scheme, verifies that it is a valid AWS attestation, and that the output is "correct"
//! - Relies on an internal `AWS_ROOT_CERT_PATH`, and assumes it contains the correct public AWS root certificate
//! 
//! This module contains:
//! - AWS valid attestation verification (based on NSM documentation <https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/docs/attestation_process.md>)
//! - Enclave scheme verification (output signed by enclave, correct session ID, correct PCRs)

use std::{iter::zip, fs, path::Path};
use libc::time_t;
use hex;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use aws_nitro_enclaves_cose::{CoseSign1, crypto::Openssl};
use openssl::{stack::Stack, x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::{X509VerifyFlags, X509VerifyParam}}};
use pontifex::{AttestationDoc, SecureModule, nsm::Digest};
use serde_bytes::{ByteArray};

use crate::{Error, SessionInput, DEFAULT_N};

const AWS_ROOT_CERT_PATH: &str = "host/root.pem";

/// Given a binary blob attestation, checks if valid AWS attestation and if the attestation's measurements are expected respective to the enclave scheme
pub fn verify_session(attestation_blob: &[u8], signed_shares: &Vec<Signature>, enc_shares: &Vec<Vec<u8>>, session_input: &SessionInput) -> Result<(), Error> {
    let attestation = SecureModule::parse_raw_attestation_doc(attestation_blob)?;
    verify_aws_attestation(attestation_blob, &attestation)?;
    verify_enclave_attestation(&attestation, signed_shares, enc_shares, session_input)?;
    Ok(())
}

/// Given an [`AttestationDoc`], checks if attestation is session and scheme correct, and if output is attested by the attestation
pub fn verify_enclave_attestation(attestation: &AttestationDoc, signed_shares: &Vec<Signature>, enc_shares: &Vec<Vec<u8>>, session_input: &SessionInput) -> Result<(), Error>{
    println!("- Enclave scheme verification");
    verify_enclave_signatures(attestation, signed_shares, enc_shares)?;
    println!("-- Verified enclave's output was signed by the public key in the enclave's attestation!");
    verify_session_id(attestation, session_input.session_id)?;
    println!("-- Verified attestation's session ID is {:?}!", session_input.session_id);
    verify_pcrs(attestation, &session_input.pcrs)?;
    println!("-- Verified attestation's PCRs are nonzero (and correct if random request included both PCR fields)!");
    // TODO: check if party public keys are consensus set
    Ok(())
}

/// Verifies that all [`pcrs`][`AttestationDoc::pcrs`] are non-zero, and checks pcr3 and pcr8 for correctness
fn verify_pcrs(attestation: &AttestationDoc, pcrs: &Option<Vec<(usize, String)>>) -> Result<(), Error> {
    let attest_pcrs = &attestation.pcrs;
    for (i, pcr) in attest_pcrs {
        // PCRs 0-2 and 8 should not be zero
        if (*i < 3 || *i == 8) &&
        pcr.iter().all(|byte| *byte == 0) { return Err(Error::AttestVerify(format!("PCR {i} is all zero"))); }
    }
    if let Some(expected_pcrs) = pcrs {
        for (pcr_index, expected_pcr) in expected_pcrs {
            let actual_pcr: &[u8] = &attest_pcrs[&pcr_index];
            check_pcr(&pcr_index, actual_pcr, expected_pcr)?;
        }
    }
    Ok(())
}

fn check_pcr(pcr_index: &usize, actual_pcr: &[u8], expected_pcr: &String) -> Result<(), Error> {
    let expected_pcr = hex::decode(expected_pcr.trim())?;
    if actual_pcr.as_ref() != expected_pcr.as_slice() {
        return Err(Error::AttestVerify(format!("Attestation pcr{pcr_index} {:?} doesn't match expected pcr{pcr_index} {:?}", actual_pcr.as_ref(), expected_pcr.as_slice())));
    }
    Ok(())
}

/// Verifies that the attestation's [`nonce`][`AttestationDoc::nonce`] is equal to given session ID
/// 
/// Requires [`nonce`][`AttestationDoc::nonce`] to exist and be of type [`u64`]
fn verify_session_id(attestation: &AttestationDoc, session_id: u64) -> Result<(), Error> {
    let Some(nonce) = &attestation.nonce else {
        return Err(Error::AttestVerify("Attestation's nonce field does not exist.".to_string()))
    };
    let nonce: &[u8; 8] = (&nonce[..]).try_into()?;
    let nonce = u64::from_be_bytes(*nonce);
    if nonce != session_id { return Err(Error::AttestVerify(format!("Attestation's nonce field {nonce} does not match session ID {session_id}"))); }
    Ok(())
}

/// Given `raw_shares` (Vec<[`Share`]>) and `signed_shares` (Vec<[`Signature`]>), verifies the shares were signed with the attestaton's [`public key`][`AttestationDoc::public_key`] 
/// 
/// Checks that `len(raw_shares) == len(signed_shares) == `[`DEFAULT_N`]
/// 
/// Requires [`public key`][`AttestationDoc::public_key`] to exist and be of type ed25519 [`VerifyingKey`]
fn verify_enclave_signatures(attestation: &AttestationDoc, signed_shares: &Vec<Signature>, enc_shares: &Vec<Vec<u8>>) -> Result<(), Error>{
    if signed_shares.len() != enc_shares.len() { return Err(Error::AttestVerify(format!("Shares' lengths do not match {DEFAULT_N}."))); }
    let Some(enclave_pk) = &attestation.public_key else {
        return Err(Error::AttestVerify("Attestation's public_key field does not exist.".to_string()))
    };
    let enclave_pk: &[u8; PUBLIC_KEY_LENGTH]  = (&enclave_pk[..]).try_into()?;
    let enclave_pk = VerifyingKey::from_bytes(enclave_pk)?;

    for (signature, message) in zip(signed_shares, enc_shares) {
        enclave_pk.verify(message, &signature)?;
    }
    Ok(())
}

/// Given a binary blob attestation, checks if valid AWS attestation, otherwise error
/// 
/// Follows NSM documentation: 
/// <https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/docs/attestation_process.md>
pub fn verify_aws_attestation(attestation_blob: &[u8], attestation: &AttestationDoc) -> Result<(), Error>{
    println!("- AWS valid attestation verification");
    // 2.2 Check attesation's fields' sizes (Note steps 1 and 2 are already done by pontifex parsing)
    if !validate_content(&attestation) { return Err(Error::AttestVerify("Attestation's field sizes are incorrect".to_string())); }
    // 3. Verify certificates chain
    verify_certificate_chain(&attestation)?;
    println!("-- Verified attestation's certificates chain!");
    // 4. Ensure Signed Attestation Document was correctly signed
    verify_aws_signature(attestation_blob, &attestation)?;
    println!("-- Verified attestation was signed by AWS!");
    Ok(())
}

/// Validate all of the [`AttestationDoc`]'s fields' sizes/lengths
fn validate_content(attestation: &AttestationDoc) -> bool {
    if attestation.module_id.len() == 0 {
        return false;
    } if attestation.timestamp <= 0 {
        return false;
    } if attestation.pcrs.len() == 0 || attestation.pcrs.len() > 32 {
        return false;
    } if attestation.cabundle.len() == 0 {
        return false;
    } 

    let pcr_len_valid = attestation.pcrs
        .iter()
        .fold(true, |acc, (_, pcr)| acc && (pcr.len() == 32 || pcr.len() == 48 || pcr.len() == 64));
    let cabundle_len_valid = attestation.cabundle
        .iter()
        .fold(true, |acc, ca| acc && (ca.len() >= 1 && ca.len() <= 1024));

    if let Digest::SHA384 = attestation.digest {} else {
        return false;
    }
    if let Some(public_key) = &attestation.public_key {
        if public_key.len() == 0 || public_key.len() > 1024 {
            return false;
        }
    } 
    if let Some(user_data) = &attestation.user_data {
        if user_data.len() > 512 {
            return false;
        }
    }
    if let Some(nonce) = &attestation.nonce {
        if nonce.len() > 12 {
            return false;
        }
    }
    return pcr_len_valid && cabundle_len_valid;
}

/// Uses OpenSSL to verify [`AttestationDoc`]'s X509 certificate chain
/// 
/// Checks if the certificates were valid when the attestation was created based on its [`timestamp`][`AttestationDoc::timestamp`]
/// 
/// Relies on internal `AWS_ROOT_CERT_PATH` to contain the correct public AWS root certificate
fn verify_certificate_chain(attestation: &AttestationDoc) -> Result<(), Error> {
    let aws_root_cert: &[u8] = &std::fs::read(AWS_ROOT_CERT_PATH)?;
    let aws_root_cert = X509::from_pem(aws_root_cert)?;

    // AWS cabundle order: {root_cert, interm_1, ..., interm_n} (target_cert)
    let (root_raw, interm_raws) = attestation.cabundle
        .split_first()
        .ok_or(Error::AttestVerify("Attestation's CA bundle cannot be split into (root cert, intermediate certs)".to_string()))?;
    let root_cert = X509::from_der(root_raw)?;
    if root_cert != aws_root_cert { return Err(Error::AttestVerify("Root certificate in attestation's CA bundle does not match AWS root certificate".to_string())); }

    // Certificate chain order: (target_cert) {interm_n, ..., interm_1} (root)
    let mut interm_certs = Stack::new()?;
    for raw_cert in interm_raws.iter().rev() {
        interm_certs.push(X509::from_der(raw_cert)?)?;
    }
    let target_cert = X509::from_der(&attestation.certificate)?;

    // From AWS: timestamp is "in milliseconds since epoch", openSSL wants "seconds since epoch"
    let mut params = X509VerifyParam::new()?;
    params.set_time((attestation.timestamp / 1000) as time_t);
    // From NSM: CRL should be disabled (default is false, this line does nothing and is just for logic)
    params.clear_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)?;

    // Add one trust anchor, the AWS root certificate, and set params for verification context
    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(aws_root_cert)?;
    store_builder.set_param(&params)?;
    let trust = store_builder.build();

    // Verify attestation's certificate with attestation's CA bundle (certificate chain) and AWS root certificate
    let mut store_context = X509StoreContext::new()?;
    store_context.init(&trust, &target_cert, &interm_certs, |trust| trust.verify_cert())?;

    Ok(())
}

/// Verifies that AWS signed the attestation document
fn verify_aws_signature(attestation_blob: &[u8], attestation: &AttestationDoc) -> Result<(), Error> {
    let cose = CoseSign1::from_bytes(attestation_blob)?;
    let target_cert = X509::from_der(&attestation.certificate)?;
    let key = target_cert.public_key()?;
    cose.verify_signature::<Openssl>(&key)?;
    Ok(())
}

pub fn save_output(attestation_blob: &[u8], signed_shares: Vec<ByteArray<64>>, enc_shares: &Vec<Vec<u8>>, session_id: u64, path: &Path) -> Result<(), Error> {
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

    fs::create_dir_all(dir_path)?;
    fs::write(blob_path, attestation_blob)?;
    fs::write(json_path, doc_json)?;
    fs::write(signed_blob_path, signed_blob)?;
    fs::write(enc_blob_path, enc_blob)?;
    fs::write(share_json_path, shares_json)?;
    Ok(())
}

/// Returns a binary blob attestation from a given file path. If file name was "attestation-{session id}", also returns the session id
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
    if extension.to_str() != Some(".bin") && extension.to_str() != Some(".json") {
        return Err(Error::AttestParse)
    };
    Ok((attestation_blob, session_id, extension.to_str() == Some(".bin")))
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