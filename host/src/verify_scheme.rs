use std::{iter::zip};
use libc::time_t;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use aws_nitro_enclaves_cose::{CoseSign1, crypto::Openssl};
use openssl::{stack::Stack, x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::{X509VerifyFlags, X509VerifyParam}}};
use pontifex::{AttestationDoc, SecureModule, nsm::Digest};

use crate::{Error, Share, DEFAULT_N};

const AWS_ROOT_CERT_PATH: &str = "host/root.pem";

/// Given a binary blob attestation, return OK(()) if valid AWS attestation and if the attestation's measurements are expected respective to the TEE scheme
pub fn verify_session(attestation_blob: &[u8], signed_shares: Vec<Signature>, raw_shares: Vec<Share>, session_id: u64) -> Result<(), Error> {
    let attestation = SecureModule::parse_raw_attestation_doc(attestation_blob)?;
    verify_aws_attestation(attestation_blob, &attestation)?;
    println!("Attestation is a valid AWS Nitro attestation!");
    verify_enclave_attestation(&attestation, signed_shares, raw_shares, session_id)?;
    println!("Attestation is valid according to TEE scheme!");
    Ok(())
}

/// Given an [`AttestationDoc`], checks if attestation is session and scheme correct, and if output is attested by the attestation
fn verify_enclave_attestation(attestation: &AttestationDoc, signed_shares: Vec<Signature>, raw_shares: Vec<Share>, session_id: u64) -> Result<(), Error>{
    verify_enclave_signatures(attestation, signed_shares, raw_shares)?;
    verify_session_id(attestation, session_id)?;
    verify_pcrs(attestation)?;
    // TODO: check if party public keys are consensus set
    Ok(())
}

/// Verifies that all pcrs [`AttestationDoc::pcrs`] are non-zero, and checks pcr3 and pcr8 for correctness
fn verify_pcrs(attestation: &AttestationDoc) -> Result<(), Error> {
    let pcrs = &attestation.pcrs;
    for (i, pcr) in pcrs {
        // PCRs 0-2 and 8 should not be zero
        if (*i < 3 || *i == 8) &&
        pcr.iter().all(|byte| *byte == 0) { return Err(Error::AttestVerify(format!("PCR {i} is all zero"))); }
    }
    let _pcr3 = &pcrs[&3];
    let _pcr8 = &pcrs[&8];
    // TODO: check pcr3 and pcr8
    Ok(())
}

/// Verifies [`AttestationDoc::nonce`] is equal to given session ID
/// 
/// Requires [`AttestationDoc::nonce`] to exist and be of type [`u64`]
fn verify_session_id(attestation: &AttestationDoc, session_id: u64) -> Result<(), Error> {
    let Some(nonce) = &attestation.nonce else {
        return Err(Error::AttestVerify("Attestation's nonce field does not exist.".to_string()))
    };
    let nonce: &[u8; 8] = (&nonce[..]).try_into()?;
    let nonce = u64::from_be_bytes(*nonce);
    if nonce != session_id { return Err(Error::AttestVerify(format!("Attestation's nonce field {nonce} does not match session ID {session_id}"))); }
    Ok(())
}

/// Given raw_shares (Vec<[`Share`]>) and signed_shares (Vec<[`Signature`]>), verifies the shares were signed with [`AttestationDoc::public_key`] 
/// 
/// Checks that len(raw_shares) == len(signed_shares) == [`DEFAULT_N`]
/// 
/// Requires [`AttestationDoc::public_key`] to exist and be of type ed25519 [`VerifyingKey`]
fn verify_enclave_signatures(attestation: &AttestationDoc, signed_shares: Vec<Signature>, raw_shares: Vec<Share>) -> Result<(), Error>{
    if signed_shares.len() != raw_shares.len() { return Err(Error::AttestVerify(format!("Signed shares {signed_shares:?} and raw shares {raw_shares:?} lengths do not match."))); }
    let Some(enclave_pk) = &attestation.public_key else {
        return Err(Error::AttestVerify("Attestation's public_key field does not exist.".to_string()))
    };
    let enclave_pk: &[u8; PUBLIC_KEY_LENGTH]  = (&enclave_pk[..]).try_into()?;
    let enclave_pk = VerifyingKey::from_bytes(enclave_pk)?;
    let shares = zip(signed_shares.iter(), raw_shares.iter());
    if shares.len() != DEFAULT_N { return Err(Error::AttestVerify(format!("Shares' length does not match {DEFAULT_N}"))); }

    for (signature, message) in shares {
        let message = serde_cbor::to_vec(message)?;
        enclave_pk.verify(&message, signature)?;
    }
    Ok(())
}

/// Given a binary blob attestation, checks if valid AWS attestation, otherwise error
/// 
/// Follows NSM documentation: 
/// <https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/docs/attestation_process.md>
fn verify_aws_attestation(attestation_blob: &[u8], attestation: &AttestationDoc) -> Result<(), Error>{
    // 2.2 Check attesation's fields' sizes (Note steps 1 and 2 are already done by pontifex parsing)
    if !validate_content(&attestation) { return Err(Error::AttestVerify("Attestation's field sizes are incorrect".to_string())); }
    // 3. Verify certificates chain
    verify_certificate_chain(&attestation)?;
    // 4. Ensure Signed Attestation Document was correctly signed
    verify_aws_signature(attestation_blob, &attestation)?;
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
/// Checks expiration based on current time and [`AttestationDoc::timestamp`]
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

// TODO: test attestations
// - expired attestations, use debug-mode to get zeroed attestations, edited attestations