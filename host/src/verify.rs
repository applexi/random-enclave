use libc::time_t;
use aws_nitro_enclaves_cose::{CoseSign1, crypto::Openssl};
use openssl::{stack::Stack, x509::{X509, X509StoreContext, store::X509StoreBuilder, verify::{X509VerifyFlags, X509VerifyParam}}};
use pontifex::{AttestationDoc, SecureModule, nsm::Digest};

use crate::error::Error;

const AWS_ROOT_CERT_PATH: &str = "host/root.pem";

/// Given a binary blob attestation, return an attestation document if valid AWS attestation, otherwise error
/// 
/// Follows NSM documentation: 
/// <https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/1993eeb0620d35f5cefc50b17638b432325328f9/docs/attestation_process.md>
pub fn verify(attestation_blob: &[u8]) -> Result<(), Error>{
    // 1. Decode CBOR and map to COSE_Sign1 structure and 2. Extract Attestation Document from COSE_Sign1 structure
    let attestation = SecureModule::parse_raw_attestation_doc(attestation_blob)?;
    // Validate field lengths
    if !validate_content(&attestation) { return Err(Error::AttestVerify); }

    // 3. Verify certificates chain
    verify_certificate_chain(&attestation)
        .expect("verify certificate chain wrong");

    // 4. Ensure Signed Attestation Document was correctly signed
    verify_signature(attestation_blob, &attestation)
        .expect("verify signature gone wrong");

    println!("verification successful!");

    // TODO: check pcrs

    Ok(())
}

/// Validate all of the attestation's fields' sizes/lengths
fn validate_content(attestation: &AttestationDoc) -> bool {
    if attestation.module_id.len() == 0 {
        return false;
    } else if attestation.timestamp <= 0 {
        return false;
    } else if attestation.pcrs.len() == 0 || attestation.pcrs.len() > 32 {
        return false;
    } else if attestation.cabundle.len() == 0 {
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

/// Uses OpenSSL to verify attestation's X509 certificate chain
/// 
/// Checks expiration based on current time and attestation's timestamp
fn verify_certificate_chain(attestation: &AttestationDoc) -> Result<(), Error> {
    let aws_root_cert: &[u8] = &std::fs::read(AWS_ROOT_CERT_PATH)?;
    let aws_root_cert = X509::from_pem(aws_root_cert)?;

    // AWS cabundle order: {root_cert, interm_1, ..., interm_n} (target_cert)
    let (root_raw, interm_raws) = attestation.cabundle
        .split_first()
        .ok_or(Error::AttestVerify)?;
    let root_cert = X509::from_der(root_raw)?;
    if root_cert != aws_root_cert { return Err(Error::AttestVerify); }

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

    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(aws_root_cert)?;
    store_builder.set_param(&params)?;
    let trust = store_builder.build();

    let mut store_context = X509StoreContext::new()?;
    store_context.init(&trust, &target_cert, &interm_certs, |trust| trust.verify_cert())?;
    
    Ok(())
}


fn verify_signature(attestation_blob: &[u8], attestation: &AttestationDoc) -> Result<(), Error> {
    let cose = CoseSign1::from_bytes(attestation_blob)?;
    let target_cert = X509::from_der(&attestation.certificate)?;
    let key = target_cert.public_key()?;
    cose.verify_signature::<Openssl>(&key)?;
    Ok(())
}