use super::*;
use std::fs;
use aws_nitro_enclaves_cose::{crypto::{Openssl}, header_map::HeaderMap};
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use openssl::{asn1::Asn1Time, bn::{BigNum, MsbOption}, ec::{EcGroup, EcKey}, hash::MessageDigest, nid::Nid, pkey::{PKey, Private}, x509::{X509Builder, X509Name}};
use crate::{BenchmarkSelection, shares_from_path, attestation_from_path};

const TIMES: usize = 20;

/// Returns a tuple of all used paths:
/// 
/// `(Vec<debug_bin, valid_bins>, Vec<debug_json, valid_jsons>, Vec<debug_shares, valid_shares>)`
fn paths() -> Result<(Vec<PathBuf>, Vec<PathBuf>, Vec<(PathBuf, PathBuf)>), Error> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let debug_bin = path.join("src/verify_scheme/test_outputs/debug_mode/attestation-0.bin");
    let bin_a: PathBuf = path.join("src/verify_scheme/test_outputs/attestation-0.bin");
    let bin_b: PathBuf = path.join("src/verify_scheme/test_outputs/attestation-1.bin");
    let bin_paths = vec![debug_bin, bin_a, bin_b];

    let debug_json = path.join("src/verify_scheme/test_outputs/debug_mode/attestation-0.json");
    let json_a: PathBuf = path.join("src/verify_scheme/test_outputs/attestation-0.json");
    let json_b: PathBuf = path.join("src/verify_scheme/test_outputs/attestation-1.json");
    let json_paths = vec![debug_json, json_a, json_b];

    let debug_enc = path.join("src/verify_scheme/test_outputs/debug_mode/encrypted-shares-0.cbor");
    let debug_signed = path.join("src/verify_scheme/test_outputs/debug_mode/signed-shares-0.cbor");
    let enc_a: PathBuf = path.join("src/verify_scheme/test_outputs/encrypted-shares-0.cbor");
    let signed_a: PathBuf = path.join("src/verify_scheme/test_outputs/signed-shares-0.cbor");
    let enc_b: PathBuf = path.join("src/verify_scheme/test_outputs/encrypted-shares-1.cbor");
    let signed_b: PathBuf = path.join("src/verify_scheme/test_outputs/signed-shares-1.cbor");
    let shares_paths = vec![(debug_signed, debug_enc), (signed_a, enc_a), (signed_b, enc_b)];

    return Ok((bin_paths, json_paths, shares_paths))
}

#[test]
/// Checks that all paths used in `paths()` are valid
fn verify_init() -> Result<(), Error> {
    let mut logger = LogConstructor::new(BenchmarkSelection::None, 0, 0);
    let (bin_paths, _, shares_paths) = paths()?;
    let bin_paths = &bin_paths[1..];
    let shares_paths = &shares_paths[1..];
    for (bin_path, (signed_path, enc_path)) in zip(bin_paths, shares_paths) {
        let (attestation_blob, some_session, is_bin) = attestation_from_path(&bin_path)?;
        assert!(is_bin);
        let Some(session_id) = some_session else {
            return Err(Error::Test("Attestation binary path should contain a session ID in file name".to_string()))
        };
        let (signed_shares, enc_shares) = shares_from_path(&signed_path, &enc_path)?;
        let input = SessionInput { session_id, pcrs: None };
        verify_session(&attestation_blob, &signed_shares, &enc_shares, &input, &mut logger)?;
    }
    Ok(())
}

#[test]
/// Given a path to a valid attestation, test AWS attestation verification by changing random bits and running verification
fn random_mutate_test() -> Result<(), Error> {
    let (bin_paths, _, _) = paths()?;
    let path = &bin_paths[1];

    let mut blob = fs::read(path)?;
    for _ in 0..TIMES {
        let index = rand::random_range(..blob.len());
        // Randomly choose to insert, remove, or update at an index
        match rand::random_range(0..3) {
            0 => { blob.remove(index); }
            1 => blob.insert(index, rand::random()),
            2 => blob[index] = rand::random(),
            _ => return Err(Error::Test("Unreachable".to_string())),
        };
    }
    let Some(doc) = SecureModule::parse_raw_attestation_doc(&blob).ok() else {
        return Ok(())
    };
    let Err(_) = verify_aws_attestation(&blob, &doc) else {
        return Err(Error::Test("Mutations should have resulted in a verification failure".to_string()))
    };
    Ok(())
}

/// This function swaps out one of attestation blob `a`'s CBOR field with attestation blob `b`'s
/// 
/// An attestation is signed and serialized as a COSE_Sign1 structure, which is a CBOR array of the form:
/// ```
///     [
///         protected:   // Header
///         unprotected: // Header
///         payload:     // This field contains the serialized content to be signed
///         signature:   // This field contains the computed signature value
///     ]
/// ```
fn cbor_swap(blob_a: &[u8], blob_b: &[u8], i: usize) -> Result<Vec<u8>, Error> {
    let Value::Array(mut cbor_a) = serde_cbor::from_slice(&blob_a)? else {
        return Err(Error::Test("Cbor should be array".to_string()))
    };
    assert!(cbor_a.len() == 4);
    let Value::Array(cbor_b) = serde_cbor::from_slice(&blob_b)? else {
        return Err(Error::Test("Cbor should be array".to_string()))
    };
    assert!(cbor_b.len() == 4);
    cbor_a[i] = cbor_b[i].clone();
    let new_blob_a = serde_cbor::to_vec(&cbor_a)?;
    Ok(new_blob_a)
}

/// Create evil X509 certificate and certificate chain based on a random ECDSA 384 keypair (like in AWS)
fn evil_certs() -> Result<(X509, PKey<Private>), Error> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
    let ec = EcKey::generate(group.as_ref())?;
    let key = PKey::from_ec_key(ec)?;

    let mut name = X509Name::builder()?;
    name.append_entry_by_text("CN", "evil")?;
    let name = name.build();

    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, true)?;

    let mut builder = X509Builder::new()?;
    builder.set_subject_name(&name)?;
    builder.set_serial_number(serial.to_asn1_integer()?.as_ref())?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
    builder.set_pubkey(&key)?;
    builder.sign(&key, MessageDigest::sha384())?;
    let cert = builder.build();

    Ok((cert, key))
}

#[test]
/// Given paths to valid attestations, test all possibilities of an adversary swapping out CBOR fields (specifically payload and/or signature)
fn cbor_swap_test() -> Result<(), Error> {
    let (bin_paths, _, _) = paths()?;
    let path_a = &bin_paths[1];
    let path_b = &bin_paths[2];

    let blob_a = fs::read(path_a)?;
    let blob_b = fs::read(path_b)?;

    // Test swapping out valid field with valid field
    for i in 0..4 {
        let temp_blob_a = cbor_swap(&blob_a, &blob_b, i)?;
        let temp_doc_a = SecureModule::parse_raw_attestation_doc(&temp_blob_a)?;
        if i < 2 {
            // Swapping out valid protected and unprotected fields of two valid attestations should pass verification
            verify_aws_attestation(&temp_blob_a, &temp_doc_a)?;
        } else {
            // Swapping out a payload/signature, even if the other payload/signature is valid, should error
            verify_certificate_chain(&temp_doc_a)?; // Should still pass certificate chain
            let Err(_) = verify_aws_signature(&temp_blob_a, &temp_doc_a) else {
                return Err(Error::Test("Swapping out cbor payloads should fail verification".to_string()))
            };
        }
    }
    
    // Create evil attestation doc with evil session ID, with certificate/cabundle based on adversary's signing key
    let mut evil_attest = SecureModule::parse_raw_attestation_doc(&blob_a)?;
    let evil_nonce = "evil session".as_bytes();
    evil_attest.nonce = Some(ByteBuf::from(evil_nonce));
    let (cert, key) = evil_certs()?;
    evil_attest.certificate = ByteBuf::from(cert.to_der()?);
    evil_attest.cabundle = vec![ByteBuf::from(cert.to_der()?)];
    let evil_attest = evil_attest.to_binary();

    // Create evil binary attestation by signing the evil attestation doc with the signing key
    let evil_cbor = CoseSign1::new::<Openssl>(&evil_attest, &HeaderMap::new(), &key)?;
    let evil_blob = serde_cbor::to_vec(&evil_cbor)?;

    // Swap valid attestation binary's payload and signature with evil binary attestation's payload and signature
    let mut temp_blob_a = cbor_swap(&blob_a, &evil_blob, 2)?;
    temp_blob_a = cbor_swap(&temp_blob_a, &evil_blob, 3)?;
    let temp_doc_a = SecureModule::parse_raw_attestation_doc(&temp_blob_a)?;

    // Signature should pass (since the certificate chain's key is the same one as the signature in the cbor)
    // But certificate chain should fail since root certificate is not AWS
    let Err(_) = verify_certificate_chain(&temp_doc_a) else {
        return Err(Error::Test("Certificate verification should have failed".to_string()))?
    };
    verify_aws_signature(&temp_blob_a, &temp_doc_a)?;
    Ok(())
}

#[test]
/// Test a debug-mode attestation (all-zero PCRs)
fn debug_attestation_test() -> Result<(), Error> {
    let (bin_paths, _, _) = paths()?;
    let debug_bin = &bin_paths[0];

    let attestation_blob = fs::read(debug_bin)?;
    let attestation = SecureModule::parse_raw_attestation_doc(&attestation_blob)?;

    // A debug-mode attestation should still be a valid attestation
    verify_aws_attestation(&attestation_blob, &attestation)?;
    // But should fail all-zero PCR check
    let Err(_) = verify_pcrs(&attestation, &None) else {
        return Err(Error::Test("Should fail when PCRs are all zero".to_string()))
    };
    Ok(())
}

#[test]
/// Test valid attestation and valid shares, but the shares aren't signed by attestation's enclave public key
fn enclave_signature_test() -> Result<(), Error> {
    let (bin_paths, _, shares_paths) = paths()?;
    let bin_a = &bin_paths[1];
    let (signed_b, enc_b) = &shares_paths[2];
    let blob_a = fs::read(bin_a)?;
    let attest_a = SecureModule::parse_raw_attestation_doc(&blob_a)?;
    let (signed_b, enc_b) = shares_from_path(signed_b, enc_b)?;
    let Err(_) = verify_enclave_signatures(&attest_a, &signed_b, &enc_b) else {
        return Err(Error::Test("Should fail when shares aren't signed by public key in attestation".to_string()))
    };
    Ok(())
}

