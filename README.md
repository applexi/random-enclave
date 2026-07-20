# Correlated Random Generator via AWS Nitro Enclave

This project contains a workspace (host, enclave, common) where the [host](./host/) AWS instance (or client) communicates with its [enclave](./enclave/) (or server) to request and receive random and correlated shares defined in [common](./common/). To prove itself and the outputs, the enclave requests and provides an AWS attestation via NSM. The host then uses that attestation and the received shares and verifies everything locally.

Additional features include:
- specify a session ID for a random request that the attestation should contain
- save the attestation and outputs from a random request
- verify an attestation is a valid AWS attestation
- verify outputs based on an attestation and the enclave scheme (if you want to edit an attestation in json form)

The vsock communication is done using [Pontifex](https://github.com/worldcoin/pontifex)!

## Overview

![Architecture diagram](random_scheme.svg)

Currently, for each random request, the host randomly generates (N = 5) dummy keypairs. It then sends the N public keys and a session ID to the enclave. The enclave then randomly generates a new signing keypair and random secret. From that random secret, it creates N correlated arithmetic and binary shares, encrypting each share bundle with a public key. It then requests an attestation with its signing public key and the session ID, and sends the attestation and the N signatures and encrypted shares to the host. The host then verifies the attestation is a valid AWS Nitro attestation, and that the outputs are correct with respect to this scheme.

In production, the host should not have the other parties' secret keys, and all parties should do the verification process locally, with consensus on a session ID.

## Prerequisites

In order to run this crate, your AWS instance should have:
- Rust
- AWS Nitro Enclaves CLI 
- Docker
- At least 2 CPU cores and 512 MiB to reserve for the enclave

### (Optional) Setting up PCR8

Do the following in your AWS instance if you want your EIF to contain PCR8 (signed EIF certificate):

```bash
mkdir -p developer

# Create a private signing key
openssl ecparam \
    -name secp384r1 \
    -noout \
    -genkey \
    -out developer/eif-signing-key.pem

# Create a certificate 
openssl req \
    -new \
    -x509 \
    -key developer/eif-signing-key.pem \
    -out developer/eif-signing-cert.pem \
    -subj "/CN=eif-signing"
```

## Installation 

In your AWS instance (which is acting as the host):

```bash
git clone https://github.com/applexi/random-enclave.git
cd random-enclave
cargo build --workspace --release

# Build docker image
docker build -t random-enclave .
```

### Build EIF

If you have a private key and signing certificate [(set it up here)](#optional-setting-up-pcr8):

```bash 
nitro-cli build-enclave \
    --docker-uri random-enclave:latest \
    --output-file random-enclave.eif \
    --private-key ../developer/eif-signing-key.pem \
    --signing-certificate ../developer/eif-signing-cert.pem
```

Otherwise:

```bash 
nitro-cli build-enclave \
    --docker-uri random-enclave:latest \
    --output-file random-enclave.eif 
```

Note that you should see PCRs 0-2 and optionally PCR8.

### Running the Nitro Enclave

Now that we have our EIF in `~/random-enclave/random-enclave.eif`, we need to get our Nitro Enclave running.

In your AWS user home directory, ensure you have enough cores and memory allocated for the Nitro Enclave:

```bash
cd ~/

# Check that memory_mib >= 512 and cpu_count >= 2, edit if not
cat /etc/nitro_enclaves/allocator.yaml

# Allocate cores and memory
sudo aws-nitro-enclaves-cli/usr/bin/nitro-enclaves-allocator
```

Now run the enclave. Add the flag `--debug-mode` to this command to test all-zero PCR attestations.


```bash
nitro-cli run-enclave \
    --cpu-count 2 \
    --memory 512 \
    --eif-path random-enclave/random-enclave.eif
```

To see the running enclave's PCRs and information:

```bash
nitro-cli describe-enclaves
```

Save the enclave's `EnclaveID`, `EnclaveCID`, and listed PCRs for later usage + verification.

## Usage

Ensure you have the enclave running. Now, let's set up "host", or the client side.

```bash
cargo build --package host
cargo run --package host -- --enclave-cid <YOUR-ENCLAVE-CID>
```

You should see `Connected to enclave <YOUR-ENCLAVE-CID> on port 1000` and a `>` prompting user input. Each line is a clap command; type `--help` for all flags.

There are three possible requests (`-r`/ `--request`):

### random

Does the full scheme as described in [Overview](#overview). Sends a random request to the enclave, which returns a response containing the attestation + shares. Then, automatically verifies the entire response.

| Flag | Meaning |
|------|---------|
| `-s` / `--session-id` `<YOUR-SESSION-ID>` | A nonce the attestation must contain (default: `0`) |
| `--pcr <INDEX>=<PCR-VALUE>` | Expected PCR(s) (optional, repeatable) |
| `--get-attest [DIR-PATH]` | Save attestation + shares (optional, default: `.`) |

Examples:
```bash
# Basic random request and response with all defaults
--request random 

# Random request with a user-specified session ID of 888
--request random --session-id 888
# Random request with a session ID and with PCR0 and PCR8 values from earlier
--request random --session-id 888 --pcr 0=<PCR0> --pcr 8=<PCR8>
# Random request, saving the attestation + outputs to ~/random-enclave/enclave-output
--request random --get-attest
```

### verify

Tests the host's local verification process and does not call the enclave. Behavior depends on what you pass:

| Flag | Meaning |
|------|---------|
| `-s` / `--session-id` `<YOUR-SESSION-ID>` | Same as in [random](#random) (default: # in `--attestation` file, else `0`) |
| `--pcr <INDEX>=<PCR-VALUE>` | Same as in [random](#random) (optional, repeatable) |
| `--attestation <PATH (.bin/.json)>` | If (.bin), checks valid attestation. If (.json), checks scheme. |
| `--signed-shares <PATH (.cbor)>` | Path to signed + encrypted shares (optional) |
| `--enc-shares <PATH> (.cbor)>` | Path to encrypted shares (optional) |

Examples:
```bash
# Verify an attestation is a valid AWS attestation and that the outputs are valid with respect to scheme, with PCR0
# If attestation file name is 'attestation-{SESSION-ID}', checks session ID with SESSION-ID
# To verify shares are signed by enclave, must include both `--signed-shares` and `--enc-shares`
--request verify --attestation <PATH (.bin)> --signed-shares <PATH (.cbor)> --enc-shares <PATH (.cbor)> --PCR0 0=<PCR0>

# Verify an attestation is a valid AWS attestation
--request verify --attestation <PATH (.bin)> 
# Verify an attestation is a valid AWS with specified session ID and PCR0 and PCR8
--request verify --attestation <PATH (.bin)> --session-id 888 --PCR0 0=<PCR0> --PCR8 8=<PCR8>

# Verify outputs are valid with respect to the attestation's fields
# Cannot verify if attestation is valid AWS attestation
# Must include `--signed-shares` and `--enc-shares`
--request verify --attestation <PATH (.json)> --signed-shares <PATH (.cbor)> --enc-shares <PATH (.cbor)> 
```

### quit

Disconnects with the enclave. Note that the host can reconnect anytime afterwards as long as the enclave is running.

```bash
--request quit
```

To fully terminate the enclave:

```bash
nitro-cli terminate-enclave --enclave-id <YOUR-ENCLAVE-ID>
```

## Tests

The crate comes with enclave sanity tests in [scheme](./enclave/src/scheme.rs). Run the following to check correctness of the secret sharing, signing, and encryption:

```bash
cargo test --package enclave
```