/*
 * Copyright 2019 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */

extern crate openssl;

use std::iter::repeat;
use self::openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sha::sha256,
    sign::Verifier,
};
use crypto::{digest::Digest, sha2::Sha256};
use protos::validator_registry::{SignUpInfo, SignUpInfoProof, ValidatorRegistryPayload};
use sawtooth_sdk::{
    messages::setting::Setting,
    processor::handler::{ApplyError, TransactionContext},
};
use validator_registry_tp_handler::{get_state, parse_from};

const SETTING_ADDRESS_PART_SIZE: usize = 16;
const SETTING_NAMESPACE: &str = "000000";
const SETTING_MAX_KEY_PARTS: usize = 4;

const SAWTOOTH_POET_REPORT_PUBLIC_KEY_STR: &str = "sawtooth.poet.report_public_key_pem";

pub fn verify_signup_info(
    context: &mut TransactionContext,
    originator_public_key_hash: &String,
    val_reg_payload: &ValidatorRegistryPayload,
) -> Result<(), ApplyError> {
    let signup_info: SignUpInfo = val_reg_payload.get_signup_info().clone();
    let proof_data: SignUpInfoProof = signup_info.get_proof_data().clone();

    // Verify the attestation verification report signature
    let verification_report = proof_data.get_verification_report();
    let signature = &proof_data.get_signature();

    // Try to get the report key from the configuration setting.  If it
    // is not there or we cannot parse it, fail verification.
    let report_public_key_pem =
        match get_config_setting(context, SAWTOOTH_POET_REPORT_PUBLIC_KEY_STR) {
            Ok(setting) => setting,
            Err(_) =>
                return Err(
                    ApplyError::InvalidTransaction(
                        format!("Error reading config setting: PoET public key"),
                    ),
                ),
        };
    if report_public_key_pem.is_none() {
        return Err(
            ApplyError::InvalidTransaction(
                format!("Error reading config setting: PoET public key"),
            ),
        );
    }
    let public_key = match PKey::public_key_from_pem(
        report_public_key_pem.unwrap().as_bytes(),
    ) {
        Ok(key) => key,
        Err(_) => return Err(
            ApplyError::InvalidTransaction(
                format!("Error creating Public Key object"),
            ),
        ),
    };

    // TODO: Need below 2 parameters for quote verification
    /*
    let valid_measurements = self._get_config_setting(
        context,
        &"sawtooth.poet.valid_enclave_measurements".to_string())
        .expect("Error reading config setting: Enclave measurements");
    let valid_basenames = self._get_config_setting(
        context,
        &"sawtooth.poet.valid_enclave_basenames".to_string())
        .expect("Error reading config setting: Enclave basename");
    */

    let decoded_sig = match base64::decode(signature) {
        Ok(sig) => sig,
        Err(_) => return Err(
            ApplyError::InvalidTransaction(
                format!("Unable to decode the signature from base64 format")
            ),
        ),
    };
    let verified =
        match verify_message_signature(&public_key, verification_report.as_bytes(), &decoded_sig) {
            Ok(result) => result,
            Err(e) => return Err(e),
    };
    if !verified {
        error!("Verification report signature does not match");
        return Err(ApplyError::InvalidTransaction(
            format!("Verification report signature does not match"),
        ));
    }

    // Convert verification_report json into HashMap
    let verification_report_tmp_value: serde_json::Value =
        match serde_json::from_str(verification_report) {
            Ok(verification_report) => verification_report,
            Err(_) => return Err(
                ApplyError::InvalidTransaction(
                    format!("Error reading verification report as Json")
                ),
            ),
        };
    let verification_report_dict =
        match verification_report_tmp_value
            .as_object() {
            Some(obj) => obj,
            None => return Err(
                ApplyError::InvalidTransaction(
                    format!("Error reading verification report as Key Value pair"),
                ),
            ),
        };
    // Verify that the verification report meets the following criteria:
    // Includes an ID field.
    if !verification_report_dict.contains_key("id") {
        error!("Verification report does not contain id field");
        return Err(
            ApplyError::InvalidTransaction(
                format!("Verification report does not contain id field")
            ),
        );
    }

    // Includes an EPID psuedonym.
    if !verification_report_dict.contains_key("epidPseudonym") {
        error!("Verification report does not contain an EPID psuedonym");
        return Err(
            ApplyError::InvalidTransaction(
                format!("Verification report does not contain an EPID psuedonym")
            ),
        );
    }

    // Verify that the verification report EPID pseudonym matches the anti-sybil ID
    let epid_pseudonym_data =
        match verification_report_dict
            .get("epidPseudonym") {
            Some(data) => data,
            None => return Err(
                ApplyError::InvalidTransaction(
                    format!("Error reading epidPseudonym from verification report"),
                ),
            ),
        };
    let epid_pseudonym =
        match epid_pseudonym_data
            .as_str() {
            Some(value) => value,
            None => return Err(
                ApplyError::InvalidTransaction(
                    format!("Error converting epidPseudonym as string reference"),
                ),
            ),
        };
    if epid_pseudonym != signup_info.anti_sybil_id {
        error!(
            "The anti-sybil ID in the verification report {} does not match the one \
             contained in the signup information {}",
            epid_pseudonym, signup_info.anti_sybil_id
        );
        return Err(
            ApplyError::InvalidTransaction(
                format!(
                    "The anti-sybil ID in the verification report {} does not match the one \
                    contained in the signup information {}",
                    epid_pseudonym, signup_info.anti_sybil_id
                ),
        ));
    }

    // Includes an enclave quote.
    if !verification_report_dict.contains_key("isvEnclaveQuoteBody") {
        error!("Verification report does not contain enclave quote body");
        return Err(ApplyError::InvalidTransaction(
            format!("Verification report does not contain enclave quote body"),
        ));
    }

    // The ISV enclave quote body is base 64 encoded
    let _enclave_quote =
        match verification_report_dict
            .get("isvEnclaveQuoteBody") {
            Some(quote) => quote,
            None => return Err(
                ApplyError::InvalidTransaction(
                    format!("Error reading isvEnclaveQuoteBody from verification report"),
                ),
            ),
        };

    // The report body should be SHA256(SHA256(OPK)|PPK)
    let hash_input = format!(
        "{}{}",
        originator_public_key_hash.to_uppercase(),
        signup_info.poet_public_key.to_uppercase()
    );
    let _hash_value = sha256(hash_input.as_bytes());
    // TODO: Quote verification
    // Verify that the nonce in the verification report matches the nonce in the transaction
    // payload submitted
    let nonce = match verification_report_dict.get("nonce") {
        Some(nonce_present) => match nonce_present.as_str() {
            Some(nonce_str) => nonce_str,
            None => return Err(
                ApplyError::InvalidTransaction(
                    format!("Error reading nonce as string reference")
                ),
            ),
        },
        None => "",
    };
    if nonce != signup_info.nonce {
        error!(
            "AVR nonce {} does not match signup info nonce {}",
            nonce, signup_info.nonce
        );
        return Err(ApplyError::InvalidTransaction(
            format!("AVR nonce doesn't match signup info nonce"),
        ));
    }
    Ok(())
}

/// Function to verify if message digest (SHA256 of message) is signed using private key
/// associated with the public key sent as a input parameter. Accepts message, public key and
/// signature of the message as input parameters.
///
/// Note: Digest of message is calculated using SHA256 algorithm in this function.
fn verify_message_signature(
    pub_key: &PKey<Public>,
    message: &[u8],
    signature: &[u8]
) -> Result<bool, ApplyError> {
    let mut verifier = match Verifier::new(MessageDigest::sha256(), pub_key) {
        Ok(obj) => obj,
        Err(_) => return Err(ApplyError::InvalidTransaction(
            format!("Error creating verifier object for SHA256 algortihm"),
        )),
    };
    if verifier.update(message).is_err() {
        return Err(ApplyError::InvalidTransaction(
            format!("Error updating message to verifier"),
        ));
    }
    match verifier.verify(signature) {
        Err(_) => return Err(ApplyError::InvalidTransaction(
            format!("Error verifying message"),
        )),
        Ok(result) => return Ok(result)
    };
}

fn get_config_setting(
    context: &mut TransactionContext,
    key: &str,
) -> Result<Option<String>, ApplyError> {
    let config_key_address = config_key_to_address(key);
    let setting_data = get_state(context, &config_key_address);

    match setting_data {
        Err(err) => Err(err),
        Ok(entries) => {
            let entries_read = match entries {
                None => return Err(
                    ApplyError::InvalidTransaction(
                        format!("Error reading entries")
                    ),
                ),
                Some(read) => read,
            };
            let setting: Setting = parse_from(&entries_read)?;
            for entry in setting.get_entries().iter() {
                if entry.get_key() == key {
                    return Ok(Some(entry.get_value().to_string()));
                }
            }
            Ok(None)
        }
    }
}

fn config_key_to_address(key: &str) -> String {
    let mut address = String::new();
    address.push_str(SETTING_NAMESPACE);
    address.push_str(
        &key.splitn(SETTING_MAX_KEY_PARTS, '.')
            .chain(repeat(""))
            .map(config_short_hash)
            .take(SETTING_MAX_KEY_PARTS)
            .collect::<Vec<_>>()
            .join(""),
    );

    address
}

fn config_short_hash(input_str: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input(input_str.as_bytes());
    hasher.result_str()[0..SETTING_ADDRESS_PART_SIZE].to_string()
}
