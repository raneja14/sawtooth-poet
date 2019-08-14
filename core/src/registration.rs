/*
 Copyright 2019 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

use hyper::{header, header::HeaderValue, Body, Client, Method, Request, Uri};
use ias_client::client_utils::read_response_future;
use poet2_util::{
    read_file_as_string_ignore_line_end, sha256_from_str, write_binary_file, sha512_of_bytearray,
    to_hex_string, sha256_from_bytes,
};
use poet_config::PoetConfig;
use protobuf::{Message, RepeatedField};
use sawtooth_sdk::{
    messages::{
        batch::{Batch, BatchHeader, BatchList},
        transaction::{Transaction, TransactionHeader},
    },
    signing::{create_context, secp256k1::Secp256k1PrivateKey, PrivateKey, PublicKey, Signer},
};
use std::{env, path::Path, str, iter::repeat};
use protos::{
    validator_registry::{
        ValidatorRegistryPayload, SignUpInfo,
    },
    settings::{
        SettingProposal, SettingsPayload, SettingsPayload_Action,
    }
};
use rand::Rng;

const SETTING_ADDRESS_PART_SIZE: usize = 16;
const VALIDATOR_REGISTRY: &str = "validator_registry";
const CONTEXT_ALGORITHM_NAME: &str = "secp256k1";
const VALIDATOR_REGISTRY_VERSION: &str = "2.0";
const VALIDATOR_MAP: &str = "validator_map";
const REGISTER_ACTION: &str = "register";
const VALIDATOR_NAME_PREFIX: &str = "validator-";
const NAMESPACE_ADDRESS_LENGTH: usize = 6;
const MAX_SETTINGS_PARTS: usize = 4;
const SETTINGS_PART_LENGTH: usize = 16;
const CONFIGSPACE_NAMESPACE: &str = "000000";
const PUBLIC_KEY_IDENTIFIER_LENGTH: usize = 8;
const DEFAULT_POET_CLIENT_PRIVATE_KEY: &str = "/etc/sawtooth/keys/validator.priv";
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";
const SETTING_KEY_SEPARATOR: &str = ".";
const EMPTY_STR: &str = "";
const SAWTOOTH_POET_VALID_MEASUREMENTS: &str = "sawtooth.poet.valid_enclave_measurements";
const SAWTOOTH_POET_VALID_BASENAMES: &str = "sawtooth.poet.valid_enclave_basenames";
const SAWTOOTH_SETTINGS_VOTE_PROPOSALS: &str = "sawtooth.settings.vote.proposals";
const SAWTOOTH_SETTINGS_VOTE_AUTHORIZED_KEYS: &str = "sawtooth.settings.vote.authorized_keys";
const SAWTOOTH_SETTINGS_VOTE_APPROVAL_THRESHOLD: &str = "sawtooth.settings.vote.approval_threshold";

/// Function to compose a registration request and send it to validator over REST API (for non
/// genesis node) or store in a batch file in case of genesis node.
/// Accepts validator private key, signup information (AVR or the quote), block_id which can be
/// used as nonce (there's registration after every K blocks, which needs to send new nonce).
///
/// Returns response from validator REST API as string.
pub fn do_create_registration(
    config: &PoetConfig,
    nonce: &str,
    signup_info: SignUpInfo,
    mr_enclave: String,
    basename: String,
) -> BatchList {
    // Read private key from default path if it's not given as input in config
    let mut key_file = config.get_poet_client_private_key_file();
    if key_file.is_empty() {
        key_file = DEFAULT_POET_CLIENT_PRIVATE_KEY.to_string();
    }
    let read_key = read_file_as_string_ignore_line_end(key_file.as_str());

    let private_key: Box<PrivateKey> =
        Box::new(Secp256k1PrivateKey::from_hex(read_key.as_str()).expect("Invalid private key"));
    let context = create_context(CONTEXT_ALGORITHM_NAME).expect("Unsupported algorithm");
    let signer = Signer::new(context.as_ref(), private_key.as_ref());
    // get signer and public key from signer in hex
    let public_key = signer.get_public_key().expect("Public key not found");

    // Construct payload and serialize it
    let verb = REGISTER_ACTION.to_string();
    let mut name = String::new();
    name.push_str(VALIDATOR_NAME_PREFIX);
    name.push_str(&public_key.as_hex()[..PUBLIC_KEY_IDENTIFIER_LENGTH]);
    let id = public_key.as_hex();
    info!("ID in transaction is {}", id.clone());

    let mut raw_payload = ValidatorRegistryPayload::new();
    raw_payload.set_verb(verb);
    raw_payload.set_name(name);
    raw_payload.set_id(id);
    raw_payload.set_signup_info(signup_info);
    let payload = raw_payload.write_to_bytes().expect("Error serializing the payload");

    // Namespace for the TP
    let vr_namespace = &sha256_from_str(VALIDATOR_REGISTRY)[..NAMESPACE_ADDRESS_LENGTH];
    // get public key hash -> sha256 in hex
    let public_key_hash = sha256_from_str(public_key.as_hex().as_str());

    // Validator map address
    let mut vr_map_address = String::new();
    vr_map_address.push_str(vr_namespace);
    vr_map_address.push_str(sha256_from_str(VALIDATOR_MAP).as_str());

    // Address to lookup this transaction
    let mut vr_entry_address = String::new();
    vr_entry_address.push_str(vr_namespace);
    vr_entry_address.push_str(public_key_hash.as_str());

    // Output address for the transaction
    let output_addresses = [vr_entry_address.clone(), vr_map_address.clone()];
    let input_addresses = [
        vr_entry_address,
        vr_map_address,
        get_address_for_setting("sawtooth.poet.report_public_key_pem"),
        get_address_for_setting(SAWTOOTH_POET_VALID_MEASUREMENTS),
        get_address_for_setting(SAWTOOTH_POET_VALID_BASENAMES),
    ];

    warn!("Input addresses are {} and {}",
        get_address_for_setting(SAWTOOTH_POET_VALID_MEASUREMENTS),
        get_address_for_setting(SAWTOOTH_POET_VALID_BASENAMES));

    // Create transaction header
    let transaction_header = create_transaction_header(
        &input_addresses,
        &output_addresses,
        &payload,
        &public_key,
        nonce.to_string(),
    );

    // Create transaction
    let transaction = create_transaction(&signer, &transaction_header, payload);

    let created_mr_enclave_batch = create_mr_enclave(&signer, &public_key, mr_enclave);
    let created_basename_batch = create_basename(&signer, &public_key, basename);

    // Create batch header, batch
    let batch = create_batch(&signer, transaction);

    // Create batch list
    create_batch_list(vec![created_mr_enclave_batch, created_basename_batch, batch])
}

/// Temporary functions to create settings transactions for enclave measuremenrs and the basename
fn create_mr_enclave(signer: &Signer, public_key: &Box<PublicKey>, mr_enclave: String) -> Batch {
    let address = get_address_for_setting(SAWTOOTH_POET_VALID_MEASUREMENTS);
    let other_address1 = get_address_for_setting(SAWTOOTH_SETTINGS_VOTE_PROPOSALS);
    let other_address2 = get_address_for_setting(SAWTOOTH_SETTINGS_VOTE_AUTHORIZED_KEYS);
    let other_address3 = get_address_for_setting(SAWTOOTH_SETTINGS_VOTE_APPROVAL_THRESHOLD);
    let input_addresses = [address.clone(), other_address1.clone(), other_address2.clone(), other_address3.clone()];
    let ouput_addresses = [address, other_address2, other_address1, other_address3];
    let nonce_bytes = rand::thread_rng().gen_iter::<u8>().take(64).collect::<Vec<u8>>();
    let nonce = to_hex_string(&nonce_bytes);
    let mut raw_payload = SettingProposal::new();
    raw_payload.set_setting(SAWTOOTH_POET_VALID_MEASUREMENTS.to_string());
    raw_payload.set_value(mr_enclave);
    raw_payload.set_nonce(nonce.clone());
    let proposal = raw_payload.write_to_bytes().expect("Error serializing the payload");
    let mut raw_pay = SettingsPayload::new();
    raw_pay.set_action(SettingsPayload_Action::PROPOSE);
    raw_pay.set_data(proposal.clone());
    let payload = raw_pay.write_to_bytes().expect("Error serializing the payload");

    let transaction_header = create_transaction_header_settings(
        &input_addresses,
        &ouput_addresses,
        &payload,
        public_key,
        nonce,
    );

    let transaction = create_transaction(
        signer,
        &transaction_header,
        payload,
    );

    create_batch(signer, transaction)
}

fn create_basename(signer: &Signer, public_key: &Box<PublicKey>, basename: String) -> Batch {
    let address = get_address_for_setting(SAWTOOTH_POET_VALID_BASENAMES);
    let other_address1 = get_address_for_setting(SAWTOOTH_SETTINGS_VOTE_PROPOSALS);
    let other_address2 = get_address_for_setting(SAWTOOTH_SETTINGS_VOTE_AUTHORIZED_KEYS);
    let other_address3 = get_address_for_setting(SAWTOOTH_SETTINGS_VOTE_APPROVAL_THRESHOLD);
    let input_addresses = [address.clone(), other_address1.clone(), other_address2.clone(), other_address3.clone()];
    let ouput_addresses = [address, other_address2, other_address1, other_address3];
    let nonce_bytes = rand::thread_rng().gen_iter::<u8>().take(64).collect::<Vec<u8>>();
    let nonce = to_hex_string(&nonce_bytes);
    let mut raw_payload = SettingProposal::new();
    raw_payload.set_setting(SAWTOOTH_POET_VALID_BASENAMES.to_string());
    raw_payload.set_value(basename);
    raw_payload.set_nonce(nonce.clone());
    let proposal = raw_payload.write_to_bytes().expect("Error serializing the payload");
    let mut raw_pay = SettingsPayload::new();
    raw_pay.set_action(SettingsPayload_Action::PROPOSE);
    raw_pay.set_data(proposal.clone());
    let payload = raw_pay.write_to_bytes().expect("Error serializing the payload");

    let transaction_header = create_transaction_header_settings(
        &input_addresses,
        &ouput_addresses,
        &payload,
        public_key,
        nonce,
    );

    let transaction = create_transaction(
        signer,
        &transaction_header,
        payload,
    );

    create_batch(signer, transaction)
}

/// Function to create the ```BatchList``` object, which later is serialized and sent to REST API
/// Accepts ```Batch``` as a input parameter.
fn create_batch_list(batches: Vec<Batch>) -> BatchList {
    // Construct batch list
    let batches = RepeatedField::from_vec(batches);
    let mut batch_list = BatchList::new();
    batch_list.set_batches(batches);
    batch_list
}

/// Function to create the ```Batch``` object, this is then added to ```BatchList```. Accepts
/// signer object and ```Transaction``` as input parameters. Constructs ```BatchHeader``` , adds
/// signature of it to ```Batch```.
fn create_batch(signer: &Signer, transaction: Transaction) -> Batch {
    // Construct BatchHeader
    let mut batch_header = BatchHeader::new();
    // set signer public key
    let public_key = signer
        .get_public_key()
        .expect("Unable to get public key")
        .as_hex();
    let transaction_ids = vec![transaction.clone()]
        .iter()
        .map(|trans| String::from(trans.get_header_signature()))
        .collect();
    batch_header.set_transaction_ids(RepeatedField::from_vec(transaction_ids));
    batch_header.set_signer_public_key(public_key);

    // Construct Batch
    let batch_header_bytes = batch_header
        .write_to_bytes()
        .expect("Error converting batch header to bytes");
    let signature = signer
        .sign(&batch_header_bytes)
        .expect("Error signing the batch header");
    let mut batch = Batch::new();
    batch.set_header_signature(signature);
    batch.set_header(batch_header_bytes);
    batch.set_transactions(RepeatedField::from_vec(vec![transaction]));
    batch
}

/// Function to create ```Transaction``` object, accepts payload, ```TransactionHeader``` and
/// ```Signer```.
fn create_transaction(
    signer: &Signer,
    transaction_header: &TransactionHeader,
    payload: Vec<u8>,
) -> Transaction {
    // Construct a transaction, it has transaction header, signature and payload
    let transaction_header_bytes = transaction_header
        .write_to_bytes()
        .expect("Error converting transaction header to bytes");
    let transaction_header_signature = signer
        .sign(&transaction_header_bytes.to_vec())
        .expect("Error signing the transaction header");
    let mut transaction = Transaction::new();
    transaction.set_header(transaction_header_bytes.to_vec());
    transaction.set_header_signature(transaction_header_signature);
    transaction.set_payload(payload);
    transaction
}

/// Function to construct ```Settings TransactionHeader``` object, accepts parameters required such as
/// input and output addresses, payload, public key of transactor, nonce to be used.
fn create_transaction_header_settings(
    input_addresses: &[String],
    output_addresses: &[String],
    payload: &[u8],
    public_key: &Box<PublicKey>,
    nonce: String,
) -> TransactionHeader {
    // Construct transaction header
    let mut transaction_header = TransactionHeader::new();
    transaction_header.set_family_name("sawtooth_settings".to_string());
    transaction_header.set_family_version("1.0".to_string());
    transaction_header.set_nonce(nonce);
    transaction_header.set_payload_sha512(sha512_of_bytearray(payload));
    transaction_header.set_signer_public_key(public_key.as_hex());
    transaction_header.set_batcher_public_key(public_key.as_hex());
    transaction_header.set_inputs(RepeatedField::from_vec(input_addresses.to_vec()));
    transaction_header.set_outputs(RepeatedField::from_vec(output_addresses.to_vec()));
    transaction_header.clear_dependencies();
    transaction_header
}

/// Function to construct ```TransactionHeader``` object, accepts parameters required such as
/// input and output addresses, payload, public key of transactor, nonce to be used.
fn create_transaction_header(
    input_addresses: &[String],
    output_addresses: &[String],
    payload: &[u8],
    public_key: &Box<PublicKey>,
    nonce: String,
) -> TransactionHeader {
    // Construct transaction header
    let mut transaction_header = TransactionHeader::new();
    transaction_header.set_family_name(VALIDATOR_REGISTRY.to_string());
    transaction_header.set_family_version(VALIDATOR_REGISTRY_VERSION.to_string());
    transaction_header.set_nonce(nonce);
    transaction_header.set_payload_sha512(sha512_of_bytearray(payload));
    transaction_header.set_signer_public_key(public_key.as_hex());
    transaction_header.set_batcher_public_key(public_key.as_hex());
    transaction_header.set_inputs(RepeatedField::from_vec(input_addresses.to_vec()));
    transaction_header.set_outputs(RepeatedField::from_vec(output_addresses.to_vec()));
    transaction_header.clear_dependencies();
    transaction_header
}

/// Computes the radix address for the given setting key. Keys are broken into four parts, based
/// on the dots in the string. For example, the key `a.b.c` address is computed based on `a`,
/// `b`, `c` and the empty string. A longer key, for example `a.b.c.d.e`, is still broken into
/// four parts, but the remaining pieces are in the last part: `a`, `b`, `c` and `d.e`.
/// Each of these peices has a short hash computed (the first 16 characters of its SHA256 hash in
/// hex), and is joined into a single address, with the config namespace (`000000`) added at the
/// beginning.
/// Args:
///     setting (&str): the setting key
/// Returns:
///     String: the computed address
fn get_address_for_setting(setting: &str) -> String {
    let mut address = String::new();
    address.push_str(CONFIGSPACE_NAMESPACE);
    address.push_str(
        &setting.splitn(MAX_SETTINGS_PARTS, '.')
            .chain(repeat(""))
            .map(config_short_hash)
            .take(MAX_SETTINGS_PARTS)
            .collect::<Vec<_>>()
            .join(""),
    );

    address
}

fn config_short_hash(input_str: &str) -> String {
    let hash = sha256_from_bytes(input_str.as_bytes());
    hash[0..SETTING_ADDRESS_PART_SIZE].to_string()
}

/// Sends the BatchList to the REST API
pub fn submit_batchlist_to_rest_api(url: &str, api: &str, batch_list: BatchList) {
    // Create request body, which in this case is batch list
    let raw_bytes = batch_list
        .write_to_bytes()
        .expect("Unable to write batch list as bytes");
    let body_length = raw_bytes.len();
    let bytes = Body::from(raw_bytes.to_vec());

    // API to call
    let mut rest_api = String::new();
    rest_api.push_str(url);
    rest_api.push_str("/");
    rest_api.push_str(api);
    let uri = rest_api.parse::<Uri>().expect("Error constructing URI");

    // Construct client to send request
    // TODO: [improvement] Try to use client_utils::get_client() method.
    let client = Client::new();

    // Compose POST request, to register
    let mut request = Request::new(bytes);
    *request.method_mut() = Method::POST;
    *request.uri_mut() = uri;
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(APPLICATION_OCTET_STREAM),
    );
    request
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(body_length));

    // Call read_response_future to block on reading the response
    let response_future = client.request(request);
    read_response_future(response_future).expect("Error reading registration response");
}

/// Saves the ```BatchList``` to a file
pub fn save_batchlist_to_file(genesis_batch_path: &str, batch_list: &BatchList) {
    let current_working_directory =
        env::current_dir().expect("Error reading current working directory");
    let file_path = if genesis_batch_path.is_empty() {
        current_working_directory.as_path()
    } else {
        Path::new(genesis_batch_path)
    };
    let raw_bytes = batch_list
        .write_to_bytes()
        .expect("Unable to write batch list as bytes");
    write_binary_file(&raw_bytes, file_path.to_str().expect("Unexpected filename"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use sawtooth_sdk::signing::{secp256k1::Secp256k1Context, Context};

    #[test]
    fn test_get_address_for_setting() {
        let precomputed_address =
            "000000ca978112ca1bbdca3e23e8160039594a2e7d2c03a9507ae2e3b0c44298fc1c14";
        let address_calculated = get_address_for_setting("a.b.c");
        assert_eq!(precomputed_address, address_calculated);

        let precomputed_address =
            "000000ca978112ca1bbdca3e23e8160039594a2e7d2c03a9507ae2e67adc8234459dc2";
        let address_calculated = get_address_for_setting("a.b.c.d.e");
        assert_eq!(precomputed_address, address_calculated);
    }

    #[test]
    fn test_create_transaction() {
        // Construct transaction header
        let random_input_addresses = ["random input addresses".to_string()];
        let random_output_addresses = ["random output addresses".to_string()];
        let random_payload = "random payload".to_string();
        let random_nonce = "random nonce".to_string();
        let context = Secp256k1Context::new();
        let random_private_key: Box<PrivateKey> = context
            .new_random_private_key()
            .expect("Error generating random private key");
        let signer = Signer::new(&context, random_private_key.as_ref());
        let random_public_key = signer.get_public_key().unwrap();
        let random_transaction_header = create_transaction_header(
            &random_input_addresses,
            &random_output_addresses,
            random_payload.as_str(),
            &random_public_key,
            random_nonce.clone(),
        );

        // Get bytes and construct transaction
        let transaction_header_bytes = random_transaction_header
            .write_to_bytes()
            .expect("Error converting transaction header to bytes");
        let header_signature = signer
            .sign(&transaction_header_bytes.to_vec())
            .expect("Error signing the transaction header");
        let transaction = create_transaction(
            &signer,
            &random_transaction_header,
            random_payload.to_string(),
        );

        // Verify if transaction is properly composed
        assert_eq!(transaction.get_header().to_vec(), transaction_header_bytes);
        assert_eq!(transaction.get_header_signature(), header_signature);
        assert_eq!(
            transaction.get_payload(),
            random_payload.to_string().as_bytes()
        );
    }

    #[test]
    fn test_create_transaction_header() {
        // Construct transaction header
        let random_input_addresses = ["random input addresses".to_string()];
        let random_output_addresses = ["random output addresses".to_string()];
        let random_payload = "random payload".to_string();
        let random_nonce = "random nonce".to_string();
        let context = Secp256k1Context::new();
        let random_private_key: Box<PrivateKey> = context
            .new_random_private_key()
            .expect("Error generating random private key");
        let signer = Signer::new(&context, random_private_key.as_ref());
        let random_public_key = signer.get_public_key().unwrap();
        let random_transaction_header = create_transaction_header(
            &random_input_addresses,
            &random_output_addresses,
            random_payload.as_str(),
            &random_public_key,
            random_nonce.clone(),
        );

        let payload_hash_bytes = sha512_from_str(random_payload.as_str());
        // Verify if transaction header is properly composed
        assert_eq!(random_transaction_header.get_nonce(), random_nonce);
        assert_eq!(
            random_transaction_header.get_payload_sha512(),
            payload_hash_bytes
        );
    }

    #[test]
    fn test_create_batch() {
        // Construct transaction header
        let random_input_addresses = ["random input addresses".to_string()];
        let random_output_addresses = ["random output addresses".to_string()];
        let random_payload = "random payload".to_string();
        let random_nonce = "random nonce".to_string();
        let context = Secp256k1Context::new();
        let random_private_key: Box<PrivateKey> = context
            .new_random_private_key()
            .expect("Error generating random private key");
        let signer = Signer::new(&context, random_private_key.as_ref());
        let random_public_key = signer.get_public_key().unwrap();
        let random_transaction_header = create_transaction_header(
            &random_input_addresses,
            &random_output_addresses,
            random_payload.as_str(),
            &random_public_key,
            random_nonce.clone(),
        );

        // Get bytes and construct transaction
        let transaction = create_transaction(
            &signer,
            &random_transaction_header,
            random_payload.to_string(),
        );

        let signer1 = Signer::new(&context, random_private_key.as_ref());
        let signer2 = Signer::new(&context, random_private_key.as_ref());
        let batch = create_batch(&signer1, transaction.clone());
        let transaction_ids = vec![transaction.clone()]
            .iter()
            .map(|trans| String::from(trans.get_header_signature()))
            .collect();

        // Construct batch header locally
        let mut batch_header = BatchHeader::new();
        batch_header.set_transaction_ids(RepeatedField::from_vec(transaction_ids));
        batch_header.set_signer_public_key(random_public_key.as_hex());
        let batch_header_bytes = batch_header.write_to_bytes().unwrap();
        let signature = signer2.sign(&batch_header_bytes).unwrap();

        // Verify if batch is composed right
        assert_eq!(batch.get_header_signature(), signature);
    }

    #[test]
    fn test_create_batch_list() {
        // Construct transaction header
        let random_input_addresses = ["random input addresses".to_string()];
        let random_output_addresses = ["random output addresses".to_string()];
        let random_payload = "random payload".to_string();
        let random_nonce = "random nonce".to_string();
        let context = Secp256k1Context::new();
        let random_private_key: Box<PrivateKey> = context
            .new_random_private_key()
            .expect("Error generating random private key");
        let signer = Signer::new(&context, random_private_key.as_ref());
        let random_public_key = signer.get_public_key().unwrap();
        let random_transaction_header = create_transaction_header(
            &random_input_addresses,
            &random_output_addresses,
            random_payload.as_str(),
            &random_public_key,
            random_nonce.clone(),
        );

        // Get bytes and construct transaction
        let transaction = create_transaction(
            &signer,
            &random_transaction_header,
            random_payload.to_string(),
        );

        let signer1 = Signer::new(&context, random_private_key.as_ref());
        let signer2 = Signer::new(&context, random_private_key.as_ref());
        let batch1 = create_batch(&signer1, transaction.clone());
        let batch2 = create_batch(&signer2, transaction.clone());
        let batch_list = create_batch_list(batch1);
        assert_eq!(batch_list.get_batches(), [batch2])
    }
}
