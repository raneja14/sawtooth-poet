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

use base64;
use chrono::{DateTime, Utc};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::sign::Signer;
use openssl::sha;
use rand::Rng;

use common::sgx_structs::{sgx_basename::SgxBasename, sgx_measurement::SgxMeasurement, SgxStruct};
use common::utils::{from_hex_string, to_hex_string};

/// The basename and enclave measurement values we will put into and verify are in the enclave
/// quote in the attestation verification report.
const VALID_BASENAME: &str = "b785c58b77152cbe7fd55ee3851c499000000000000000000000000000000000";
const VALID_ENCLAVE_MEASUREMENT: &str =
    "c99f21955e38dbb03d2ca838d3af6e43ef438926ed02db4cc729380c8c7a174e";

/// We use the report private key PEM to create the private key used to sign attestation
/// verification reports.  On the flip side, the report public key PEM is used to create the
/// public key used to verify the signature on the attestation verification reports.
const REPORT_PRIVATE_KEY_PEM: &str =
    "-----BEGIN PRIVATE KEY-----\n\
    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCsy/NmLwZP6Uj0\n\
    p5mIiefgK8VOK7KJ34g3h0/X6aFOd/Ff4j+e23wtQpkxsjVHWLM5SjElGhfpVDhL\n\
    1WAMsQI9bpCWR4sjV6p7gOJhv34nkA2Grj5eSHCAJRQXCl+pJ9dYIeKaNoaxkdtq\n\
    +Xme//ohtkkv/ZjMTfsjMl0RLXokJ+YhSuTpNSovRaCtZfLB5MihVJuV3Qzb2ROh\n\
    KQxcuyPy9tBtOIrBWJaFiXOLRxAijs+ICyzrqUBbRfoAztkljIBx9KNItHiC4zPv\n\
    o6DxpGSO2yMQSSrs13PkfyGWVZSgenEYOouEz07X+H5B29PPuW5mCl4nkoH3a9gv\n\
    rI6VLEx9AgMBAAECggEAImfFge4RCq4/eX85gcc7pRXyBjuLJAqe+7d0fWAmXxJg\n\
    vB+3XTEEi5p8GDoMg7U0kk6kdGe6pRnAz9CffEduU78FCPcbzCCzcD3cVWwkeUok\n\
    d1GQV4OC6vD3DBNjsrGdHg45KU18CjUphCZCQhdjvXynG+gZmWxZecuYXkg4zqPT\n\
    LwOkcdWBPhJ9CbjtiYOtKDZbhcbdfnb2fkxmvnAoz1OWNfVFXh+x7651FrmL2Pga\n\
    xGz5XoxFYYT6DWW1fL6GNuVrd97wkcYUcjazMgunuUMC+6XFxqK+BoqnxeaxnsSt\n\
    G2r0sdVaCyK1sU41ftbEQsc5oYeQ3v5frGZL+BgrYQKBgQDgZnjqnVI/B+9iarx1\n\
    MjAFyhurcKvFvlBtGKUg9Q62V6wI4VZvPnzA2zEaR1J0cZPB1lCcMsFACpuQF2Mr\n\
    3VDyJbnpSG9q05POBtfLjGQdXKtGb8cfXY2SwjzLH/tvxHm3SP+RxvLICQcLX2/y\n\
    GTJ+mY9C6Hs6jIVLOnMWkRWamQKBgQDFITE3Qs3Y0ZwkKfGQMKuqJLRw29Tyzw0n\n\
    XKaVmO/pEzYcXZMPBrFhGvdmNcJLo2fcsmGZnmit8RP4ChwHUlD11dH1Ffqw9FWc\n\
    387i0chlE5FhQPirSM8sWFVmjt2sxC4qFWJoAD/COQtKHgEaVKVc4sH/yRostL1C\n\
    r+7aWuqzhQKBgQDcuC5LJr8VPGrbtPz1kY3mw+r/cG2krRNSm6Egj6oO9KFEgtCP\n\
    zzjKQU9E985EtsqNKI5VdR7cLRLiYf6r0J6j7zO0IAlnXADP768miUqYDuRw/dUw\n\
    JsbwCZneefDI+Mp325d1/egjla2WJCNqUBp4p/Zf62f6KOmbGzzEf6RuUQKBgG2y\n\
    E8YRiaTOt5m0MXUwcEZk2Hg5DF31c/dkalqy2UYU57aPJ8djzQ8hR2x8G9ulWaWJ\n\
    KiCm8s9gaOFNFt3II785NfWxPmh7/qwmKuUzIdWFNxAsbHQ8NvURTqyccaSzIpFO\n\
    hw0inlhBEBQ1cB2r3r06fgQNb2BTT0Itzrd5gkNVAoGBAJcMgeKdBMukT8dKxb4R\n\
    1PgQtFlR3COu2+B00pDyUpROFhHYLw/KlUv5TKrH1k3+E0KM+winVUIcZHlmFyuy\n\
    Ilquaova1YSFXP5cpD+PKtxRV76Qlqt6o+aPywm81licdOAXotT4JyJhrgz9ISnn\n\
    J13KkHoAZ9qd0rX7s37czb3O\n\
    -----END PRIVATE KEY-----";

pub fn get_avr(
    quote: &[u8],
    nonce: &str,
    originator_pub_key: &str
) -> Result<(String, String), ()> {
    let mut epid_pseudonym_bytes: [u8; 64] = [0; 64];

    let mut sha_calculator = Sha256::new();
    sha_calculator.input_str(originator_pub_key);
    sha_calculator.result(&mut epid_pseudonym_bytes);

    // Epid pseudonym is unique for each validator
    let epid_pseudonym = to_hex_string(&epid_pseudonym_bytes);

    // Generate random
    let id_bytes = rand::thread_rng().gen_iter::<u8>().take(64).collect::<Vec<u8>>();
    let id = base64::encode(&id_bytes);

    // Generate enclave body quote
    let enclave_quote = base64::encode(quote);

    let timestamp = Utc::now();

    let verification_report_json = json!({
        "epidPseudonym": epid_pseudonym,
        "id": id,
        "isvEnclaveQuoteStatus": "OK",
        "isvEnclaveQuoteBody": enclave_quote,
        "nonce": nonce.to_string(),
        "timestamp": timestamp.to_rfc3339()
        });

    let verification_report = verification_report_json.to_string();

    let private_key = match PKey::private_key_from_pem(
        REPORT_PRIVATE_KEY_PEM.as_bytes(),
    ) {
        Ok(key) => key,
        Err(_) => return Err(()),
    };

    let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
    signer.update(verification_report.as_bytes());
    let signature_bytes = signer.sign_to_vec().unwrap();

    let signature = base64::encode(&signature_bytes);

    return Ok((verification_report, signature));
}
