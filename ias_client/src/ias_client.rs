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

extern crate serde;

use client_utils::{get_http_client, read_response_future, send_response, ClientError,
                   ClientResponse};
use hyper::{header, header::HeaderValue, Body, Method, Request, Uri, StatusCode};
use serde_json;
use std::{collections::HashMap, str, time::Duration};
use ias_client_sim::get_avr;
use hyper::HeaderMap;

/// Structure for storing IAS connection information
#[derive(Debug, Clone)]
pub struct IasClient {
    // IAS URL to connect to
    ias_url: String,
    // IAS subscription key used for REST calls
    ias_subscription_key: String,
    // Timeout for the client requests in seconds
    timeout: Duration,
    // Whether IAS Client makes a simulated request or actual request
    is_simulator: bool,
}

const SIGRL_LINK: &str = "/attestation/v3/sigrl";
const AVR_LINK: &str = "/attestation/v3/report";
const EMPTY_STR: &str = "";
const REQUEST_HEADER_KEY: &str = "Ocp-Apim-Subscription-Key";
const IAS_REPORT_SIGNATURE: &str = "x-iasreport-signature";
// Note: Structure can be used for serialization and deserialization, but it won't skip null values
const ISV_ENCLAVE_QUOTE: &str = "isvEnclaveQuote";
const PSE_MANIFEST: &str = "pseManifest";
const NONCE: &str = "nonce";
// timeout constants
const DEFAULT_TIMEOUT_SECS: u64 = 300;
const DEFAULT_TIMEOUT_NANO_SECS: u32 = 0;

/// Implement how the IasClient is going to be used
impl IasClient {
    /// default constructor for IasClient, remember to use setters later
    pub fn default() -> Self {
        IasClient {
            ias_url: String::new(),
            ias_subscription_key: EMPTY_STR.to_string(),
            timeout: Duration::new(DEFAULT_TIMEOUT_SECS, DEFAULT_TIMEOUT_NANO_SECS),
            is_simulator: true,
        }
    }

    /// constructor for IasClient
    pub fn new(url: String, key: String, time: Option<u64>, is_simulator: bool) -> Self {
        IasClient {
            ias_url: url,
            ias_subscription_key: key,
            timeout: Duration::new(
                time.unwrap_or(DEFAULT_TIMEOUT_SECS),
                DEFAULT_TIMEOUT_NANO_SECS,
            ),
            is_simulator,
        }
    }

    /// Setters for IasClient structure
    pub fn set_ias_url(&mut self, url: String) {
        self.ias_url = url;
    }

    pub fn set_ias_subscription_key(&mut self, key: String) {
        self.ias_subscription_key = key;
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn set_is_simulator(&mut self, is_simulator: bool) {
        self.is_simulator = is_simulator;
    }

    /// Get request to receive signature revocation list for input Group ID (gid). Accepts
    /// optional 'gid' and optional 'api_path' as input. Optional 'gid' field is used for the
    /// case of IAS Proxy server, which receives request with 'gid' appended already.
    ///
    /// return: A ClientResponse object containing the following:
    ///     Body of the response has 'signature revocation list', the body of the response from IAS.
    ///     Header of the response has nothing.
    pub fn get_signature_revocation_list(
        &self,
        gid: Option<&str>,
        api_path: Option<&str>,
    ) -> Result<ClientResponse, ClientError> {
        if !self.is_simulator {
            self.get_sigrl(gid, api_path)
        } else {
            self.simulate_sigrl(gid, api_path)
        }
    }

    /// Get request to receive signature revocation list for input Group ID (gid). Accepts
    /// optional 'gid' and optional 'api_path' as input. Optional 'gid' field is used for the
    /// case of IAS Proxy server, which receives request with 'gid' appended already.
    ///
    /// return: A ClientResponse object containing the following:
    ///     Body of the response has 'signature revocation list', the body of the response from IAS.
    ///     Header of the response has nothing.
    fn get_sigrl(
        &self,
        gid: Option<&str>,
        api_path: Option<&str>,
    ) -> Result<ClientResponse, ClientError> {
        // Path to get SigRL from
        let mut final_path = String::new();
        final_path.push_str(self.ias_url.as_str());
        // Received REST path if any
        let received_path = match api_path {
            Some(path_present) => path_present,
            _ => SIGRL_LINK,
        };
        final_path.push_str(received_path);
        // Append gid to the path if present
        let received_gid = match gid {
            Some(gid_present) => {
                final_path.push_str("/");
                gid_present
            }
            _ => "",
        };
        info!("received_gid= {:?}", received_gid);
       // received_gid = "00000AFB";
        info!("received_gid Modified= {:?}", received_gid);
        final_path.push_str(received_gid);
        let url = final_path
            .parse::<Uri>()
            .expect("Error constructing URI from string");
        info!("Fetching SigRL from:= {:?}", url);
        debug!("Fetching SigRL from: {}", url);
        
        let req = Request::builder()
            .method("GET")
            .uri(url.clone())
            .header("Ocp-Apim-Subscription-Key", self.ias_subscription_key.clone())
            .body(Body::from(""))
            .expect("Error constructing the GET request");
        // Send request to get SigRL
        let client = get_http_client()
            .expect("Error creating http/s client");
        // TODO: Add logic for request timeout
        let response_fut = client.request(req);
        read_response_future(response_fut)
    }

    /// Simulates a GET request to receive signature revocation list for input Group ID (gid).
    /// Accepts optional 'gid' and optional 'api_path' as input. Optional 'gid' field is used for
    /// the case of IAS Proxy server, which receives request with 'gid' appended already.
    ///
    /// return: A ClientResponse object containing the following:
    ///     Body of the response has 'signature revocation list', the body of the response from IAS.
    ///     Header of the response has nothing.
    fn simulate_sigrl(
        &self,
        gid: Option<&str>,
        api_path: Option<&str>,
    ) -> Result<ClientResponse, ClientError> {
        debug!("Simulating SigRL");
        Ok(ClientResponse{
            body: Body::empty(),
            header_map: HeaderMap::new(),
        })
    }

    /// Post request to send Attestation Enclave Payload and get response having Attestation
    /// Verification Report. Accepts quote and optional values pse_manifest, nonce as input.
    ///
    /// return: A ClientResponse object containing the following:
    ///     Body of the response has 'attestation verification report', the body (JSON) of the
    ///         response from ISA.
    ///     Header of the response has 'signature', the base 64-encoded RSA-SHA256 signature of the
    ///         response body (aka, AVR) using the report key.
    pub fn post_verify_attestation(
        &self,
        quote: &str,
        manifest: Option<&str>,
        nonce: Option<&str>,
        originator_public_key: Option<&str>,
    ) -> Result<ClientResponse, ClientError> {
        if !self.is_simulator {
            self.post_aep_request(quote, manifest, nonce)
        } else {
            self.simulate_aep_request(quote, manifest, nonce, originator_public_key.unwrap())
        }
    }

    /// Post request to send Attestation Enclave Payload and get response having Attestation
    /// Verification Report. Accepts quote and optional values pse_manifest, nonce as input.
    ///
    /// return: A ClientResponse object containing the following:
    ///     Body of the response has 'attestation verification report', the body (JSON) of the
    ///         response from ISA.
    ///     Header of the response has 'signature', the base 64-encoded RSA-SHA256 signature of the
    ///         response body (aka, AVR) using the report key.
    fn post_aep_request(
        &self,
        quote: &str,
        manifest: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<ClientResponse, ClientError> {

        info!("POST VERIFY ATTESTATION=");
        // REST API to connect to for getting AVR
        let mut final_path = String::new();
        final_path.push_str(self.ias_url.as_str());
        final_path.push_str("/");
        final_path.push_str(AVR_LINK);
        let url = final_path
            .parse::<Uri>()
            .expect("Error constructing URI from string");
        debug!("Posting attestation verification request to: {}", url);

        // Construct AEP, request parameter
        // Note: Replace following HashMap with a structure if Integration test with IAS succeeds
        // with keys in request json with empty value. With following code, we are avoiding even
        // addition of keys in request json.
        let mut request_aep: HashMap<String, String> = HashMap::new();
        request_aep.insert(
            String::from(ISV_ENCLAVE_QUOTE),
            quote.to_string(),
        );
        // Optional manifest, add to request param if present
        if manifest.is_some() {
            request_aep.insert(String::from(PSE_MANIFEST), manifest.unwrap().to_owned());
        }
        // Optional nonce, add to request param if present
        if nonce.is_some() {
            request_aep.insert(String::from(NONCE), nonce.unwrap().to_string());
        }

        let request_aep_str = serde_json::to_string(&request_aep)
            .expect("Error occurred during AEP serialization");

        // Construct hyper's request to be sent
        let req = Request::builder()
            .method("POST")
            .uri(url.clone())
            .header("Ocp-Apim-Subscription-Key", self.ias_subscription_key.clone())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(request_aep_str))
            .expect("Error constucting the POST request");
        // Send request to get AVR
        let client = get_http_client()
            .expect("Error creating http client");

        debug!("Posting attestation evidence payload: {:#?}", request_aep);
        let response_fut = client.request(req);
        // TODO: Add logic for request timeout
        read_response_future(response_fut)
    }

    /// Simulate post request to send Attestation Enclave Payload and get response having
    /// Attestation Verification Report. Accepts quote and optional values pse_manifest, nonce as
    /// input.
    ///
    /// return: A ClientResponse object containing the following:
    ///     Body of the response has 'attestation verification report', the body (JSON) of the
    ///         response from ISA.
    ///     Header of the response has 'signature', the base 64-encoded RSA-SHA256 signature of the
    ///         response body (aka, AVR) using the report key.
    fn simulate_aep_request(
        &self,
        quote: &str,
        manifest: Option<&str>,
        nonce: Option<&str>,
        originator_pub_key: &str,
    ) -> Result<ClientResponse, ClientError> {
        let (verification_report, signature) =
            get_avr(quote, nonce.unwrap(), originator_pub_key).unwrap();
        let mut header_map = HeaderMap::new();
        header_map.insert(IAS_REPORT_SIGNATURE, HeaderValue::from_str(&signature).unwrap());
        Ok(ClientResponse{
            body: Body::from(verification_report),
            header_map,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_DURATION: u64 = 300;
    const DUMMY_DURATION: u64 = 0;
    const DEFAULT_URL: &str = "";
    const DUMMY_URL: &str = "dummy.url";
    const DUMMY_IAS_SUBSCRIPTION_KEY: &str = "dummy subscription key";

    #[test]
    fn test_default_ias_client_creation() {
        let default_client = IasClient::default();
        assert_eq!(default_client.ias_url, DEFAULT_URL.clone());
        assert_eq!(default_client.ias_subscription_key, DUMMY_IAS_SUBSCRIPTION_KEY);
        assert_eq!(default_client.timeout.as_secs(), DEFAULT_DURATION);
    }

    #[test]
    fn test_new_ias_client_creation() {
        let new_ias_client = IasClient::new(
            DUMMY_URL.clone().to_string(),
            DUMMY_IAS_SUBSCRIPTION_KEY.to_string(),
            Option::from(DUMMY_DURATION),
            true,
        );
        assert_eq!(new_ias_client.ias_url, DUMMY_URL.clone());
        assert_eq!(new_ias_client.ias_subscription_key, DUMMY_IAS_SUBSCRIPTION_KEY);
        assert_eq!(new_ias_client.timeout.as_secs(), DUMMY_DURATION);
    }

    #[test]
    fn test_new_ias_client_with_assignment() {
        let mut default_client = IasClient::default();
        default_client.set_ias_url(DUMMY_URL.clone().to_string());
        default_client.set_ias_subscription_key(DUMMY_IAS_SUBSCRIPTION_KEY.to_string());
        default_client.set_timeout(Duration::new(DUMMY_DURATION, 0));
        assert_eq!(default_client.ias_url, DUMMY_URL.clone());
        assert_eq!(default_client.ias_subscription_key, DUMMY_IAS_SUBSCRIPTION_KEY);
        assert_eq!(default_client.timeout.as_secs(), DUMMY_DURATION);
    }
    // Reading from response / body, reading of headers are handled in client_utils.rs
    // Please find the file for unit tests on those
}
