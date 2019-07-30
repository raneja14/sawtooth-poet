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

use sgx_structs::{SgxStruct, sgx_struct_error::SgxStructError,
                  sgx_struct_serde::{serialize_to_bytes, parse_from_bytes, SgxSerdeEndian}};
use sgx_structs::sgx_basename::SgxBasename;
use sgx_structs::sgx_report_body::SgxReportBody;

const STRUCT_SIZE: usize = 432;
const EPID_GROUP_ID_SIZE: usize = 4;
const DEFAULT_VALUE: u8 = 0;
const DEFAULT_VALUE_U16: u16 = 0;
const DEFAULT_VALUE_U32: u32 = 0;
const ENDIANNESS: SgxSerdeEndian = SgxSerdeEndian::LittleEndian;

/// Provide a wrapper around sgx_quote_t structure
/// typedef uint8_t sgx_epid_group_id_t[4];
/// typedef uint16_t sgx_isv_svn_t;
/// typedef struct _quote_t
/// {
///     uint16_t            version;                /* 0   */
///     uint16_t            sign_type;              /* 2   */
///     sgx_epid_group_id_t epid_group_id;          /* 4   */
///     sgx_isv_svn_t       qe_svn;                 /* 8   */
///     sgx_isv_svn_t       pce_svn;                /* 10  */
///     uint32_t            extended_epid_group_id; /* 12  */
///     sgx_basename_t      basename;               /* 16  */
///     sgx_report_body_t   report_body;            /* 48  */
///     uint32_t            signature_len;          /* 432 */
///     uint8_t             signature[];            /* 436 */
/// } sgx_quote_t;
///
/// See: https://01.org/sites/default/files/documentation/
///     intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf
#[derive(Serialize, Deserialize)]
pub struct SgxQuote {
    version: u16,
    sign_type: u16,
    epid_group_id: [u8; EPID_GROUP_ID_SIZE],
    qe_svn: u16,
    pce_svn: u16,
    extended_epid_group_id: u32,
    pub basename: SgxBasename,
    pub report_body: SgxReportBody,
    signature_len: u32,
    signature: u8,
}

impl SgxStruct for SgxQuote {
    /// Create an instance of SgxMeasurements with default value
    fn default() -> SgxQuote {
        SgxQuote {
            version: DEFAULT_VALUE_U16,
            sign_type: DEFAULT_VALUE_U16,
            epid_group_id: [DEFAULT_VALUE; EPID_GROUP_ID_SIZE],
            qe_svn: DEFAULT_VALUE_U16,
            pce_svn: DEFAULT_VALUE_U16,
            extended_epid_group_id: DEFAULT_VALUE_U32,
            basename: SgxBasename::default(),
            report_body: SgxReportBody::default(),
            signature_len: DEFAULT_VALUE_U32,
            signature: DEFAULT_VALUE,
        }
    }

    /// Serializes a object representing an SGX structure to bytes laid out in its corresponding
    /// C/C++ format.
    fn serialize_to_bytes(&self) -> Result<Vec<u8>, SgxStructError> {
        serialize_to_bytes(&ENDIANNESS, &self)
    }

    /// Parses a byte array and creates the Sgx* object corresponding to the C/C++ struct.
    fn parse_from_bytes(&mut self, raw_buffer: &[u8]) -> Result<(), SgxStructError> {
        let _: SgxQuote = match parse_from_bytes(&ENDIANNESS, raw_buffer) {
            Ok(quote) => quote,
            Err(err) => return Err(err),
        };
        Ok(())
    }
}
