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

pub mod sgx_struct_serde;
pub mod sgx_struct_error;
pub mod sgx_basename;
pub mod sgx_report_body;
pub mod sgx_cpu_svn;
pub mod sgx_attributes;
pub mod sgx_measurement;
pub mod sgx_report_data;

use sgx_structs::sgx_struct_error::SgxStructError;

/// SgxStruct defines the trait that all Sgx* structures must implement
pub trait SgxStruct {
    /// Create a default instance of the SgxStruct
    fn default() -> Self;

    /// Serializes a object representing an SGX structure to bytes laid out in its corresponding
    /// C/C++ format.

    /// NOTE: All integer struct fields are serialized to little endian format
    fn serialize_to_bytes(&self) -> Result<Vec<u8>, SgxStructError>;

    /// Parses a byte array and creates the Sgx* object corresponding to the C/C++ struct.
    ///
    /// NOTE: All integer struct fields are parsed as little endian format
    fn parse_from_bytes(&mut self, raw_buffer: &[u8]) -> Result<(), SgxStructError>
        where Self: std::marker::Sized;
}
