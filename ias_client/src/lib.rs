/*
 Copyright 2018 Intel Corporation

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

// common extern crate imports for all modules in this crate
extern crate futures;
extern crate hyper;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate serde_json;
extern crate tokio;
extern crate common;
extern crate crypto;
extern crate rand;
extern crate base64;
extern crate chrono;
extern crate openssl;

// modules defined in this crate
pub mod client_utils;
pub mod ias_client;
mod ias_client_sim;
