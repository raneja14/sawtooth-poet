# Copyright 2019 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

FROM ubuntu:bionic

RUN \
 apt-get update \
 && apt-get install -y -q curl gnupg \
 && (curl -sSL 'http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x44FC67F19B2466EA' | apt-key add - \
 || curl -sSL 'p80.pool.sks-keyservers.net/pks/lookup?op=get&search=0x44FC67F19B2466EA' | apt-key add -) \
 && echo "deb [arch=amd64] http://repo.sawtooth.me/ubuntu/nightly bionic universe" >> /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y -q --allow-downgrades \
 build-essential \
 ocaml \
 curl \
 gcc \
 cmake \
 clang \
 libclang-dev \
 libprotobuf-dev \
 openssl \
 libssl-dev \
 libcurl4-openssl-dev \
 libc6-dev \
 libcrypto++-dev \
 libjson-c-dev \
 libzmq3-dev \
 libtool \
 make \
 wget \
 pkg-config \
 python3-grpcio-tools \
 unzip \
 git \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN curl -OLsS https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip \
 && unzip protoc-3.5.1-linux-x86_64.zip -d protoc3 \
 && rm protoc-3.5.1-linux-x86_64.zip

RUN curl https://sh.rustup.rs -sSf > /usr/bin/rustup-init \
 && chmod +x /usr/bin/rustup-init \
 && rustup-init -y

ENV PATH=$PATH:/protoc3/bin:/project/sawtooth-poet/bin:/root/.cargo/bin \
    CARGO_INCREMENTAL=0

WORKDIR /tmp

RUN bash -c " mkdir /etc/init \
  && wget https://download.01.org/intel-sgx/linux-2.3/ubuntu18.04-server/libsgx-enclave-common_2.3.100.46354-1_amd64.deb \
  && dpkg -i libsgx-enclave-common_2.3.100.46354-1_amd64.deb \
  && wget https://download.01.org/intel-sgx/linux-2.3/ubuntu18.04-server/sgx_linux_x64_sdk_2.3.100.46354.bin \
  && chmod +x sgx_linux_x64_sdk_2.3.100.46354.bin \
  && echo \"yes\" | ./sgx_linux_x64_sdk_2.3.100.46354.bin \
  && chmod +x ./sgxsdk/environment"
