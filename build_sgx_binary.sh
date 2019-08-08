#!/bin/bash
WORK_DIR=/project/sawtooth-poet
SGX_DIR=/tmp/sgxsdk

#setting SGX environment
source $SGX_DIR/environment

echo "proxy type = manual" >> /etc/aesmd.conf
echo "aesm proxy = $http_proxy" >> /etc/aesmd.conf

#starting aesm service
echo "Starting aesm service"
/opt/intel/libsgx-enclave-common/aesm/aesm_service &


#building SGX bridge and Enclave
cd $WORK_DIR
mkdir build
cd build
cmake $WORK_DIR/sgx

make 

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$WORK_DIR/build/bin
cd $WORK_DIR/core
