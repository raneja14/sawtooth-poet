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

#include <stdio.h>  
#include "common.h"
#include "poet_enclave.h"
#include "poet.h"
#include "error.h"
#include <iostream>
#include <vector>


Poet* Poet::instance = 0;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool _is_sgx_simulator()
{
    return 0 != Poet_IsSgxSimulator();
} // _is_sgx_simulator


Poet* _get_poet_instance(
    const std::string& enclaveModulePath,
    const std::string& spid ){
    printf("NEW POET INSTANCE\n");    
    return Poet::getInstance(enclaveModulePath, spid);
}// _get_poet_instance


poet_err_t _set_signature_revocation_list(
    const std::string& signature_revocation_list
    ){
      printf("SIG ARG=> %s\n",signature_revocation_list.c_str());
      return Poet::set_signature_revocation_list(signature_revocation_list);
}// _set_signature_revocation_list

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Poet::Poet(
    const std::string& enclaveModulePath,
    const std::string& spid
    )
{
    poet_err_t ret = POET_SUCCESS;
    try {
        MyLog(POET_LOG_INFO, "Initializing SGX Poet enclave\n");
        
	printf("MODULE PATH = %s\n",enclaveModulePath.c_str());
	printf("SPID = %s\n",spid.c_str());

	ret = Poet_Initialize(
            enclaveModulePath.c_str(),
            spid.c_str(),
            MyLog
            );          
        printf("\nIntialization value %x\nIn decimal it is %d\n", ret, ret);
	
        ThrowPoetError(ret);
        StringBuffer mrEnclaveBuffer(Poet_GetEnclaveMeasurementSize());
        StringBuffer basenameBuffer(Poet_GetEnclaveBasenameSize());
        StringBuffer epidGroupBuffer(Poet_GetEpidGroupSize());

        
        ret = Poet_GetEnclaveCharacteristics(
                mrEnclaveBuffer.data(),
                mrEnclaveBuffer.length,
                basenameBuffer.data(),
                basenameBuffer.length,
                epidGroupBuffer.data(),
                epidGroupBuffer.length);
        printf("\nError returned from GetEnclaveCharacteristics %u - %x\n", ret, ret);
        ThrowPoetError(ret);
	    this->mr_enclave = mrEnclaveBuffer.str();
        this->basename = basenameBuffer.str();
        this->epid_group = epidGroupBuffer.str();
    } catch(...) {
        MyLog(POET_LOG_INFO, "Enclave initialization failed\n");
        ret = POET_ERR_UNKNOWN;
        ThrowPoetError(ret);
    }
}// Poet::Poet

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Poet::~Poet()
{
    try {
        Poet_Terminate();
        TerminateInternal();
    } catch (...) {
    }
} // Poet::~Poet

Poet* Poet::getInstance(
    const std::string& enclaveModulePath,
    const std::string& spid)
{
    if(!Poet::instance){
        Poet::instance = new Poet(enclaveModulePath, spid);
    }
    return Poet::instance;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
poet_err_t Poet::set_signature_revocation_list(
    const std::string& signature_revocation_list
    )
{    
    poet_err_t ret = POET_SUCCESS;
    try {
        ThrowPoetError(
            Poet_SetSignatureRevocationList(signature_revocation_list.c_str()));
    } catch(...) {
        MyLog(POET_LOG_INFO, "Exception in set signature revocation list\n");
        ret = POET_ERR_UNKNOWN;
        ThrowPoetError(ret);
    }
    return ret;
} // Poet::set_signature_revocation_lists

