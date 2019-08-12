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
#include <string.h>
#include <iostream>
#include "poet_enclave_u.h"
#include "sgx_urts.h"
#include "rust_sgx_bridge.h"
#include "dynamic_libs.h"
#include "poet_enclave.h"
#include "c11_support.h"
#include "error.h"
#include <iostream>
#include "common.h"
#include <dlfcn.h>

#define DURATION_LENGTH_BYTES 8 //Duration to return is 64 bits (8 bytes)


//void *lib_handle;

WaitCertificate* validate_wait_certificate(const char *ser_wait_cert,
              const char *ser_wait_cert_sig);

r_error_code_t initialize_func_ptr(void *lib_handle){
	printf("Initializing function pointers\n");

	fptr_create_signup_data = (_SignupData* (*)(const std::string&))dlsym(lib_handle,"_create_signup_data");
    if(!fptr_create_signup_data) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

    fptr_destroy_signup_data = (void (*)(_SignupData*))dlsym(lib_handle,"_destroy_signup_data");
    if(!fptr_destroy_signup_data) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

    fptr_deserialize_signup_info = (SignupInfo* (*)(const std::string&))dlsym(lib_handle,"deserialize_signup_info");
    if(!fptr_deserialize_signup_info) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

    fptr_deserialize_wait_certificate = (WaitCertificate* (*)(const std::string&,const std::string&))dlsym(lib_handle,"deserialize_wait_certificate");
    if(!fptr_deserialize_wait_certificate) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

	fptr_initialize_wait_certificate = (poet_err_t (*)(const std::string&,const std::string&,const std::string&,const std::string&,uint8_t*,size_t))dlsym(lib_handle,"initialize_wait_certificate");
    if(!fptr_initialize_wait_certificate) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

    fptr_finalize_wait_certificate = (WaitCertificate* (*)(const std::string&,const std::string&,const std::string&,const std::string&,uint64_t))dlsym(lib_handle,"finalize_wait_certificate");
    if(!fptr_finalize_wait_certificate) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

	fptr_verify_wait_certificate = (bool (*)(const std::string&,const std::string&,const std::string&))dlsym(lib_handle,"_verify_wait_certificate");
    if(!fptr_verify_wait_certificate) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

    fptr_destroy_wait_certificate = (void (*)(WaitCertificate*))dlsym(lib_handle,"_destroy_wait_certificate");
    if(!fptr_destroy_wait_certificate) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

	fptr_get_poet_instance = (Poet* (*)(const std::string&,const std::string&))dlsym(lib_handle,"_get_poet_instance");
    if(!fptr_get_poet_instance) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

    fptr_set_signature_revocation_list = (poet_err_t (*)(const std::string&))dlsym(lib_handle,"_set_signature_revocation_list");
    if(!fptr_set_signature_revocation_list) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }

    fptr_is_sgx_simulator = (bool (*)(void)) dlsym(lib_handle,"_is_sgx_simulator"); 
    if(!fptr_is_sgx_simulator) {
        printf("%s\n", dlerror());
        return R_FAILURE;
    }
    printf("Initialized function pointers\n");
    return R_SUCCESS;
}

r_error_code_t r_link_bridge(const char *bridge_path){
	void *lib_handle = dlopen(bridge_path,RTLD_LAZY);
	if(!lib_handle) {
   		printf("%s\n", dlerror());
        return R_FAILURE;
	}
    if(initialize_func_ptr(lib_handle) == R_FAILURE){
        return R_FAILURE;
    }
    return R_SUCCESS;
}


r_error_code_t r_initialize_enclave(r_sgx_enclave_id_t *eid,
                                    const char *enclave_path,
                                    const char *spid)
{
    //check parameters
    if (!eid || !enclave_path || !spid) {
        return R_FAILURE;
    }
    try{
        Poet *poet_enclave_id = (*fptr_get_poet_instance)(enclave_path, spid);
        //store the enclave id
        eid->handle = (intptr_t)poet_enclave_id;
        eid->mr_enclave = (char *)poet_enclave_id->mr_enclave.c_str();
        eid->basename = (char *)poet_enclave_id->basename.c_str();
        eid->epid_group = (char *)poet_enclave_id->epid_group.c_str();
    } catch( sawtooth::poet::PoetError& e) {
        return R_FAILURE;
    } catch(...) {
        return R_FAILURE;
    }
    return R_SUCCESS;
}

r_error_code_t r_free_enclave(r_sgx_enclave_id_t *eid)
{
    if (eid->handle) {
        Poet *poet_enclave_id = (Poet *)eid->handle;
        delete poet_enclave_id;
        eid->handle = 0;
    }

    return R_SUCCESS;
}

r_error_code_t r_is_sgx_simulator(r_sgx_enclave_id_t *eid,
                                  bool *sgx_simulator) {
    if (!eid) {
        return R_FAILURE;
    }
    if (!eid->handle) {
        return R_FAILURE;
    }
    bool is_simulator = (*fptr_is_sgx_simulator)();
    if (!is_simulator) {
        *sgx_simulator = false;
    } else {
        *sgx_simulator = true;
    }
    return R_SUCCESS;
}

r_error_code_t r_set_signature_revocation_list(r_sgx_enclave_id_t *eid,
                                            const char *sig_revocation_list) {
    if (!eid) {
        return R_FAILURE;
    }
    if (!eid->handle) {
        return R_FAILURE;
    }
    try {
        poet_err_t ret = (*fptr_set_signature_revocation_list)(sig_revocation_list);
        if (ret != POET_SUCCESS) {
            return R_FAILURE;
        }
    } catch (sawtooth::poet::PoetError& e) {
        return R_FAILURE;
    } catch (...) {
        return R_FAILURE;
    }
    return R_SUCCESS;
}

r_error_code_t r_create_signup_info(r_sgx_enclave_id_t *eid,
                                    const char *opk_hash,
                                    r_sgx_signup_info_t *signup_info) {
	
    if (!eid || !opk_hash || !signup_info) {
        return R_FAILURE;
    }

    if (!eid->handle) {
        return R_FAILURE;
    }

    try {
        _SignupData *signup_data = (*fptr_create_signup_data)(opk_hash);
        if (signup_data == nullptr) {
            return R_FAILURE;
        }
        //store the _SignupData handle
        signup_info->handle = (intptr_t)signup_data; 

        if (signup_data->poet_public_key.empty()) {
            return R_FAILURE;
        }
        signup_info->poet_public_key = (char *)signup_data->poet_public_key
                                                                    .c_str();
        signup_info->enclave_quote = (char *)signup_data->enclave_quote.c_str();
    } catch ( sawtooth::poet::PoetError& e) {
        return R_FAILURE;
    } catch (...) {
        return R_FAILURE;
    }
    return R_SUCCESS; 
}


r_error_code_t r_initialize_wait_certificate(r_sgx_enclave_id_t *eid,
                                  uint8_t *duration,
                                  const char *prev_wait_cert,
                                  const char *prev_wait_cert_sig,
                                  const char *validator_id,
                                  const char *poet_pub_key) {
    if (!eid || (prev_wait_cert == nullptr) || (prev_wait_cert_sig == nullptr)
          || (validator_id == nullptr) || (poet_pub_key == nullptr)) {
       return R_FAILURE;
    }

    if (!eid-> handle) {
        return R_FAILURE;
    }

    try {
        poet_err_t ret = (*fptr_initialize_wait_certificate)(prev_wait_cert,
                                            validator_id, prev_wait_cert_sig,
                                            poet_pub_key, duration,
                                            DURATION_LENGTH_BYTES);
        if (ret != POET_SUCCESS) {
            return R_FAILURE;
        }
    } catch (sawtooth::poet::PoetError& e) {
        return R_FAILURE;
    } catch (...) {
        return R_FAILURE;
    }
    return R_SUCCESS;
}

r_error_code_t r_finalize_wait_certificate(r_sgx_enclave_id_t *eid,
                                r_sgx_wait_certificate_t *wait_cert,
                                const char *prev_wait_cert,
                                const char *prev_block_id,
                                const char *prev_wait_cert_sig,
                                const char *block_summary,
                                uint64_t wait_time) {

    if (!eid || (prev_block_id == nullptr) || (prev_wait_cert_sig == nullptr)
        || (block_summary == nullptr)) {
        return R_FAILURE;
    }
    
    if (!eid->handle) {
        return R_FAILURE;
    }

    try {
        WaitCertificate *wait_certificate = (*fptr_finalize_wait_certificate)(
                                                            prev_wait_cert,
                                                            prev_block_id,
                                                            prev_wait_cert_sig,
                                                            block_summary,
                                                            wait_time);
        if (wait_certificate == nullptr) {
            return R_FAILURE;
        }
        //store wait certificate handle
        wait_cert->handle = (intptr_t) wait_certificate;
        if (wait_certificate->serialized.empty()) {
            return R_FAILURE;
        }
        wait_cert->ser_wait_cert = (char*) wait_certificate->serialized.c_str();
        if (wait_certificate->signature.empty()) {
            return R_FAILURE;
        }
        wait_cert->ser_wait_cert_sign = (char*) wait_certificate->signature
                                                                    .c_str();
    } catch (sawtooth::poet::PoetError& e) {
        return R_FAILURE;
    } catch (...) {
        return R_FAILURE;
    }
    return R_SUCCESS;
}


WaitCertificate* validate_wait_certificate(const char *ser_wait_cert,
                                           const char *ser_wait_cert_sig) {
    
    return (*fptr_deserialize_wait_certificate)(ser_wait_cert, 
                                          ser_wait_cert_sig);
}

r_error_code_t r_verify_wait_certificate(r_sgx_enclave_id_t *eid, const char *ppk,
                              const char *wait_cert, const char *wait_cert_sign,
                              bool *verify_cert_status) {
    if (!eid || (ppk == nullptr) || (wait_cert == nullptr) || (wait_cert_sign == nullptr)) {
        return R_FAILURE;
    }

    if (!eid->handle){
        return R_FAILURE;
    }

    try {
        bool ret = (*fptr_verify_wait_certificate)(wait_cert, wait_cert_sign, ppk);
        if (!ret) {
            *verify_cert_status = false;
        } else {
            *verify_cert_status = true;
        }
    } catch (sawtooth::poet::PoetError& e) {
        return R_FAILURE;
    } catch (...) {
        return R_FAILURE;
    }
    return R_SUCCESS;
}


r_error_code_t r_release_signup_info(r_sgx_enclave_id_t *eid,
                                     r_sgx_signup_info_t *signup_info)
{
    if (!eid || !signup_info) {
        return R_FAILURE;
    }

    if (!eid->handle) {
        return R_FAILURE;
    }

    if (!signup_info->handle) {
       return R_FAILURE;
    }

    _SignupData *signup_data = (_SignupData *)signup_info->handle;
    if (signup_data != nullptr) {
        (*fptr_destroy_signup_data)(signup_data);
        signup_info->handle = 0;
    }    
    return R_SUCCESS;
}

r_error_code_t r_release_wait_certificate(r_sgx_enclave_id_t *eid, 
                               r_sgx_wait_certificate_t *wait_cert)
{
    if (!eid || !wait_cert) {
        return R_FAILURE;
    }
    
    if (!eid->handle || !wait_cert->handle) {
        return R_FAILURE;
    }

    WaitCertificate *wait_certificate = (WaitCertificate *)wait_cert->handle;
    if (wait_certificate != nullptr) {
        (*fptr_destroy_wait_certificate)(wait_certificate);
        wait_cert->handle = 0;
    }
    return R_SUCCESS;
}
