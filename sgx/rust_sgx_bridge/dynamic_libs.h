
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "poet_enclave.h"

_SignupData* (*fptr_create_signup_data)
    (const std::string& originator_public_key_hash
    );

bool (*fptr_is_sgx_simulator)();

