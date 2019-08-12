#include <string.h>
#include "poet_enclave.h"

_SignupData* (*fptr_create_signup_data)(
    const std::string& originator_public_key_hash
    );

void (*fptr_destroy_signup_data)(
    _SignupData* signup_data
    );

SignupInfo* (*fptr_deserialize_signup_info)(
    const std::string& serialized_signup_info
    );

WaitCertificate* (*fptr_deserialize_wait_certificate)(
    const std::string& serialized_certificate,
    const std::string& signature
    );

poet_err_t (*fptr_initialize_wait_certificate)(
    const std::string& prevWaitCertificate,
    const std::string& validatorId,
    const std::string& prevWaitCertificateSig,
    const std::string& poetPubKey,
    uint8_t *duration,
    size_t durationLen
    );

WaitCertificate* (*fptr_finalize_wait_certificate)(
    const std::string& prevWaitCertificate,
    const std::string& prevBlockId,
    const std::string& prevWaitCertificateSig,
    const std::string& blockSummary,
    uint64_t waitTime
    );

bool (*fptr_verify_wait_certificate)(
    const std::string& serializedWaitCertificate,
    const std::string& waitCertificateSignature,
    const std::string& poetPublicKey
    );

void (*fptr_destroy_wait_certificate)(
    WaitCertificate *waitCert
    );


Poet* (*fptr_get_poet_instance)(
    const std::string& enclaveModulePath,
    const std::string& spid
    );

poet_err_t (*fptr_set_signature_revocation_list)(
     const std::string& signature_revocation_list
     );

bool (*fptr_is_sgx_simulator)(void);

