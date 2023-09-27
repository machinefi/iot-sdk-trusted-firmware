cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_psa_rot_partition_crypto STATIC)

target_sources(tfm_psa_rot_partition_crypto
    PRIVATE
        crypto_init.c
        crypto_alloc.c
        crypto_cipher.c
        crypto_hash.c
        crypto_mac.c
        crypto_key.c
        crypto_aead.c
        crypto_asymmetric.c
        crypto_key_derivation.c
        crypto_key_management.c
        crypto_rng.c
)

target_include_directories(tfm_psa_rot_partition_crypto
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(tfm_services
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Linking to crypto library
# Note: the crypto lib needs to be linked before other libraries so mbedcrypto-src/include
# takes preference over interface/include
# both of them duplicate crypto_struct.h and we need to use the mbedcrypto one
# TODO handle this in a less error prone way
if(CRYPTO_IMPL STREQUAL "MbedTLS")
    target_link_libraries(tfm_psa_rot_partition_crypto 
        PRIVATE mbedcrypto
    )
else ()
    if(CRYPTO_IMPL STREQUAL "TinyCrypt")
        target_link_libraries(tfm_psa_rot_partition_crypto PRIVATE tinycrypt)
    else ()
        target_compile_options(tfm_psa_rot_partition_crypto PUBLIC -imacros ${EXTERN_MBEDTLS_CONFIG})
        add_definitions(-DCRYPTO_IMPLEMENTATION="MbedTLS")
        add_definitions(-DCRYPTO_IMPLEMENTATION_MBEDTLS)
        target_link_libraries(tfm_psa_rot_partition_crypto PRIVATE mbedTLS)
    endif()
endif()

# Linking to external interfaces
target_link_libraries(tfm_psa_rot_partition_crypto
    PRIVATE
        platform_s
        iotex_sdk_interface
        tfm_spm_core
)

target_compile_definitions(tfm_psa_rot_partition_crypto
    PUBLIC
        $<$<BOOL:${CRYPTO_RNG_MODULE_DISABLED}>:TFM_CRYPTO_RNG_MODULE_DISABLED>
        $<$<BOOL:${CRYPTO_KEY_MODULE_DISABLED}>:TFM_CRYPTO_KEY_MODULE_DISABLED>
        $<$<BOOL:${CRYPTO_AEAD_MODULE_DISABLED}>:TFM_CRYPTO_AEAD_MODULE_DISABLED>
        $<$<BOOL:${CRYPTO_MAC_MODULE_DISABLED}>:TFM_CRYPTO_MAC_MODULE_DISABLED>
        $<$<BOOL:${CRYPTO_CIPHER_MODULE_DISABLED}>:TFM_CRYPTO_CIPHER_MODULE_DISABLED>
        $<$<BOOL:${CRYPTO_HASH_MODULE_DISABLED}>:TFM_CRYPTO_HASH_MODULE_DISABLED>
        $<$<BOOL:${CRYPTO_ASYM_SIGN_MODULE_DISABLED}>:TFM_CRYPTO_ASYM_SIGN_MODULE_DISABLED>
        $<$<BOOL:${CRYPTO_ASYM_ENCRYPT_MODULE_DISABLED}>:TFM_CRYPTO_ASYM_ENCRYPT_MODULE_DISABLED>
        $<$<BOOL:${CRYPTO_KEY_DERIVATION_MODULE_DISABLED}>:TFM_CRYPTO_KEY_DERIVATION_MODULE_DISABLED>
    PRIVATE
        $<$<BOOL:${CRYPTO_ENGINE_BUF_SIZE}>:TFM_CRYPTO_ENGINE_BUF_SIZE=${CRYPTO_ENGINE_BUF_SIZE}>
        $<$<BOOL:${CRYPTO_CONC_OPER_NUM}>:TFM_CRYPTO_CONC_OPER_NUM=${CRYPTO_CONC_OPER_NUM}>
        $<$<AND:$<BOOL:${TFM_PSA_API}>,$<BOOL:${CRYPTO_IOVEC_BUFFER_SIZE}>>:TFM_CRYPTO_IOVEC_BUFFER_SIZE=${CRYPTO_IOVEC_BUFFER_SIZE}>
)

################ Display the configuration being applied #######################
if (NOT CONFIG_TFM_PARTITION_QUIET)
    message(STATUS "---------- Display crypto configuration - start --------------")

    message(STATUS "CRYPTO_RNG_MODULE_DISABLED is set to ${CRYPTO_RNG_MODULE_DISABLED}")
    message(STATUS "CRYPTO_KEY_MODULE_DISABLED is set to ${CRYPTO_KEY_MODULE_DISABLED}")
    message(STATUS "CRYPTO_AEAD_MODULE_DISABLED is set to ${CRYPTO_AEAD_MODULE_DISABLED}")
    message(STATUS "CRYPTO_MAC_MODULE_DISABLED is set to ${CRYPTO_MAC_MODULE_DISABLED}")
    message(STATUS "CRYPTO_CIPHER_MODULE_DISABLED is set to ${CRYPTO_CIPHER_MODULE_DISABLED}")
    message(STATUS "CRYPTO_HASH_MODULE_DISABLED is set to ${CRYPTO_HASH_MODULE_DISABLED}")
    message(STATUS "CRYPTO_KEY_DERIVATION_MODULE_DISABLED is set to ${CRYPTO_KEY_DERIVATION_MODULE_DISABLED}")
    message(STATUS "CRYPTO_ASYM_SIGN_MODULE_DISABLED is set to ${CRYPTO_ASYM_SIGN_MODULE_DISABLED}")
    message(STATUS "CRYPTO_ASYM_ENCRYPT_MODULE_DISABLED is set to ${CRYPTO_ASYM_ENCRYPT_MODULE_DISABLED}")
    message(STATUS "CRYPTO_ENGINE_BUF_SIZE is set to ${CRYPTO_ENGINE_BUF_SIZE}")
    message(STATUS "CRYPTO_CONC_OPER_NUM is set to ${CRYPTO_CONC_OPER_NUM}")
    if (${TFM_PSA_API})
        message(STATUS "CRYPTO_IOVEC_BUFFER_SIZE is set to ${CRYPTO_IOVEC_BUFFER_SIZE}")
    endif()
    message(STATUS "---------- Display crypto configuration - stop ---------------")
endif()

# Add properties to tfm_services target

target_link_libraries(tfm_services
    INTERFACE
        tfm_psa_rot_partition_crypto
)
