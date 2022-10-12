/*
 * Copyright (c) 2018-2019, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*********** WARNING: This is an auto-generated file. Do not edit! ***********/

#ifndef __TFM_VENEERS_H__
#define __TFM_VENEERS_H__

#include "tfm_api.h"

#ifdef __cplusplus
extern "C" {
#endif


psa_status_t tfm_crypto_init(void);

/******** TFM_SP_STORAGE ********/
psa_status_t tfm_ps_set_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_ps_get_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_ps_get_info_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_ps_remove_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_ps_get_support_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);

// psa_status_t tfm_tfm_sst_set_req_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// psa_status_t tfm_tfm_sst_get_req_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// psa_status_t tfm_tfm_sst_get_info_req_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// psa_status_t tfm_tfm_sst_remove_req_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// psa_status_t tfm_tfm_sst_get_support_req_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);

/******** TFM_SP_ITS ********/
psa_status_t tfm_its_set_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_its_get_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_its_get_info_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_its_remove_req(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);

//#ifdef TFM_PARTITION_AUDIT_LOG
/******** TFM_SP_AUDIT_LOG ********/
psa_status_t audit_core_retrieve_record(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t audit_core_add_record(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t audit_core_get_info(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t audit_core_get_record_info(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t audit_core_delete_record(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
//#endif /* TFM_PARTITION_AUDIT_LOG */

/******** TFM_SP_CRYPTO ********/

// Key Management
psa_status_t tfm_crypto_open_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_close_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_import_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_destroy_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_get_key_attributes(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_reset_key_attributes(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_export_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_export_public_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_purge_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_copy_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// Cipher
psa_status_t tfm_crypto_cipher_generate_iv(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_cipher_set_iv(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_cipher_encrypt_setup(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_cipher_decrypt_setup(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_cipher_update(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_cipher_abort(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_cipher_finish(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_cipher_encrypt(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_cipher_decrypt(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// Hash
psa_status_t tfm_crypto_hash_setup(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_hash_update(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_hash_finish(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_hash_verify(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_hash_abort(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_hash_clone(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_hash_compute(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_hash_compare(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// Mac
psa_status_t tfm_crypto_mac_sign_setup(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_mac_verify_setup(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_mac_update(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_mac_sign_finish(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_mac_verify_finish(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_mac_abort(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_mac_compute(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_mac_verify(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// aead
psa_status_t tfm_crypto_aead_encrypt(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_decrypt(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_encrypt_setup(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_decrypt_setup(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_generate_nonce(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_set_nonce(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_set_lengths(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_update_ad(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_update(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_finish(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_verify(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_aead_abort(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// asymmetric
psa_status_t tfm_crypto_sign_message(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_verify_message(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_sign_hash(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_verify_hash(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_asymmetric_encrypt(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_asymmetric_decrypt(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
// key_derivation
psa_status_t tfm_crypto_key_derivation_get_capacity(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_key_derivation_output_bytes(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_key_derivation_input_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_key_derivation_abort(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_key_derivation_key_agreement(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_key_derivation_setup(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_key_derivation_set_capacity(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_key_derivation_input_bytes(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_key_derivation_output_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);

psa_status_t tfm_crypto_generate_random(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_generate_key(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_crypto_raw_key_agreement(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);


#ifdef TFM_PARTITION_PLATFORM
/******** TFM_SP_PLATFORM ********/
psa_status_t tfm_platform_sp_system_reset_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_platform_sp_ioctl_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
#endif /* TFM_PARTITION_PLATFORM */

/******** TFM_SP_INITIAL_ATTESTATION ********/
psa_status_t tfm_initial_attest_get_token_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_initial_attest_get_token_size_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);

#ifdef TFM_PARTITION_TEST_CORE
/******** TFM_SP_CORE_TEST ********/
psa_status_t tfm_spm_core_test_sfn_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_spm_core_test_sfn_init_success_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_spm_core_test_sfn_direct_recursion_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
#endif /* TFM_PARTITION_TEST_CORE */

#ifdef TFM_PARTITION_TEST_CORE
/******** TFM_SP_CORE_TEST_2 ********/
psa_status_t tfm_spm_core_test_2_slave_service_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_spm_core_test_2_sfn_invert_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_spm_core_test_2_check_caller_client_id_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_spm_core_test_2_get_every_second_byte_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_spm_core_test_2_prepare_test_scenario_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_spm_core_test_2_execute_test_scenario_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
#endif /* TFM_PARTITION_TEST_CORE */

#ifdef TFM_PARTITION_TEST_SECURE_SERVICES
/******** TFM_SP_SECURE_TEST_PARTITION ********/
psa_status_t tfm_tfm_secure_client_service_sfn_run_tests_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
#endif /* TFM_PARTITION_TEST_SECURE_SERVICES */

#ifdef TFM_PARTITION_TEST_CORE_IPC
/******** TFM_SP_IPC_SERVICE_TEST ********/
#endif /* TFM_PARTITION_TEST_CORE_IPC */

#ifdef TFM_PARTITION_TEST_CORE_IPC
/******** TFM_SP_IPC_CLIENT_TEST ********/
#endif /* TFM_PARTITION_TEST_CORE_IPC */

#ifdef TFM_ENABLE_IRQ_TEST
/******** TFM_IRQ_TEST_1 ********/
psa_status_t tfm_spm_irq_test_1_prepare_test_scenario_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
psa_status_t tfm_spm_irq_test_1_execute_test_scenario_veneer(psa_invec *in_vec, size_t in_len, psa_outvec *out_vec, size_t out_len);
#endif /* TFM_ENABLE_IRQ_TEST */

#ifdef __cplusplus
}
#endif

#endif /* __TFM_VENEERS_H__ */
