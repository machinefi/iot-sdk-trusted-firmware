cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_psa_rot_partition_its STATIC)

target_sources(tfm_psa_rot_partition_its
    PRIVATE
        tfm_its_req_mngr.c
        tfm_internal_trusted_storage.c
        its_utils.c
)

target_link_libraries(tfm_psa_rot_partition_its
    PRIVATE
        platform_s
        iotex_sdk_interface
        tfm_spm_core
)

# Add properties to the tfm_services target

target_link_libraries(tfm_services
    INTERFACE
        tfm_psa_rot_partition_its
)
