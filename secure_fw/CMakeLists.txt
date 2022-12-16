cmake_minimum_required(VERSION 3.15)

add_library(iotex_tf INTERFACE)
target_link_libraries(iotex_tf
    INTERFACE
        tfm_psa_rot_partition_crypto
        tfm_psa_rot_partition_its
        tfm_service_audit
        tfm_app_rot_partition_ps
)

add_subdirectory(core)
add_subdirectory(services)

