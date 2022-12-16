cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_app_rot_partition_ps STATIC)

target_include_directories(tfm_app_rot_partition_ps
    INTERFACE 
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_sources(tfm_app_rot_partition_ps
    PRIVATE
        tfm_ps_req_mngr.c
        tfm_protected_storage.c
)

target_link_libraries(tfm_app_rot_partition_ps
    PRIVATE
        iotex_sdk_interface
        platform_s
        tfm_psa_rot_partition_its
)

# Add properties to the tfm_services target

target_link_libraries(tfm_services
    INTERFACE
        tfm_app_rot_partition_ps
)
