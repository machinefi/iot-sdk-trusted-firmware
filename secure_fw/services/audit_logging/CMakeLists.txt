cmake_minimum_required(VERSION 3.16) 

add_library(tfm_service_audit STATIC
    audit_core.c
)

target_link_libraries(tfm_service_audit
    PRIVATE
        platform_s
        iotex_sdk_interface
)

# Add properties to tfm_services target

target_link_libraries(tfm_services
    INTERFACE
        tfm_service_audit
)
