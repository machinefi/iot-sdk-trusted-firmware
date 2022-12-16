cmake_minimum_required(VERSION 3.15)

add_library(tfm_services INTERFACE)
target_link_libraries(tfm_services
    INTERFACE
        tfm_spm_core
)

option(BUILD_SERVICE_AUDIT_LOGGING "Build audit logging service" ON)
option(BUILD_SERVICE_CRYPTO "Build cryoti service" ON)
option(BUILD_SERVICE_TRUSTED_STORAGE "Build trusted storage service" ON)

if (BUILD_SERVICE_AUDIT_LOGGING)
    add_subdirectory(audit_logging)
endif()

if (BUILD_SERVICE_CRYPTO)
    add_subdirectory(crypto)
endif()

if (BUILD_SERVICE_TRUSTED_STORAGE)
    add_subdirectory(protected_storage)
    add_subdirectory(internal_trusted_storage)
endif()
