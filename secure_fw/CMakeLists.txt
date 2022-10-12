#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/core/src SRCS_CORE)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/services/internal_trusted_storage SRCS_ITS) 
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/services/protected_storage SRCS_PS)  
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/services/audit_logging SRCS_AL)  
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/services/crypto SRCS_CRYPTO) 

#aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/secure_fw/ns_callable SRCS_NS_CALLABLE) 
add_library(iotex_tf_secure ${SRCS_CORE} ${SRCS_ITS} ${SRCS_PS} ${SRCS_AL} ${SRCS_CRYPTO})

target_include_directories(iotex_tf_secure
PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/../../crypto
#        ${PROJECT_SOURCE_DIR}/../mbed-crypto/include
#        ${PROJECT_SOURCE_DIR}/../mbed-crypto/include/mbedtls
#        ${PROJECT_SOURCE_DIR}/../mbed-crypto/include/psa
        ${PROJECT_SOURCE_DIR}/../../crypto/mbedtls/include
        ${PROJECT_SOURCE_DIR}/../../crypto/mbedtls/include/mbedtls
        ${PROJECT_SOURCE_DIR}/../../crypto/mbedtls/include/psa
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/interface/include
        ${PROJECT_SOURCE_DIR}/platform/ext/common
        ${PROJECT_SOURCE_DIR}/platform/ext/driver
        ${PROJECT_SOURCE_DIR}/platform/include
        ${CMAKE_CURRENT_SOURCE_DIR}/core
        ${CMAKE_CURRENT_SOURCE_DIR}/core/include
)
