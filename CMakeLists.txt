#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

project(iotex_trusted_firmware)
include(CMakePrintHelpers)

include(${PROJECT_SOURCE_DIR}/config/set_config.cmake)

configure_file(interface/include/psa/framework_feature.h.in
               ${CMAKE_BINARY_DIR}/generated/interface/include/psa/framework_feature.h
               @ONLY)


ADD_SUBDIRECTORY(${PROJECT_SOURCE_DIR}/interface)				
ADD_SUBDIRECTORY(${PROJECT_SOURCE_DIR}/secure_fw)
		
add_library(iotex_trusted_firmware STATIC 
    $<TARGET_OBJECTS:iotex_tf_nonsecure>)

# Also add a copy of the target iotex_trusted_firmware that exposes mbedcrypto and iotex_tf_secure
# We need this because the PSA tests need to access these libraries
# TODO Check if the user facing library (non test) need to expose mbedcrypto and iotex_tf_secure
add_library(iotex_trusted_firmware_test STATIC 
    $<TARGET_OBJECTS:iotex_tf_nonsecure>)

target_link_libraries(iotex_trusted_firmware_test
    PUBLIC $<TARGET_OBJECTS:iotex_tf_secure>)

if(CRYPTO_IMPL STREQUAL "MbedTLS")
  target_link_libraries(iotex_trusted_firmware_test
    PUBLIC mbedcrypto
  )
endif()

if(CRYPTO_IMPL STREQUAL "TinyCrypt")
  target_link_libraries(iotex_trusted_firmware_test
    PUBLIC tinycrypt
  )
endif()