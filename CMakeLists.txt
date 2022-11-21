#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

project(iotex_tf)
include(CMakePrintHelpers)

include(${PROJECT_SOURCE_DIR}/config/set_config.cmake)

configure_file(interface/include/psa/framework_feature.h.in
               ${CMAKE_BINARY_DIR}/generated/interface/include/psa/framework_feature.h
               @ONLY)


ADD_SUBDIRECTORY(${PROJECT_SOURCE_DIR}/interface)				
ADD_SUBDIRECTORY(${PROJECT_SOURCE_DIR}/secure_fw)
		
add_library(iotex_trusted_firmware STATIC 
  $<TARGET_OBJECTS:iotex_tf_nonsecure>
  $<TARGET_OBJECTS:iotex_tf_secure>)


if(CRYPTO_IMPL STREQUAL "MbedTLS")
  target_link_libraries(iotex_trusted_firmware
    PUBLIC mbedcrypto
  )
endif()

if(CRYPTO_IMPL STREQUAL "TinyCrypt")
  target_link_libraries(iotex_trusted_firmware
    PUBLIC tinycrypt
  )
endif()