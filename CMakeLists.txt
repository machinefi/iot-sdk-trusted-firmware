#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

project(iotex_trusted_firmware)

include(${CMAKE_SOURCE_DIR}/config/set_config.cmake)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/interface/include/psa/framework_feature.h.in
               ${CMAKE_BINARY_DIR}/generated/interface/include/psa/framework_feature.h
               @ONLY)

#SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)		
#SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)		
SET(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../../build/out/lib)		

ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/interface)				
ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/secure_fw)
					
add_library(iotex_trusted_firmware STATIC $<TARGET_OBJECTS:iotex_tf_nonsecure> $<TARGET_OBJECTS:iotex_tf_secure>)

#target_link_libraries(iotex_trusted_firmware PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib/libmbedcrypto.a)
