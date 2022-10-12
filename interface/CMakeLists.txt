#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src SRCS_INTERFACE)

add_library(iotex_tf_nonsecure ${SRCS_INTERFACE})

target_include_directories(iotex_tf_nonsecure
PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/generated/interface/include
)
