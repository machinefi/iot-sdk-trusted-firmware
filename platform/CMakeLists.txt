#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0076 NEW)
cmake_policy(SET CMP0079 NEW)

add_library(platform_s INTERFACE)
add_library(platform_region_defs INTERFACE)
add_library(platform_common_interface INTERFACE)
add_library(platform_ns INTERFACE)

set(PLATFORM_DIR ${CMAKE_CURRENT_LIST_DIR})

if (!TFM_PLATFORM STREQUAL "")
    add_subdirectory(ext/target/${TFM_PLATFORM} target)
endif()

#========================= Platform Common interface ==========================#

target_include_directories(platform_common_interface
    INTERFACE
        ./ext
        ./ext/cmsis
        ./ext/common
        ./ext/driver
        ./include
)

#========================= Platform Secure ====================================#

target_include_directories(platform_s
    INTERFACE
        $<$<BOOL:${CRYPTO_HW_ACCELERATOR}>:${CMAKE_CURRENT_SOURCE_DIR}/ext/accelerator/interface>
)

target_link_libraries(platform_s
    INTERFACE
        platform_common_interface
        platform_region_defs
)

target_compile_options(platform_s
    PUBLIC
        ${COMPILER_CP_FLAG}
)
