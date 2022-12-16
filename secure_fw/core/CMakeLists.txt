cmake_minimum_required(VERSION 3.15)

add_library(tfm_spm_core STATIC)

target_include_directories(tfm_spm_core
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_sources(tfm_spm_core PRIVATE
    src/tfm_memory_utils.c)