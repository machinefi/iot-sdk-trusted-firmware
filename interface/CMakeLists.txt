cmake_minimum_required(VERSION 3.15)

add_library(iotex_sdk_interface STATIC
  src/iotex_audit_func_api.c
  src/iotex_crypto_func_api.c
  src/iotex_its_func_api.c
  src/iotex_ns_interface.c
  src/iotex_ps_func_api.c
)

target_include_directories(iotex_sdk_interface
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/generated/interface/include
  )

target_link_libraries(iotex_sdk_interface
    PRIVATE
      tfm_services
)
