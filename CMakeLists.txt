cmake_minimum_required(VERSION 3.15)

add_subdirectory(platform)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/secure_fw)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/interface)				