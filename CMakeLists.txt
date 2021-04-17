cmake_minimum_required(VERSION 3.10)
project(SDF-CRYPTO VERSION "1.1.0")
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
set(HSM_CRYPTO_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${HSM_CRYPTO_CMAKE_DIR})
include(ProjectHSM)

include_directories("${CMAKE_SOURCE_DIR}")
add_subdirectory(sdf)
add_subdirectory(test)
	
