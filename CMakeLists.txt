cmake_minimum_required(VERSION 3.10)
project(HSM-CRYPTO VERSION "1.1.0")
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
set(HSM_CRYPTO_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
set(CMAKE_CXX_FLAGS "-std=c++11")
list(APPEND CMAKE_MODULE_PATH ${HSM_CRYPTO_CMAKE_DIR})
include_directories("${CMAKE_SOURCE_DIR}")
include(Options)
print_config(${PROJECT_NAME})

include(ProjectSDF)
add_subdirectory(hsm)

if(BUILD_SHARED_LIBS)
    add_subdirectory(test)
endif()

install(
    DIRECTORY "hsm"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/hsm-crypto"
    FILES_MATCHING PATTERN "*.h"
)
