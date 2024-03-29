cmake_minimum_required(VERSION 3.10)
project(HSM-CRYPTO VERSION "1.1.0" LANGUAGES CXX)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${EXECUTABLE_OUTPUT_PATH})
set(HSM_CRYPTO_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
set(CMAKE_CXX_STANDARD 20)
list(APPEND CMAKE_MODULE_PATH ${HSM_CRYPTO_CMAKE_DIR})
if (WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
    add_definitions(-DBOOST_USE_WINAPI_VERSION=BOOST_WINAPI_VERSION_WIN7)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS "ON")
endif ()
include_directories("${CMAKE_SOURCE_DIR}")
include(Options)
print_config(${PROJECT_NAME})

include(ProjectSDF)
add_subdirectory(hsm)

if(TESTS)
    add_subdirectory(test)
endif()

install(
    DIRECTORY "hsm"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/hsm-crypto"
    FILES_MATCHING PATTERN "*.h"
)
