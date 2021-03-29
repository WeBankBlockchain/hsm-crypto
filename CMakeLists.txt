cmake_minimum_required(VERSION 3.10)
project(test-sdf-crypto VERSION "0.1.0")

set(CMAKE_CXX_STANDARD 11) 
#set(SDF_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${SDF_CMAKE_DIR}/build/out)

# file("SDFCryptoProvider.cpp")
# file("SDFCryptoProvider.h")
# file("libsdf/swsds.h"
set(INK_DIR ${CMAKE_CURRENT_LIST_DIR}/libsdf/swsds)
set(LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/libsdf/libswsds)
include_directories(${INK_DIR})
link_directories(${LIB_DIR})
link_libraries(swsds)
# target_link_libraries(sdf-crypto PUBLIC libsdf/swsds.so)

add_library(sdf-crypto SHARED SDFCryptoProvider.cpp SDFCryptoProvider.h)
target_link_libraries(sdf-crypto swsds)
add_executable(${PROJECT_NAME} TestSDF.cpp)
target_link_libraries(${PROJECT_NAME} sdf-crypto)