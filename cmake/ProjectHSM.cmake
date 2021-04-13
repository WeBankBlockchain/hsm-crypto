include(ExternalProject)

if("${CMAKE_HOST_SYSTEM_NAME}" MATCHES "Linux")
    if("${ARCHITECTURE}" MATCHES "aarch64")
        set(HSM_LIB_NAME libswsds.so)
    else()
        message(FATAL "unsupported platform") 
    endif()
else()
    message(FATAL "unsupported platform")
endif()

ExternalProject_Add(libsdf
    PREFIX ${CMAKE_SOURCE_DIR}/deps
    DOWNLOAD_NAME libhsm.tar.gz
    DOWNLOAD_NO_PROGRESS 1
    URL https://github.com/MaggieNgWu/devices/archive/refs/tags/v1.0.0.tar.gz
    URL_HASH SHA256=effdbe1531ab35c21377dd425fbae0c39c0dcd89173ef3436ad5677ede0ffab3
    BUILD_IN_SOURCE 1
    LOG_CONFIGURE 1
    LOG_BUILD 1
    LOG_INSTALL 1
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND bash -c "/bin/cp ${CMAKE_SOURCE_DIR}/deps/src/libhsm/NF2180M3/kylin_v10/${HSM_LIB_NAME} ${CMAKE_SOURCE_DIR}/deps/lib/libswsds.so"
)

ExternalProject_Get_Property(libsdf SOURCE_DIR)
add_library(HSM STATIC IMPORTED)

set(HSM_INCLUDE_DIR ${SOURCE_DIR}/include)
file(MAKE_DIRECTORY ${HSM_INCLUDE_DIR})  # Must exist.

set(HSM_LIB "${CMAKE_SOURCE_DIR}/deps/lib/libswsds.so")

set_property(TARGET HSM PROPERTY IMPORTED_LOCATION ${HSM_LIB})
set_property(TARGET HSM PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${HSM_INCLUDE_DIR})
add_dependencies(HSM libhsm)
unset(SOURCE_DIR)