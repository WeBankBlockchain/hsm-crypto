include(ExternalProject)
if("${CMAKE_HOST_SYSTEM_NAME}" MATCHES "Linux")
	if("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "aarch64")
	set(SDF_LIB_NAME libswsds.so)
    else()
        message(FATAL " unsupported platform") 
    endif()
else()
    message(FATAL " unsupported platform")
endif()

ExternalProject_Add(libsdf
    PREFIX ${CMAKE_SOURCE_DIR}/deps
    DOWNLOAD_NAME libsdf.tar.gz
    DOWNLOAD_NO_PROGRESS 1
    URL https://github.com/MaggieNgWu/devices/archive/refs/tags/v1.0.0.tar.gz
    URL_HASH SHA256=effdbe1531ab35c21377dd425fbae0c39c0dcd89173ef3436ad5677ede0ffab3
    BUILD_IN_SOURCE 1
    LOG_CONFIGURE 1
    LOG_BUILD 1
    LOG_INSTALL 1
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
)

ExternalProject_Get_Property(libsdf SOURCE_DIR)
add_library(SDF STATIC IMPORTED)
set(SDF_INCLUDE_DIR ${SOURCE_DIR}/NF2180M3/kylin_v10)
file(MAKE_DIRECTORY ${SDF_INCLUDE_DIR})  # Must exist.
set(SDF_LIB "/lib/libswsds.so")

set_property(TARGET SDF PROPERTY IMPORTED_LOCATION ${SDF_LIB})
set_property(TARGET SDF PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${SDF_INCLUDE_DIR})
add_dependencies(SDF libsdf)

unset(SOURCE_DIR)
