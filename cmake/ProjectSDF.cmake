include(ExternalProject)
if("${CMAKE_HOST_SYSTEM_NAME}" MATCHES "Linux")
	if("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "aarch64")
        message(STATUS " ${CMAKE_HOST_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR} supported platform")
    else()
        message(STATUS " ${CMAKE_HOST_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR} supported platform") 
    endif()
else()
    message(FATAL " ${CMAKE_HOST_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR} unsupported platform")
endif()



find_library(SWSDS swsds /usr/lib)
if(NOT SWSDS)
    message()
    message(FATAL " Can not find library libswsds.so under /usr/lib, please make sure you have a crypto PCI card on your machine, as well as the the driver and libraries are installed.")
endif()
find_file(SWSDS_H csmsds.h /usr/include)
if(NOT SWSDS_H)
    message(FATAL " Can not find swsds.h under /usr/include, please make sure you have a crypto PCI card on your machine, as well as the the driver and libraries are installed.")
endif()


add_library(SDF SHARED IMPORTED)
set_property(TARGET SDF PROPERTY IMPORTED_LOCATION ${SWSDS})
#set_property(TARGET SDF PROPERTY INTERFACE_INCLUDE_DIRECTORIES SWSDS_H)