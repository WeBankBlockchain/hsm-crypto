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



find_library(GMT0018 gmt0018)
if(NOT GMT0018)
    message(FATAL " Can not find library libgmt0018.so under /usr/lib, please make sure you have a crypto PCI card on your machine, as well as the the driver and libraries are installed.")
endif()
find_file(GMT0018_H gmt0018.h /usr/include)
if(NOT GMT0018_H)
    message(FATAL " Can not find libgmt0018.h under /usr/include, please make sure you have a crypto PCI card on your machine, as well as the the driver and libraries are installed.")
endif()


add_library(SDF SHARED IMPORTED)
set_property(TARGET SDF PROPERTY IMPORTED_LOCATION ${GMT0018})
#set_property(TARGET SDF PROPERTY INTERFACE_INCLUDE_DIRECTORIES GMT0018_H)
