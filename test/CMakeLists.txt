file(GLOB HEADERS "*.h")
file(GLOB SRC_LIST "*.cpp")
add_executable(test-sdf-crypto ${SRC_LIST} ${HEADERS})
EXECUTE_PROCESS(COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE)
set(LIBRARY_NAME "sdf-crypto")

target_link_libraries(test-sdf-crypto PUBLIC ${LIBRARY_NAME} pthread ${CMAKE_DL_LIBS})