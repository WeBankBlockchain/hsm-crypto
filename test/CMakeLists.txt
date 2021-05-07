file(GLOB HEADERS "*.h")
file(GLOB SRC_LIST "*.cpp")
add_executable(test-sdf-crypto ${SRC_LIST} ${HEADERS})
target_link_libraries(test-sdf-crypto PUBLIC sdf-crypto_arm)