cmake_minimum_required(VERSION 3.20)
project(UniTelem LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(UNITELEM_BUILD_TESTS "Build UniTelem C/C++ unit and interop tests" ON)
option(UNITELEM_ENABLE_SANITIZERS "Enable ASan/UBSan on tests" OFF)
set(UNITELEM_CRYPTO "OPENSSL" CACHE STRING "Crypto backend (OPENSSL)")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Vendored yyjson (C99)
add_library(unitelem_yyjson STATIC
    third_party/yyjson/yyjson.c
)
target_include_directories(unitelem_yyjson PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yyjson
)
set_target_properties(unitelem_yyjson PROPERTIES C_STANDARD 99)

# C11 Core Library
add_library(unitelem_c STATIC
    src/crc16.c
    src/ccsds.c
    src/blake2s.c
    src/crypto_openssl.c
    src/hash_chain.c
    src/merkle_tree.c
    src/ring_buffer.c
    src/state_crdt.c
    src/discovery.c
    src/transport.c
    src/node.c
)

target_include_directories(unitelem_c PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(unitelem_c PUBLIC
    _POSIX_C_SOURCE=200809L
)
target_compile_definitions(unitelem_c PRIVATE
    _DEFAULT_SOURCE
)
target_compile_options(unitelem_c PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)
target_link_libraries(unitelem_c PUBLIC
    unitelem_yyjson
    OpenSSL::Crypto
    Threads::Threads
    m
)

# C++20 Ergonomic Header Wrapper
add_library(unitelem_cpp INTERFACE)
target_include_directories(unitelem_cpp INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_features(unitelem_cpp INTERFACE cxx_std_20)
target_link_libraries(unitelem_cpp INTERFACE unitelem_c)

if(UNITELEM_ENABLE_SANITIZERS)
    target_compile_options(unitelem_c PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(unitelem_c PUBLIC -fsanitize=address,undefined)
endif()

if(UNITELEM_BUILD_TESTS)
    enable_testing()
    find_package(Python3 COMPONENTS Interpreter)

    add_executable(test_protocol tests/test_protocol.c)
    target_link_libraries(test_protocol PRIVATE unitelem_c)
    target_compile_options(test_protocol PRIVATE -Wall -Wextra -Werror)
    add_test(NAME protocol COMMAND test_protocol)

    add_executable(test_crypto tests/test_crypto.c)
    target_link_libraries(test_crypto PRIVATE unitelem_c)
    target_compile_options(test_crypto PRIVATE -Wall -Wextra -Werror)
    add_test(NAME crypto COMMAND test_crypto)

    add_executable(test_ring_buffer tests/test_ring_buffer.cpp)
    target_link_libraries(test_ring_buffer PRIVATE unitelem_cpp)
    target_compile_options(test_ring_buffer PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ring_buffer COMMAND test_ring_buffer)

    add_executable(test_state_crdt tests/test_state_crdt.c)
    target_link_libraries(test_state_crdt PRIVATE unitelem_c)
    target_compile_options(test_state_crdt PRIVATE -Wall -Wextra -Werror)
    add_test(NAME state_crdt COMMAND test_state_crdt)

    add_executable(test_node_loopback tests/test_node_loopback.cpp)
    target_link_libraries(test_node_loopback PRIVATE unitelem_cpp)
    target_compile_options(test_node_loopback PRIVATE -Wall -Wextra -Werror)
    add_test(NAME node_loopback COMMAND test_node_loopback)

    add_executable(interop_helper tests/interop_helper.cpp)
    target_link_libraries(interop_helper PRIVATE unitelem_cpp)
    target_compile_options(interop_helper PRIVATE -Wall -Wextra -Werror)

    add_executable(c_interop_node tests/c_interop_node.c)
    target_link_libraries(c_interop_node PRIVATE unitelem_c)
    target_compile_options(c_interop_node PRIVATE -Wall -Wextra -Werror)

    if(Python3_Interpreter_FOUND)
        add_test(
            NAME python_interop
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_python_interop.py $<TARGET_FILE:interop_helper> $<TARGET_FILE:c_interop_node>
        )
    endif()
endif()
