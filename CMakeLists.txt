cmake_minimum_required(VERSION 3.16)
project(dsv VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build options
option(DSV_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(DSV_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(DSV_ENABLE_FUZZ "Enable fuzzing targets" OFF)
option(DSV_BUILD_TESTS "Build tests" ON)

# Compiler warnings
if(MSVC)
    # MSVC 전용
    add_compile_options(/W4 /WX)
    add_compile_options(/sdl)  # Security Development Lifecycle checks
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    # GCC/Clang 전용
    add_compile_options(-Wall -Wextra -Werror -Wpedantic)
    add_compile_options(-Wformat=2 -Wformat-security -Wstack-protector)
    add_compile_options(-fstack-protector-strong -D_FORTIFY_SOURCE=2)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2 -DNDEBUG)
else()
    add_compile_options(-g -O0)
endif()

# Sanitizers
if(DSV_ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

if(DSV_ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(LEVELDB REQUIRED leveldb)
pkg_check_modules(LIBEVENT REQUIRED libevent)
pkg_check_modules(CJSON REQUIRED libcjson)
if(NOT WIN32)
  pkg_check_modules(PTHREAD_STUBS REQUIRED pthread-stubs)
endif()


# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/node/include
    ${CMAKE_SOURCE_DIR}/wallet/include
    ${CMAKE_SOURCE_DIR}/common/include
    ${SODIUM_INCLUDE_DIRS}
    ${LEVELDB_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
)

link_directories(
    ${SODIUM_LIBRARY_DIRS}
    ${LEVELDB_LIBRARY_DIRS}
    ${LIBEVENT_LIBRARY_DIRS}
    ${CJSON_LIBRARY_DIRS}
)

# Common library
file(GLOB COMMON_SOURCES "common/src/*.c")
add_library(dsv_common STATIC ${COMMON_SOURCES})
target_link_libraries(dsv_common ${SODIUM_LIBRARIES})

# Node library and executable
file(GLOB NODE_SOURCES "node/src/*.c")
add_library(dsv_node_lib STATIC ${NODE_SOURCES})

if(WIN32)
    target_link_libraries(dsv_node_lib 
        dsv_common
        ${SODIUM_LIBRARIES}
        ${LEVELDB_LIBRARIES}
        ${LIBEVENT_LIBRARIES}
        ${CJSON_LIBRARIES}
        ws2_32
    )
else()
    target_link_libraries(dsv_node_lib 
        dsv_common
        ${SODIUM_LIBRARIES}
        ${LEVELDB_LIBRARIES}
        ${LIBEVENT_LIBRARIES}
        ${CJSON_LIBRARIES}
        pthread
    )
endif()

add_executable(dsvd node/main.c)
target_link_libraries(dsvd dsv_node_lib)

if(WIN32)
    target_link_libraries(dsvd ws2_32)
endif()

if (WIN32)
  message(STATUS "Skipping dsv-cli and dsv-wallet on Windows (needs porting)")
else()
  # Wallet executable (non-Windows)
  add_executable(dsv-wallet wallet/main.c)
  target_link_libraries(dsv-wallet dsv_wallet_lib)

  # CLI tool (non-Windows)
  add_executable(dsv-cli cli/main.c cli/src/rpc_client.c)
  target_link_libraries(dsv-cli dsv_common ${CJSON_LIBRARIES})
endif()

# Tests
if(DSV_BUILD_TESTS)
    enable_testing()
    
    file(GLOB TEST_SOURCES "tests/unit/*.c")
    foreach(TEST_SOURCE ${TEST_SOURCES})
        get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
        add_executable(${TEST_NAME} ${TEST_SOURCE})
        if(WIN32)
            target_link_libraries(${TEST_NAME} dsv_common dsv_node_lib ws2_32)
        else()
            target_link_libraries(${TEST_NAME} dsv_common dsv_node_lib dsv_wallet_lib)
        endif()
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endforeach()
endif()

# Fuzz targets
if(DSV_ENABLE_FUZZ)
    add_compile_options(-fsanitize=fuzzer,address)
    add_link_options(-fsanitize=fuzzer,address)
    
    add_executable(fuzz_tx_parse tests/fuzz/fuzz_tx_parse.c)
    target_link_libraries(fuzz_tx_parse dsv_common dsv_node_lib)
    
    add_executable(fuzz_block_parse tests/fuzz/fuzz_block_parse.c)
    target_link_libraries(fuzz_block_parse dsv_common dsv_node_lib)
    
    add_executable(fuzz_rpc_input tests/fuzz/fuzz_rpc_input.c)
    target_link_libraries(fuzz_rpc_input dsv_common dsv_node_lib)
endif()

# Install targets
install(TARGETS dsvd RUNTIME DESTINATION bin)

if(NOT WIN32)
  install(TARGETS dsv-wallet dsv-cli RUNTIME DESTINATION bin)
endif()

install(DIRECTORY ${CMAKE_SOURCE_DIR}/docs/
    DESTINATION share/doc/dsv
)

message(STATUS "DSV Build Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  ASAN: ${DSV_ENABLE_ASAN}")
message(STATUS "  UBSAN: ${DSV_ENABLE_UBSAN}")
message(STATUS "  Fuzz: ${DSV_ENABLE_FUZZ}")
message(STATUS "  Tests: ${DSV_BUILD_TESTS}")

