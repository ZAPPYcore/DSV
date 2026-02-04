# DSV Test Suite CMake Configuration

cmake_minimum_required(VERSION 3.16)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/common/include
    ${CMAKE_SOURCE_DIR}/node/include
    ${CMAKE_SOURCE_DIR}/wallet/include
    ${SODIUM_INCLUDE_DIRS}
)

# Link directories
link_directories(${SODIUM_LIBRARY_DIRS})

# Common test libraries
set(TEST_LIBS
    dsv_common
    dsv_node
    dsv_wallet
    ${SODIUM_LIBRARIES}
    pthread
)

# =============================================================================
# Unit Tests
# =============================================================================

# Test U320
add_executable(test_u320 unit/test_u320.c)
target_link_libraries(test_u320 ${TEST_LIBS})
add_test(NAME unit_u320 COMMAND test_u320)

# Test Crypto
add_executable(test_crypto unit/test_crypto.c)
target_link_libraries(test_crypto ${TEST_LIBS})
add_test(NAME unit_crypto COMMAND test_crypto)

# Test Consensus
add_executable(test_consensus unit/test_consensus.c)
target_link_libraries(test_consensus ${TEST_LIBS})
add_test(NAME unit_consensus COMMAND test_consensus)

# Test Serialize
add_executable(test_serialize unit/test_serialize.c)
target_link_libraries(test_serialize ${TEST_LIBS})
add_test(NAME unit_serialize COMMAND test_serialize)

# =============================================================================
# Integration Tests
# =============================================================================

# Test Chain
add_executable(test_chain integration/test_chain.c)
target_link_libraries(test_chain ${TEST_LIBS})
add_test(NAME integration_chain COMMAND test_chain)

# Test Wallet
add_executable(test_wallet integration/test_wallet.c)
target_link_libraries(test_wallet ${TEST_LIBS})
add_test(NAME integration_wallet COMMAND test_wallet)

# =============================================================================
# Fuzz Tests (optional, requires libFuzzer)
# =============================================================================

option(ENABLE_FUZZING "Enable fuzz tests" OFF)

if(ENABLE_FUZZING)
    # Check for libFuzzer
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(FUZZER_FLAGS "-fsanitize=fuzzer,address,undefined")
        
        # Fuzz TX Parse
        add_executable(fuzz_tx_parse fuzz/fuzz_tx_parse.c)
        target_compile_options(fuzz_tx_parse PRIVATE ${FUZZER_FLAGS})
        target_link_options(fuzz_tx_parse PRIVATE ${FUZZER_FLAGS})
        target_link_libraries(fuzz_tx_parse dsv_common ${SODIUM_LIBRARIES})
        target_compile_definitions(fuzz_tx_parse PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        
        # Fuzz Block Parse
        add_executable(fuzz_block_parse fuzz/fuzz_block_parse.c)
        target_compile_options(fuzz_block_parse PRIVATE ${FUZZER_FLAGS})
        target_link_options(fuzz_block_parse PRIVATE ${FUZZER_FLAGS})
        target_link_libraries(fuzz_block_parse dsv_common ${SODIUM_LIBRARIES})
        target_compile_definitions(fuzz_block_parse PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        
        # Fuzz RPC Input
        add_executable(fuzz_rpc_input fuzz/fuzz_rpc_input.c)
        target_compile_options(fuzz_rpc_input PRIVATE ${FUZZER_FLAGS})
        target_link_options(fuzz_rpc_input PRIVATE ${FUZZER_FLAGS})
        target_link_libraries(fuzz_rpc_input dsv_common dsv_node ${SODIUM_LIBRARIES})
        target_compile_definitions(fuzz_rpc_input PRIVATE FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
        
        message(STATUS "Fuzz tests enabled")
    else()
        message(WARNING "Fuzz tests require Clang compiler with libFuzzer")
    endif()
else()
    # Build standalone fuzz test drivers (for manual testing)
    add_executable(fuzz_tx_parse_standalone fuzz/fuzz_tx_parse.c)
    target_link_libraries(fuzz_tx_parse_standalone dsv_common ${SODIUM_LIBRARIES})
    
    add_executable(fuzz_block_parse_standalone fuzz/fuzz_block_parse.c)
    target_link_libraries(fuzz_block_parse_standalone dsv_common ${SODIUM_LIBRARIES})
endif()

# =============================================================================
# Sanitizer Builds
# =============================================================================

option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
    message(STATUS "AddressSanitizer enabled")
endif()

if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
    message(STATUS "UndefinedBehaviorSanitizer enabled")
endif()

# =============================================================================
# Test Targets
# =============================================================================

# Run all unit tests
add_custom_target(test_unit
    COMMAND ${CMAKE_CTEST_COMMAND} -R "^unit_" --output-on-failure
    DEPENDS test_u320 test_crypto test_consensus test_serialize
    COMMENT "Running unit tests"
)

# Run all integration tests
add_custom_target(test_integration
    COMMAND ${CMAKE_CTEST_COMMAND} -R "^integration_" --output-on-failure
    DEPENDS test_chain test_wallet
    COMMENT "Running integration tests"
)

# Run all tests
add_custom_target(test_all
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_u320 test_crypto test_consensus test_serialize test_chain test_wallet
    COMMENT "Running all tests"
)

