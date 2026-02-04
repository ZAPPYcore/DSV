#!/bin/bash
#
# DSV Test Runner Script
#
# Usage: ./scripts/run_tests.sh [OPTIONS]
#
# Options:
#   --unit          Run unit tests only
#   --integration   Run integration tests only
#   --fuzz          Run fuzz test smoke tests
#   --asan          Run with AddressSanitizer
#   --ubsan         Run with UndefinedBehaviorSanitizer
#   --all           Run all tests (default)
#   --verbose       Verbose output
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
TESTS_DIR="${PROJECT_DIR}/tests"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default options
RUN_UNIT=0
RUN_INTEGRATION=0
RUN_FUZZ=0
RUN_ASAN=0
RUN_UBSAN=0
VERBOSE=0

# Parse arguments
if [ $# -eq 0 ]; then
    RUN_UNIT=1
    RUN_INTEGRATION=1
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit)
            RUN_UNIT=1
            shift
            ;;
        --integration)
            RUN_INTEGRATION=1
            shift
            ;;
        --fuzz)
            RUN_FUZZ=1
            shift
            ;;
        --asan)
            RUN_ASAN=1
            shift
            ;;
        --ubsan)
            RUN_UBSAN=1
            shift
            ;;
        --all)
            RUN_UNIT=1
            RUN_INTEGRATION=1
            RUN_FUZZ=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Build with sanitizers if requested
build_project() {
    local cmake_args=""
    
    if [ $RUN_ASAN -eq 1 ]; then
        cmake_args="$cmake_args -DENABLE_ASAN=ON"
    fi
    
    if [ $RUN_UBSAN -eq 1 ]; then
        cmake_args="$cmake_args -DENABLE_UBSAN=ON"
    fi
    
    if [ $RUN_FUZZ -eq 1 ]; then
        cmake_args="$cmake_args -DENABLE_FUZZING=ON"
    fi
    
    log_info "Building project..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. $cmake_args
    make -j$(nproc)
    cd "$PROJECT_DIR"
}

# Run unit tests
run_unit_tests() {
    log_info "Running unit tests..."
    
    cd "$BUILD_DIR"
    
    local tests=(
        "test_u320"
        "test_crypto"
        "test_consensus"
        "test_serialize"
    )
    
    local passed=0
    local failed=0
    
    for test in "${tests[@]}"; do
        if [ -f "$test" ]; then
            echo -n "  Running $test... "
            if [ $VERBOSE -eq 1 ]; then
                echo ""
                if "./$test"; then
                    ((passed++))
                else
                    ((failed++))
                fi
            else
                if "./$test" > /dev/null 2>&1; then
                    echo -e "${GREEN}PASS${NC}"
                    ((passed++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((failed++))
                fi
            fi
        else
            log_warn "Test $test not found"
        fi
    done
    
    cd "$PROJECT_DIR"
    
    echo ""
    log_info "Unit tests: $passed passed, $failed failed"
    
    return $failed
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."
    
    cd "$BUILD_DIR"
    
    local tests=(
        "test_chain"
        "test_wallet"
    )
    
    local passed=0
    local failed=0
    
    for test in "${tests[@]}"; do
        if [ -f "$test" ]; then
            echo -n "  Running $test... "
            if [ $VERBOSE -eq 1 ]; then
                echo ""
                if "./$test"; then
                    ((passed++))
                else
                    ((failed++))
                fi
            else
                if "./$test" > /dev/null 2>&1; then
                    echo -e "${GREEN}PASS${NC}"
                    ((passed++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((failed++))
                fi
            fi
        else
            log_warn "Test $test not found"
        fi
    done
    
    cd "$PROJECT_DIR"
    
    echo ""
    log_info "Integration tests: $passed passed, $failed failed"
    
    return $failed
}

# Run fuzz test smoke tests
run_fuzz_smoke() {
    log_info "Running fuzz test smoke tests..."
    
    # Create some seed inputs
    local seed_dir="$BUILD_DIR/fuzz_seeds"
    mkdir -p "$seed_dir"
    
    # Create minimal valid-ish inputs
    echo -n "deadbeef" | xxd -r -p > "$seed_dir/seed1"
    dd if=/dev/urandom of="$seed_dir/seed2" bs=100 count=1 2>/dev/null
    dd if=/dev/urandom of="$seed_dir/seed3" bs=500 count=1 2>/dev/null
    
    cd "$BUILD_DIR"
    
    local passed=0
    local failed=0
    
    # Run each fuzzer for a short time
    for fuzzer in fuzz_tx_parse fuzz_block_parse; do
        if [ -f "$fuzzer" ]; then
            echo -n "  Smoke testing $fuzzer... "
            
            if [ $VERBOSE -eq 1 ]; then
                echo ""
                # Run with timeout
                if timeout 10s "./$fuzzer" -max_total_time=5 "$seed_dir" 2>&1; then
                    ((passed++))
                else
                    ((failed++))
                fi
            else
                if timeout 10s "./$fuzzer" -max_total_time=5 "$seed_dir" > /dev/null 2>&1; then
                    echo -e "${GREEN}PASS${NC}"
                    ((passed++))
                else
                    echo -e "${RED}FAIL${NC}"
                    ((failed++))
                fi
            fi
        else
            log_warn "Fuzzer $fuzzer not found"
        fi
    done
    
    # Run Python API fuzzer
    if [ -f "$TESTS_DIR/fuzz/fuzz_explorer_api.py" ]; then
        echo -n "  Smoke testing explorer API fuzzer... "
        if python3 "$TESTS_DIR/fuzz/fuzz_explorer_api.py" > /dev/null 2>&1; then
            echo -e "${GREEN}PASS${NC}"
            ((passed++))
        else
            echo -e "${YELLOW}SKIP${NC} (dependencies missing)"
        fi
    fi
    
    cd "$PROJECT_DIR"
    
    echo ""
    log_info "Fuzz smoke tests: $passed passed, $failed failed"
    
    return $failed
}

# Main
main() {
    echo "======================================"
    echo "       DSV Test Runner"
    echo "======================================"
    echo ""
    
    # Build
    build_project
    
    local total_failed=0
    
    # Run tests
    if [ $RUN_UNIT -eq 1 ]; then
        run_unit_tests || ((total_failed+=$?))
    fi
    
    if [ $RUN_INTEGRATION -eq 1 ]; then
        run_integration_tests || ((total_failed+=$?))
    fi
    
    if [ $RUN_FUZZ -eq 1 ]; then
        run_fuzz_smoke || ((total_failed+=$?))
    fi
    
    # Summary
    echo ""
    echo "======================================"
    if [ $total_failed -eq 0 ]; then
        echo -e "       ${GREEN}ALL TESTS PASSED${NC}"
    else
        echo -e "       ${RED}$total_failed TESTS FAILED${NC}"
    fi
    echo "======================================"
    
    return $total_failed
}

main

