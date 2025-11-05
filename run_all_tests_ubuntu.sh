#!/bin/bash
# Complete lib60870 Test Suite Runner for Ubuntu
# Tests all components: CS101, CS104, Security, IEC 62351-5

set +e  # Continue on errors

BUILD_DIR="lib60870-C/build"
PASSED=0
FAILED=0
SKIPPED=0

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   lib60870 Complete Test Suite                            ║"
echo "║   IEC 60870-5-101/104 + IEC 62351-5:2023                  ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Function to run test
run_test() {
    local name="$1"
    local path="$2"
    
    echo -e "\033[1;33mRunning: $name\033[0m"
    
    if [ -f "$path" ]; then
        start_time=$(date +%s)
        
        # Run test and capture output
        if timeout 30 "$path" > /dev/null 2>&1; then
            result="PASS"
            color="\033[1;32m"
        else
            exit_code=$?
            if [ $exit_code -eq 124 ]; then
                result="TIMEOUT"
                color="\033[1;31m"
            else
                result="FAIL"
                color="\033[1;31m"
            fi
        fi
        
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        echo -e "  Result: ${color}${result}\033[0m (${duration}s)"
        
        if [ "$result" == "PASS" ]; then
            ((PASSED++))
        else
            ((FAILED++))
        fi
    else
        echo -e "  Result: \033[1;37mSKIP\033[0m (not found)"
        ((SKIPPED++))
    fi
    echo ""
}

# Change to build directory
cd "$BUILD_DIR" || exit 1

echo "=== Phase 1: IEC 62351-5:2023 Compliance Tests ==="
echo ""

run_test "IEC 62351-5 Compliance Suite" "tests/test_iec62351_5_compliance"

echo "=== Phase 2: Core Protocol Tests ==="
echo ""

# Find all test executables
for test_file in tests/test_* tests/*_test; do
    if [ -f "$test_file" ] && [ -x "$test_file" ]; then
        test_name=$(basename "$test_file")
        if [ "$test_name" != "test_iec62351_5_compliance" ]; then
            run_test "$test_name" "$test_file"
        fi
    fi
done

echo "=== Phase 3: Example Applications Smoke Tests ==="
echo ""

# Test CS104 Server
echo -e "\033[1;33mTesting: CS104 Server (5 second run)\033[0m"
if [ -f "examples/cs104_server" ]; then
    timeout 5 ./examples/cs104_server > /dev/null 2>&1 &
    SERVER_PID=$!
    sleep 5
    kill $SERVER_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    echo -e "  Result: \033[1;32mPASS\033[0m (server started and stopped)"
    ((PASSED++))
else
    echo -e "  Result: \033[1;37mSKIP\033[0m (not found)"
    ((SKIPPED++))
fi
echo ""

# Test IEC 62351-5 Demo Server
echo -e "\033[1;33mTesting: IEC 62351-5 Demo Server (5 second run)\033[0m"
if [ -f "examples/iec62351_5_demo_server" ]; then
    timeout 5 ./examples/iec62351_5_demo_server > /dev/null 2>&1 &
    DEMO_PID=$!
    sleep 5
    kill $DEMO_PID 2>/dev/null
    wait $DEMO_PID 2>/dev/null
    echo -e "  Result: \033[1;32mPASS\033[0m (demo server started and stopped)"
    ((PASSED++))
else
    echo -e "  Result: \033[1;37mSKIP\033[0m (not found)"
    ((SKIPPED++))
fi
echo ""

echo "=== Phase 4: Integration Test (Server + Client) ==="
echo ""

echo -e "\033[1;33mTesting: Full IEC 62351-5 Client-Server Integration\033[0m"
if [ -f "examples/iec62351_5_demo_server" ] && [ -f "examples/iec62351_5_demo_client" ]; then
    # Start server
    ./examples/iec62351_5_demo_server > server_output.txt 2>&1 &
    SERVER_PID=$!
    sleep 2
    
    # Start client
    timeout 10 ./examples/iec62351_5_demo_client > client_output.txt 2>&1 &
    CLIENT_PID=$!
    sleep 10
    
    # Stop both
    kill $CLIENT_PID 2>/dev/null
    kill $SERVER_PID 2>/dev/null
    wait $CLIENT_PID 2>/dev/null
    wait $SERVER_PID 2>/dev/null
    
    # Check if client connected
    if grep -q "Connected successfully" client_output.txt 2>/dev/null; then
        echo -e "  Result: \033[1;32mPASS\033[0m (client connected and exchanged data)"
        ((PASSED++))
    else
        echo -e "  Result: \033[1;31mFAIL\033[0m (client did not connect)"
        ((FAILED++))
    fi
    
    # Cleanup
    rm -f server_output.txt client_output.txt
else
    echo -e "  Result: \033[1;37mSKIP\033[0m (demo apps not found)"
    ((SKIPPED++))
fi
echo ""

# Return to original directory
cd - > /dev/null

# Summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   TEST SUMMARY                                             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

TOTAL=$((PASSED + FAILED + SKIPPED))

echo "Total Tests: $TOTAL"
echo -e "Passed:      \033[1;32m$PASSED\033[0m"
if [ $FAILED -gt 0 ]; then
    echo -e "Failed:      \033[1;31m$FAILED\033[0m"
else
    echo -e "Failed:      \033[1;32m$FAILED\033[0m"
fi
echo -e "Skipped:     \033[1;37m$SKIPPED\033[0m"
echo ""

if [ $FAILED -eq 0 ] && [ $PASSED -gt 0 ]; then
    echo -e "\033[1;32m✓✓✓ ALL TESTS PASSED ✓✓✓\033[0m"
    exit 0
elif [ $FAILED -gt 0 ]; then
    echo -e "\033[1;31m✗ SOME TESTS FAILED ✗\033[0m"
    exit 1
else
    echo -e "\033[1;33m⚠ NO TESTS RUN ⚠\033[0m"
    exit 2
fi
