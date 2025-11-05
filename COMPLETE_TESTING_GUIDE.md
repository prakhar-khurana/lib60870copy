# Complete lib60870 Testing Guide

## Overview
This guide covers testing the **entire lib60870 package** including:
- IEC 62351-5:2023 compliance tests
- CS101 (serial) protocol tests
- CS104 (TCP/IP) protocol tests
- Integration tests
- Performance tests

---

## Quick Start

### Windows
```powershell
# Build everything with tests
.\COMPILE_AND_TEST.ps1

# Run complete test suite
.\RUN_ALL_TESTS.ps1
```

### Ubuntu
```bash
# Build everything with tests
./compile_ubuntu.sh

# Run complete test suite
chmod +x run_all_tests_ubuntu.sh
./run_all_tests_ubuntu.sh
```

---

## Phase 1: Build with Tests Enabled

### Windows (PowerShell)

```powershell
cd c:\Users\z005653n\Desktop\lib60870\lib60870-C

# Clean build
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
mkdir build
cd build

# Configure with ALL options
cmake -G "Visual Studio 17 2022" -A x64 `
    -DBUILD_TESTS=ON `
    -DBUILD_EXAMPLES=ON `
    -DCONFIG_CS104_APROFILE=1 `
    ..

# Build everything
cmake --build . --config Release --parallel

# List all built executables
Get-ChildItem -Recurse -Filter "*.exe" | Select-Object Name, Directory
```

### Ubuntu (Bash)

```bash
cd ~/Desktop/lib60870/lib60870-C

# Clean build
rm -rf build
mkdir build
cd build

# Configure with ALL options
cmake -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=ON \
    -DBUILD_EXAMPLES=ON \
    -DCONFIG_CS104_APROFILE=1 \
    ..

# Build everything
make -j$(nproc)

# List all built executables
find . -type f -executable | grep -E "(test|example)" | sort
```

---

## Phase 2: Run Individual Test Suites

### 1. IEC 62351-5:2023 Compliance Tests

**Windows:**
```powershell
cd lib60870-C\build
.\tests\Release\test_iec62351_5_compliance.exe
```

**Ubuntu:**
```bash
cd lib60870-C/build
./tests/test_iec62351_5_compliance
```

**Expected Output:**
```
╔════════════════════════════════════════════════════════════╗
║   IEC 62351-5:2023 COMPLIANCE TEST SUITE                  ║
╚════════════════════════════════════════════════════════════╝

=== Test: ASDU Type Definitions ===
✓ All ASDU types correctly defined

=== Test: DSQ Initialization ===
✓ DSQ correctly initialized to 1

=== Test: Two-Level Key Hierarchy ===
✓ Two-level key hierarchy structure verified

=== Test: State Machine ===
✓ State machine initialized to IDLE

=== Test: Separate Direction Keys ===
✓ Control and Monitoring keys are separate

╔════════════════════════════════════════════════════════════╗
║   COMPLIANCE TEST RESULTS                                 ║
╚════════════════════════════════════════════════════════════╝

5 Tests 0 Failures 0 Ignored
OK
```

### 2. CS104 Protocol Tests

Run all CS104 examples to verify protocol functionality:

**Windows:**
```powershell
# Test CS104 Server
Start-Process .\examples\Release\cs104_server.exe
Start-Sleep 2

# Test CS104 Client (in new terminal)
.\examples\Release\cs104_client.exe

# Test CS104 Async Client
.\examples\Release\cs104_client_async.exe
```

**Ubuntu:**
```bash
# Test CS104 Server
./examples/cs104_server &
SERVER_PID=$!
sleep 2

# Test CS104 Client
./examples/cs104_client

# Cleanup
kill $SERVER_PID
```

### 3. CS101 Serial Protocol Tests

**Windows:**
```powershell
# Test CS101 Master (balanced mode)
.\examples\Release\cs101_master_balanced.exe

# Test CS101 Master (unbalanced mode)
.\examples\Release\cs101_master_unbalanced.exe

# Test CS101 Slave
.\examples\Release\cs101_slave.exe
```

**Ubuntu:**
```bash
# Test CS101 Master (balanced mode)
./examples/cs101_master_balanced

# Test CS101 Master (unbalanced mode)
./examples/cs101_master_unbalanced

# Test CS101 Slave
./examples/cs101_slave
```

---

## Phase 3: Integration Tests

### Test 1: Basic CS104 Client-Server

**Terminal 1 - Server:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\cs104_server.exe

# Ubuntu
./lib60870-C/build/examples/cs104_server
```

**Terminal 2 - Client:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\cs104_client.exe

# Ubuntu
./lib60870-C/build/examples/cs104_client
```

**Verify:**
- ✓ Client connects successfully
- ✓ STARTDT/STARTDT_CON exchange
- ✓ Interrogation command sent
- ✓ Data points received
- ✓ STOPDT/STOPDT_CON exchange

### Test 2: IEC 62351-5 Secure Communication

**Terminal 1 - Secure Server:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\iec62351_5_demo_server.exe

# Ubuntu
./lib60870-C/build/examples/iec62351_5_demo_server
```

**Terminal 2 - Secure Client:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\iec62351_5_demo_client.exe

# Ubuntu
./lib60870-C/build/examples/iec62351_5_demo_client
```

**Verify:**
- ✓ TCP connection established
- ✓ 8-message security handshake completed
- ✓ Encrypted data exchange
- ✓ Periodic measurements received
- ✓ Clean shutdown

### Test 3: Multi-Client Server

**Terminal 1 - Multi-Client Server:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\multi_client_server.exe

# Ubuntu
./lib60870-C/build/examples/multi_client_server
```

**Terminal 2-4 - Multiple Clients:**
```powershell
# Windows (run 3 times in different terminals)
.\lib60870-C\build\examples\Release\cs104_client.exe

# Ubuntu
for i in {1..3}; do
    ./lib60870-C/build/examples/cs104_client &
done
```

**Verify:**
- ✓ All 3 clients connect
- ✓ Each client receives data independently
- ✓ Server handles concurrent connections

### Test 4: Redundancy Server

**Terminal 1 - Redundancy Server:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\cs104_redundancy_server.exe

# Ubuntu
./lib60870-C/build/examples/cs104_redundancy_server
```

**Terminal 2 - Primary Client:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\cs104_client.exe

# Ubuntu
./lib60870-C/build/examples/cs104_client
```

**Terminal 3 - Backup Client:**
```powershell
# Windows (connect to same server)
.\lib60870-C\build\examples\Release\cs104_client.exe

# Ubuntu
./lib60870-C/build/examples/cs104_client
```

**Verify:**
- ✓ Primary client receives data
- ✓ Backup client on standby
- ✓ Failover works when primary disconnects

---

## Phase 4: Performance Tests

### Test 1: Throughput Test

```powershell
# Windows
$server = Start-Process .\lib60870-C\build\examples\Release\cs104_server.exe -PassThru
Start-Sleep 2

# Run client and measure
Measure-Command {
    .\lib60870-C\build\examples\Release\cs104_client.exe
}

Stop-Process $server.Id
```

```bash
# Ubuntu
./lib60870-C/build/examples/cs104_server &
SERVER_PID=$!
sleep 2

# Run client and measure
time ./lib60870-C/build/examples/cs104_client

kill $SERVER_PID
```

### Test 2: Connection Stress Test

```powershell
# Windows - Connect/disconnect 100 times
$server = Start-Process .\lib60870-C\build\examples\Release\cs104_server.exe -PassThru

for ($i=1; $i -le 100; $i++) {
    Write-Host "Connection $i/100"
    .\lib60870-C\build\examples\Release\cs104_client.exe
}

Stop-Process $server.Id
```

```bash
# Ubuntu - Connect/disconnect 100 times
./lib60870-C/build/examples/cs104_server &
SERVER_PID=$!

for i in {1..100}; do
    echo "Connection $i/100"
    timeout 5 ./lib60870-C/build/examples/cs104_client
done

kill $SERVER_PID
```

### Test 3: Memory Leak Test

```bash
# Ubuntu with Valgrind
sudo apt install valgrind

# Run server under valgrind
valgrind --leak-check=full --show-leak-kinds=all \
    ./lib60870-C/build/examples/cs104_server &
VALGRIND_PID=$!

# Connect client multiple times
for i in {1..10}; do
    ./lib60870-C/build/examples/cs104_client
    sleep 1
done

# Stop and check results
kill $VALGRIND_PID
```

---

## Phase 5: Network Analysis

### Wireshark Capture

**Windows:**
```powershell
# Start Wireshark
wireshark

# Filter: tcp.port == 2404
# Start server and client, observe traffic
```

**Ubuntu:**
```bash
# Capture to file
sudo tcpdump -i lo -n port 2404 -w iec104_capture.pcap

# Start server and client in other terminals

# Stop capture (Ctrl+C)
# Analyze with Wireshark
wireshark iec104_capture.pcap
```

**What to Look For:**
- TCP 3-way handshake
- STARTDT (0x68 0x04 0x07 0x00 0x00 0x00)
- STARTDT_CON (0x68 0x04 0x0B 0x00 0x00 0x00)
- I-frames with ASDU data
- S-frames (acknowledgments)
- U-frames (TESTFR, STOPDT)

### Protocol Verification

```bash
# Ubuntu - Decode IEC 104 packets
tshark -r iec104_capture.pcap -Y "tcp.port==2404" -V
```

---

## Phase 6: Automated Test Suite

### Run Complete Test Suite

**Windows:**
```powershell
.\RUN_ALL_TESTS.ps1
```

**Ubuntu:**
```bash
chmod +x run_all_tests_ubuntu.sh
./run_all_tests_ubuntu.sh
```

**Expected Summary:**
```
╔════════════════════════════════════════════════════════════╗
║   TEST SUMMARY                                             ║
╚════════════════════════════════════════════════════════════╝

Total Tests: 8
Passed:      8
Failed:      0
Skipped:     0

✓✓✓ ALL TESTS PASSED ✓✓✓
```

---

## Test Checklist

### ✅ Compliance Tests
- [ ] IEC 62351-5:2023 ASDU types defined
- [ ] DSQ initialized to 1
- [ ] Two-level key hierarchy
- [ ] State machine implemented
- [ ] Separate direction keys
- [ ] 8-message handshake (if integration test enabled)

### ✅ Protocol Tests
- [ ] CS104 server starts and listens
- [ ] CS104 client connects
- [ ] STARTDT/STOPDT exchange
- [ ] Interrogation command works
- [ ] Data points transmitted
- [ ] CS101 serial communication

### ✅ Security Tests
- [ ] IEC 62351-5 server starts
- [ ] IEC 62351-5 client connects
- [ ] Encrypted data exchange
- [ ] Key derivation (HKDF)
- [ ] Key wrapping (AES-256-KW)
- [ ] MAC authentication (HMAC-SHA256)

### ✅ Integration Tests
- [ ] Client-server communication
- [ ] Multi-client support
- [ ] Redundancy failover
- [ ] File transfer
- [ ] TLS/SSL (if enabled)

### ✅ Performance Tests
- [ ] Throughput acceptable (>1000 msgs/sec)
- [ ] Latency acceptable (<10ms)
- [ ] No memory leaks
- [ ] Stable under load

---

## Troubleshooting

### Tests Fail to Build

```powershell
# Ensure tests are enabled
cmake -DBUILD_TESTS=ON ..

# Check for Unity test framework
ls lib60870-C/tests/unity/
```

### Tests Timeout

```powershell
# Increase timeout in test runner
# Edit RUN_ALL_TESTS.ps1, change timeout values
```

### Integration Tests Fail

```bash
# Check if port 2404 is available
netstat -an | grep 2404  # Linux
netstat -an | findstr 2404  # Windows

# Kill existing processes
sudo fuser -k 2404/tcp  # Linux
```

### Network Tests Fail

```bash
# Check firewall
sudo ufw allow 2404/tcp  # Ubuntu
netsh advfirewall firewall add rule name="IEC104" dir=in action=allow protocol=TCP localport=2404  # Windows
```

---

## Continuous Integration

### GitHub Actions Example

```yaml
name: lib60870 Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: sudo apt install -y cmake build-essential libmbedtls-dev
      - name: Build
        run: |
          cd lib60870-C
          mkdir build && cd build
          cmake -DBUILD_TESTS=ON ..
          make -j$(nproc)
      - name: Run tests
        run: ./run_all_tests_ubuntu.sh
```

---

## Summary

**Complete Test Coverage:**
- ✅ Unit tests (compliance)
- ✅ Integration tests (client-server)
- ✅ Performance tests (throughput, stress)
- ✅ Security tests (IEC 62351-5)
- ✅ Protocol tests (CS101, CS104)

**Quick Test Command:**
```powershell
# Windows
.\RUN_ALL_TESTS.ps1

# Ubuntu
./run_all_tests_ubuntu.sh
```

This ensures the **entire lib60870 package** is thoroughly tested and production-ready.
