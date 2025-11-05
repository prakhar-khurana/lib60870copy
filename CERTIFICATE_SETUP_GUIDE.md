# Certificate Setup Guide for lib60870

## Important: Certificate Usage in lib60870

### ⚠️ Key Information

**Your IEC 62351-5 demo applications DO NOT use certificates!**

The IEC 62351-5:2023 implementation uses:
- ✅ **ECDH** for key exchange (ephemeral, no certificates needed)
- ✅ **HKDF** for key derivation
- ✅ **AES-256-GCM** for encryption
- ✅ **HMAC-SHA256** for authentication

**Certificates are ONLY needed for:**
- TLS/SSL examples (`tls_server`, `tls_client`)
- X.509 certificate-based authentication (optional feature)

---

## When Do You Need Certificates?

### ✅ You DON'T Need Certificates For:

1. **IEC 62351-5 Demo Applications**
   - `iec62351_5_demo_server.exe`
   - `iec62351_5_demo_client.exe`
   - These use ECDH key exchange (no certificates)

2. **Standard CS104 Examples**
   - `cs104_server.exe`
   - `cs104_client.exe`
   - These use plain TCP (no encryption)

### ❌ You ONLY Need Certificates For:

1. **TLS Examples**
   - `tls_server.exe` - Requires server certificate
   - `tls_client.exe` - Requires client certificate

2. **Custom TLS/X.509 Implementation**
   - If you explicitly enable TLS in your code
   - If you use `CS104_Slave_createSecure()` or `CS104_Connection_createSecure()`

---

## Certificate Generation (For TLS Examples Only)

### Windows (PowerShell)

```powershell
cd c:\Users\z005653n\Desktop\lib60870

# Run the certificate generation script
.\generate_certs.ps1
```

This creates certificates in: `c:\Users\z005653n\Desktop\lib60870\certs\`

### Ubuntu (Bash)

```bash
cd ~/Desktop/lib60870

# Make script executable
chmod +x generate_certs.sh

# Run the certificate generation script
./generate_certs.sh
```

This creates certificates in: `~/Desktop/lib60870/certs/`

---

## Certificate Directory Structure

After running the generation script:

```
lib60870/
├── certs/                    ← Certificates stored here
│   ├── ca.crt               ← Certificate Authority
│   ├── ca.key               ← CA private key
│   ├── server.crt           ← Server certificate
│   ├── server.key           ← Server private key
│   ├── client.crt           ← Client certificate
│   └── client.key           ← Client private key
│
└── lib60870-C/
    └── build/
        └── examples/
            ├── Release/      ← Windows executables
            │   ├── tls_server.exe
            │   └── tls_client.exe
            └── (Linux)       ← Ubuntu executables
                ├── tls_server
                └── tls_client
```

---

## Where Executables Look for Certificates

### Current Behavior (Default)

The TLS examples look for certificates in the **current working directory**:

```c
// From tls_server.c line 218-220
TLSConfiguration_setOwnKeyFromFile(tlsConfig, "server_CA1_1.key", NULL);
TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "server_CA1_1.pem");
TLSConfiguration_addCACertificateFromFile(tlsConfig, "root_CA1.pem");
```

**Problem:** These filenames don't match what our script generates!

### Solution: Update Certificate Paths

You have **3 options**:

#### Option 1: Copy Certificates to Build Directory (Quick Fix)

**Windows:**
```powershell
# Copy certificates to where executables run
Copy-Item certs\*.crt lib60870-C\build\examples\Release\
Copy-Item certs\*.key lib60870-C\build\examples\Release\
```

**Ubuntu:**
```bash
# Copy certificates to where executables run
cp certs/*.crt lib60870-C/build/examples/
cp certs/*.key lib60870-C/build/examples/
```

#### Option 2: Run Executables from Certificate Directory

**Windows:**
```powershell
cd certs
..\lib60870-C\build\examples\Release\tls_server.exe
```

**Ubuntu:**
```bash
cd certs
../lib60870-C/build/examples/tls_server
```

#### Option 3: Update Code to Use Correct Paths (Recommended)

Update the TLS examples to use our certificate names:

**File:** `lib60870-C/examples/tls_server/tls_server.c` (lines 218-222)

Change from:
```c
TLSConfiguration_setOwnKeyFromFile(tlsConfig, "server_CA1_1.key", NULL);
TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "server_CA1_1.pem");
TLSConfiguration_addCACertificateFromFile(tlsConfig, "root_CA1.pem");
TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "client_CA1_1.pem");
```

To:
```c
TLSConfiguration_setOwnKeyFromFile(tlsConfig, "../../../certs/server.key", NULL);
TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "../../../certs/server.crt");
TLSConfiguration_addCACertificateFromFile(tlsConfig, "../../../certs/ca.crt");
TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "../../../certs/client.crt");
```

**File:** `lib60870-C/examples/tls_client/tls_client.c` (lines 159-163)

Change from:
```c
TLSConfiguration_setOwnKeyFromFile(tlsConfig, "client_CA1_1.key", NULL);
TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "client_CA1_1.pem");
TLSConfiguration_addCACertificateFromFile(tlsConfig, "root_CA1.pem");
TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "server_CA1_1.pem");
```

To:
```c
TLSConfiguration_setOwnKeyFromFile(tlsConfig, "../../../certs/client.key", NULL);
TLSConfiguration_setOwnCertificateFromFile(tlsConfig, "../../../certs/client.crt");
TLSConfiguration_addCACertificateFromFile(tlsConfig, "../../../certs/ca.crt");
TLSConfiguration_addAllowedCertificateFromFile(tlsConfig, "../../../certs/server.crt");
```

Then rebuild:
```powershell
# Windows
cd lib60870-C\build
cmake --build . --config Release

# Ubuntu
cd lib60870-C/build
make -j$(nproc)
```

---

## Testing TLS Examples (With Certificates)

### Step 1: Generate Certificates

**Windows:**
```powershell
cd c:\Users\z005653n\Desktop\lib60870
.\generate_certs.ps1
```

**Ubuntu:**
```bash
cd ~/Desktop/lib60870
chmod +x generate_certs.sh
./generate_certs.sh
```

### Step 2: Copy Certificates (Using Option 1)

**Windows:**
```powershell
Copy-Item certs\ca.crt lib60870-C\build\examples\Release\root_CA1.pem
Copy-Item certs\server.crt lib60870-C\build\examples\Release\server_CA1_1.pem
Copy-Item certs\server.key lib60870-C\build\examples\Release\server_CA1_1.key
Copy-Item certs\client.crt lib60870-C\build\examples\Release\client_CA1_1.pem
Copy-Item certs\client.key lib60870-C\build\examples\Release\client_CA1_1.key
```

**Ubuntu:**
```bash
cp certs/ca.crt lib60870-C/build/examples/root_CA1.pem
cp certs/server.crt lib60870-C/build/examples/server_CA1_1.pem
cp certs/server.key lib60870-C/build/examples/server_CA1_1.key
cp certs/client.crt lib60870-C/build/examples/client_CA1_1.pem
cp certs/client.key lib60870-C/build/examples/client_CA1_1.key
```

### Step 3: Run TLS Server

**Windows:**
```powershell
cd lib60870-C\build\examples\Release
.\tls_server.exe
```

**Ubuntu:**
```bash
cd lib60870-C/build/examples
./tls_server
```

### Step 4: Run TLS Client (New Terminal)

**Windows:**
```powershell
cd lib60870-C\build\examples\Release
.\tls_client.exe
```

**Ubuntu:**
```bash
cd lib60870-C/build/examples
./tls_client
```

---

## Testing IEC 62351-5 Demo (NO Certificates Needed!)

### Just Run Directly:

**Terminal 1 - Server:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\iec62351_5_demo_server.exe

# Ubuntu
./lib60870-C/build/examples/iec62351_5_demo_server
```

**Terminal 2 - Client:**
```powershell
# Windows
.\lib60870-C\build\examples\Release\iec62351_5_demo_client.exe

# Ubuntu
./lib60870-C/build/examples/iec62351_5_demo_client
```

**No certificates required!** The IEC 62351-5 implementation uses ECDH key exchange.

---

## Verify Certificates

### Check Certificate Details

**Windows:**
```powershell
# View CA certificate
openssl x509 -in certs\ca.crt -text -noout

# View server certificate
openssl x509 -in certs\server.crt -text -noout

# Verify server cert signed by CA
openssl verify -CAfile certs\ca.crt certs\server.crt
```

**Ubuntu:**
```bash
# View CA certificate
openssl x509 -in certs/ca.crt -text -noout

# View server certificate
openssl x509 -in certs/server.crt -text -noout

# Verify server cert signed by CA
openssl verify -CAfile certs/ca.crt certs/server.crt
```

Expected output:
```
certs/server.crt: OK
```

---

## Summary

### For IEC 62351-5 Demo (Your Main Use Case):

✅ **NO certificates needed**
✅ **NO certificate generation required**
✅ **Just run the executables directly**

```powershell
# Windows - Just run these!
.\lib60870-C\build\examples\Release\iec62351_5_demo_server.exe
.\lib60870-C\build\examples\Release\iec62351_5_demo_client.exe
```

### For TLS Examples (Optional):

❌ **Certificates ARE needed**
❌ **Must generate certificates first**
❌ **Must copy to correct directory**

```powershell
# Windows - Generate certs first
.\generate_certs.ps1

# Copy to build directory
Copy-Item certs\*.crt lib60870-C\build\examples\Release\
Copy-Item certs\*.key lib60870-C\build\examples\Release\

# Then run
.\lib60870-C\build\examples\Release\tls_server.exe
.\lib60870-C\build\examples\Release\tls_client.exe
```

---

## Quick Reference

| Application | Certificates Needed? | Certificate Location |
|-------------|---------------------|---------------------|
| `iec62351_5_demo_server` | ❌ NO | N/A |
| `iec62351_5_demo_client` | ❌ NO | N/A |
| `cs104_server` | ❌ NO | N/A |
| `cs104_client` | ❌ NO | N/A |
| `tls_server` | ✅ YES | Current working directory |
| `tls_client` | ✅ YES | Current working directory |

**Bottom Line:** Your IEC 62351-5 implementation is ready to run without any certificate setup!
