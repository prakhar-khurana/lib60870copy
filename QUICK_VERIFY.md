# Quick Verification - 3 Simple Steps

## Step 1: Build (2-3 minutes)
```powershell
cd c:\Users\z005653n\Desktop\lib60870
.\COMPILE_AND_TEST.ps1
```

## Step 2: Run Server (Terminal 1)
```powershell
.\lib60870-C\build\examples\Release\iec62351_5_demo_server.exe
```

## Step 3: Run Client (Terminal 2)
```powershell
.\lib60870-C\build\examples\Release\iec62351_5_demo_client.exe
```

---

## What to Look For

### ✅ Success Indicators

1. **All 8 steps appear** (numbered 1/8 through 8/8)
2. **Success banner:**
   ```
   ╔════════════════════════════════════════════════════════════╗
   ║   HANDSHAKE COMPLETE - SESSION ESTABLISHED                ║
   ╚════════════════════════════════════════════════════════════╝
   ```
3. **Success message:**
   ```
   [SECURITY] The connection establishment works perfectly
   [SECURITY] Now test the ASDUs and APDUs being sent
   ```
4. **ASDU exchange begins**

### 📊 Key Logs to Verify

**TCP Connection:**
- `[CLIENT] Sending TCP SYN to server`
- `[SERVER] Received TCP SYN from client`
- `[SERVER] Sending TCP SYN-ACK`

**Cryptographic Operations:**
- `[CRYPTO] Deriving Update Keys using HKDF-SHA256`
- `[CRYPTO] Wrapping Session Keys with AES-256-KW`
- `[CRYPTO] Unwrapping Session Keys using AES-256-KW`
- `[CRYPTO] Setting DSQ (Data Sequence Number) = 1`

**Data Exchange:**
- `[ASDU] Received type: 11`
- `SERVER: Sent measurement value: X`

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Executables not found | Run `.\COMPILE_AND_TEST.ps1` first |
| Connection refused | Start server first, wait 2 seconds |
| Port 2404 in use | Kill existing process: `Stop-Process -Name iec62351_5_demo_server` |
| No handshake logs | Rebuild: `.\COMPILE_AND_TEST.ps1` |

---

## Complete Flow (Expected Output)

```
SERVER                              CLIENT
======                              ======
Waiting on port 2404...             
                                    Connecting to 127.0.0.1:2404
                                    Sending TCP SYN
Received TCP SYN                    
Sending TCP SYN-ACK                 Received TCP SYN-ACK
                                    Sending TCP ACK
Connection opened                   Connection opened

                                    [STEP 1/8] Sending Association Request
[STEP 1/8] Received Assoc Request   
Deriving Update Keys                
[STEP 2/8] Sending Assoc Response   
                                    [STEP 2/8] Received Assoc Response
                                    Deriving Update Keys

                                    [STEP 3/8] Sending Update Key Request
[STEP 3/8] Received Update Key Req  
MAC verification: SUCCESS           
[STEP 4/8] Sending Update Key Resp  
                                    [STEP 4/8] Received Update Key Response
                                    MAC verification: SUCCESS

                                    [STEP 5/8] Sending Session Request
[STEP 5/8] Received Session Request 
[STEP 6/8] Sending Session Response 
                                    [STEP 6/8] Received Session Response
                                    MAC verification: SUCCESS

                                    [STEP 7/8] Sending Session Key Request
                                    Wrapping Session Keys with AES-256-KW
[STEP 7/8] Received Session Key Req 
Unwrapping Session Keys             
MAC verification: SUCCESS           
Setting DSQ = 1                     
[STEP 8/8] Sending Session Key Resp 
                                    [STEP 8/8] Received Session Key Response
                                    MAC verification: SUCCESS
                                    Setting DSQ = 1

╔═══════════════════════════════╗   ╔═══════════════════════════════╗
║ HANDSHAKE COMPLETE            ║   ║ HANDSHAKE COMPLETE            ║
╚═══════════════════════════════╝   ╚═══════════════════════════════╝

                                    [SECURITY] Connection works perfectly
                                    [SECURITY] Now test ASDUs/APDUs

Sent measurement: 0                 Received ASDU type 11, value 0
Sent measurement: 1                 Received ASDU type 11, value 1
...                                 ...
```

---

**Total Time:** ~8 seconds from start to secure data exchange

**Status:** ✅ Ready for submission verification
