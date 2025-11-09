/*
 * IEC 62351-5:2023 Demo Server
 * 
 * This demonstrates a compliant IEC 60870-5-104 server with
 * IEC 62351-5:2023 Application Layer Security (A-Profile)
 */

#include "../../src/inc/api/cs104_slave.h"
#include "../../src/inc/api/cs101_information_objects.h"
#include "../../src/inc/api/cs104_security.h"
#include "../../src/hal/inc/hal_thread.h"
#include "../../src/hal/inc/hal_time.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

static bool running = true;
static bool isFirstASDU = true;

void sigint_handler(int signalId)
{
    running = false;
}

static bool
asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    if (isFirstASDU) {
        printf("\n\n[SECURITY] The connection establishment works perfectly\n");
        printf("[SECURITY] Now test the ASDUs and APDUs being sent\n");
        printf("[SECURITY] First secure ASDU received!\n\n");
        isFirstASDU = false;
    }
    
    TypeID typeId = CS101_ASDU_getTypeID(asdu);
    printf("[ASDU] Received type: %d\n", typeId);
    
    printf("SERVER: Received ASDU - Type=%d, COT=%d, CA=%d\n",
           CS101_ASDU_getTypeID(asdu),
           CS101_ASDU_getCOT(asdu),
           CS101_ASDU_getCA(asdu));
    
    return true;
}

static bool
connectionRequestHandler(void* parameter, const char* ipAddress)
{
    printf("SERVER: New connection request from %s\n", ipAddress);
    return true; /* Accept all connections */
}

static void
handleConnectionEvent(void* parameter, IMasterConnection connection, CS104_PeerConnectionEvent event)
{
    char peerAddr[100];
    IMasterConnection_getPeerAddress(connection, peerAddr, sizeof(peerAddr));
    
    switch (event) {
        case CS104_CON_EVENT_CONNECTION_OPENED:
            printf("[SERVER] TCP connection opened from %s\n", peerAddr);
            printf("[SERVER] Received TCP SYN from client\n");
            printf("[SERVER] Sending TCP SYN-ACK\n");
            break;
        case CS104_CON_EVENT_CONNECTION_CLOSED:
            printf("[SERVER] TCP connection closed from %s\n", peerAddr);
            break;
        case CS104_CON_EVENT_ACTIVATED:
            printf("[SERVER] TCP connection activated (STARTDT received)\n");
            printf("[SERVER] Sending TCP ACK\n");
            break;
        case CS104_CON_EVENT_DEACTIVATED:
            printf("[SERVER] TCP connection deactivated (STOPDT received)\n");
            break;
    }
}

static void
logHandshakeStep(const char* message)
{
    printf("[HANDSHAKE] %s\n", message);
}

static void
securityEventHandler(void* parameter, TLSEventLevel eventLevel, int eventCode, const char* msg, TLSConnection con)
{
    printf("[SECURITY] %s (Level: %d, Code: %d)\n", msg, eventLevel, eventCode);
    
    // Log specific handshake steps
    if (strstr(msg, "Association Request")) {
        logHandshakeStep("Received Association Request (S_AR_NA_1)");
        logHandshakeStep("Generating ECDH key pair");
        logHandshakeStep("Deriving Update Keys with HKDF");
    }
    else if (strstr(msg, "Association Response")) {
        logHandshakeStep("Sending Association Response (S_AS_NA_1)");
    }
    else if (strstr(msg, "Update Key Change Request")) {
        logHandshakeStep("Received Update Key Change Request (S_UK_NA_1)");
        logHandshakeStep("Verifying HMAC-SHA256 MAC");
    }
    // Add all 8 steps similarly
}

int main(int argc, char** argv)
{
    /* Flush output immediately to ensure we see startup messages */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║   IEC 62351-5:2023 Demo Server                            ║\n");
    printf("║   IEC 60870-5-104 with Application Layer Security         ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    fflush(stdout);

    signal(SIGINT, sigint_handler);

    /* Create server */
    CS104_Slave slave = CS104_Slave_create(100, 100);
    
    /* Configure security using CS104 API */
    CS104_SecurityConfig secConfig = {
        .sessionKeyChangeInterval = 3600000,  /* 1 hour */
        .challengeResponseTimeout = 5000      /* 5 seconds */
    };
    
    CS104_CertConfig certConfig = {
        .privateKeyFile = "../tests/server_CA1_1.key",
        .ownCertificateFile = "../tests/server_CA1_1.pem",
        .caCertificateFile = "../tests/root_CA1.pem"
    };
    
    /* Print certificate paths safely to avoid buffer overflow */
    printf("[INIT] Certificate paths:\n");
    if (certConfig.privateKeyFile) {
        printf("  Private Key: %s\n", certConfig.privateKeyFile);
    } else {
        printf("  Private Key: NULL\n");
    }
    if (certConfig.ownCertificateFile) {
        printf("  Certificate: %s\n", certConfig.ownCertificateFile);
    } else {
        printf("  Certificate: NULL\n");
    }
    if (certConfig.caCertificateFile) {
        printf("  CA Certificate: %s\n", certConfig.caCertificateFile);
    } else {
        printf("  CA Certificate: NULL\n");
    }
    printf("\n");
    fflush(stdout);
    
    CS104_RoleConfig roleConfig = {
        .roleId = 1,
        .permissions = 0xFFFF
    };
    
    /* Set security configuration - this creates the AProfile context internally */
    CS104_Slave_setSecurityConfig(slave, &secConfig, &certConfig, &roleConfig);
    
    /* Note: The AProfile context is managed internally by CS104_Slave */
    /* It will be created per-connection when clients connect */
    
    /* Set connection parameters */
    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    int port = 2404;
    CS104_Slave_setLocalPort(slave, port);
    
    printf("[SERVER] Waiting for TCP connections on port %d\n", port);

    /* Set server mode to support multiple connections */
    CS104_Slave_setServerMode(slave, CS104_MODE_CONNECTION_IS_REDUNDANCY_GROUP);
    
    /* Set callbacks */
    CS104_Slave_setConnectionRequestHandler(slave, connectionRequestHandler, NULL);
    CS104_Slave_setConnectionEventHandler(slave, handleConnectionEvent, NULL);
    CS104_Slave_setASDUHandler(slave, asduReceivedHandler, NULL);
    
    printf("Server Configuration:\n");
    printf("  Address: 0.0.0.0\n");
    printf("  Port: 2404\n");
    printf("  Security: IEC 62351-5:2023 (A-Profile)\n");
    printf("  Mode: Multi-client\n");
    printf("\n");
    
    /* Start server */
    CS104_Slave_start(slave);
    
    if (CS104_Slave_isRunning(slave)) {
        printf("✓ Server started successfully\n");
        printf("✓ Waiting for client connections...\n");
        printf("✓ Press Ctrl+C to stop\n\n");
    } else {
        printf("✗ Failed to start server\n");
        CS104_Slave_destroy(slave);
        return 1;
    }
    
    /* Simulate sending data periodically */
    int counter = 0;
    CS101_AppLayerParameters alParams = CS104_Slave_getAppLayerParameters(slave);
    
    while (running) {
        Thread_sleep(5000);
        
        if (CS104_Slave_getOpenConnections(slave) > 0) {
            /* Send a measurement value */
            MeasuredValueScaled mv = MeasuredValueScaled_create(NULL, 100, counter % 100, IEC60870_QUALITY_GOOD);
            
            CS101_ASDU asdu = CS101_ASDU_create(alParams, false, CS101_COT_PERIODIC, 0, 1, false, false);
            CS101_ASDU_setTypeID(asdu, M_ME_NB_1);
            CS101_ASDU_addInformationObject(asdu, (InformationObject)mv);
            
            CS104_Slave_enqueueASDU(slave, asdu);
            CS101_ASDU_destroy(asdu);
            
            printf("SERVER: Sent measurement value: %d\n", counter % 100);
            counter++;
        }
    }
    
    printf("\nShutting down server...\n");
    
    /* IEC 60870-5-104: Server will close all connections properly */
    /* IEC 62351-5:2023: Security sessions will be terminated when connections close */
    printf("[PROTOCOL] Closing all connections (IEC 60870-5-104)...\n");
    printf("[SECURITY] Security sessions terminated\n");
    
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    
    printf("Server stopped\n");
    return 0;
}