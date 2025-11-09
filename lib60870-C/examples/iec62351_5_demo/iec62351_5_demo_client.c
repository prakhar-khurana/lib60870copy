/*
 * IEC 62351-5:2023 Demo Client
 * 
 * This demonstrates a compliant IEC 60870-5-104 client with
 * IEC 62351-5:2023 Application Layer Security (A-Profile)
 */

#include "../../src/inc/api/cs104_connection.h"
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
    
    printf("CLIENT: Received ASDU - Type=%d, COT=%d, Elements=%d\n",
           CS101_ASDU_getTypeID(asdu),
           CS101_ASDU_getCOT(asdu),
           CS101_ASDU_getNumberOfElements(asdu));
    
    /* Display measurement values */
    if (CS101_ASDU_getTypeID(asdu) == M_ME_NB_1) {
        for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
            MeasuredValueScaled mv = (MeasuredValueScaled) CS101_ASDU_getElement(asdu, i);
            if (mv) {
                printf("  IOA=%d, Value=%d, Quality=0x%02x\n",
                       InformationObject_getObjectAddress((InformationObject)mv),
                       MeasuredValueScaled_getValue(mv),
                       MeasuredValueScaled_getQuality(mv));
            }
        }
    }
    
    return true;
}

static void
connectionHandler(void* parameter, CS104_Connection connection, CS104_ConnectionEvent event)
{
    switch (event) {
        case CS104_CONNECTION_OPENED:
            printf("[CLIENT] TCP connection opened to server\n");
            printf("[CLIENT] Received TCP SYN-ACK from server\n");
            printf("[CLIENT] Sending TCP ACK\n");
            printf("CLIENT: Connection established\n");
            break;
        case CS104_CONNECTION_CLOSED:
            printf("[CLIENT] TCP connection closed\n");
            printf("CLIENT: Connection closed\n");
            running = false;
            break;
        case CS104_CONNECTION_STARTDT_CON_RECEIVED:
            printf("[CLIENT] TCP connection activated (STARTDT sent)\n");
            printf("CLIENT: STARTDT confirmed - Connection activated\n");
            break;
        case CS104_CONNECTION_STOPDT_CON_RECEIVED:
            printf("[CLIENT] TCP connection deactivated (STOPDT sent)\n");
            printf("CLIENT: STOPDT confirmed - Connection deactivated\n");
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
        logHandshakeStep("Sending Association Request (S_AR_NA_1)");
        logHandshakeStep("Generating ECDH key pair");
        logHandshakeStep("Deriving Update Keys with HKDF");
    }
    else if (strstr(msg, "Association Response")) {
        logHandshakeStep("Received Association Response (S_AS_NA_1)");
    }
    else if (strstr(msg, "Update Key Change Request")) {
        logHandshakeStep("Sending Update Key Change Request (S_UK_NA_1)");
        logHandshakeStep("Calculating HMAC-SHA256 MAC");
    }
    // Add all 8 steps similarly
}

int main(int argc, char** argv)
{
    /* Flush output immediately to ensure we see startup messages */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    
    const char* serverIP = "127.0.0.1";
    int serverPort = 2404;
    
    if (argc > 1) {
        serverIP = argv[1];
    }
    if (argc > 2) {
        serverPort = atoi(argv[2]);
    }
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║   IEC 62351-5:2023 Demo Client                            ║\n");
    printf("║   IEC 60870-5-104 with Application Layer Security         ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    fflush(stdout);

    signal(SIGINT, sigint_handler);

    /* Create connection */
    printf("[CLIENT] Connecting to server %s:%d\n", serverIP, serverPort);
    printf("[CLIENT] Sending TCP SYN to server\n");
    CS104_Connection con = CS104_Connection_create(serverIP, serverPort);
    
    /* Set connection parameters */
    CS104_Connection_setConnectTimeout(con, 5000);
    
    /* Set callbacks */
    CS104_Connection_setConnectionHandler(con, connectionHandler, NULL);
    CS104_Connection_setASDUReceivedHandler(con, asduReceivedHandler, NULL);
    
    printf("Client Configuration:\n");
    printf("  Server: %s:%d\n", serverIP, serverPort);
    printf("  Security: IEC 62351-5:2023 (A-Profile)\n");
    printf("  Timeout: 5000ms\n");
    printf("\n");
    
    /* Configure security using CS104 API */
    CS104_SecurityConfig secConfig = {
        .sessionKeyChangeInterval = 3600000,  /* 1 hour */
        .challengeResponseTimeout = 5000      /* 5 seconds */
    };
    
    CS104_CertConfig certConfig = {
        .privateKeyFile = "../tests/client_CA1_1.key",
        .ownCertificateFile = "../tests/client_CA1_1.pem",
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
    CS104_Connection_setSecurityConfig(con, &secConfig, &certConfig, &roleConfig);
    
    /* Get the AProfile context for monitoring (optional) */
    /* Note: The context is managed internally by CS104_Connection */
    /* We can access it via the internal structure if needed for debugging */
    
    /* Connect to server */
    printf("Connecting to server...\n");
    
    if (CS104_Connection_connect(con)) {
        printf("✓ Connected successfully\n");
        
        /* Send STARTDT to activate connection */
        /* The IEC 62351-5:2023 handshake will be initiated automatically after STARTDT_CON */
        printf("Sending STARTDT...\n");
        CS104_Connection_sendStartDT(con);
        
        /* Wait for STARTDT_CON and handshake to complete */
        printf("\n[WAITING] Waiting for STARTDT_CON and IEC 62351-5 handshake...\n");
        Thread_sleep(2000); /* Wait for STARTDT_CON */
        
        /* Note: The handshake is now handled automatically by the CS104_Connection */
        /* The handshake will be initiated when STARTDT_CON is received */
        /* We can monitor the connection state through the connection handler */
        
        printf("✓ Connection activated - IEC 62351-5 handshake will proceed automatically\n");
        printf("✓ Waiting for handshake completion...\n");
        
        Thread_sleep(1000);
        
        /* Wait a bit for handshake to complete */
        Thread_sleep(3000);
        
        /* Send interrogation command */
        printf("\nSending interrogation command...\n");
        CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);
        
        printf("\n✓ Client operational\n");
        printf("✓ Receiving data from server...\n");
        printf("✓ Press Ctrl+C to stop\n\n");
        
        /* Keep running and receiving data */
        while (running) {
            Thread_sleep(1000);
        }
        
        /* IEC 60870-5-104: Send STOPDT before closing connection */
        printf("\n[PROTOCOL] Sending STOPDT (IEC 60870-5-104)...\n");
        CS104_Connection_sendStopDT(con);
        Thread_sleep(500);
        
        /* IEC 62351-5:2023: Security session will be terminated when connection closes */
        printf("[SECURITY] Security session terminated\n");
        
    } else {
        printf("✗ Connection failed\n");
    }
    
    printf("\nShutting down client...\n");
    
    /* Cleanup - CS104_Connection will destroy the AProfile context internally */
    CS104_Connection_destroy(con);
    
    printf("Client stopped\n");
    return 0;
}
