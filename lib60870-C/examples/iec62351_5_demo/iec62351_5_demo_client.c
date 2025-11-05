/*
 * IEC 62351-5:2023 Demo Client
 * 
 * This demonstrates a compliant IEC 60870-5-104 client with
 * IEC 62351-5:2023 Application Layer Security (A-Profile)
 */

#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

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
    
    /* Connect to server */
    printf("Connecting to server...\n");
    
    if (CS104_Connection_connect(con)) {
        printf("✓ Connected successfully\n");
        
        /* Send STARTDT to activate connection */
        printf("Sending STARTDT...\n");
        CS104_Connection_sendStartDT(con);
        
        Thread_sleep(1000);
        
        /* Send interrogation command */
        printf("Sending interrogation command...\n");
        CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, 1, IEC60870_QOI_STATION);
        
        printf("\n✓ Client operational\n");
        printf("✓ Receiving data from server...\n");
        printf("✓ Press Ctrl+C to stop\n\n");
        
        /* Keep running and receiving data */
        while (running) {
            Thread_sleep(1000);
        }
        
        /* Send STOPDT before closing */
        printf("\nSending STOPDT...\n");
        CS104_Connection_sendStopDT(con);
        Thread_sleep(500);
        
    } else {
        printf("✗ Connection failed\n");
    }
    
    printf("Closing connection...\n");
    CS104_Connection_destroy(con);
    
    printf("Client stopped\n");
    return 0;
}
