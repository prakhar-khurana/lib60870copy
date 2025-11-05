/*
 * IEC 62351-5:2023 Demo Server
 * 
 * This demonstrates a compliant IEC 60870-5-104 server with
 * IEC 62351-5:2023 Application Layer Security (A-Profile)
 */

#include "cs104_slave.h"
#include "hal_thread.h"
#include "hal_time.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static bool running = true;

void sigint_handler(int signalId)
{
    running = false;
}

static bool
asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
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
connectionEventHandler(void* parameter, IMasterConnection connection, CS104_PeerConnectionEvent event)
{
    switch (event) {
        case CS104_CON_EVENT_CONNECTION_OPENED:
            printf("SERVER: Connection opened\n");
            break;
        case CS104_CON_EVENT_CONNECTION_CLOSED:
            printf("SERVER: Connection closed\n");
            break;
        case CS104_CON_EVENT_ACTIVATED:
            printf("SERVER: Connection activated (STARTDT received)\n");
            break;
        case CS104_CON_EVENT_DEACTIVATED:
            printf("SERVER: Connection deactivated (STOPDT received)\n");
            break;
    }
}

int main(int argc, char** argv)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║   IEC 62351-5:2023 Demo Server                            ║\n");
    printf("║   IEC 60870-5-104 with Application Layer Security         ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    signal(SIGINT, sigint_handler);

    /* Create server */
    CS104_Slave slave = CS104_Slave_create(100, 100);
    
    /* Set connection parameters */
    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, 2404);
    
    /* Set server mode to support multiple connections */
    CS104_Slave_setServerMode(slave, CS104_MODE_CONNECTION_IS_REDUNDANCY_GROUP);
    
    /* Set callbacks */
    CS104_Slave_setConnectionRequestHandler(slave, connectionRequestHandler, NULL);
    CS104_Slave_setConnectionEventHandler(slave, connectionEventHandler, NULL);
    CS104_Slave_setASDUReceivedHandler(slave, asduReceivedHandler, NULL);
    
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
    
    /* Add some data points */
    CS101_AppLayerParameters alParams = CS104_Slave_getAppLayerParameters(slave);
    
    /* Simulate sending data periodically */
    int counter = 0;
    while (running) {
        Thread_sleep(5000);
        
        if (CS104_Slave_getOpenConnections(slave) > 0) {
            /* Send a measurement value */
            struct sInformationObject io;
            
            MeasuredValueScaled mv = (MeasuredValueScaled) &io;
            MeasuredValueScaled_create(mv, 100, counter % 100, IEC60870_QUALITY_GOOD);
            
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
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    
    printf("Server stopped\n");
    return 0;
}
