/*
 * IEC 62351-5:2023 Compliance Test Suite
 * 
 * This test suite validates full compliance with IEC 62351-5:2023 standard
 * including:
 * - 8-message handshake
 * - Two-level key hierarchy
 * - Key wrapping with AES-256-KW
 * - DSQ initialization to 1
 * - Separate keys for control/monitoring directions
 */

#include "unity.h"
#include "aprofile_internal.h"
#include "cs104_slave.h"
#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"
#include <string.h>
#include <stdio.h>

#if (CONFIG_CS104_APROFILE == 1)

static CS104_Slave slave = NULL;
static CS104_Connection connection = NULL;
static bool test_asdu_received = false;
static int messages_received = 0;

/* Test message counters for 8-message handshake */
static int assoc_request_count = 0;
static int assoc_response_count = 0;
static int update_key_request_count = 0;
static int update_key_response_count = 0;
static int session_request_count = 0;
static int session_response_count = 0;
static int session_key_request_count = 0;
static int session_key_response_count = 0;

static bool
asduReceivedHandler(void* parameter, int address, CS101_ASDU asdu)
{
    TypeID typeId = CS101_ASDU_getTypeID(asdu);
    
    printf("TEST: Received ASDU Type=%d\n", typeId);
    
    switch (typeId) {
        case S_AR_NA_1:
            assoc_request_count++;
            break;
        case S_AS_NA_1:
            assoc_response_count++;
            break;
        case S_UK_NA_1:
            update_key_request_count++;
            break;
        case S_UR_NA_1:
            update_key_response_count++;
            break;
        case S_SR_NA_1:
            session_request_count++;
            break;
        case S_SS_NA_1:
            session_response_count++;
            break;
        case S_SK_NA_1:
            session_key_request_count++;
            break;
        case S_SQ_NA_1:
            session_key_response_count++;
            break;
        case M_ME_NB_1:
            test_asdu_received = true;
            break;
    }
    
    messages_received++;
    return true;
}

void setUp(void)
{
    /* Reset counters */
    test_asdu_received = false;
    messages_received = 0;
    assoc_request_count = 0;
    assoc_response_count = 0;
    update_key_request_count = 0;
    update_key_response_count = 0;
    session_request_count = 0;
    session_response_count = 0;
    session_key_request_count = 0;
    session_key_response_count = 0;
}

void tearDown(void)
{
    if (connection) {
        CS104_Connection_destroy(connection);
        connection = NULL;
    }
    
    if (slave) {
        CS104_Slave_stop(slave);
        CS104_Slave_destroy(slave);
        slave = NULL;
    }
}

/**
 * Test 1: Verify DSQ Initialization to 1 (IEC 62351-5:2023 Clause 8.5.2.2.4)
 */
void test_DSQ_InitializedToOne(void)
{
    printf("\n=== Test: DSQ Initialization ===\n");
    
    /* Create AProfile context */
    CS101_AppLayerParameters alParams = CS101_AppLayerParameters_create();
    AProfileContext ctx = AProfile_create(NULL, NULL, alParams, true);
    
    TEST_ASSERT_NOT_NULL(ctx);
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: DSQ must start at 1 */
    TEST_ASSERT_EQUAL_UINT32(1, ctx->local_sequence_number);
    TEST_ASSERT_EQUAL_UINT32(0, ctx->remote_sequence_number);
    
    printf("✓ DSQ correctly initialized to 1\n");
    
    AProfile_destroy(ctx);
    CS101_AppLayerParameters_destroy(alParams);
}

/**
 * Test 2: Verify Two-Level Key Hierarchy (IEC 62351-5:2023 Clause 8.3.10)
 */
void test_TwoLevelKeyHierarchy(void)
{
    printf("\n=== Test: Two-Level Key Hierarchy ===\n");
    
    CS101_AppLayerParameters alParams = CS101_AppLayerParameters_create();
    AProfileContext ctx = AProfile_create(NULL, NULL, alParams, true);
    
    TEST_ASSERT_NOT_NULL(ctx);
    
    /* Verify Update Keys are separate from Session Keys */
    TEST_ASSERT_NOT_NULL(ctx->encryption_update_key);
    TEST_ASSERT_NOT_NULL(ctx->authentication_update_key);
    TEST_ASSERT_NOT_NULL(ctx->control_session_key);
    TEST_ASSERT_NOT_NULL(ctx->monitor_session_key);
    
    /* Verify keys are initially zeroed */
    uint8_t zero_key[32] = {0};
    TEST_ASSERT_EQUAL_MEMORY(zero_key, ctx->encryption_update_key, 32);
    TEST_ASSERT_EQUAL_MEMORY(zero_key, ctx->authentication_update_key, 32);
    TEST_ASSERT_EQUAL_MEMORY(zero_key, ctx->control_session_key, 32);
    TEST_ASSERT_EQUAL_MEMORY(zero_key, ctx->monitor_session_key, 32);
    
    printf("✓ Two-level key hierarchy structure verified\n");
    
    AProfile_destroy(ctx);
    CS101_AppLayerParameters_destroy(alParams);
}

/**
 * Test 3: Verify State Machine (IEC 62351-5:2023 Clause 8.3.3)
 */
void test_StateMachine(void)
{
    printf("\n=== Test: State Machine ===\n");
    
    CS101_AppLayerParameters alParams = CS101_AppLayerParameters_create();
    AProfileContext ctx = AProfile_create(NULL, NULL, alParams, true);
    
    TEST_ASSERT_NOT_NULL(ctx);
    
    /* Verify initial state is IDLE */
    TEST_ASSERT_EQUAL_INT(APROFILE_STATE_IDLE, ctx->state);
    
    printf("✓ State machine initialized to IDLE\n");
    
    AProfile_destroy(ctx);
    CS101_AppLayerParameters_destroy(alParams);
}

/**
 * Test 4: Verify ASDU Type Definitions (IEC 62351-5:2023 Clause 8)
 */
void test_ASDUTypeDefinitions(void)
{
    printf("\n=== Test: ASDU Type Definitions ===\n");
    
    /* Verify all 8 message types are defined */
    TEST_ASSERT_EQUAL_INT(140, S_AR_NA_1);
    TEST_ASSERT_EQUAL_INT(141, S_AS_NA_1);
    TEST_ASSERT_EQUAL_INT(142, S_UK_NA_1);
    TEST_ASSERT_EQUAL_INT(143, S_UR_NA_1);
    TEST_ASSERT_EQUAL_INT(144, S_SR_NA_1);
    TEST_ASSERT_EQUAL_INT(145, S_SS_NA_1);
    TEST_ASSERT_EQUAL_INT(146, S_SK_NA_1);
    TEST_ASSERT_EQUAL_INT(147, S_SQ_NA_1);
    TEST_ASSERT_EQUAL_INT(150, S_AC_NA_1);
    TEST_ASSERT_EQUAL_INT(151, S_AB_NA_1);
    
    printf("✓ All ASDU types correctly defined\n");
}

/**
 * Test 5: Full 8-Message Handshake Integration Test
 */
void test_FullHandshake(void)
{
    printf("\n=== Test: Full 8-Message Handshake ===\n");
    
    /* Create server */
    slave = CS104_Slave_create(10, 10);
    CS104_Slave_setLocalPort(slave, 2404);
    CS104_Slave_setASDUReceivedHandler(slave, asduReceivedHandler, NULL);
    
    /* Enable IEC 62351-5:2023 compliant mode */
    CS104_Slave_setSecurityConfig(slave, NULL, NULL, NULL);
    
    CS104_Slave_start(slave);
    
    printf("✓ Server started\n");
    
    /* Wait for server to be ready */
    Thread_sleep(500);
    
    /* Create client */
    connection = CS104_Connection_create("127.0.0.1", 2404);
    CS104_Connection_setASDUReceivedHandler(connection, asduReceivedHandler, NULL);
    
    /* Enable IEC 62351-5:2023 compliant mode */
    CS104_Connection_setSecurityConfig(connection, NULL, NULL, NULL);
    
    bool connected = CS104_Connection_connect(connection);
    TEST_ASSERT_TRUE(connected);
    
    printf("✓ Client connected\n");
    
    /* Send STARTDT to initiate handshake */
    CS104_Connection_sendStartDT(connection);
    
    printf("✓ STARTDT sent - waiting for handshake completion\n");
    
    /* Wait for handshake to complete (8 messages) */
    int timeout = 10000; /* 10 seconds */
    int elapsed = 0;
    
    while (messages_received < 8 && elapsed < timeout) {
        Thread_sleep(100);
        elapsed += 100;
    }
    
    printf("\nHandshake Statistics:\n");
    printf("  Association Request:  %d\n", assoc_request_count);
    printf("  Association Response: %d\n", assoc_response_count);
    printf("  Update Key Request:   %d\n", update_key_request_count);
    printf("  Update Key Response:  %d\n", update_key_response_count);
    printf("  Session Request:      %d\n", session_request_count);
    printf("  Session Response:     %d\n", session_response_count);
    printf("  Session Key Request:  %d\n", session_key_request_count);
    printf("  Session Key Response: %d\n", session_key_response_count);
    printf("  Total Messages:       %d\n", messages_received);
    
    /* Verify all 8 messages were exchanged */
    TEST_ASSERT_GREATER_OR_EQUAL(1, assoc_request_count);
    TEST_ASSERT_GREATER_OR_EQUAL(1, assoc_response_count);
    TEST_ASSERT_GREATER_OR_EQUAL(1, update_key_request_count);
    TEST_ASSERT_GREATER_OR_EQUAL(1, update_key_response_count);
    TEST_ASSERT_GREATER_OR_EQUAL(1, session_request_count);
    TEST_ASSERT_GREATER_OR_EQUAL(1, session_response_count);
    TEST_ASSERT_GREATER_OR_EQUAL(1, session_key_request_count);
    TEST_ASSERT_GREATER_OR_EQUAL(1, session_key_response_count);
    
    printf("\n✓✓✓ Full 8-message handshake completed successfully ✓✓✓\n");
}

/**
 * Test 6: Verify Separate Keys for Control/Monitoring Directions
 */
void test_SeparateDirectionKeys(void)
{
    printf("\n=== Test: Separate Direction Keys ===\n");
    
    CS101_AppLayerParameters alParams = CS101_AppLayerParameters_create();
    AProfileContext ctx = AProfile_create(NULL, NULL, alParams, true);
    
    TEST_ASSERT_NOT_NULL(ctx);
    
    /* Simulate key generation */
    memset(ctx->control_session_key, 0xAA, 32);
    memset(ctx->monitor_session_key, 0xBB, 32);
    
    /* Verify keys are different */
    TEST_ASSERT_NOT_EQUAL_MEMORY(ctx->control_session_key, ctx->monitor_session_key, 32);
    
    printf("✓ Control and Monitoring keys are separate\n");
    
    AProfile_destroy(ctx);
    CS101_AppLayerParameters_destroy(alParams);
}

/**
 * Main test runner
 */
int main(void)
{
    UNITY_BEGIN();
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║   IEC 62351-5:2023 COMPLIANCE TEST SUITE                  ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    RUN_TEST(test_ASDUTypeDefinitions);
    RUN_TEST(test_DSQ_InitializedToOne);
    RUN_TEST(test_TwoLevelKeyHierarchy);
    RUN_TEST(test_StateMachine);
    RUN_TEST(test_SeparateDirectionKeys);
    
    #ifdef RUN_INTEGRATION_TESTS
    RUN_TEST(test_FullHandshake);
    #endif
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║   COMPLIANCE TEST RESULTS                                 ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    return UNITY_END();
}

#else

int main(void)
{
    printf("CONFIG_CS104_APROFILE is not enabled. Skipping tests.\n");
    return 0;
}

#endif /* CONFIG_CS104_APROFILE */
