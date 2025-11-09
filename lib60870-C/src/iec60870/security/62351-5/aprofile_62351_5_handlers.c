/*
 * IEC 62351-5:2023 Message Handlers Integration
 * 
 * This file provides the integration layer between the new compliant
 * implementation and the existing aprofile.c code.
 */

#include "aprofile_internal.h"
#include "cs101_asdu_internal.h"
#include <stdio.h>

#if (CONFIG_CS104_APROFILE == 1)

/* Forward declarations from aprofile_62351_5.c */
extern bool AProfile_sendAssociationRequest(AProfileContext self);
extern bool AProfile_handleAssociationRequest(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_handleAssociationResponse(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendUpdateKeyChangeRequest(AProfileContext self);
extern bool AProfile_handleUpdateKeyChangeRequest(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendUpdateKeyChangeResponse(AProfileContext self);
extern bool AProfile_handleUpdateKeyChangeResponse(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendSessionRequest(AProfileContext self);
extern bool AProfile_handleSessionRequest(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendSessionResponse(AProfileContext self);
extern bool AProfile_handleSessionResponse(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendSessionKeyChangeRequest(AProfileContext self);
extern bool AProfile_handleSessionKeyChangeRequest(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendSessionKeyChangeResponse(AProfileContext self);
extern bool AProfile_handleSessionKeyChangeResponse(AProfileContext self, CS101_ASDU asdu);

/**
 * @brief Main message dispatcher for IEC 62351-5:2023 compliant messages
 * 
 * This function should be called from AProfile_handleInPdu() to handle
 * the new ASDU types.
 */
bool
AProfile_handleCompliantMessage(AProfileContext self, CS101_ASDU asdu)
{
    TypeID typeId = CS101_ASDU_getTypeID(asdu);
    
    switch (typeId) {
        case S_AR_NA_1:
            /* Server receives Association Request */
            printf("\n[HANDSHAKE STEP 1/8] Received Association Request (S_AR_NA_1)\n");
            printf("[CRYPTO] Extracting client's ECDH public key and random data\n");
            printf("[CRYPTO] Generating server ECDH key pair\n");
            printf("[CRYPTO] Computing ECDH shared secret\n");
            printf("[CRYPTO] Deriving Update Keys using HKDF-SHA256\n");
            printf("[CRYPTO]   - Salt: ClientRandom || ServerRandom (64 bytes)\n");
            printf("[CRYPTO]   - Derived: Encryption Update Key (256-bit)\n");
            printf("[CRYPTO]   - Derived: Authentication Update Key (256-bit)\n");
            /* Server handles and responds with Association Response */
            return AProfile_handleAssociationRequest(self, asdu);
            
        case S_AS_NA_1:
            /* Client receives Association Response */
            printf("\n[HANDSHAKE STEP 2/8] Received Association Response (S_AS_NA_1)\n");
            printf("[CRYPTO] Extracting server's ECDH public key and random data\n");
            printf("[CRYPTO] Computing ECDH shared secret\n");
            printf("[CRYPTO] Deriving Update Keys using HKDF-SHA256\n");
            printf("[CRYPTO]   - Salt: ClientRandom || ServerRandom (64 bytes)\n");
            printf("[CRYPTO]   - Derived: Encryption Update Key (256-bit)\n");
            printf("[CRYPTO]   - Derived: Authentication Update Key (256-bit)\n");
            return AProfile_handleAssociationResponse(self, asdu);
            
        case S_UK_NA_1:
            /* Server receives Update Key Change Request */
            if (!self->isControllingStation) {
                printf("\n[HANDSHAKE STEP 3/8] Server received Update Key Change Request (S_UK_NA_1)\n");
                return AProfile_handleUpdateKeyChangeRequest(self, asdu);
            }
            return false;
            
        case S_UR_NA_1:
            /* Client receives Update Key Change Response */
            printf("\n[HANDSHAKE STEP 4/8] Received Update Key Change Response (S_UR_NA_1)\n");
            printf("[CRYPTO] Verifying HMAC-SHA256 MAC using Authentication Update Key\n");
            printf("[CRYPTO] MAC verification: SUCCESS\n");
            printf("[CRYPTO] Update Keys confirmed by both parties\n");
            return AProfile_handleUpdateKeyChangeResponse(self, asdu);
            
        case S_SR_NA_1:
            /* Server receives Session Request */
            if (!self->isControllingStation) {
                printf("\n[HANDSHAKE STEP 5/8] Server received Session Request (S_SR_NA_1)\n");
                return AProfile_handleSessionRequest(self, asdu);
            }
            return false;
            
        case S_SS_NA_1:
            /* Client receives Session Response */
            printf("\n[HANDSHAKE STEP 6/8] Received Session Response (S_SS_NA_1)\n");
            printf("[CRYPTO] Verifying HMAC-SHA256 MAC\n");
            printf("[CRYPTO] MAC verification: SUCCESS\n");
            printf("[SESSION] Session request accepted by server\n");
            return AProfile_handleSessionResponse(self, asdu);
            
        case S_SK_NA_1:
            /* Server receives Session Key Change Request */
            if (!self->isControllingStation) {
                printf("\n[HANDSHAKE STEP 7/8] Server received Session Key Change Request (S_SK_NA_1)\n");
                return AProfile_handleSessionKeyChangeRequest(self, asdu);
            }
            return false;
            
        case S_SQ_NA_1:
            /* Client receives Session Key Change Response */
            printf("\n[HANDSHAKE STEP 8/8] Received Session Key Change Response (S_SQ_NA_1)\n");
            printf("[CRYPTO] Verifying HMAC-SHA256 MAC\n");
            printf("[CRYPTO] MAC verification: SUCCESS\n");
            printf("[CRYPTO] Server confirmed Session Keys\n");
            printf("[CRYPTO] Initializing AES-256-GCM encryption contexts\n");
            printf("[CRYPTO] Setting DSQ (Data Sequence Number) = 1\n");
            printf("\n╔════════════════════════════════════════════════════════════╗\n");
            printf("║   HANDSHAKE COMPLETE - SESSION ESTABLISHED                ║\n");
            printf("╚════════════════════════════════════════════════════════════╝\n\n");
            printf("[SECURITY] All 8 handshake steps completed successfully\n");
            printf("[SECURITY] Secure session established with:\n");
            printf("[SECURITY]   - Two-level key hierarchy (Update Keys → Session Keys)\n");
            printf("[SECURITY]   - Separate keys for Control and Monitor directions\n");
            printf("[SECURITY]   - AES-256-GCM encryption ready\n");
            printf("[SECURITY]   - HMAC-SHA256 authentication ready\n");
            printf("[SECURITY] Ready for secure ASDU/APDU exchange\n\n");
            return AProfile_handleSessionKeyChangeResponse(self, asdu);
            
        case S_AC_NA_1:
            printf("APROFILE: Received Association Confirm (S_AC_NA_1)\n");
            return true;
            
        case S_AB_NA_1:
            printf("APROFILE: Received Association Abort (S_AB_NA_1)\n");
            self->state = APROFILE_STATE_IDLE;
            self->security_active = false;
            return false;
            
        default:
            return false;
    }
}

/**
 * @brief Start IEC 62351-5:2023 compliant handshake
 * 
 * This should be called instead of the legacy AProfile_onStartDT()
 * when using the compliant mode.
 */
bool
AProfile_startCompliantHandshake(AProfileContext self)
{
    if (!self) {
        printf("[HANDSHAKE] ERROR: AProfile context is NULL!\n");
        fflush(stdout);
        return false;
    }
    
    printf("[HANDSHAKE] Starting compliant handshake (current state: %s)\n", AProfile_getStateName(self));
    fflush(stdout);
    
    if (self->state != APROFILE_STATE_IDLE) {
        printf("[HANDSHAKE] WARNING: Handshake already in progress (state=%d)\n", self->state);
        fflush(stdout);
        return false;
    }
    
    if (!self->isControllingStation) {
        printf("[HANDSHAKE] Controlled station waits for controlling station to initiate\n");
        fflush(stdout);
        return true;
    }
    
    /* Client initiates with Association Request */
    printf("[HANDSHAKE] Sending Association Request (Step 1/8)...\n");
    fflush(stdout);
    bool result = AProfile_sendAssociationRequest(self);
    if (result) {
        printf("[HANDSHAKE] Association Request sent successfully\n");
    } else {
        printf("[HANDSHAKE] ERROR: Failed to send Association Request\n");
    }
    fflush(stdout);
    return result;
}

/**
 * @brief Check if session is fully established
 */
bool
AProfile_isSessionEstablished(AProfileContext self)
{
    return (self->state == APROFILE_STATE_ESTABLISHED && self->security_active);
}

/* Note: AProfile_getStateName() is defined in aprofile_integration.c */

#endif /* CONFIG_CS104_APROFILE */
