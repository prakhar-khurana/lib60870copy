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
extern bool AProfile_handleAssociationResponse(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendUpdateKeyChangeRequest(AProfileContext self);
extern bool AProfile_handleUpdateKeyChangeResponse(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendSessionRequest(AProfileContext self);
extern bool AProfile_handleSessionResponse(AProfileContext self, CS101_ASDU asdu);
extern bool AProfile_sendSessionKeyChangeRequest(AProfileContext self);
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
            printf("APROFILE: Received Association Request (S_AR_NA_1)\n");
            /* Server should respond with Association Response */
            /* This is handled by the server-side logic */
            return true;
            
        case S_AS_NA_1:
            /* Client receives Association Response */
            return AProfile_handleAssociationResponse(self, asdu);
            
        case S_UK_NA_1:
            /* Server receives Update Key Change Request */
            printf("APROFILE: Received Update Key Change Request (S_UK_NA_1)\n");
            /* Server should respond with Update Key Change Response */
            return true;
            
        case S_UR_NA_1:
            /* Client receives Update Key Change Response */
            return AProfile_handleUpdateKeyChangeResponse(self, asdu);
            
        case S_SR_NA_1:
            /* Server receives Session Request */
            printf("APROFILE: Received Session Request (S_SR_NA_1)\n");
            /* Server should respond with Session Response */
            return true;
            
        case S_SS_NA_1:
            /* Client receives Session Response */
            return AProfile_handleSessionResponse(self, asdu);
            
        case S_SK_NA_1:
            /* Server receives Session Key Change Request */
            printf("APROFILE: Received Session Key Change Request (S_SK_NA_1)\n");
            /* Server should unwrap keys and respond */
            return true;
            
        case S_SQ_NA_1:
            /* Client receives Session Key Change Response */
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
    if (self->state != APROFILE_STATE_IDLE) {
        printf("APROFILE: Handshake already in progress (state=%d)\n", self->state);
        return false;
    }
    
    if (!self->isClient) {
        printf("APROFILE: Server waits for client to initiate\n");
        return true;
    }
    
    /* Client initiates with Association Request */
    return AProfile_sendAssociationRequest(self);
}

/**
 * @brief Check if session is fully established
 */
bool
AProfile_isSessionEstablished(AProfileContext self)
{
    return (self->state == APROFILE_STATE_ESTABLISHED && self->security_active);
}

/**
 * @brief Get current state as string for debugging
 */
const char*
AProfile_getStateString(AProfileContext self)
{
    switch (self->state) {
        case APROFILE_STATE_IDLE: return "IDLE";
        case APROFILE_STATE_ASSOC_PENDING: return "ASSOC_PENDING";
        case APROFILE_STATE_ASSOC_COMPLETE: return "ASSOC_COMPLETE";
        case APROFILE_STATE_UPDATE_KEY_PENDING: return "UPDATE_KEY_PENDING";
        case APROFILE_STATE_UPDATE_KEY_COMPLETE: return "UPDATE_KEY_COMPLETE";
        case APROFILE_STATE_SESSION_PENDING: return "SESSION_PENDING";
        case APROFILE_STATE_SESSION_KEY_PENDING: return "SESSION_KEY_PENDING";
        case APROFILE_STATE_ESTABLISHED: return "ESTABLISHED";
        default: return "UNKNOWN";
    }
}

#endif /* CONFIG_CS104_APROFILE */
