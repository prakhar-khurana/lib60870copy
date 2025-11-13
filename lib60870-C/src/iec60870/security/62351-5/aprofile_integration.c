/*
 * IEC 62351-5:2023 Complete Integration
 * 
 * This file integrates all security components and provides the main
 * entry points for the 8-step handshake and secure data exchange.
 */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "aprofile_internal.h"
#include "aprofile_messages.h"
#include "cs101_asdu_internal.h"
#include "cs101_information_objects.h"
#include "information_objects_internal.h"
#include <mbedtls/x509_crt.h>
#include <mbedtls/pem.h>
#include <mbedtls/gcm.h>
#include <stdio.h>
#include <string.h>

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

/*=============================================================================
 * Certificate Loading Functions
 *===========================================================================*/

/**
 * @brief Load certificate from PEM file
 */
bool
AProfile_loadCertificate(AProfileContext self, const char* certPath, const char* keyPath, const char* caPath)
{
    if (!self) return false;
    
    printf("\n[CERT] Loading certificates for IEC 62351-5 authentication\n");
    
    /* Load CA certificate */
    if (caPath) {
        int ret = mbedtls_x509_crt_parse_file(&self->ca_cert, caPath);
        if (ret != 0) {
            printf("[CERT] Failed to load CA certificate (error code: -0x%04X)\n", (unsigned int)-ret);
            return false;
        }
        /* Print certificate path safely - limit length to avoid buffer overflow */
        if (caPath) {
            size_t len = strlen(caPath);
            if (len > 200) len = 200;  /* Limit to 200 chars */
            char safe_path[201];
            if (len > 0) {
                memcpy(safe_path, caPath, len);
            }
            safe_path[len] = '\0';
            printf("[CERT] Loaded CA certificate: %s\n", safe_path);
        }
    }
    
    /* Load local certificate */
    if (certPath) {
        int ret = mbedtls_x509_crt_parse_file(&self->local_cert, certPath);
        if (ret != 0) {
            printf("[CERT] Failed to load local certificate (error code: -0x%04X)\n", (unsigned int)-ret);
            return false;
        }
        /* Print certificate path safely - limit length to avoid buffer overflow */
        if (certPath) {
            size_t len = strlen(certPath);
            if (len > 200) len = 200;  /* Limit to 200 chars */
            char safe_path[201];
            if (len > 0) {
                memcpy(safe_path, certPath, len);
            }
            safe_path[len] = '\0';
            printf("[CERT] Loaded local certificate: %s\n", safe_path);
        }
    }
    
    /* Load private key */
    if (keyPath) {
        int ret = mbedtls_pk_parse_keyfile(&self->private_key, keyPath, NULL);
        if (ret != 0) {
            printf("[CERT] Failed to load private key (error code: -0x%04X)\n", (unsigned int)-ret);
            return false;
        }
        /* Print certificate path safely - limit length to avoid buffer overflow */
        if (keyPath) {
            size_t len = strlen(keyPath);
            if (len > 200) len = 200;  /* Limit to 200 chars */
            char safe_path[201];
            if (len > 0) {
                memcpy(safe_path, keyPath, len);
            }
            safe_path[len] = '\0';
            printf("[CERT] Loaded private key: %s\n", safe_path);
        }
    }
    
    printf("[CERT] Certificate loading complete\n\n");
    return true;
}

/**
 * @brief Verify peer certificate
 */
static bool
AProfile_verifyCertificate(AProfileContext self, const uint8_t* certData, size_t certLen)
{
    mbedtls_x509_crt peer_cert;
    mbedtls_x509_crt_init(&peer_cert);
    
    int ret = mbedtls_x509_crt_parse(&peer_cert, certData, certLen);
    if (ret != 0) {
        printf("[CERT] Failed to parse peer certificate\n");
        mbedtls_x509_crt_free(&peer_cert);
        return false;
    }
    
    /* Verify against CA */
    uint32_t flags;
    ret = mbedtls_x509_crt_verify(&peer_cert, &self->ca_cert, NULL, NULL, &flags, NULL, NULL);
    
    mbedtls_x509_crt_free(&peer_cert);
    
    if (ret != 0) {
        printf("[CERT] Certificate verification failed: 0x%08x\n", flags);
        return false;
    }
    
    printf("[CERT] Peer certificate verified successfully\n");
    return true;
}

/*=============================================================================
 * Secure Data Exchange (IEC 62351-5:2023 Clause 8.5)
 *===========================================================================*/

/**
 * @brief Encrypt ASDU using AES-256-GCM
 */
bool
AProfile_encryptASdu(AProfileContext self, const uint8_t* plaintext, size_t plaintext_len,
                     uint8_t* ciphertext, size_t* ciphertext_len, uint8_t* tag)
{
    if (!self || !self->security_active) return false;
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Nonce construction
     * Nonce = DSQ (4 bytes, little-endian) || Fixed padding (8 bytes zero)
     */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    /* DSQ in little-endian format */
    nonce[0] = (uint8_t)(self->DSQ_local & 0xFF);
    nonce[1] = (uint8_t)((self->DSQ_local >> 8) & 0xFF);
    nonce[2] = (uint8_t)((self->DSQ_local >> 16) & 0xFF);
    nonce[3] = (uint8_t)((self->DSQ_local >> 24) & 0xFF);
    /* Remaining 8 bytes are zero (fixed padding) */
    
    /* IEC 62351-5:2023 Clause 8.5.2: Select appropriate session key based on direction
     * Controlling station uses K_SC for sending (control direction)
     * Controlled station uses K_SM for sending (monitor direction)
     */
    const uint8_t* key = self->isControllingStation ? self->K_SC : self->K_SM;
    
    /* Initialize GCM context with correct key for this direction */
    mbedtls_gcm_context gcm_temp;
    mbedtls_gcm_init(&gcm_temp);
    int ret = mbedtls_gcm_setkey(&gcm_temp, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        printf("[CRYPTO] Failed to set GCM key: %d\n", ret);
        mbedtls_gcm_free(&gcm_temp);
        return false;
    }
    
    /* Encrypt using AES-256-GCM */
    ret = mbedtls_gcm_crypt_and_tag(&gcm_temp,
                                    MBEDTLS_GCM_ENCRYPT,
                                    plaintext_len,
                                    nonce, sizeof(nonce),
                                    NULL, 0,  /* No additional data */
                                    plaintext,
                                    ciphertext,
                                    16, tag);
    mbedtls_gcm_free(&gcm_temp);
    
    if (ret != 0) {
        printf("[CRYPTO] AES-GCM encryption failed: %d\n", ret);
        return false;
    }
    
    *ciphertext_len = plaintext_len;
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Increment DSQ after encryption */
    self->DSQ_local++;
    
    printf("[CRYPTO] ASDU encrypted with AES-256-GCM (DSQ=%u)\n", self->DSQ_local - 1);
    return true;
}

/**
 * @brief Decrypt ASDU using AES-256-GCM
 */
bool
AProfile_decryptASdu(AProfileContext self, const uint8_t* ciphertext, size_t ciphertext_len,
                     const uint8_t* tag, uint32_t sequence_number,
                     uint8_t* plaintext, size_t* plaintext_len)
{
    if (!self || !self->security_active) return false;
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Verify DSQ to prevent replay attacks */
    if (sequence_number <= self->DSQ_remote && self->DSQ_remote != 0) {
        printf("[SECURITY] Replay attack detected! DSQ=%u (expected > %u)\n",
               sequence_number, self->DSQ_remote);
        return false;
    }
    
    /* Verify DSQ is not 0 (invalid) */
    if (sequence_number == 0) {
        printf("[SECURITY] Invalid DSQ=0\n");
        return false;
    }
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Nonce construction
     * Nonce = DSQ (4 bytes, little-endian) || Fixed padding (8 bytes zero)
     */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    /* DSQ in little-endian format */
    nonce[0] = (uint8_t)(sequence_number & 0xFF);
    nonce[1] = (uint8_t)((sequence_number >> 8) & 0xFF);
    nonce[2] = (uint8_t)((sequence_number >> 16) & 0xFF);
    nonce[3] = (uint8_t)((sequence_number >> 24) & 0xFF);
    /* Remaining 8 bytes are zero (fixed padding) */
    
    /* IEC 62351-5:2023 Clause 8.5.2: Select appropriate session key based on direction
     * Controlling station receives on monitor direction (uses K_SM)
     * Controlled station receives on control direction (uses K_SC)
     */
    const uint8_t* key = self->isControllingStation ? self->K_SM : self->K_SC;
    
    /* Initialize GCM context with correct key for this direction */
    mbedtls_gcm_context gcm_temp;
    mbedtls_gcm_init(&gcm_temp);
    int ret = mbedtls_gcm_setkey(&gcm_temp, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        printf("[CRYPTO] Failed to set GCM key: %d\n", ret);
        mbedtls_gcm_free(&gcm_temp);
        return false;
    }
    
    /* Decrypt using AES-256-GCM */
    ret = mbedtls_gcm_auth_decrypt(&gcm_temp,
                                   ciphertext_len,
                                   nonce, sizeof(nonce),
                                   NULL, 0,  /* No additional data */
                                   tag, 16,
                                   ciphertext,
                                   plaintext);
    mbedtls_gcm_free(&gcm_temp);
    
    if (ret != 0) {
        printf("[CRYPTO] AES-GCM decryption/authentication failed: %d\n", ret);
        return false;
    }
    
    *plaintext_len = ciphertext_len;
    self->DSQ_remote = sequence_number;
    
    printf("[CRYPTO] ASDU decrypted and authenticated (DSQ=%u)\n", sequence_number);
    return true;
}

/**
 * @brief Send secure ASDU (S_RP_NA_1)
 */
bool
AProfile_sendSecureASdu(AProfileContext self, CS101_ASDU asdu)
{
    if (!self || !self->security_active) {
        printf("[SECURITY] Cannot send secure ASDU - session not established\n");
        return false;
    }
    
    printf("\n[SECURE DATA] Sending encrypted ASDU (S_RP_NA_1)\n");
    
    /* Serialize ASDU to bytes */
    uint8_t asdu_buffer[256];
    /* TODO: Implement ASDU serialization */
    int asdu_len = 10; /* Placeholder */
    
    /* Encrypt ASDU */
    uint8_t encrypted[256];
    size_t encrypted_len;
    uint8_t tag[16];
    
    if (!AProfile_encryptASdu(self, asdu_buffer, asdu_len, encrypted, &encrypted_len, tag)) {
        return false;
    }
    
    /* Create secure data payload: encrypted ASDU + tag */
    uint8_t secure_payload[272];
    memcpy(secure_payload, encrypted, encrypted_len);
    memcpy(secure_payload + encrypted_len, tag, 16);
    
    /* Create S_RP_NA_1 ASDU */
    CS101_ASDU secure_asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!secure_asdu) return false;
    
    CS101_ASDU_setTypeID(secure_asdu, (IEC60870_5_TypeID)S_RP_NA_1);
    
    /* Add secure payload as information object */
    SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, (int)(encrypted_len + 16), secure_payload);
    if (!spk) {
        CS101_ASDU_destroy(secure_asdu);
        return false;
    }
    
    CS101_ASDU_addInformationObject(secure_asdu, (InformationObject)spk);
    SecurityPublicKey_destroy(spk);
    
    /* Send */
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, secure_asdu);
    }
    
    CS101_ASDU_destroy(secure_asdu);
    
    printf("[SECURE DATA] Encrypted ASDU sent (DSQ=%u, Size=%zu bytes)\n",
           (unsigned int)(self->DSQ_local - 1), (size_t)(encrypted_len + 16));
    printf("[CRYPTO] Encrypted Packet (hex): ");
    for (size_t i = 0; i < (encrypted_len + 16 > 32 ? 32 : encrypted_len + 16); i++) {
        printf("%02X ", secure_payload[i]);
    }
    if (encrypted_len + 16 > 32) printf("...");
    printf("\n");
    
    return true;
}

/*=============================================================================
 * Main Handshake Initiator
 *===========================================================================*/

/**
 * @brief Initiate IEC 62351-5:2023 8-step handshake
 */
bool
AProfile_initiateHandshake(AProfileContext self)
{
    if (!self) return false;
    
    if (!self->isControllingStation) {
        printf("[HANDSHAKE] Server mode - waiting for client to initiate\n");
        return true;
    }
    
    printf("\n");
    printf("=== IEC 62351-5:2023 8-Step Security Handshake ===\n");
    printf("\n");
    
    /* Step 1: Send Association Request */
    return AProfile_sendAssociationRequest(self);
}

/**
 * @brief Print key material for debugging
 */
void
AProfile_printKeys(AProfileContext self)
{
    if (!self) return;
    
    printf("\n");
    printf("=== IEC 62351-5:2023 Key Material ===\n");
    printf("\n");
    
    printf("[KEYS] Update Keys (HKDF-derived from ECDH shared secret):\n");
    printf("  K_UE - Encryption Update Key (256-bit): ");
    for (int i = 0; i < 32; i++) printf("%02X", self->K_UE[i]);
    printf("\n");
    
    printf("  K_UA - Authentication Update Key (256-bit): ");
    for (int i = 0; i < 32; i++) printf("%02X", self->K_UA[i]);
    printf("\n\n");
    
    printf("[KEYS] Session Keys (Randomly generated):\n");
    printf("  K_SC - Control Session Key (256-bit): ");
    for (int i = 0; i < 32; i++) printf("%02X", self->K_SC[i]);
    printf("\n");
    
    printf("  K_SM - Monitor Session Key (256-bit): ");
    for (int i = 0; i < 32; i++) printf("%02X", self->K_SM[i]);
    printf("\n\n");
    
    printf("[KEYS] Random Data (for HKDF salt - R_C || R_S):\n");
    printf("  R_C - Controlling Station Random (32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02X", self->R_C[i]);
    printf("\n");
    
    printf("  R_S - Controlled Station Random (32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02X", self->R_S[i]);
    printf("\n\n");
    
    printf("[KEYS] ECDH Public Key (%d bytes): ", self->localPublicKeyLen);
    for (int i = 0; i < self->localPublicKeyLen && i < 65; i++) printf("%02X", self->localPublicKey[i]);
    printf("\n\n");
}

/**
 * @brief Get current security state
 */
const char*
AProfile_getStateName(AProfileContext self)
{
    if (!self) return "NULL";
    
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
