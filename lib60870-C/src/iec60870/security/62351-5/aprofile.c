/*
 * Copyright 2024
 *
 * This file is part of lib60870-C
 *
 * lib60870-C is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * lib60870-C is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lib60870-C.  If not, see <http://www.gnu.org/licenses/>.
 */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include "aprofile_internal.h"
#include "cs104_frame.h"
#include "lib_memory.h"
#include "cs101_asdu_internal.h"
#include "cs101_information_objects.h"
#include "information_objects_internal.h"
#include <stdio.h>
#include <string.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pem.h>
#include <mbedtls/error.h>
#include "hal_time.h"

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

#if (CONFIG_CS104_APROFILE == 1)

void
AProfile_setAlgorithm(AProfileContext self, AProfileAlgorithm alg)
{
    if (self) self->selectedAlgorithm = alg;
}

#ifdef HAVE_LIBOQS
/* Chunking format inside SecurityPublicKey.keyValue[]
 * [0] kind: 0xA1 (Kyber PK), 0xA2 (Kyber CT)
 * [1..2] total_chunks (uint16 LE)
 * [3..4] chunk_index (0-based, uint16 LE)
 * [5..6] total_length (uint16 LE, modulo 65536; 0 means unknown)
 * [7..8] suite_id (uint16 LE)
 * [9..10] kem_id (uint16 LE)
 * [11] hash_id (uint8)
 * [12..] payload bytes (chunk)
 */
#define KYBER_CHUNK_KIND_PK 0xA1
#define KYBER_CHUNK_KIND_CT 0xA2
#define KYBER_CHUNK_HDR 12
#define KYBER_CHUNK_PAYLOAD 180

static void ap_chunk_reset(AProfileContext self)
{
    self->chunk_expected_len = 0;
    self->chunk_expected_total = 0;
    self->chunk_received_count = 0;
    memset(self->chunk_received_bitmap, 0, sizeof(self->chunk_received_bitmap));
}

static bool ap_chunk_store(AProfileContext self, uint8_t kind, const uint8_t* buf, int len)
{
    if (len < KYBER_CHUNK_HDR) return false;
    uint16_t total = (uint16_t)(buf[1] | (buf[2] << 8));
    uint16_t index = (uint16_t)(buf[3] | (buf[4] << 8));
    uint16_t totlen = (uint16_t)(buf[5] | (buf[6] << 8));
    uint16_t suite_id = (uint16_t)(buf[7] | (buf[8] << 8));
    uint16_t kem_id = (uint16_t)(buf[9] | (buf[10] << 8));
    uint8_t hash_id = buf[11];
    
    if (index >= total) return false;
    
    if (self->chunk_expected_total == 0) {
        self->chunk_expected_total = total;
        self->chunk_expected_len = totlen; /* informative; may be 0 */
        self->chunk_for_ciphertext = (kind == KYBER_CHUNK_KIND_CT);
        self->chunk_kind = kind;
        self->chunk_hash_id = hash_id;
        
        /* Initialize transcript hash if this is the first chunk */
        mbedtls_md_init(&self->th_ctx);
        mbedtls_md_setup(&self->th_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&self->th_ctx);
    }
    
    if (total != self->chunk_expected_total) return false;
    if (suite_id != self->suite_id || kem_id != self->kem_id || hash_id != self->hash_id) {
        return false; /* Inconsistent parameters */
    }
    
    /* Update transcript hash with the entire chunk (header and payload) */
    mbedtls_md_update(&self->th_ctx, buf, len);
    
    size_t payload_len = (size_t) (len - KYBER_CHUNK_HDR);
    size_t offset = (size_t)index * KYBER_CHUNK_PAYLOAD;
    if (offset + payload_len > sizeof(self->chunk_assemble_buf)) return false;
    memcpy(self->chunk_assemble_buf + offset, buf + KYBER_CHUNK_HDR, payload_len);
    size_t bit = index & 7u; size_t byte = index >> 3;
    if (((self->chunk_received_bitmap[byte] >> bit) & 1u) == 0) {
        self->chunk_received_bitmap[byte] |= (uint8_t)(1u << bit);
        self->chunk_received_count++;
    }
    
    self->last_chunk_time = (uint32_t)Hal_getTimeInMs();
    
    return true;
}

static bool ap_chunk_complete(AProfileContext self)
{
    return (self->chunk_expected_total > 0) && (self->chunk_received_count >= self->chunk_expected_total);
}

static int ap_send_chunks(AProfileContext self, const uint8_t* src, size_t total_len, bool isCiphertext)
{
    uint8_t kind = isCiphertext ? KYBER_CHUNK_KIND_CT : KYBER_CHUNK_KIND_PK;
    uint16_t total_chunks = (uint16_t)((total_len + KYBER_CHUNK_PAYLOAD - 1) / KYBER_CHUNK_PAYLOAD);
    for (uint16_t i = 0; i < total_chunks; i++) {
        size_t offset = (size_t)i * KYBER_CHUNK_PAYLOAD;
        size_t remain = (total_len > offset) ? (total_len - offset) : 0;
        size_t clen = remain > KYBER_CHUNK_PAYLOAD ? KYBER_CHUNK_PAYLOAD : remain;
        uint8_t payload[KYBER_CHUNK_HDR + KYBER_CHUNK_PAYLOAD];
        payload[0] = kind;
        payload[1] = (uint8_t)(total_chunks & 0xff);
        payload[2] = (uint8_t)(total_chunks >> 8);
        payload[3] = (uint8_t)(i & 0xff);
        payload[4] = (uint8_t)(i >> 8);
        uint16_t tot16 = (uint16_t)(total_len & 0xffff);
        payload[5] = (uint8_t)(tot16 & 0xff);
        payload[6] = (uint8_t)(tot16 >> 8);
        /* New fields: suite_id, kem_id, hash_id */
        payload[7] = (uint8_t)(self->suite_id & 0xff);
        payload[8] = (uint8_t)(self->suite_id >> 8);
        payload[9] = (uint8_t)(self->kem_id & 0xff);
        payload[10] = (uint8_t)(self->kem_id >> 8);
        payload[11] = self->hash_id;
        memcpy(payload + KYBER_CHUNK_HDR, src + offset, clen);

        CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
        if (!asdu) return -1;
        CS101_ASDU_setTypeID(asdu, S_RP_NA_1);
        SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, (int)(KYBER_CHUNK_HDR + clen), payload);
        if (!spk) { CS101_ASDU_destroy(asdu); return -1; }
        CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
        SecurityPublicKey_destroy(spk);
        if (self->sendAsdu) (void) self->sendAsdu(self->connection, asdu);
        CS101_ASDU_destroy(asdu);
    }
    return 0;
}
#endif /* HAVE_LIBOQS */

AProfileContext
AProfile_create(void* connection, AProfile_SendAsduCallback sendAsduCallback, CS101_AppLayerParameters parameters, bool isClient)
{
    AProfileContext self = (AProfileContext) GLOBAL_CALLOC(1, sizeof(struct sAProfileContext));

    if (self == NULL)
        return NULL;

    self->connection = connection;
    self->sendAsdu = sendAsduCallback;
    self->parameters = parameters;
    self->isControllingStation = isClient; /* IEC 62351-5:2023: controlling station = client */

    mbedtls_gcm_init(&self->gcm_encrypt);
    
    mbedtls_ecdh_init(&self->ecdh);
    
    /* For mbedtls 2.x with new context, set point format */
    #if !defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    self->ecdh.point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
    #endif
    
    mbedtls_ctr_drbg_init(&self->ctr_drbg);
    mbedtls_entropy_init(&self->entropy);
    mbedtls_gcm_init(&self->gcm_decrypt);
    mbedtls_x509_crt_init(&self->ca_cert);
    mbedtls_x509_crt_init(&self->local_cert);
    mbedtls_pk_init(&self->private_key);
    mbedtls_rsa_init(&self->rsa_private_key, MBEDTLS_RSA_PKCS_V15, 0);

    /* Seed the random number generator */
    const char* pers = "lib60870";
    int ret = mbedtls_ctr_drbg_seed(&self->ctr_drbg, mbedtls_entropy_func, &self->entropy,
                           (const unsigned char*) pers, strlen(pers));

    if (ret != 0) {
        AProfile_destroy(self);
        return NULL;
    }

    self->keyExchangeState = KEY_EXCHANGE_IDLE;
    self->selectedAlgorithm = APROFILE_ALG_ECDH;
    self->security_active = false;
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: DSQ starts at 1, not 0 */
    self->DSQ_local = 1;
    self->DSQ_remote = 0;
    
    /* Initialize IEC 62351-5:2023 state machine */
    self->state = APROFILE_STATE_IDLE;
    self->AIM = 0;  /* Association ID for controlling station */
    self->AIS = 0;  /* Association ID for controlled station */
    
    /* Clear key material - IEC 62351-5:2023 standard nomenclature */
    memset(self->K_UE, 0, sizeof(self->K_UE));
    memset(self->K_UA, 0, sizeof(self->K_UA));
    memset(self->K_SC, 0, sizeof(self->K_SC));
    memset(self->K_SM, 0, sizeof(self->K_SM));
    memset(self->R_C, 0, sizeof(self->R_C));
    memset(self->R_S, 0, sizeof(self->R_S));

    return self;
}

void
AProfile_destroy(AProfileContext self)
{
    if (self) {
        mbedtls_ecdh_free(&self->ecdh);
        mbedtls_ctr_drbg_free(&self->ctr_drbg);
        mbedtls_entropy_free(&self->entropy);
        mbedtls_gcm_free(&self->gcm_encrypt);
        mbedtls_gcm_free(&self->gcm_decrypt);
        
        mbedtls_x509_crt_free(&self->ca_cert);
        mbedtls_pk_free(&self->private_key);
        mbedtls_x509_crt_free(&self->local_cert);
        mbedtls_rsa_free(&self->rsa_private_key);

        GLOBAL_FREEMEM(self);
    }
}

#else /* CONFIG_CS104_APROFILE == 0 */

AProfileContext
AProfile_create(void* connection, void* sendAsduCallback, CS101_AppLayerParameters parameters)
{
    AProfileContext self = (AProfileContext) GLOBAL_CALLOC(1, sizeof(struct sAProfileContext));
    if (self) {
        self->security_active = false;
    }
    return self;
}

void
AProfile_destroy(AProfileContext self)
{
    GLOBAL_FREEMEM(self);
    (void)self; /* avoid unused parameter warning */
}

#endif /* CONFIG_CS104_APROFILE */


bool
AProfile_onStartDT(AProfileContext self)
{
#if (CONFIG_CS104_APROFILE == 1)
    /* LEGACY FUNCTION - DISABLED for IEC 62351-5:2023 compliance
     * The compliant handshake should be initiated via AProfile_startCompliantHandshake()
     * or AProfile_initiateHandshake() which implements the full 8-step handshake.
     * This function is kept for backward compatibility but should not be used.
     */
    /* Return true to allow connection, but do not initiate legacy key exchange */
    return true;
    
    /* DISABLED LEGACY CODE - DO NOT USE
     * This code is commented out because we now use the compliant 8-step handshake
     * implemented in aprofile_62351_5_handlers.c
     */
#else
    return true;
#endif
}

static bool load_certificates(AProfileContext self, const char* cert_path, const char* key_path, const char* ca_path)
{
    (void)self; (void)cert_path; (void)key_path; (void)ca_path;
    return false;
}

bool
AProfile_ready(AProfileContext self)
{
#if (CONFIG_CS104_APROFILE == 1)
    return self->security_active;
#else
    return false;
#endif
}

bool
AProfile_wrapOutAsdu(AProfileContext self, T104Frame frame)
{
#if (CONFIG_CS104_APROFILE == 1)
    printf("\n=== IEC 62351-5 ENCRYPTION - PRE-PROCESSING ===\n");
    printf("[ENCRYPT-DEBUG] AProfile_wrapOutAsdu called\n");
    printf("[ENCRYPT-DEBUG] security_active: %s\n", self->security_active ? "TRUE" : "FALSE");
    printf("[ENCRYPT-DEBUG] AProfile_ready: %s\n", AProfile_ready(self) ? "TRUE" : "FALSE");
    printf("[ENCRYPT-DEBUG] State: %d (0=IDLE, 1=ASSOC_SENT, 2=ASSOC_RCVD, 3=UPDATE_SENT, 4=UPDATE_RCVD, 5=SESSION_SENT, 6=SESSION_RCVD, 7=ESTABLISHED)\n", self->state);
    printf("[ENCRYPT-DEBUG] DSQ_local (before increment): %u\n", self->DSQ_local);
    printf("[ENCRYPT-DEBUG] isControllingStation: %s\n", self->isControllingStation ? "TRUE (using K_SC)" : "FALSE (using K_SM)");
    
    if (!self->security_active || !AProfile_ready(self)) {
        printf("[ENCRYPT-DEBUG] Skipping encryption - security not active/ready\n");
        printf("\n");
        return true; /* Do nothing if security is not active */
    }
    
    printf("[ENCRYPT-DEBUG] Proceeding with AES-256-GCM encryption...\n");

    /* Use Frame interface instead of T104Frame to avoid type mismatch issues */
    Frame genericFrame = (Frame)frame;
    uint8_t* frame_buffer = Frame_getBuffer(genericFrame);
    uint8_t* asdu_buffer = frame_buffer + 6;
    int frame_size = Frame_getMsgSize(genericFrame);
    int asdu_len = frame_size - 6;

    printf("\n[PAYLOAD-PRE] ----- PLAINTEXT ASDU (BEFORE ENCRYPTION) -----\n");
    printf("[PAYLOAD-PRE] ASDU Length: %d bytes\n", asdu_len);
    printf("[PAYLOAD-PRE] ASDU Type: %d\n", asdu_buffer[0]);
    printf("[PAYLOAD-PRE] VSQ: %d\n", asdu_buffer[1]);
    printf("[PAYLOAD-PRE] COT: %d\n", asdu_buffer[2]);
    printf("[PAYLOAD-PRE] Full ASDU hex dump:\n[PAYLOAD-PRE] ");
    for (int i = 0; i < asdu_len; i++) {
        printf("%02X ", asdu_buffer[i]);
        if ((i + 1) % 16 == 0 && i < asdu_len - 1) printf("\n[PAYLOAD-PRE] ");
    }
    printf("\n[PAYLOAD-PRE] ----- END PLAINTEXT ASDU -----\n\n");

    /* Save original ASDU for encryption */
    uint8_t* original_asdu = (uint8_t*)GLOBAL_MALLOC(asdu_len);
    if (!original_asdu)
        return false;
    
    memcpy(original_asdu, asdu_buffer, asdu_len);

    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Nonce construction
     * Nonce = DSQ (4 bytes, little-endian) || Fixed padding (8 bytes zero)
     * Note: Standard allows for 8 bytes of fixed padding or random, but
     * for deterministic behavior and compliance, we use zeros.
     */
    uint8_t nonce[12];
    memset(nonce, 0, 12);
    /* DSQ in little-endian format (IEC 62351-5:2023) */
    nonce[0] = (uint8_t)(self->DSQ_local & 0xFF);
    nonce[1] = (uint8_t)((self->DSQ_local >> 8) & 0xFF);
    nonce[2] = (uint8_t)((self->DSQ_local >> 16) & 0xFF);
    nonce[3] = (uint8_t)((self->DSQ_local >> 24) & 0xFF);
    /* Remaining 8 bytes are zero (fixed padding per standard) */
    
    printf("[CRYPTO-PARAMS] ----- AES-256-GCM PARAMETERS -----\n");
    printf("[CRYPTO-PARAMS] Nonce (12 bytes): ");
    for (int i = 0; i < 12; i++) printf("%02X ", nonce[i]);
    printf("\n[CRYPTO-PARAMS] DSQ (little-endian): %u (0x%08X)\n", self->DSQ_local, self->DSQ_local);
    printf("[CRYPTO-PARAMS] Session Key (%s): ", self->isControllingStation ? "K_SC" : "K_SM");
    const uint8_t* session_key = self->isControllingStation ? self->K_SC : self->K_SM;
    for (int i = 0; i < 32; i++) printf("%02X ", session_key[i]);
    printf("\n[CRYPTO-PARAMS] ----- END AES-256-GCM PARAMETERS -----\n\n");

    uint8_t tag[16];
    uint8_t* ciphertext = (uint8_t*)GLOBAL_MALLOC(asdu_len);
    if (!ciphertext) {
        GLOBAL_FREEMEM(original_asdu);
        return false;
    }

    /* IEC 62351-5:2023 Clause 8.5.2: Select appropriate session key based on direction
     * Controlling station uses K_SC for sending (control direction)
     * Controlled station uses K_SM for sending (monitor direction)
     */
    const uint8_t* session_key_ptr = self->isControllingStation ? self->K_SC : self->K_SM;
    
    /* Reinitialize GCM context with correct key for this direction */
    mbedtls_gcm_context gcm_temp;
    mbedtls_gcm_init(&gcm_temp);
    int ret = mbedtls_gcm_setkey(&gcm_temp, MBEDTLS_CIPHER_ID_AES, session_key_ptr, 256);
    if (ret != 0) {
        printf("[CRYPTO-ERROR] Failed to set GCM key: -0x%04X\n", -ret);
        mbedtls_gcm_free(&gcm_temp);
        GLOBAL_FREEMEM(original_asdu);
        GLOBAL_FREEMEM(ciphertext);
        return false;
    }
    
    printf("[CRYPTO-EXEC] Executing AES-256-GCM encryption...\n");
    printf("[CRYPTO-EXEC] Input length: %d bytes\n", asdu_len);
    printf("[CRYPTO-EXEC] Nonce length: 12 bytes\n");
    printf("[CRYPTO-EXEC] Tag length: 16 bytes\n");
    
    /* Encrypt ASDU using AES-256-GCM (IEC 62351-5:2023 Clause 8.5.2.2) */
    ret = mbedtls_gcm_crypt_and_tag(&gcm_temp, MBEDTLS_GCM_ENCRYPT, 
                                    asdu_len, nonce, 12, NULL, 0, 
                                    original_asdu, ciphertext, 16, tag);
    mbedtls_gcm_free(&gcm_temp);
    
    if (ret != 0) {
        printf("[CRYPTO-ERROR] Encryption failed: -0x%04X\n", -ret);
        GLOBAL_FREEMEM(original_asdu);
        GLOBAL_FREEMEM(ciphertext);
        return false;
    }
    
    printf("[CRYPTO-EXEC] Encryption successful\n\n");
    
    printf("[PAYLOAD-POST] ----- ENCRYPTED OUTPUT -----\n");
    printf("[PAYLOAD-POST] Authentication Tag (16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02X ", tag[i]);
    printf("\n[PAYLOAD-POST] Ciphertext (%d bytes):\n[PAYLOAD-POST] ", asdu_len);
    for (int i = 0; i < asdu_len; i++) {
        printf("%02X ", ciphertext[i]);
        if ((i + 1) % 16 == 0 && i < asdu_len - 1) printf("\n[PAYLOAD-POST] ");
    }
    printf("\n[PAYLOAD-POST] ----- END ENCRYPTED OUTPUT -----\n\n");
    
    GLOBAL_FREEMEM(original_asdu);

    /* Reset frame and rebuild with encrypted ASDU */
    Frame_resetFrame(genericFrame);
    
    /* Build encrypted ASDU using frame API */
    Frame_setNextByte(genericFrame, S_SE_NA_1);  /* Type ID for secure ASDU */
    Frame_setNextByte(genericFrame, 1);           /* VSQ: 1 element */
    Frame_setNextByte(genericFrame, CS101_COT_SPONTANEOUS);  /* COT */
    Frame_setNextByte(genericFrame, 0);           /* OA */
    Frame_setNextByte(genericFrame, 0);           /* CA LSB */
    Frame_setNextByte(genericFrame, 0);           /* CA MSB */
    
    /* Add SecurityEncryptedData information object */
    /* IOA (3 bytes) - using 0 */
    Frame_setNextByte(genericFrame, 0);
    Frame_setNextByte(genericFrame, 0);
    Frame_setNextByte(genericFrame, 0);
    
    /* Nonce (12 bytes) */
    Frame_appendBytes(genericFrame, nonce, 12);
    
    /* Tag (16 bytes) */
    Frame_appendBytes(genericFrame, tag, 16);
    
    /* Ciphertext (variable length - no length field, calculated from remaining bytes) */
    Frame_appendBytes(genericFrame, ciphertext, asdu_len);
    
    GLOBAL_FREEMEM(ciphertext);
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Increment DSQ after encryption */
    self->DSQ_local++;
    
    printf("[ENCRYPT-RESULT] ----- ENCRYPTION COMPLETE -----\n");
    printf("[ENCRYPT-RESULT] New ASDU Type: %d (S_SE_NA_1 - Encrypted wrapper)\n", S_SE_NA_1);
    printf("[ENCRYPT-RESULT] New ASDU Length: %d bytes (header:9 + nonce:12 + tag:16 + ciphertext:%d)\n", 
           9 + 12 + 16 + asdu_len, asdu_len);
    printf("[ENCRYPT-RESULT] DSQ incremented to: %u\n", self->DSQ_local);
    printf("[ENCRYPT-RESULT] Ready for transmission\n");
    printf("\n");

    return true;
#else
    return true;
#endif
}

/* Forward declaration */
extern bool AProfile_handleCompliantMessage(AProfileContext self, CS101_ASDU asdu);

AProfileKind
AProfile_handleInPdu(AProfileContext self, const uint8_t* in, int inSize, const uint8_t** out, int* outSize)
{
#if (CONFIG_CS104_APROFILE == 1)
    /* Handle incoming key exchange messages */
    printf("[APROFILE] AProfile_handleInPdu called (inSize=%d)\n", inSize);
    fflush(stdout);
    
    /* Debug: Print first few bytes of buffer */
    if (inSize > 0) {
        printf("[APROFILE] First 10 bytes of buffer: ");
        for (int i = 0; i < (inSize > 10 ? 10 : inSize); i++) {
            printf("%02X ", in[i]);
        }
        printf("\n");
        fflush(stdout);
    }
    
    struct sCS101_ASDU _asdu;
    CS101_ASDU asdu = CS101_ASDU_createFromBufferEx(&_asdu, self->parameters, (uint8_t*)in, inSize);

    if (asdu) {
        TypeID typeId = CS101_ASDU_getTypeID(asdu);
        printf("[APROFILE] Received ASDU Type: %d (expected S_AR_NA_1=140, S_AS_NA_1=141, etc.)\n", typeId);
        fflush(stdout);
        
        /* Route IEC 62351-5:2023 compliant messages to the proper handler */
        if (typeId == S_AR_NA_1 || typeId == S_AS_NA_1 || 
            typeId == S_UK_NA_1 || typeId == S_UR_NA_1 ||
            typeId == S_SR_NA_1 || typeId == S_SS_NA_1 ||
            typeId == S_SK_NA_1 || typeId == S_SQ_NA_1) {
            
            printf("[APROFILE] Routing security message (Type=%d) to handler...\n", typeId);
            fflush(stdout);
            
            if (AProfile_handleCompliantMessage(self, asdu)) {
                printf("[APROFILE] Security message handled successfully\n");
                fflush(stdout);
                *out = NULL;
                *outSize = 0;
                return APROFILE_CTRL_MSG;
            } else {
                printf("[APROFILE] ERROR: Failed to handle security message\n");
                fflush(stdout);
            }
        } else {
            printf("[APROFILE] Not a security message (Type=%d), passing through\n", typeId);
            fflush(stdout);
        }
    } else {
        printf("[APROFILE] WARNING: Failed to parse ASDU from buffer (inSize=%d)\n", inSize);
        fflush(stdout);
    }

    /* LEGACY S_RP_NA_1 HANDLING - DISABLED for IEC 62351-5:2023 compliance
     * S_RP_NA_1 is now only used for legacy compatibility or post-quantum (Kyber) key exchange.
     * The compliant 8-step handshake uses S_AR_NA_1, S_AS_NA_1, etc.
     * This legacy path is kept only for Kyber support, but ECDH path is disabled.
     */
    if (asdu && CS101_ASDU_getTypeID(asdu) == S_RP_NA_1) {
        /* Only process if using Kyber algorithm - legacy ECDH path is disabled */
#ifdef HAVE_LIBOQS
        if (self->selectedAlgorithm == APROFILE_ALG_KYBER) {
            int ret;
            for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
                union uInformationObject _io;
                SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, i);
                
                if (spk && InformationObject_getObjectAddress((InformationObject)spk) == 65535) {
                    const uint8_t* peer_key = SecurityPublicKey_getKeyValue(spk);
                    int peer_key_len = SecurityPublicKey_getKeyLength(spk);
                    
                    if (peer_key_len >= KYBER_CHUNK_HDR && (peer_key[0] == KYBER_CHUNK_KIND_PK || peer_key[0] == KYBER_CHUNK_KIND_CT)) {
                        /* Kyber chunked data handling - kept for post-quantum support */
                        uint8_t kind = peer_key[0];
                        if (ap_chunk_store(self, kind, peer_key, peer_key_len) == false) {
                            break;
                        } else if (ap_chunk_complete(self)) {
                            if (!self->chunk_for_ciphertext) {
                                if (!self->isControllingStation) {
                                    /* Server receiving Kyber public key */
                                    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
                                    if (kem != NULL) {
                                        if (kem->length_ciphertext <= sizeof(self->kyber_ciphertext) && 
                                            kem->length_shared_secret <= sizeof(self->kyber_shared_secret)) {
                                            if (OQS_KEM_encaps(kem, self->kyber_ciphertext, self->kyber_shared_secret, self->chunk_assemble_buf) == OQS_SUCCESS) {
                                                self->kyber_ciphertext_len = kem->length_ciphertext;
                                                self->kyber_shared_secret_len = kem->length_shared_secret;
                                                /* Note: Kyber path uses simplified key derivation - not full IEC 62351-5:2023 */
                                                uint8_t session_key[32]; /* AES-256 key */
                                                ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                                                                   self->kyber_shared_secret, self->kyber_shared_secret_len,
                                                                   (const unsigned char*)"IEC62351-5", 11,
                                                                   session_key, sizeof(session_key));
                                                if (ret == 0) {
                                                    /* Use AES-256, not AES-128 */
                                                    memcpy(self->K_SC, session_key, 32);
                                                    memcpy(self->K_SM, session_key, 32); /* Simplified for Kyber */
                                                    mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, session_key, 256);
                                                    mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, session_key, 256);
                                                    ap_chunk_reset(self);
                                                    (void) ap_send_chunks(self, self->kyber_ciphertext, self->kyber_ciphertext_len, true);
                                                    self->security_active = true;
                                                    self->keyExchangeState = KEY_EXCHANGE_COMPLETE;
                                                }
                                            }
                                        }
                                        OQS_KEM_free(kem);
                                    }
                                }
                            } else {
                                /* Client receiving Kyber ciphertext */
                                OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
                                if (kem != NULL && self->kyber_secret_key_len == kem->length_secret_key) {
                                    uint8_t shared[64];
                                    if (OQS_KEM_decaps(kem, shared, peer_key, self->kyber_secret_key) == OQS_SUCCESS) {
                                        uint8_t session_key[32]; /* AES-256 key */
                                        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                                                          shared, kem->length_shared_secret,
                                                          (const unsigned char*)"IEC62351-5", 11,
                                                          session_key, sizeof(session_key));
                                        if (ret == 0) {
                                            /* Use AES-256, not AES-128 */
                                            memcpy(self->K_SC, session_key, 32);
                                            memcpy(self->K_SM, session_key, 32); /* Simplified for Kyber */
                                            mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, session_key, 256);
                                            mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, session_key, 256);
                                            self->security_active = true;
                                            self->keyExchangeState = KEY_EXCHANGE_COMPLETE;
                                        }
                                    }
                                    OQS_KEM_free(kem);
                                }
                            }
                        }
                        break;
                    }
                }
            }
            return APROFILE_CTRL_MSG;
        }
#endif
        /* Legacy ECDH path via S_RP_NA_1 is DISABLED - use compliant 8-step handshake instead */
        /* Return as control message but do not process */
        return APROFILE_CTRL_MSG;
    }
    

    /* Check if security is active and if this is an encrypted ASDU */
    printf("[DECRYPT-DEBUG] Checking if security is active: %s\n", self->security_active ? "TRUE" : "FALSE");
    if (!self->security_active) {
        printf("[DECRYPT-DEBUG] Security not active - passing through plaintext\n");
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }

    /* Check if the incoming message is a secure ASDU (type S_SE_NA_1) */
    printf("[DECRYPT-DEBUG] Checking ASDU type: %d (S_SE_NA_1=%d)\n", (inSize > 0) ? in[0] : -1, S_SE_NA_1);
    if (inSize < 1 || in[0] != S_SE_NA_1) {
        printf("[DECRYPT-DEBUG] Not S_SE_NA_1 - passing through plaintext\n");
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }
    
    printf("[DECRYPT-DEBUG] Received S_SE_NA_1 - proceeding with AES-256-GCM decryption...\n");

    /* Parse the SecurityEncryptedData information object */
    SecurityEncryptedData sed = SecurityEncryptedData_getFromBuffer(NULL, self->parameters, (uint8_t*)in + 6, inSize - 6, 0, false);
    if (!sed) {
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }

    const uint8_t* nonce = SecurityEncryptedData_getNonce(sed);
    const uint8_t* tag = SecurityEncryptedData_getTag(sed);
    const uint8_t* ciphertext = SecurityEncryptedData_getCiphertext(sed);
    int ciphertext_len = SecurityEncryptedData_getCiphertextLength(sed);

    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Extract DSQ from nonce (first 4 bytes, little-endian) */
    uint32_t received_dsq;
    received_dsq = (uint32_t)nonce[0] | 
                   ((uint32_t)nonce[1] << 8) | 
                   ((uint32_t)nonce[2] << 16) | 
                   ((uint32_t)nonce[3] << 24);

    /* Debug: Show encrypted input prior to decryption */
    printf("\n[DECRYPT-PRE] ----- ENCRYPTED INPUT RECEIVED -----\n");
    printf("[DECRYPT-PRE] Nonce (12 bytes): ");
    for (int i = 0; i < 12; i++) printf("%02X ", nonce[i]);
    printf("\n[DECRYPT-PRE] DSQ (little-endian): %u (0x%08X)\n", received_dsq, received_dsq);
    printf("[DECRYPT-PRE] Authentication Tag (16 bytes): ");
    for (int i = 0; i < 16; i++) printf("%02X ", tag[i]);
    printf("\n[DECRYPT-PRE] Ciphertext (%d bytes):\n[DECRYPT-PRE] ", ciphertext_len);
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02X ", ciphertext[i]);
        if ((i + 1) % 16 == 0 && i < ciphertext_len - 1) printf("\n[DECRYPT-PRE] ");
    }
    printf("\n[DECRYPT-PRE] ----- END ENCRYPTED INPUT -----\n\n");

    /* Verify DSQ to prevent replay attacks - IEC 62351-5:2023 Clause 8.5.2.2.4 */
    /* Note: DSQ_remote starts at 0, first message should have DSQ=1 */
    if (self->DSQ_remote != 0 && received_dsq <= self->DSQ_remote) {
        SecurityEncryptedData_destroy(sed);
        *out = NULL;
        *outSize = 0;
        return APROFILE_PLAINTEXT;
    }
    
    /* Verify DSQ is not 0 (invalid) */
    if (received_dsq == 0) {
        SecurityEncryptedData_destroy(sed);
        *out = NULL;
        *outSize = 0;
        return APROFILE_PLAINTEXT;
    }

    /* Allocate buffer for decrypted plaintext */
    *outSize = ciphertext_len;
    *out = (const uint8_t*)GLOBAL_MALLOC(*outSize);
    if (!*out) {
        SecurityEncryptedData_destroy(sed);
        *outSize = 0;
        return APROFILE_PLAINTEXT;
    }

    /* IEC 62351-5:2023 Clause 8.5.2: Select appropriate session key based on direction
     * Controlling station receives on monitor direction (uses K_SM)
     * Controlled station receives on control direction (uses K_SC)
     */
    const uint8_t* session_key = self->isControllingStation ? self->K_SM : self->K_SC;
    printf("[DECRYPT-PARAMS] Session Key (%s): ", self->isControllingStation ? "K_SM" : "K_SC");
    for (int i = 0; i < 32; i++) printf("%02X ", session_key[i]);
    printf("\n");
    
    /* Reinitialize GCM context with correct key for this direction */
    mbedtls_gcm_context gcm_temp;
    mbedtls_gcm_init(&gcm_temp);
    int ret = mbedtls_gcm_setkey(&gcm_temp, MBEDTLS_CIPHER_ID_AES, session_key, 256);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm_temp);
        SecurityEncryptedData_destroy(sed);
        GLOBAL_FREEMEM((void*)*out);
        *out = NULL;
        *outSize = 0;
        return APROFILE_PLAINTEXT;
    }
    
    /* Decrypt and authenticate using AES-256-GCM - IEC 62351-5:2023 Clause 8.5.2.2 */
    printf("[DECRYPT-EXEC] Executing AES-256-GCM decryption...\n");
    printf("[DECRYPT-EXEC] Input length: %d bytes\n", ciphertext_len);
    printf("[DECRYPT-EXEC] Nonce length: 12 bytes\n");
    printf("[DECRYPT-EXEC] Tag length: 16 bytes\n");
    int dec_ret = mbedtls_gcm_auth_decrypt(&gcm_temp, ciphertext_len, 
                                           nonce, 12, NULL, 0, 
                                           tag, 16, ciphertext, (uint8_t*)*out);
    mbedtls_gcm_free(&gcm_temp);

    SecurityEncryptedData_destroy(sed);

    if (dec_ret != 0) {
        GLOBAL_FREEMEM((void*)*out);
        *out = NULL;
        *outSize = 0;
        return APROFILE_PLAINTEXT;
    }

    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Update DSQ after successful decryption */
    self->DSQ_remote = received_dsq;
    
    /* Debug: Show decrypted plaintext ASDU */
    printf("[DECRYPT-POST] ----- PLAINTEXT ASDU (AFTER DECRYPTION) -----\n");
    const uint8_t* plaintext = *out;
    int plaintext_len = *outSize;
    printf("[DECRYPT-POST] ASDU Length: %d bytes\n", plaintext_len);
    if (plaintext_len >= 3) {
        printf("[DECRYPT-POST] ASDU Type: %d\n", plaintext[0]);
        printf("[DECRYPT-POST] VSQ: %d\n", plaintext[1]);
        printf("[DECRYPT-POST] COT: %d\n", plaintext[2]);
    }
    printf("[DECRYPT-POST] Full ASDU hex dump:\n[DECRYPT-POST] ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02X ", plaintext[i]);
        if ((i + 1) % 16 == 0 && i < plaintext_len - 1) printf("\n[DECRYPT-POST] ");
    }
    printf("\n[DECRYPT-POST] ----- END PLAINTEXT ASDU -----\n\n");
    
    return APROFILE_SECURE_DATA;
#else
    *out = in;
    *outSize = inSize;
    return APROFILE_PLAINTEXT;
#endif
}


