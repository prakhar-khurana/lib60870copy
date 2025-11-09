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

#ifndef APROFILE_INTERNAL_H_
#define APROFILE_INTERNAL_H_

#include "lib60870_config.h"
#include "aprofile_context.h"

#ifdef __cplusplus
extern "C" {}
#endif

#if (CONFIG_CS104_APROFILE == 1)

#include "mbedtls/gcm.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/entropy.h"

#include "iec60870_common.h"

#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>

typedef bool (*AProfile_SendAsduCallback)(void* connection, CS101_ASDU asdu);

typedef enum {
    KEY_EXCHANGE_IDLE,
    KEY_EXCHANGE_AWAIT_REPLY,
    KEY_EXCHANGE_COMPLETE
} KeyExchangeState;

/* IEC 62351-5:2023 Compliant State Machine */
typedef enum {
    APROFILE_STATE_IDLE = 0,
    APROFILE_STATE_ASSOC_PENDING = 1,
    APROFILE_STATE_ASSOC_COMPLETE = 2,
    APROFILE_STATE_UPDATE_KEY_PENDING = 3,
    APROFILE_STATE_UPDATE_KEY_COMPLETE = 4,
    APROFILE_STATE_SESSION_PENDING = 5,
    APROFILE_STATE_SESSION_KEY_PENDING = 6,
    APROFILE_STATE_ESTABLISHED = 7
} AProfileState;

/* Placeholder for security state */
struct sAProfileContext
{
    bool security_active;  /* Security session active flag */
    bool isControllingStation; /* true for controlling station (CS104_Connection/client), false for controlled station (MasterConnection/server) - IEC 62351-5:2023 */
    /* Note: DSQ_local and DSQ_remote moved below with other IEC 62351-5:2023 variables */

    void* connection; /* Reference to the CS104_Connection or MasterConnection */
    AProfile_SendAsduCallback sendAsdu;
    CS101_AppLayerParameters parameters; /* Application layer parameters for ASDU creation */

    KeyExchangeState keyExchangeState;

    AProfileAlgorithm selectedAlgorithm;

    mbedtls_ecdh_context ecdh;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_gcm_context gcm_encrypt;
    mbedtls_gcm_context gcm_decrypt;

    uint8_t localPublicKey[65];
    int localPublicKeyLen;

    /* IEC 62351-5:2023 Two-Level Key Hierarchy - Standard Nomenclature */
    uint8_t K_UE[32];      /* K_UE: Encryption Update Key (256-bit) - Clause 8.3.10 */
    uint8_t K_UA[32];      /* K_UA: Authentication Update Key (256-bit) - Clause 8.3.10 */
    uint8_t K_SC[32];      /* K_SC: Control Direction Session Key (256-bit) - Clause 8.4.2 */
    uint8_t K_SM[32];      /* K_SM: Monitor Direction Session Key (256-bit) - Clause 8.4.2 */
    
    /* Random Data for HKDF Salt - IEC 62351-5:2023 Clause 8.3.10.4 */
    uint8_t R_C[32];       /* R_C: Controlling Station Random (32 bytes) */
    uint8_t R_S[32];       /* R_S: Controlled Station Random (32 bytes) */
    
    /* State Machine - IEC 62351-5:2023 Clause 8.3 */
    AProfileState state;
    
    /* Association IDs - IEC 62351-5:2023 Clause 8.3.1 */
    uint16_t AIM;          /* AIM: Controlling Station Association ID */
    uint16_t AIS;          /* AIS: Controlled Station Association ID */
    
    /* Data Sequence Number - IEC 62351-5:2023 Clause 8.5.2.2.4 */
    uint32_t DSQ_local;    /* DSQ: Local Data Sequence Number (starts at 1) */
    uint32_t DSQ_remote;   /* DSQ: Remote Data Sequence Number */

    /* Buffer for hybrid key exchange material */
    uint8_t localHybridKey[2048];
    int localHybridKeyLen;

    uint16_t suite_id;          /* Security suite ID */
    uint16_t kem_id;            /* KEM algorithm ID */
    uint8_t hash_id;            /* Hash algorithm ID */
    
    /* Transcript hash context */
    mbedtls_md_context_t th_ctx;
    
    /* Policy flags */
    uint16_t required_suite;    /* Required suite (reject downgrade) */
    uint8_t role_who_decapsulates; /* OPTION_1 or OPTION_2 */
    
    /* Reassembly state */
    uint32_t last_chunk_time;   /* Timestamp of last received chunk */
    uint16_t chunk_association_id; /* Association ID for current reassembly */
    uint8_t chunk_kind;         /* Kind of current reassembly */
    uint8_t chunk_hash_id;      /* Hash ID of current reassembly */

    /* mbedTLS certificate fields */
    mbedtls_x509_crt ca_cert;
    mbedtls_pk_context private_key;
    mbedtls_x509_crt local_cert;
    mbedtls_rsa_context rsa_private_key;

#ifdef HAVE_LIBOQS
    /* Kyber buffers (sizes per Kyber768 worst-case) */
    uint8_t kyber_pubkey[2048];
    size_t kyber_pubkey_len;
    uint8_t kyber_ciphertext[2048];
    size_t kyber_ciphertext_len;
    uint8_t kyber_shared_secret[64];
    size_t kyber_shared_secret_len;
    uint8_t kyber_secret_key[4096];
    size_t kyber_secret_key_len;

    /* Chunk reassembly state */
    uint8_t chunk_assemble_buf[4096];
    size_t chunk_expected_len;
    uint16_t chunk_expected_total;
    uint16_t chunk_received_count;
    uint8_t chunk_received_bitmap[512]; /* up to 4096/8 chunks */
    bool chunk_for_ciphertext; /* false: assembling pubkey, true: assembling ciphertext */
#endif
};

void AProfile_setAlgorithm(AProfileContext self, AProfileAlgorithm alg);

/* IEC 62351-5:2023 Integration Functions */
bool AProfile_loadCertificate(AProfileContext self, const char* certPath, const char* keyPath, const char* caPath);
bool AProfile_initiateHandshake(AProfileContext self);
bool AProfile_sendSecureASdu(AProfileContext self, CS101_ASDU asdu);
void AProfile_printKeys(AProfileContext self);
const char* AProfile_getStateName(AProfileContext self);
bool AProfile_encryptASdu(AProfileContext self, const uint8_t* plaintext, size_t plaintext_len,
                          uint8_t* ciphertext, size_t* ciphertext_len, uint8_t* tag);
bool AProfile_decryptASdu(AProfileContext self, const uint8_t* ciphertext, size_t ciphertext_len,
                          const uint8_t* tag, uint32_t sequence_number,
                          uint8_t* plaintext, size_t* plaintext_len);
                          
bool AProfile_sendUpdateKeyChangeRequest(AProfileContext self);
bool AProfile_sendSessionRequest(AProfileContext self);
bool AProfile_sendSessionKeyChangeRequest(AProfileContext self);
bool AProfile_startCompliantHandshake(AProfileContext self);

#else

/* This is a dummy struct for when A-profile is disabled */
struct sAProfileContext
{
    bool security_active;
};

#endif /* CONFIG_CS104_APROFILE */



#endif /* APROFILE_INTERNAL_H_ */