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

#include "aprofile_context.h"

#if (CONFIG_CS104_APROFILE == 1)

#include "mbedtls/gcm.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/entropy.h"

#include "iec60870_common.h"

typedef bool (*AProfile_SendAsduCallback)(void* connection, CS101_ASDU asdu);

typedef enum {
    APROFILE_ALG_ECDH = 1,
    APROFILE_ALG_KYBER = 2
} AProfileAlgorithm;

typedef enum {
    KEY_EXCHANGE_IDLE,
    KEY_EXCHANGE_AWAIT_REPLY,
    KEY_EXCHANGE_COMPLETE
} KeyExchangeState;

/* Placeholder for security state */
struct sAProfileContext
{
    bool security_active;
    bool isClient; /* true for client (CS104_Connection), false for server (MasterConnection) */
    uint32_t local_sequence_number;
    uint32_t remote_sequence_number;

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

#else

/* This is a dummy struct for when A-profile is disabled */
struct sAProfileContext
{
    bool security_active;
};

#endif /* CONFIG_CS104_APROFILE */

#endif /* APROFILE_INTERNAL_H_ */