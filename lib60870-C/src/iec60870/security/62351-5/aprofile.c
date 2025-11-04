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
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

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
    self->isClient = isClient;

    mbedtls_gcm_init(&self->gcm_encrypt);
    
    mbedtls_ecdh_init(&self->ecdh);
    
    /* For mbedtls 2.x with new context, set point format */
    #if !defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    self->ecdh.point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
    #endif
    
    mbedtls_ctr_drbg_init(&self->ctr_drbg);
    mbedtls_entropy_init(&self->entropy);
    mbedtls_gcm_init(&self->gcm_decrypt);

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
    self->local_sequence_number = 1;
    self->remote_sequence_number = 0;
    
    /* Initialize IEC 62351-5:2023 state machine */
    self->state = APROFILE_STATE_IDLE;
    self->association_id = 0;
    
    /* Clear key material */
    memset(self->encryption_update_key, 0, sizeof(self->encryption_update_key));
    memset(self->authentication_update_key, 0, sizeof(self->authentication_update_key));
    memset(self->control_session_key, 0, sizeof(self->control_session_key));
    memset(self->monitor_session_key, 0, sizeof(self->monitor_session_key));
    memset(self->controlling_station_random, 0, sizeof(self->controlling_station_random));
    memset(self->controlled_station_random, 0, sizeof(self->controlled_station_random));

    /* Initialize OpenSSL */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);

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
        
        /* Free OpenSSL resources */
        if (self->ca_cert) X509_free(self->ca_cert);
        if (self->private_key) EVP_PKEY_free(self->private_key);
        if (self->local_cert) X509_free(self->local_cert);

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
    /* Prevent multiple key exchanges */
    if (self->keyExchangeState != KEY_EXCHANGE_IDLE)
        return true;

    /* Only client initiates key exchange */
    if (!self->isClient)
        return true;

    int ret;

    if (self->selectedAlgorithm == APROFILE_ALG_ECDH) {
        /* Free and re-initialize the group to ensure clean state */
        mbedtls_ecp_group_free(&self->ecdh.grp);
        mbedtls_ecp_group_init(&self->ecdh.grp);

        /* Initialize ECDH context and load the curve */
        ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0)
            return false;

        /* Generate our ECDH key pair using low-level ECP API */
        ret = mbedtls_ecdh_gen_public(&self->ecdh.grp, &self->ecdh.d, &self->ecdh.Q,
                                       mbedtls_ctr_drbg_random, &self->ctr_drbg);
        if (ret != 0)
            return false;

        /* Export public key to buffer */
        size_t olen = 0;
        ret = mbedtls_ecp_point_write_binary(&self->ecdh.grp, &self->ecdh.Q,
                                              MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                              self->localPublicKey, sizeof(self->localPublicKey));
        if (ret != 0)
            return false;

        self->localPublicKeyLen = (int)olen;
    }
#ifdef HAVE_LIBOQS
    else if (self->selectedAlgorithm == APROFILE_ALG_KYBER) {
        /* Generate ECDH part of hybrid key */
        mbedtls_ecp_group_free(&self->ecdh.grp);
        mbedtls_ecp_group_init(&self->ecdh.grp);
        ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) return false;
        ret = mbedtls_ecdh_gen_public(&self->ecdh.grp, &self->ecdh.d, &self->ecdh.Q, mbedtls_ctr_drbg_random, &self->ctr_drbg);
        if (ret != 0) return false;
        size_t ecdh_pk_len = 0;
        ret = mbedtls_ecp_point_write_binary(&self->ecdh.grp, &self->ecdh.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &ecdh_pk_len, self->localPublicKey, sizeof(self->localPublicKey));
        if (ret != 0) return false;
        self->localPublicKeyLen = (int)ecdh_pk_len;

        /* Generate Kyber part of hybrid key */
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        if (kem == NULL) return false;
        if (kem->length_public_key > sizeof(self->kyber_pubkey) || kem->length_secret_key > sizeof(self->kyber_secret_key)) {
            OQS_KEM_free(kem);
            return false;
        }
        if (OQS_KEM_keypair(kem, self->kyber_pubkey, self->kyber_secret_key) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            return false;
        }
        self->kyber_pubkey_len = kem->length_public_key;
        self->kyber_secret_key_len = kem->length_secret_key;
        OQS_KEM_free(kem);

        /* Concatenate ECDH pubkey and Kyber pubkey for transmission */
        if (self->localPublicKeyLen + self->kyber_pubkey_len > sizeof(self->localHybridKey)) return false;
        memcpy(self->localHybridKey, self->localPublicKey, self->localPublicKeyLen);
        memcpy(self->localHybridKey + self->localPublicKeyLen, self->kyber_pubkey, self->kyber_pubkey_len);
        self->localHybridKeyLen = self->localPublicKeyLen + self->kyber_pubkey_len;
    }
#endif
    else if (self->selectedAlgorithm == APROFILE_ALG_CERT) {
        /* Load certificates */
        if (!load_certificates(self, 
            "server.crt", "server.key", "ca.crt")) {
            return false;
        }
        
        /* Send certificate */
        uint8_t cert_der[2048];
        uint8_t* p = cert_der;
        int len = i2d_X509(self->local_cert, &p);
        
        CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
        if (!asdu) return false;
        CS101_ASDU_setTypeID(asdu, S_RP_NA_1);
        SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, len, cert_der);
        if (!spk) { CS101_ASDU_destroy(asdu); return false; }
        CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
        SecurityPublicKey_destroy(spk);
        if (self->sendAsdu) (void) self->sendAsdu(self->connection, asdu);
        CS101_ASDU_destroy(asdu);
    }
    else {
        return false;
    }

    /* Send key exchange material */
#ifdef HAVE_LIBOQS
    if (self->selectedAlgorithm == APROFILE_ALG_KYBER) {
        /* Send hybrid ECDH+Kyber public key in chunks */
        ap_chunk_reset(self);
        if (ap_send_chunks(self, self->localHybridKey, self->localHybridKeyLen, false) != 0) return false;
    } else
#endif
    {
        CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
        if (!asdu) return false;
        CS101_ASDU_setTypeID(asdu, S_RP_NA_1);
        SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, self->localPublicKeyLen, self->localPublicKey);
        if (!spk) { CS101_ASDU_destroy(asdu); return false; }
        CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
        SecurityPublicKey_destroy(spk);
        if (self->sendAsdu) self->sendAsdu(self->connection, asdu);
        CS101_ASDU_destroy(asdu);
    }

    self->keyExchangeState = KEY_EXCHANGE_AWAIT_REPLY;

    return true; /* We are not ready yet, but the process has started */
#else
    return true;
#endif
}

static bool load_certificates(AProfileContext self, const char* cert_path, const char* key_path, const char* ca_path)
{
    FILE* fp = fopen(cert_path, "r");
    if (!fp) return false;
    self->local_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!self->local_cert) return false;

    fp = fopen(key_path, "r");
    if (!fp) return false;
    self->private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!self->private_key) return false;

    fp = fopen(ca_path, "r");
    if (!fp) return false;
    self->ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return (self->ca_cert != NULL);
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
    if (!self->security_active || !AProfile_ready(self)) {
        return true; /* Do nothing if security is not active */
    }

    /* Use Frame interface instead of T104Frame to avoid type mismatch issues */
    Frame genericFrame = (Frame)frame;
    uint8_t* frame_buffer = Frame_getBuffer(genericFrame);
    uint8_t* asdu_buffer = frame_buffer + 6;
    int frame_size = Frame_getMsgSize(genericFrame);
    int asdu_len = frame_size - 6;

    /* Save original ASDU for encryption */
    uint8_t* original_asdu = (uint8_t*)GLOBAL_MALLOC(asdu_len);
    if (!original_asdu)
        return false;
    
    memcpy(original_asdu, asdu_buffer, asdu_len);

    /* Generate nonce: 4 bytes sequence number + 8 bytes random */
    uint8_t nonce[12];
    memcpy(nonce, &self->local_sequence_number, 4);
    mbedtls_ctr_drbg_random(&self->ctr_drbg, nonce + 4, 8);

    uint8_t tag[16];
    uint8_t* ciphertext = (uint8_t*)GLOBAL_MALLOC(asdu_len);
    if (!ciphertext) {
        GLOBAL_FREEMEM(original_asdu);
        return false;
    }

    /* Encrypt ASDU using AES-GCM */
    int ret = mbedtls_gcm_crypt_and_tag(&self->gcm_encrypt, MBEDTLS_GCM_ENCRYPT, 
                                        asdu_len, nonce, 12, NULL, 0, 
                                        original_asdu, ciphertext, 16, tag);
    
    GLOBAL_FREEMEM(original_asdu);
    
    if (ret != 0) {
        GLOBAL_FREEMEM(ciphertext);
        return false;
    }

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
    
    /* Increment sequence number */
    self->local_sequence_number++;

    return true;
#else
    return true;
#endif
}

AProfileKind
AProfile_handleInPdu(AProfileContext self, const uint8_t* in, int inSize, const uint8_t** out, int* outSize)
{
#if (CONFIG_CS104_APROFILE == 1)
    /* Handle incoming key exchange messages */
    struct sCS101_ASDU _asdu;
    CS101_ASDU asdu = CS101_ASDU_createFromBufferEx(&_asdu, self->parameters, (uint8_t*)in, inSize);

    if (asdu && CS101_ASDU_getTypeID(asdu) == S_RP_NA_1) {

        int ret;
        for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
            union uInformationObject _io;
            SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, i);
            
            if (spk && InformationObject_getObjectAddress((InformationObject)spk) == 65535) {
                /* Extract public key and perform key exchange */
                const uint8_t* peer_key = SecurityPublicKey_getKeyValue(spk);
                int peer_key_len = SecurityPublicKey_getKeyLength(spk);
                bool treated = false;
                bool is_hybrid = false;

#ifdef HAVE_LIBOQS
                if (peer_key_len >= KYBER_CHUNK_HDR && (peer_key[0] == KYBER_CHUNK_KIND_PK || peer_key[0] == KYBER_CHUNK_KIND_CT)) {
                    /* Chunked Kyber data */
                    uint8_t kind = peer_key[0];
                    if (ap_chunk_store(self, kind, peer_key, peer_key_len) == false) {
                        treated = true; /* ignore bad chunk */
                    } else if (ap_chunk_complete(self)) {
                        if (!self->chunk_for_ciphertext) {
                            /* We received full Kyber public key from client */
                            if (!self->isClient) {
                                OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
                                if (kem == NULL) { treated = true; }
                                else {
                                    if (kem->length_ciphertext > sizeof(self->kyber_ciphertext) || kem->length_shared_secret > sizeof(self->kyber_shared_secret)) {
                                        OQS_KEM_free(kem);
                                    } else if (OQS_KEM_encaps(kem, self->kyber_ciphertext, self->kyber_shared_secret, self->chunk_assemble_buf) == OQS_SUCCESS) {
                                        self->kyber_ciphertext_len = kem->length_ciphertext;
                                        self->kyber_shared_secret_len = kem->length_shared_secret;
                                        uint8_t session_key[16];
                                        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                                                           self->kyber_shared_secret, self->kyber_shared_secret_len,
                                                           (const unsigned char*)"IEC62351-5", 11,
                                                           session_key, sizeof(session_key));
                                        if (ret == 0) {
                                            mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                                            mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                                            /* send ciphertext in chunks */
                                            ap_chunk_reset(self);
                                            (void) ap_send_chunks(self, self->kyber_ciphertext, self->kyber_ciphertext_len, true);
                                            self->security_active = true;
                                            self->keyExchangeState = KEY_EXCHANGE_COMPLETE;
                                        }
                                    }
                                    OQS_KEM_free(kem);
                                }
                            }
                            treated = true;
                        } else {
                        /* Client receiving server response: peer_key is ciphertext, decapsulate using stored secret key */
                        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
                        if (kem == NULL) break;
                        if (self->kyber_secret_key_len != kem->length_secret_key) { OQS_KEM_free(kem); break; }
                        uint8_t shared[64];
                        if (OQS_KEM_decaps(kem, shared, peer_key, self->kyber_secret_key) != OQS_SUCCESS) { OQS_KEM_free(kem); break; }
                        uint8_t session_key[16];
                        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                                          shared, kem->length_shared_secret,
                                          (const unsigned char*)"IEC62351-5", 11,
                                          session_key, sizeof(session_key));
                        OQS_KEM_free(kem);
                        if (ret != 0) break;
                        mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                        mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                        self->security_active = true;
                        self->keyExchangeState = KEY_EXCHANGE_COMPLETE;
                        treated = true;
                    }
                }
#endif

                if (!treated) {
                    /* ECDH path */
                    /* Ensure the group is loaded */
                    if (self->ecdh.grp.id == MBEDTLS_ECP_DP_NONE) {
                        ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
                        if (ret != 0) { break; }

                        /* Generate our key pair if not done yet */
                        ret = mbedtls_ecdh_gen_public(&self->ecdh.grp, &self->ecdh.d, &self->ecdh.Q,
                                                       mbedtls_ctr_drbg_random, &self->ctr_drbg);
                        if (ret != 0) { break; }

                        /* If we're the server, send our public key back */
                        if (!self->isClient) {
                            size_t olen = 0;
                            ret = mbedtls_ecp_point_write_binary(&self->ecdh.grp, &self->ecdh.Q,
                                                                  MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                                                  self->localPublicKey, sizeof(self->localPublicKey));
                            if (ret == 0) {
                                self->localPublicKeyLen = (int)olen;

                                CS101_ASDU response = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
                                if (response) {
                                    CS101_ASDU_setTypeID(response, S_RP_NA_1);
                                    SecurityPublicKey spk_resp = SecurityPublicKey_create(NULL, 65535, self->localPublicKeyLen, self->localPublicKey);
                                    if (spk_resp) {
                                        CS101_ASDU_addInformationObject(response, (InformationObject)spk_resp);
                                        SecurityPublicKey_destroy(spk_resp);
                                        if (self->sendAsdu) { (void) self->sendAsdu(self->connection, response); }
                                        CS101_ASDU_destroy(response);
                                    } else {
                                        CS101_ASDU_destroy(response);
                                    }
                                }
                            }
                        }
                    }

                    /* Read peer's public key using low-level ECP API */
                    ret = mbedtls_ecp_point_read_binary(&self->ecdh.grp, &self->ecdh.Qp, peer_key, peer_key_len);
                    if (ret != 0) { break; }

                    /* Compute shared secret using low-level ECDH API */
                    ret = mbedtls_ecdh_compute_shared(&self->ecdh.grp, &self->ecdh.z,
                                                       &self->ecdh.Qp, &self->ecdh.d,
                                                       mbedtls_ctr_drbg_random, &self->ctr_drbg);
                    if (ret != 0) { break; }

                    /* Export shared secret to buffer */
                    uint8_t shared_secret[32];
                    size_t shared_secret_len = mbedtls_mpi_size(&self->ecdh.z);
                    if (shared_secret_len > sizeof(shared_secret)) { break; }
                    ret = mbedtls_mpi_write_binary(&self->ecdh.z, shared_secret, shared_secret_len);
                    if (ret != 0) { break; }

                    uint8_t session_key[16];
                    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                                      shared_secret, shared_secret_len,
                                      (const unsigned char*)"IEC62351-5", 11,
                                      session_key, sizeof(session_key));
                    if (ret != 0) { break; }

                    mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                    mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);

                    self->security_active = true;
                    self->keyExchangeState = KEY_EXCHANGE_COMPLETE;
                }

                break;
            }
        }

        return APROFILE_CTRL_MSG;
    }
    

    /* Check if security is active and if this is an encrypted ASDU */
    if (!self->security_active) {
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }

    /* Check if the incoming message is a secure ASDU (type S_SE_NA_1) */
    if (inSize < 1 || in[0] != S_SE_NA_1) {
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }

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

    /* Extract sequence number from nonce (first 4 bytes) for replay protection */
    uint32_t received_seq;
    memcpy(&received_seq, nonce, 4);

    /* Verify sequence number to prevent replay attacks */
    /* Note: For the first message, remote_sequence_number is 0, so we accept seq=0 */
    if (self->remote_sequence_number != 0 && received_seq <= self->remote_sequence_number) {
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

    /* Decrypt and authenticate using AES-GCM */
    int dec_ret = mbedtls_gcm_auth_decrypt(&self->gcm_decrypt, ciphertext_len, 
                                           nonce, 12, NULL, 0, 
                                           tag, 16, ciphertext, (uint8_t*)*out);

    SecurityEncryptedData_destroy(sed);

    if (dec_ret != 0) {
        GLOBAL_FREEMEM((void*)*out);
        *out = NULL;
        *outSize = 0;
        return APROFILE_PLAINTEXT;
    }

    /* Update sequence number after successful decryption */
    self->remote_sequence_number = received_seq;
    
    return APROFILE_SECURE_DATA;
#else
    *out = in;
    *outSize = inSize;
    return APROFILE_PLAINTEXT;
#endif
}

AProfileKind
AProfile_handleInPdu(AProfileContext self, const uint8_t* in, int inSize, const uint8_t** out, int* outSize)
{
#if (CONFIG_CS104_APROFILE == 1)
    /* Handle incoming key exchange messages */
    struct sCS101_ASDU _asdu;
    CS101_ASDU asdu = CS101_ASDU_createFromBufferEx(&_asdu, self->parameters, (uint8_t*)in, inSize);

    if (asdu && CS101_ASDU_getTypeID(asdu) == S_RP_NA_1) {

        int ret;
        for (int i = 0; i < CS101_ASDU_getNumberOfElements(asdu); i++) {
            union uInformationObject _io;
            SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, i);
            
            if (spk && InformationObject_getObjectAddress((InformationObject)spk) == 65535) {
                /* Extract public key and perform key exchange */
                const uint8_t* peer_key = SecurityPublicKey_getKeyValue(spk);
                int peer_key_len = SecurityPublicKey_getKeyLength(spk);
                bool treated = false;
                bool is_hybrid = false;

#ifdef HAVE_LIBOQS
                if (peer_key_len >= KYBER_CHUNK_HDR && (peer_key[0] == KYBER_CHUNK_KIND_PK || peer_key[0] == KYBER_CHUNK_KIND_CT)) {
                    /* Chunked Kyber data */
                    uint8_t kind = peer_key[0];
                    if (ap_chunk_store(self, kind, peer_key, peer_key_len) == false) {
                        treated = true; /* ignore bad chunk */
                    } else if (ap_chunk_complete(self)) {
                        if (!self->chunk_for_ciphertext) {
                            /* We received full Kyber public key from client */
                            if (!self->isClient) {
                                OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
                                if (kem == NULL) { treated = true; }
                                else {
                                    if (kem->length_ciphertext > sizeof(self->kyber_ciphertext) || kem->length_shared_secret > sizeof(self->kyber_shared_secret)) {
                                        OQS_KEM_free(kem);
                                    } else if (OQS_KEM_encaps(kem, self->kyber_ciphertext, self->kyber_shared_secret, self->chunk_assemble_buf) == OQS_SUCCESS) {
                                        self->kyber_ciphertext_len = kem->length_ciphertext;
                                        self->kyber_shared_secret_len = kem->length_shared_secret;
                                        uint8_t session_key[16];
                                        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                                                           self->kyber_shared_secret, self->kyber_shared_secret_len,
                                                           (const unsigned char*)"IEC62351-5", 11,
                                                           session_key, sizeof(session_key));
                                        if (ret == 0) {
                                            mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                                            mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                                            /* send ciphertext in chunks */
                                            ap_chunk_reset(self);
                                            (void) ap_send_chunks(self, self->kyber_ciphertext, self->kyber_ciphertext_len, true);
                                            self->security_active = true;
                                            self->keyExchangeState = KEY_EXCHANGE_COMPLETE;
                                        }
                                    }
                                    OQS_KEM_free(kem);
                                }
                            }
                            treated = true;
                        } else {
                        /* Client receiving server response: peer_key is ciphertext, decapsulate using stored secret key */
                        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
                        if (kem == NULL) break;
                        if (self->kyber_secret_key_len != kem->length_secret_key) { OQS_KEM_free(kem); break; }
                        uint8_t shared[64];
                        if (OQS_KEM_decaps(kem, shared, peer_key, self->kyber_secret_key) != OQS_SUCCESS) { OQS_KEM_free(kem); break; }
                        uint8_t session_key[16];
                        ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                                          shared, kem->length_shared_secret,
                                          (const unsigned char*)"IEC62351-5", 11,
                                          session_key, sizeof(session_key));
                        OQS_KEM_free(kem);
                        if (ret != 0) break;
                        mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                        mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, session_key, 128);
                        self->security_active = true;
                        self->keyExchangeState = KEY_EXCHANGE_COMPLETE;
                        treated = true;
                    }
                }
#endif

                if (!treated) {
                    /* Certificate verification */
                    const uint8_t* peer_cert_der = SecurityPublicKey_getKeyValue(spk);
                    int peer_cert_len = SecurityPublicKey_getKeyLength(spk);
                    
                    X509* peer_cert = d2i_X509(NULL, &peer_cert_der, peer_cert_len);
                    if (!peer_cert) break;
                    
                    X509_STORE* store = X509_STORE_new();
                    X509_STORE_add_cert(store, self->ca_cert);
                    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
                    X509_STORE_CTX_init(ctx, store, peer_cert, NULL);
                    
                    int verify_ret = X509_verify_cert(ctx);
                    
                    if (verify_ret != 1) {
                        /* Send Association Abort */
                        CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, 
                            CS101_COT_ASSOC_ABORT, 0, self->association_id, false, false);
                        CS101_ASDU_setTypeID(asdu, S_AB_NA_1);
                        {{ ... }}
                        break;
                    }
                    
                    /* Send Association Confirm */
                    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, 
                        CS101_COT_ASSOC_CONFIRM, 0, self->association_id, false, false);
                    CS101_ASDU_setTypeID(asdu, S_AC_NA_1);
                    {{ ... }}
                    {{ ... }}
                }

                break;
            }
        }

        return APROFILE_CTRL_MSG;
    }
    

    /* Check if security is active and if this is an encrypted ASDU */
    if (!self->security_active) {
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }

    /* Check if the incoming message is a secure ASDU (type S_SE_NA_1) */
    if (inSize < 1 || in[0] != S_SE_NA_1) {
        *out = in;
        *outSize = inSize;
        return APROFILE_PLAINTEXT;
    }

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

    /* Extract sequence number from nonce (first 4 bytes) for replay protection */
    uint32_t received_seq;
    memcpy(&received_seq, nonce, 4);

    /* Verify sequence number to prevent replay attacks */
    /* Note: For the first message, remote_sequence_number is 0, so we accept seq=0 */
    if (self->remote_sequence_number != 0 && received_seq <= self->remote_sequence_number) {
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

    /* Decrypt and authenticate using AES-GCM */
    int dec_ret = mbedtls_gcm_auth_decrypt(&self->gcm_decrypt, ciphertext_len, 
                                           nonce, 12, NULL, 0, 
                                           tag, 16, ciphertext, (uint8_t*)*out);

    SecurityEncryptedData_destroy(sed);

    if (dec_ret != 0) {
        GLOBAL_FREEMEM((void*)*out);
        *out = NULL;
        *outSize = 0;
        return APROFILE_PLAINTEXT;
    }

    /* Update sequence number after successful decryption */
    self->remote_sequence_number = received_seq;
    
    return APROFILE_SECURE_DATA;
#else
    *out = in;
    *outSize = inSize;
    return APROFILE_PLAINTEXT;
#endif
}
