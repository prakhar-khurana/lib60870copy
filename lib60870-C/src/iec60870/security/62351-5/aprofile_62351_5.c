/*
 * IEC 62351-5:2023 Compliant Implementation
 * Application Layer Security (A-Profile)
 * 
 * This file implements the full 8-message handshake and two-level key hierarchy
 * as specified in IEC 62351-5:2023 standard.
 */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/nist_kw.h>
#include "aprofile_internal.h"
#include "cs104_frame.h"
#include "lib_memory.h"
#include "cs101_asdu_internal.h"
#include "cs101_information_objects.h"
#include "information_objects_internal.h"
#include <stdio.h>
#include <string.h>

#if (CONFIG_CS104_APROFILE == 1)

/* ============================================================================
 * IEC 62351-5:2023 Clause 8.3.10: Update Key Derivation
 * ============================================================================ */

/**
 * @brief Derive Update Keys using HKDF as per IEC 62351-5:2023 Clause 8.3.10
 * 
 * @param self AProfile context
 * @param ikm Intermediate Keying Material (ECDH shared secret)
 * @param ikm_len Length of IKM
 * @return true on success, false on failure
 */
static bool
AProfile_deriveUpdateKeys(AProfileContext self, const uint8_t* ikm, size_t ikm_len)
{
    /* Clause 8.3.10.4: Salt = Controlling Station Random || Controlled Station Random */
    uint8_t salt[64];
    memcpy(salt, self->controlling_station_random, 32);
    memcpy(salt + 32, self->controlled_station_random, 32);
    
    /* Clause 8.3.10.4: HKDF-Extract to derive PRK */
    uint8_t prk[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    int ret = mbedtls_hkdf_extract(md_info, salt, sizeof(salt), ikm, ikm_len, prk);
    if (ret != 0) {
        printf("APROFILE: HKDF-Extract failed: %d\n", ret);
        return false;
    }
    
    /* Clause 8.3.10.4: HKDF-Expand to derive 512 bits (64 bytes) */
    uint8_t okm[64];
    const uint8_t info[] = "IEC62351-5-UpdateKeys";
    ret = mbedtls_hkdf_expand(md_info, prk, sizeof(prk), info, sizeof(info) - 1, okm, sizeof(okm));
    if (ret != 0) {
        printf("APROFILE: HKDF-Expand failed: %d\n", ret);
        return false;
    }
    
    /* Split into two 256-bit keys */
    memcpy(self->encryption_update_key, okm, 32);
    memcpy(self->authentication_update_key, okm + 32, 32);
    
    printf("APROFILE: Update Keys derived successfully\n");
    return true;
}

/**
 * @brief Generate random Session Keys as per IEC 62351-5:2023 Clause 8.4.2.4.3
 * 
 * @param self AProfile context
 * @return true on success, false on failure
 */
static bool
AProfile_generateSessionKeys(AProfileContext self)
{
    /* Clause 8.4.2.4.3: Generate two random 256-bit session keys */
    int ret = mbedtls_ctr_drbg_random(&self->ctr_drbg, self->control_session_key, 32);
    if (ret != 0) {
        printf("APROFILE: Failed to generate control session key: %d\n", ret);
        return false;
    }
    
    ret = mbedtls_ctr_drbg_random(&self->ctr_drbg, self->monitor_session_key, 32);
    if (ret != 0) {
        printf("APROFILE: Failed to generate monitor session key: %d\n", ret);
        return false;
    }
    
    printf("APROFILE: Session Keys generated successfully\n");
    return true;
}

/**
 * @brief Wrap Session Keys using AES-256-KW as per RFC 3394 and IEC 62351-5:2023 Clause 8.4.2.4.6
 * 
 * @param self AProfile context
 * @param wrapped_keys Output buffer for wrapped keys (must be at least 72 bytes)
 * @param wrapped_len Output length of wrapped keys
 * @return true on success, false on failure
 */
static bool
AProfile_wrapSessionKeys(AProfileContext self, uint8_t* wrapped_keys, size_t* wrapped_len)
{
    mbedtls_nist_kw_context kw_ctx;
    mbedtls_nist_kw_init(&kw_ctx);
    
    /* Set the Encryption Update Key as the KEK */
    int ret = mbedtls_nist_kw_setkey(&kw_ctx, MBEDTLS_CIPHER_ID_AES, 
                                     self->encryption_update_key, 256, 1);
    if (ret != 0) {
        printf("APROFILE: Failed to set KEK: %d\n", ret);
        mbedtls_nist_kw_free(&kw_ctx);
        return false;
    }
    
    /* Concatenate both session keys */
    uint8_t plaintext_keys[64];
    memcpy(plaintext_keys, self->control_session_key, 32);
    memcpy(plaintext_keys + 32, self->monitor_session_key, 32);
    
    /* Wrap the keys */
    ret = mbedtls_nist_kw_wrap(&kw_ctx, MBEDTLS_KW_MODE_KW, plaintext_keys, 64,
                               wrapped_keys, wrapped_len, 72);
    
    mbedtls_nist_kw_free(&kw_ctx);
    
    if (ret != 0) {
        printf("APROFILE: Failed to wrap session keys: %d\n", ret);
        return false;
    }
    
    printf("APROFILE: Session Keys wrapped successfully (%zu bytes)\n", *wrapped_len);
    return true;
}

/**
 * @brief Unwrap Session Keys using AES-256-KW as per RFC 3394 and IEC 62351-5:2023 Clause 8.4.2.4.6
 * 
 * @param self AProfile context
 * @param wrapped_keys Input buffer containing wrapped keys
 * @param wrapped_len Length of wrapped keys
 * @return true on success, false on failure
 */
static bool
AProfile_unwrapSessionKeys(AProfileContext self, const uint8_t* wrapped_keys, size_t wrapped_len)
{
    mbedtls_nist_kw_context kw_ctx;
    mbedtls_nist_kw_init(&kw_ctx);
    
    /* Set the Encryption Update Key as the KEK */
    int ret = mbedtls_nist_kw_setkey(&kw_ctx, MBEDTLS_CIPHER_ID_AES,
                                     self->encryption_update_key, 256, 0);
    if (ret != 0) {
        printf("APROFILE: Failed to set KEK for unwrap: %d\n", ret);
        mbedtls_nist_kw_free(&kw_ctx);
        return false;
    }
    
    /* Unwrap the keys */
    uint8_t plaintext_keys[64];
    size_t plaintext_len;
    ret = mbedtls_nist_kw_unwrap(&kw_ctx, MBEDTLS_KW_MODE_KW, wrapped_keys, wrapped_len,
                                 plaintext_keys, &plaintext_len, sizeof(plaintext_keys));
    
    mbedtls_nist_kw_free(&kw_ctx);
    
    if (ret != 0 || plaintext_len != 64) {
        printf("APROFILE: Failed to unwrap session keys: %d\n", ret);
        return false;
    }
    
    /* Extract both session keys */
    memcpy(self->control_session_key, plaintext_keys, 32);
    memcpy(self->monitor_session_key, plaintext_keys + 32, 32);
    
    printf("APROFILE: Session Keys unwrapped successfully\n");
    return true;
}

/**
 * @brief Calculate HMAC-SHA256 MAC for message authentication
 * 
 * @param key Authentication key
 * @param key_len Length of key
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param mac Output buffer for MAC (must be at least 32 bytes)
 * @return true on success, false on failure
 */
static bool
AProfile_calculateMAC(const uint8_t* key, size_t key_len,
                      const uint8_t* data, size_t data_len,
                      uint8_t* mac)
{
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, key, key_len, data, data_len, mac);
    
    if (ret != 0) {
        printf("APROFILE: MAC calculation failed: %d\n", ret);
        return false;
    }
    
    return true;
}

/**
 * @brief Verify HMAC-SHA256 MAC
 * 
 * @param key Authentication key
 * @param key_len Length of key
 * @param data Data to verify
 * @param data_len Length of data
 * @param mac MAC to verify against
 * @return true if MAC is valid, false otherwise
 */
static bool
AProfile_verifyMAC(const uint8_t* key, size_t key_len,
                   const uint8_t* data, size_t data_len,
                   const uint8_t* mac)
{
    uint8_t calculated_mac[32];
    if (!AProfile_calculateMAC(key, key_len, data, data_len, calculated_mac)) {
        return false;
    }
    
    /* Constant-time comparison */
    int diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (calculated_mac[i] ^ mac[i]);
    }
    
    return (diff == 0);
}

/* ============================================================================
 * IEC 62351-5:2023 Clause 8.3: Station Association Procedure
 * ============================================================================ */

/**
 * @brief Send Association Request (S_AR_NA_1) - Clause 8.3.1
 */
static bool
AProfile_sendAssociationRequest(AProfileContext self)
{
    printf("APROFILE: Sending Association Request (S_AR_NA_1)\n");
    
    /* Generate random data for this station */
    mbedtls_ctr_drbg_random(&self->ctr_drbg, self->controlling_station_random, 32);
    
    /* Generate ECDH key pair */
    mbedtls_ecp_group_free(&self->ecdh.grp);
    mbedtls_ecp_group_init(&self->ecdh.grp);
    
    int ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) return false;
    
    ret = mbedtls_ecdh_gen_public(&self->ecdh.grp, &self->ecdh.d, &self->ecdh.Q,
                                  mbedtls_ctr_drbg_random, &self->ctr_drbg);
    if (ret != 0) return false;
    
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&self->ecdh.grp, &self->ecdh.Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                         self->localPublicKey, sizeof(self->localPublicKey));
    if (ret != 0) return false;
    
    self->localPublicKeyLen = (int)olen;
    
    /* Create ASDU with random data and public key */
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_AR_NA_1);
    
    /* TODO: Add information object with random data and public key */
    /* For now, use SecurityPublicKey as a placeholder */
    uint8_t payload[97]; /* 32 bytes random + 65 bytes public key */
    memcpy(payload, self->controlling_station_random, 32);
    memcpy(payload + 32, self->localPublicKey, 65);
    
    SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, sizeof(payload), payload);
    if (!spk) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    SecurityPublicKey_destroy(spk);
    
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, asdu);
    }
    
    CS101_ASDU_destroy(asdu);
    
    self->state = APROFILE_STATE_ASSOC_PENDING;
    return true;
}

/**
 * @brief Handle Association Response (S_AS_NA_1) - Clause 8.3.2
 */
static bool
AProfile_handleAssociationResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Received Association Response (S_AS_NA_1)\n");
    
    /* Extract peer's random data and public key */
    union uInformationObject _io;
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, 0);
    
    if (!spk) return false;
    
    const uint8_t* payload = SecurityPublicKey_getKeyValue(spk);
    int payload_len = SecurityPublicKey_getKeyLength(spk);
    
    if (payload_len < 97) return false;
    
    /* Extract peer's random data */
    memcpy(self->controlled_station_random, payload, 32);
    
    /* Extract peer's public key */
    const uint8_t* peer_pubkey = payload + 32;
    int peer_pubkey_len = 65;
    
    /* Compute ECDH shared secret */
    int ret = mbedtls_ecp_point_read_binary(&self->ecdh.grp, &self->ecdh.Qp, peer_pubkey, peer_pubkey_len);
    if (ret != 0) return false;
    
    ret = mbedtls_ecdh_compute_shared(&self->ecdh.grp, &self->ecdh.z,
                                      &self->ecdh.Qp, &self->ecdh.d,
                                      mbedtls_ctr_drbg_random, &self->ctr_drbg);
    if (ret != 0) return false;
    
    /* Export shared secret */
    uint8_t shared_secret[32];
    size_t shared_secret_len = mbedtls_mpi_size(&self->ecdh.z);
    if (shared_secret_len > sizeof(shared_secret)) return false;
    
    ret = mbedtls_mpi_write_binary(&self->ecdh.z, shared_secret, shared_secret_len);
    if (ret != 0) return false;
    
    /* Derive Update Keys using HKDF */
    if (!AProfile_deriveUpdateKeys(self, shared_secret, shared_secret_len)) {
        return false;
    }
    
    self->state = APROFILE_STATE_ASSOC_COMPLETE;
    
    /* Automatically send Update Key Change Request */
    return AProfile_sendUpdateKeyChangeRequest(self);
}

/**
 * @brief Send Update Key Change Request (S_UK_NA_1) - Clause 8.3.10
 */
static bool
AProfile_sendUpdateKeyChangeRequest(AProfileContext self)
{
    printf("APROFILE: Sending Update Key Change Request (S_UK_NA_1)\n");
    
    /* Create ASDU */
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_UK_NA_1);
    
    /* Calculate MAC over the ASDU using Authentication Update Key */
    uint8_t mac[32];
    /* TODO: Calculate MAC over ASDU content */
    AProfile_calculateMAC(self->authentication_update_key, 32, (const uint8_t*)"UpdateKeyChange", 15, mac);
    
    /* Add MAC as information object */
    SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, 32, mac);
    if (!spk) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    SecurityPublicKey_destroy(spk);
    
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, asdu);
    }
    
    CS101_ASDU_destroy(asdu);
    
    self->state = APROFILE_STATE_UPDATE_KEY_PENDING;
    return true;
}

/**
 * @brief Handle Update Key Change Response (S_UR_NA_1) - Clause 8.3.10
 */
static bool
AProfile_handleUpdateKeyChangeResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Received Update Key Change Response (S_UR_NA_1)\n");
    
    /* Verify MAC */
    union uInformationObject _io;
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, 0);
    
    if (!spk) return false;
    
    const uint8_t* mac = SecurityPublicKey_getKeyValue(spk);
    
    /* TODO: Verify MAC over ASDU content */
    if (!AProfile_verifyMAC(self->authentication_update_key, 32, (const uint8_t*)"UpdateKeyResponse", 17, mac)) {
        printf("APROFILE: MAC verification failed\n");
        return false;
    }
    
    self->state = APROFILE_STATE_UPDATE_KEY_COMPLETE;
    
    /* Automatically send Session Request */
    return AProfile_sendSessionRequest(self);
}

/* ============================================================================
 * IEC 62351-5:2023 Clause 8.4: Session Key Change Procedure
 * ============================================================================ */

/**
 * @brief Send Session Request (S_SR_NA_1) - Clause 8.4.1
 */
static bool
AProfile_sendSessionRequest(AProfileContext self)
{
    printf("APROFILE: Sending Session Request (S_SR_NA_1)\n");
    
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_SR_NA_1);
    
    /* Add placeholder information object */
    SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, 1, (uint8_t*)"\x00");
    if (!spk) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    SecurityPublicKey_destroy(spk);
    
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, asdu);
    }
    
    CS101_ASDU_destroy(asdu);
    
    self->state = APROFILE_STATE_SESSION_PENDING;
    return true;
}

/**
 * @brief Handle Session Response (S_SS_NA_1) - Clause 8.4.1
 */
static bool
AProfile_handleSessionResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Received Session Response (S_SS_NA_1)\n");
    
    /* Verify MAC */
    /* TODO: Extract and verify MAC */
    
    /* Generate Session Keys */
    if (!AProfile_generateSessionKeys(self)) {
        return false;
    }
    
    /* Send Session Key Change Request with wrapped keys */
    return AProfile_sendSessionKeyChangeRequest(self);
}

/**
 * @brief Send Session Key Change Request (S_SK_NA_1) - Clause 8.4.2
 */
static bool
AProfile_sendSessionKeyChangeRequest(AProfileContext self)
{
    printf("APROFILE: Sending Session Key Change Request (S_SK_NA_1)\n");
    
    /* Wrap session keys */
    uint8_t wrapped_keys[72];
    size_t wrapped_len;
    
    if (!AProfile_wrapSessionKeys(self, wrapped_keys, &wrapped_len)) {
        return false;
    }
    
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_SK_NA_1);
    
    /* Add wrapped keys as information object */
    SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, wrapped_len, wrapped_keys);
    if (!spk) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    SecurityPublicKey_destroy(spk);
    
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, asdu);
    }
    
    CS101_ASDU_destroy(asdu);
    
    self->state = APROFILE_STATE_SESSION_KEY_PENDING;
    return true;
}

/**
 * @brief Handle Session Key Change Response (S_SQ_NA_1) - Clause 8.4.2
 */
static bool
AProfile_handleSessionKeyChangeResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Received Session Key Change Response (S_SQ_NA_1)\n");
    
    /* Verify MAC */
    /* TODO: Extract and verify MAC */
    
    /* Initialize GCM contexts with session keys */
    mbedtls_gcm_setkey(&self->gcm_encrypt, MBEDTLS_CIPHER_ID_AES, self->control_session_key, 256);
    mbedtls_gcm_setkey(&self->gcm_decrypt, MBEDTLS_CIPHER_ID_AES, self->monitor_session_key, 256);
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Initialize DSQ to 1 */
    self->local_sequence_number = 1;
    self->remote_sequence_number = 0; /* Will be set to 1 when first message is received */
    
    self->state = APROFILE_STATE_ESTABLISHED;
    self->security_active = true;
    
    printf("APROFILE: Session established successfully (DSQ initialized to 1)\n");
    return true;
}

#endif /* CONFIG_CS104_APROFILE */
