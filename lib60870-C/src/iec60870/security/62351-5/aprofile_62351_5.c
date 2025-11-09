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
// #include "cs104_frame_internal.h"
#include "lib_memory.h"
#include "cs101_asdu_internal.h"
#include "cs101_information_objects.h"
#include "information_objects_internal.h"
#include <stdio.h>
#include <string.h>

#if (CONFIG_CS104_APROFILE == 1)

/* Forward declarations - these functions are defined later in this file */
bool AProfile_sendUpdateKeyChangeResponse(AProfileContext self);
bool AProfile_sendSessionResponse(AProfileContext self);
bool AProfile_sendSessionKeyChangeResponse(AProfileContext self);

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
    /* IEC 62351-5:2023 Clause 8.3.10.4: Salt = R_C || R_S (Controlling Station Random || Controlled Station Random) */
    uint8_t salt[64];
    memcpy(salt, self->R_C, 32);
    memcpy(salt + 32, self->R_S, 32);
    
    /* Clause 8.3.10.4: HKDF-Extract to derive PRK */
    uint8_t prk[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    int ret = mbedtls_hkdf_extract(md_info, salt, sizeof(salt), ikm, ikm_len, prk);
    if (ret != 0) {
        printf("APROFILE: HKDF-Extract failed: %d\n", ret);
        return false;
    }
    
    /* Clause 8.3.10.4: HKDF-Expand to derive 512 bits (64 bytes) for K_UE and K_UA */
    uint8_t okm[64];
    const uint8_t info[] = "IEC62351-5-UpdateKeys";
    ret = mbedtls_hkdf_expand(md_info, prk, sizeof(prk), info, sizeof(info) - 1, okm, sizeof(okm));
    if (ret != 0) {
        printf("APROFILE: HKDF-Expand failed: %d\n", ret);
        return false;
    }
    
    /* Split into two 256-bit keys - IEC 62351-5:2023 standard nomenclature */
    memcpy(self->K_UE, okm, 32);      /* K_UE: Encryption Update Key */
    memcpy(self->K_UA, okm + 32, 32); /* K_UA: Authentication Update Key */
    
    printf("APROFILE: Update Keys (K_UE, K_UA) derived successfully\n");
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
    /* IEC 62351-5:2023 Clause 8.4.2.4.3: Generate two random 256-bit session keys */
    int ret = mbedtls_ctr_drbg_random(&self->ctr_drbg, self->K_SC, 32);
    if (ret != 0) {
        printf("APROFILE: Failed to generate K_SC (Control Session Key): %d\n", ret);
        return false;
    }
    
    ret = mbedtls_ctr_drbg_random(&self->ctr_drbg, self->K_SM, 32);
    if (ret != 0) {
        printf("APROFILE: Failed to generate K_SM (Monitor Session Key): %d\n", ret);
        return false;
    }
    
    printf("APROFILE: Session Keys (K_SC, K_SM) generated successfully\n");
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
    
    /* IEC 62351-5:2023 Clause 8.4.2.4.6: Use K_UE as the KEK (Key Encryption Key) */
    int ret = mbedtls_nist_kw_setkey(&kw_ctx, MBEDTLS_CIPHER_ID_AES, 
                                     self->K_UE, 256, 1);
    if (ret != 0) {
        printf("APROFILE: Failed to set KEK (K_UE): %d\n", ret);
        mbedtls_nist_kw_free(&kw_ctx);
        return false;
    }
    
    /* Concatenate both session keys: K_SC || K_SM */
    uint8_t plaintext_keys[64];
    memcpy(plaintext_keys, self->K_SC, 32);
    memcpy(plaintext_keys + 32, self->K_SM, 32);
    
    /* Wrap the keys using AES-256-KW (RFC 3394) */
    ret = mbedtls_nist_kw_wrap(&kw_ctx, MBEDTLS_KW_MODE_KW, plaintext_keys, 64,
                               wrapped_keys, wrapped_len, 72);
    
    mbedtls_nist_kw_free(&kw_ctx);
    
    if (ret != 0) {
        printf("APROFILE: Failed to wrap session keys: %d\n", ret);
        return false;
    }
    
    printf("APROFILE: Session Keys (K_SC, K_SM) wrapped successfully (%zu bytes)\n", *wrapped_len);
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
    
    /* IEC 62351-5:2023 Clause 8.4.2.4.6: Use K_UE as the KEK (Key Encryption Key) */
    int ret = mbedtls_nist_kw_setkey(&kw_ctx, MBEDTLS_CIPHER_ID_AES,
                                     self->K_UE, 256, 0);
    if (ret != 0) {
        printf("APROFILE: Failed to set KEK (K_UE) for unwrap: %d\n", ret);
        mbedtls_nist_kw_free(&kw_ctx);
        return false;
    }
    
    /* Unwrap the keys using AES-256-KW (RFC 3394) */
    uint8_t plaintext_keys[64];
    size_t plaintext_len;
    ret = mbedtls_nist_kw_unwrap(&kw_ctx, MBEDTLS_KW_MODE_KW, wrapped_keys, wrapped_len,
                                 plaintext_keys, &plaintext_len, sizeof(plaintext_keys));
    
    mbedtls_nist_kw_free(&kw_ctx);
    
    if (ret != 0 || plaintext_len != 64) {
        printf("APROFILE: Failed to unwrap session keys: %d\n", ret);
        return false;
    }
    
    /* Extract both session keys: K_SC || K_SM */
    memcpy(self->K_SC, plaintext_keys, 32);
    memcpy(self->K_SM, plaintext_keys + 32, 32);
    
    printf("APROFILE: Session Keys (K_SC, K_SM) unwrapped successfully\n");
    return true;
}

/**
 * @brief Calculate HMAC-SHA256 MAC over ASDU bytes per IEC 62351-5:2023
 * 
 * IEC 62351-5:2023 Clause 8.3.10.5: MAC is calculated over the ASDU content
 * (Type ID, VSQ, COT, OA, CA, and Information Objects) but EXCLUDING the MAC field itself.
 * 
 * @param self AProfile context (for accessing K_UA)
 * @param asdu ASDU to calculate MAC over
 * @param mac Output buffer for MAC (must be at least 32 bytes)
 * @return true on success, false on failure
 */
static bool
AProfile_calculateMACOverASDU(AProfileContext self, CS101_ASDU asdu, uint8_t* mac)
{
    /* Get ASDU bytes for MAC calculation */
    /* The ASDU structure: TypeID (1) | VSQ (1) | COT (1-2) | OA (0-1) | CA (1-2) | Payload */
    uint8_t asdu_buffer[256];
    Frame temp_frame = (Frame)T104Frame_create();
    if (!temp_frame) return false;
    
    /* Encode ASDU to get the bytes */
    CS101_ASDU_encode(asdu, temp_frame);
    uint8_t* frame_buffer = Frame_getBuffer(temp_frame);
    int frame_size = Frame_getMsgSize(temp_frame);
    
    /* Extract ASDU from frame (skip APCI header, which is 6 bytes) */
    int asdu_len = frame_size - 6;
    if (asdu_len < 0 || asdu_len > sizeof(asdu_buffer)) {
        T104Frame_destroy(temp_frame);
        return false;
    }
    
    memcpy(asdu_buffer, frame_buffer + 6, asdu_len);
    T104Frame_destroy(temp_frame);
    
    /* Calculate HMAC-SHA256 using K_UA (Authentication Update Key) */
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, asdu_buffer, asdu_len, mac);
    
    if (ret != 0) {
        printf("APROFILE: MAC calculation over ASDU failed: %d\n", ret);
        return false;
    }
    
    return true;
}

/**
 * @brief Calculate HMAC-SHA256 MAC for generic data (used for handshake messages)
 * 
 * @param key Authentication key (typically K_UA)
 * @param key_len Length of key (should be 32 for K_UA)
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
 * @brief Verify HMAC-SHA256 MAC over ASDU bytes per IEC 62351-5:2023
 * 
 * @param self AProfile context (for accessing K_UA)
 * @param asdu ASDU to verify MAC over
 * @param mac MAC to verify against
 * @return true if MAC is valid, false otherwise
 */
static bool
AProfile_verifyMACOverASDU(AProfileContext self, CS101_ASDU asdu, const uint8_t* mac)
{
    uint8_t calculated_mac[32];
    if (!AProfile_calculateMACOverASDU(self, asdu, calculated_mac)) {
        return false;
    }
    
    /* Constant-time comparison to prevent timing attacks */
    int diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (calculated_mac[i] ^ mac[i]);
    }
    
    return (diff == 0);
}

/**
 * @brief Verify HMAC-SHA256 MAC for generic data
 * 
 * @param key Authentication key (typically K_UA)
 * @param key_len Length of key (should be 32 for K_UA)
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
    
    /* Constant-time comparison to prevent timing attacks */
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
bool
AProfile_sendAssociationRequest(AProfileContext self)
{
    printf("\n[HANDSHAKE STEP 1/8] Sending Association Request (S_AR_NA_1)\n");
    printf("[CRYPTO] Generating 32-byte random data\n");
    printf("[CRYPTO] Generating ECDH key pair (SECP256R1)\n");
    
    /* Generate random data for this station - IEC 62351-5:2023 Clause 8.3.1 */
    mbedtls_ctr_drbg_random(&self->ctr_drbg, self->R_C, 32);
    
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
    
    /* Split into two information objects to avoid buffer overflow:
     * 1. Random data (32 bytes) - IOA 1
     * 2. ECDH Public Key (65 bytes) - IOA 2
     */
    
    /* Add random data as first information object - R_C (Controlling Station Random) */
    SecurityPublicKey spk_random = SecurityPublicKey_create(NULL, 1, 32, self->R_C);
    if (!spk_random) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_random);
    SecurityPublicKey_destroy(spk_random);
    
    /* Add ECDH public key as second information object */
    SecurityPublicKey spk_key = SecurityPublicKey_create(NULL, 2, self->localPublicKeyLen, self->localPublicKey);
    if (!spk_key) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_key);
    SecurityPublicKey_destroy(spk_key);
    
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, asdu);
    }
    
    CS101_ASDU_destroy(asdu);
    
    self->state = APROFILE_STATE_ASSOC_PENDING;
    printf("[CRYPTO] Sent: ClientRandom (32 bytes) + ECDH Public Key (65 bytes)\n");
    printf("[STATE] Waiting for Association Response...\n");
    return true;
}

/**
 * @brief Handle Association Response (S_AS_NA_1) - Clause 8.3.2
 */
bool
AProfile_handleAssociationResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Received Association Response (S_AS_NA_1)\n");
    
    /* Extract peer's random data and public key (now in two separate IOs) */
    union uInformationObject _io1, _io2;
    
    /* Get first information object (random data, 32 bytes) */
    SecurityPublicKey spk_random = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io1, 0);
    if (!spk_random) return false;
    
    const uint8_t* peer_random = SecurityPublicKey_getKeyValue(spk_random);
    int random_len = SecurityPublicKey_getKeyLength(spk_random);
    if (random_len != 32) return false;
    
    /* Copy peer's random data - R_S (Controlled Station Random) */
    memcpy(self->R_S, peer_random, 32);
    
    /* Get second information object (ECDH public key, 65 bytes) */
    SecurityPublicKey spk_key = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io2, 1);
    if (!spk_key) return false;
    
    const uint8_t* peer_pubkey = SecurityPublicKey_getKeyValue(spk_key);
    int peer_pubkey_len = SecurityPublicKey_getKeyLength(spk_key);
    if (peer_pubkey_len != 65) return false;
    
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
 * @brief Handle Association Request from client (server side) and send Association Response
 */
bool
AProfile_handleAssociationRequest(AProfileContext self, CS101_ASDU asdu)
{
    printf("\n[HANDSHAKE STEP 2/8] Server handling Association Request (S_AR_NA_1)\n");
    
    /* Extract client's random data and public key (two separate IOs) */
    union uInformationObject _io1, _io2;
    
    /* Get first information object (client random data, 32 bytes) */
    SecurityPublicKey spk_random = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io1, 0);
    if (!spk_random) return false;
    
    const uint8_t* client_random = SecurityPublicKey_getKeyValue(spk_random);
    int random_len = SecurityPublicKey_getKeyLength(spk_random);
    if (random_len != 32) return false;
    
    /* Copy client's random data - R_C (Controlling Station Random) */
    memcpy(self->R_C, client_random, 32);
    
    /* Get second information object (client ECDH public key, 65 bytes) */
    SecurityPublicKey spk_key = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io2, 1);
    if (!spk_key) return false;
    
    const uint8_t* client_pubkey = SecurityPublicKey_getKeyValue(spk_key);
    int client_pubkey_len = SecurityPublicKey_getKeyLength(spk_key);
    if (client_pubkey_len != 65) return false;
    
    /* Generate server's random data - R_S (Controlled Station Random) */
    mbedtls_ctr_drbg_random(&self->ctr_drbg, self->R_S, 32);
    
    /* Generate server's ECDH key pair */
    int ret = mbedtls_ecdh_gen_public(&self->ecdh.grp, &self->ecdh.d, &self->ecdh.Q,
                                      mbedtls_ctr_drbg_random, &self->ctr_drbg);
    if (ret != 0) return false;
    
    /* Export server's public key */
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&self->ecdh.grp, &self->ecdh.Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                         self->localPublicKey, sizeof(self->localPublicKey));
    if (ret != 0) return false;
    
    self->localPublicKeyLen = (int)olen;
    
    /* Compute ECDH shared secret with client's public key */
    ret = mbedtls_ecp_point_read_binary(&self->ecdh.grp, &self->ecdh.Qp, client_pubkey, client_pubkey_len);
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
    
    /* Derive Update Keys */
    if (!AProfile_deriveUpdateKeys(self, shared_secret, shared_secret_len)) {
        return false;
    }
    
    /* Send Association Response (S_AS_NA_1) with server's random data and public key */
    CS101_ASDU response = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!response) return false;
    
    CS101_ASDU_setTypeID(response, S_AS_NA_1);
    
    /* Add server's random data as first information object - R_S (Controlled Station Random) */
    SecurityPublicKey spk_resp_random = SecurityPublicKey_create(NULL, 1, 32, self->R_S);
    if (!spk_resp_random) {
        CS101_ASDU_destroy(response);
        return false;
    }
    CS101_ASDU_addInformationObject(response, (InformationObject)spk_resp_random);
    SecurityPublicKey_destroy(spk_resp_random);
    
    /* Add server's ECDH public key as second information object */
    SecurityPublicKey spk_resp_key = SecurityPublicKey_create(NULL, 2, self->localPublicKeyLen, self->localPublicKey);
    if (!spk_resp_key) {
        CS101_ASDU_destroy(response);
        return false;
    }
    CS101_ASDU_addInformationObject(response, (InformationObject)spk_resp_key);
    SecurityPublicKey_destroy(spk_resp_key);
    
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, response);
    }
    
    CS101_ASDU_destroy(response);
    
    self->state = APROFILE_STATE_ASSOC_COMPLETE;
    printf("[CRYPTO] Sent: ServerRandom (32 bytes) + ECDH Public Key (65 bytes)\n");
    
    return true;
}

/**
 * @brief Send Update Key Change Request (S_UK_NA_1) - Clause 8.3.10
 */
bool
AProfile_sendUpdateKeyChangeRequest(AProfileContext self)
{
    printf("\n[HANDSHAKE STEP 3/8] Sending Update Key Change Request (S_UK_NA_1)\n");
    printf("[CRYPTO] Calculating HMAC-SHA256 MAC using Authentication Update Key\n");
    
    /* Create ASDU */
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_UK_NA_1);
    
    /* IEC 62351-5:2023 Clause 8.3.10.5: Calculate MAC over ASDU bytes (before adding MAC field) */
    /* First, encode ASDU to get bytes for MAC calculation */
    Frame temp_frame = (Frame)T104Frame_create();
    if (!temp_frame) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    CS101_ASDU_encode(asdu, temp_frame);
    uint8_t* frame_buffer = Frame_getBuffer(temp_frame);
    int frame_size = Frame_getMsgSize(temp_frame);
    int asdu_len = frame_size - 6; /* Skip APCI header */
    
    /* Calculate MAC over ASDU bytes using K_UA */
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, frame_buffer + 6, asdu_len, mac);
    T104Frame_destroy(temp_frame);
    
    if (ret != 0) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
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
 * @brief Handle Update Key Change Request (S_UK_NA_1) - Server side - Clause 8.3.10
 */
bool
AProfile_handleUpdateKeyChangeRequest(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Server received Update Key Change Request (S_UK_NA_1)\n");
    
    /* Verify MAC */
    union uInformationObject _io;
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, 0);
    
    if (!spk) return false;
    
    const uint8_t* received_mac = SecurityPublicKey_getKeyValue(spk);
    
    /* IEC 62351-5:2023 Clause 8.3.10.5: Verify MAC over ASDU bytes using K_UA */
    if (!AProfile_verifyMACOverASDU(self, asdu, received_mac)) {
        printf("APROFILE: MAC verification failed for Update Key Change Request\n");
        return false;
    }
    
    printf("APROFILE: MAC verification successful - Update Keys confirmed\n");
    
    /* Send Update Key Change Response */
    return AProfile_sendUpdateKeyChangeResponse(self);
}

/**
 * @brief Send Update Key Change Response (S_UR_NA_1) - Server side - Clause 8.3.10
 */
bool
AProfile_sendUpdateKeyChangeResponse(AProfileContext self)
{
    printf("APROFILE: Sending Update Key Change Response (S_UR_NA_1)\n");
    
    /* Create ASDU */
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_UR_NA_1);
    
    /* Calculate MAC over ASDU bytes (before adding MAC field) */
    Frame temp_frame = (Frame)T104Frame_create();
    if (!temp_frame) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    CS101_ASDU_encode(asdu, temp_frame);
    uint8_t* frame_buffer = Frame_getBuffer(temp_frame);
    int frame_size = Frame_getMsgSize(temp_frame);
    int asdu_len = frame_size - 6;
    
    /* Calculate MAC over ASDU bytes using K_UA */
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, frame_buffer + 6, asdu_len, mac);
    T104Frame_destroy(temp_frame);
    
    if (ret != 0) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
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
    
    self->state = APROFILE_STATE_UPDATE_KEY_COMPLETE;
    return true;
}

/**
 * @brief Handle Update Key Change Response (S_UR_NA_1) - Client side - Clause 8.3.10
 */
bool
AProfile_handleUpdateKeyChangeResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Client received Update Key Change Response (S_UR_NA_1)\n");
    
    /* Verify MAC */
    union uInformationObject _io;
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, 0);
    
    if (!spk) return false;
    
    const uint8_t* received_mac = SecurityPublicKey_getKeyValue(spk);
    
    /* IEC 62351-5:2023 Clause 8.3.10.5: Verify MAC over ASDU bytes using K_UA */
    if (!AProfile_verifyMACOverASDU(self, asdu, received_mac)) {
        printf("APROFILE: MAC verification failed for Update Key Change Response\n");
        return false;
    }
    
    printf("APROFILE: MAC verification successful - Update Keys confirmed by both parties\n");
    
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
bool
AProfile_sendSessionRequest(AProfileContext self)
{
    printf("\n[HANDSHAKE STEP 5/8] Sending Session Request (S_SR_NA_1)\n");
    printf("[SESSION] Requesting new session establishment\n");
    
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
 * @brief Handle Session Request (S_SR_NA_1) - Server side - Clause 8.4.1
 */
bool
AProfile_handleSessionRequest(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Server received Session Request (S_SR_NA_1)\n");
    
    /* Send Session Response */
    return AProfile_sendSessionResponse(self);
}

/**
 * @brief Send Session Response (S_SS_NA_1) - Server side - Clause 8.4.1
 */
bool
AProfile_sendSessionResponse(AProfileContext self)
{
    printf("APROFILE: Sending Session Response (S_SS_NA_1)\n");
    
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_SS_NA_1);
    
    /* Calculate MAC over ASDU bytes (before adding MAC field) */
    Frame temp_frame = (Frame)T104Frame_create();
    if (!temp_frame) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    CS101_ASDU_encode(asdu, temp_frame);
    uint8_t* frame_buffer = Frame_getBuffer(temp_frame);
    int frame_size = Frame_getMsgSize(temp_frame);
    int asdu_len = frame_size - 6;
    
    /* Calculate MAC over ASDU bytes using K_UA */
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, frame_buffer + 6, asdu_len, mac);
    T104Frame_destroy(temp_frame);
    
    if (ret != 0) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
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
    
    self->state = APROFILE_STATE_SESSION_PENDING;
    return true;
}

/**
 * @brief Handle Session Response (S_SS_NA_1) - Client side - Clause 8.4.1
 */
bool
AProfile_handleSessionResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Client received Session Response (S_SS_NA_1)\n");
    
    /* Verify MAC */
    union uInformationObject _io;
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, 0);
    
    if (!spk) return false;
    
    const uint8_t* received_mac = SecurityPublicKey_getKeyValue(spk);
    
    /* IEC 62351-5:2023 Clause 8.4.1: Verify MAC over ASDU bytes using K_UA */
    if (!AProfile_verifyMACOverASDU(self, asdu, received_mac)) {
        printf("APROFILE: MAC verification failed for Session Response\n");
        return false;
    }
    
    printf("APROFILE: MAC verification successful - Session request accepted by server\n");
    
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
bool
AProfile_sendSessionKeyChangeRequest(AProfileContext self)
{
    printf("\n[HANDSHAKE STEP 7/8] Sending Session Key Change Request (S_SK_NA_1)\n");
    printf("[CRYPTO] Generating random Session Keys\n");
    printf("[CRYPTO]   - Control Session Key (256-bit)\n");
    printf("[CRYPTO]   - Monitor Session Key (256-bit)\n");
    printf("[CRYPTO] Wrapping Session Keys with AES-256-KW\n");
    printf("[CRYPTO]   - KEK: Encryption Update Key (256-bit)\n");
    printf("[CRYPTO] Calculating HMAC-SHA256 MAC\n");
    
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
    SecurityPublicKey spk_keys = SecurityPublicKey_create(NULL, 65535, (int)wrapped_len, wrapped_keys);
    if (!spk_keys) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_keys);
    SecurityPublicKey_destroy(spk_keys);
    
    /* Calculate MAC over ASDU bytes (including wrapped keys, before adding MAC field) */
    Frame temp_frame = (Frame)T104Frame_create();
    if (!temp_frame) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    CS101_ASDU_encode(asdu, temp_frame);
    uint8_t* frame_buffer = Frame_getBuffer(temp_frame);
    int frame_size = Frame_getMsgSize(temp_frame);
    int asdu_len = frame_size - 6;
    
    /* Calculate MAC over ASDU bytes using K_UA */
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, frame_buffer + 6, asdu_len, mac);
    T104Frame_destroy(temp_frame);
    
    if (ret != 0) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
    /* Add MAC as second information object */
    SecurityPublicKey spk_mac = SecurityPublicKey_create(NULL, 65534, 32, mac);
    if (!spk_mac) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_mac);
    SecurityPublicKey_destroy(spk_mac);
    
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, asdu);
    }
    
    CS101_ASDU_destroy(asdu);
    
    self->state = APROFILE_STATE_SESSION_KEY_PENDING;
    return true;
}

/**
 * @brief Handle Session Key Change Request (S_SK_NA_1) - Server side - Clause 8.4.2
 */
bool
AProfile_handleSessionKeyChangeRequest(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Server received Session Key Change Request (S_SK_NA_1)\n");
    
    /* Extract wrapped keys (first information object) */
    union uInformationObject _io1, _io2;
    SecurityPublicKey spk_keys = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io1, 0);
    
    if (!spk_keys) return false;
    
    const uint8_t* wrapped_keys = SecurityPublicKey_getKeyValue(spk_keys);
    int wrapped_keys_len = SecurityPublicKey_getKeyLength(spk_keys);
    
    /* Extract MAC (second information object) */
    SecurityPublicKey spk_mac = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io2, 1);
    
    if (!spk_mac) return false;
    
    const uint8_t* received_mac = SecurityPublicKey_getKeyValue(spk_mac);
    
    /* Verify MAC over ASDU bytes (excluding MAC field) - IEC 62351-5:2023 Clause 8.4.2 */
    /* Create temporary ASDU without MAC for verification */
    CS101_ASDU temp_asdu = CS101_ASDU_create(self->parameters, false, 
                                             CS101_ASDU_getCOT(asdu), 
                                             CS101_ASDU_getOA(asdu), 
                                             CS101_ASDU_getCA(asdu), 
                                             CS101_ASDU_isTest(asdu), 
                                             CS101_ASDU_isNegative(asdu));
    if (!temp_asdu) return false;
    
    CS101_ASDU_setTypeID(temp_asdu, S_SK_NA_1);
    
    /* Add only the wrapped keys (without MAC) */
    SecurityPublicKey temp_spk = SecurityPublicKey_create(NULL, 65535, wrapped_keys_len, wrapped_keys);
    if (!temp_spk) {
        CS101_ASDU_destroy(temp_asdu);
        return false;
    }
    CS101_ASDU_addInformationObject(temp_asdu, (InformationObject)temp_spk);
    SecurityPublicKey_destroy(temp_spk);
    
    /* Verify MAC */
    if (!AProfile_verifyMACOverASDU(self, temp_asdu, received_mac)) {
        printf("APROFILE: MAC verification failed for Session Key Change Request\n");
        CS101_ASDU_destroy(temp_asdu);
        return false;
    }
    
    CS101_ASDU_destroy(temp_asdu);
    
    printf("APROFILE: MAC verification successful\n");
    
    /* Unwrap session keys using K_UE */
    if (!AProfile_unwrapSessionKeys(self, wrapped_keys, wrapped_keys_len)) {
        printf("APROFILE: Failed to unwrap session keys\n");
        return false;
    }
    
    printf("APROFILE: Session Keys (K_SC, K_SM) unwrapped successfully\n");
    
    /* Send Session Key Change Response */
    return AProfile_sendSessionKeyChangeResponse(self);
}

/**
 * @brief Send Session Key Change Response (S_SQ_NA_1) - Server side - Clause 8.4.2
 */
bool
AProfile_sendSessionKeyChangeResponse(AProfileContext self)
{
    printf("APROFILE: Sending Session Key Change Response (S_SQ_NA_1)\n");
    
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_SQ_NA_1);
    
    /* Calculate MAC over ASDU bytes (before adding MAC field) */
    Frame temp_frame = (Frame)T104Frame_create();
    if (!temp_frame) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    CS101_ASDU_encode(asdu, temp_frame);
    uint8_t* frame_buffer = Frame_getBuffer(temp_frame);
    int frame_size = Frame_getMsgSize(temp_frame);
    int asdu_len = frame_size - 6;
    
    /* Calculate MAC over ASDU bytes using K_UA */
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, frame_buffer + 6, asdu_len, mac);
    T104Frame_destroy(temp_frame);
    
    if (ret != 0) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
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
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Initialize DSQ to 1 */
    self->DSQ_local = 1;
    self->DSQ_remote = 0; /* Will be set to 1 when first message is received */
    
    self->state = APROFILE_STATE_ESTABLISHED;
    self->security_active = true;
    
    printf("APROFILE: Session established successfully (DSQ initialized to 1)\n");
    printf("APROFILE: K_SC and K_SM are ready for AES-256-GCM encryption\n");
    return true;
}

/**
 * @brief Handle Session Key Change Response (S_SQ_NA_1) - Client side - Clause 8.4.2
 */
bool
AProfile_handleSessionKeyChangeResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Client received Session Key Change Response (S_SQ_NA_1)\n");
    
    /* Verify MAC */
    union uInformationObject _io;
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElementEx(asdu, (InformationObject)&_io, 0);
    
    if (!spk) return false;
    
    const uint8_t* received_mac = SecurityPublicKey_getKeyValue(spk);
    
    /* IEC 62351-5:2023 Clause 8.4.2: Verify MAC over ASDU bytes using K_UA */
    if (!AProfile_verifyMACOverASDU(self, asdu, received_mac)) {
        printf("APROFILE: MAC verification failed for Session Key Change Response\n");
        return false;
    }
    
    printf("APROFILE: MAC verification successful - Server confirmed Session Keys\n");
    
    /* IEC 62351-5:2023 Clause 8.5.2.2.4: Initialize DSQ to 1 */
    self->DSQ_local = 1;
    self->DSQ_remote = 0; /* Will be set to 1 when first message is received */
    
    self->state = APROFILE_STATE_ESTABLISHED;
    self->security_active = true;
    
    printf("APROFILE: Session established successfully (DSQ initialized to 1)\n");
    printf("APROFILE: K_SC and K_SM are ready for AES-256-GCM encryption\n");
    return true;
}

#endif /* CONFIG_CS104_APROFILE */
