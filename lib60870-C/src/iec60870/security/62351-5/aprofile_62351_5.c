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
#include "../../../hal/inc/hal_time.h"
/* Forward declaration of sInformationObject structure to allow type override */
struct sInformationObjectVFT;
struct sInformationObject {
    int objectAddress;
    TypeID type;
    struct sInformationObjectVFT* virtualFunctionTable;
};

#include "lib_memory.h"
#include "cs101_asdu_internal.h"
// #include "cs101_information_objects.h"
#include "information_objects_internal.h"
#include <stdio.h>
#include <string.h>
// #include "iec62351_5.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "inc/api/cs101_information_objects.h"  // For SecurityPublicKey functions

#if (CONFIG_CS104_APROFILE == 1)

/* Forward declaration for function defined later */
bool AProfile_sendAssociationResponse(AProfileContext self);

/**
 * @brief Handle incoming Association Request (S_AR_NA_1) message
 * 
 * This function is called when a server receives an Association Request from a client.
 * It extracts the client's ECDH public key and random data, generates a server ECDH key pair,
 * computes the shared secret, and derives the update keys.
 * 
 * @param self The A-Profile context
 * @param asdu The received ASDU containing the Association Request
 * @return true if the request was handled successfully, false otherwise
 */
bool 
AProfile_handleAssociationRequest(AProfileContext self, CS101_ASDU asdu)
{
    if (!self || !asdu) {
        return false;
    }

    /* Extract client's ECDH public key and random data from ASDU */
    uint8_t clientPublicKey[65] = {0}; /* 65 bytes for uncompressed SEC1 format */
    uint8_t clientRandom[32] = {0};
    
    /* Extract client's ECDH public key and random data from ASDU */
    printf("[CRYPTO] Extracting client's ECDH public key and random data\n");
    
    /* The ASDU should contain two information objects:
     * 1. Random data (32 bytes) - IOA 1
     * 2. ECDH Public Key (65 bytes) - IOA 2
     */
    int elementCount = CS101_ASDU_getNumberOfElements(asdu);
    if (elementCount < 2) {
        printf("[ERROR] Expected at least 2 information objects, got %d\n", elementCount);
        return false;
    }
    
    bool success = false;
    InformationObject io = NULL;
    
    /* First, get the random data (IOA 1) */
    io = CS101_ASDU_getElement(asdu, 0);
    if (io) {
        SecurityPublicKey spk = (SecurityPublicKey)io;
        if (SecurityPublicKey_getKeyLength(spk) >= 32) {
            memcpy(clientRandom, SecurityPublicKey_getKeyValue(spk), 32);
            printf("[CRYPTO] Extracted client random data (32 bytes)\n");
            success = true;
        }
        InformationObject_destroy(io);
    }
    
    if (!success) {
        printf("[ERROR] Failed to extract client random data\n");
        return false;
    }
    
    /* Then get the public key (IOA 2) */
    io = CS101_ASDU_getElement(asdu, 1);
    if (!io) {
        printf("[ERROR] Failed to get public key information object\n");
        return false;
    }
    
    SecurityPublicKey spk = (SecurityPublicKey)io;
    int keySize = SecurityPublicKey_getKeyLength(spk);
    
    if (keySize != 65) {
        printf("[ERROR] Invalid public key size: %d (expected 65 bytes for SECP256R1 uncompressed)\n", keySize);
        InformationObject_destroy(io);
        return false;
    }
    
    const uint8_t* keyData = SecurityPublicKey_getKeyValue(spk);
    memcpy(clientPublicKey, keyData, 65);
    
    /* Verify the public key format (first byte should be 0x04 for uncompressed) */
    if (clientPublicKey[0] != 0x04) {
        printf("[ERROR] Invalid public key format. First byte: 0x%02X (expected 0x04 for uncompressed)\n", 
               clientPublicKey[0]);
        InformationObject_destroy(io);
        return false;
    }
    
    printf("[CRYPTO] Extracted client public key (65 bytes)\n");
    InformationObject_destroy(io);
    /* Initialize ECDH group if not already done */

    if (self->ecdh.grp.id == NULL) {
        mbedtls_ecp_group_init(&self->ecdh.grp);
        int ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) {
            printf("[ERROR] Failed to initialize ECDH group: -0x%04X\n", -ret);
            return false;
        }
    }
    
    /* Parse and validate the client's public key */
    printf("[CRYPTO] Parsing and validating client's ECDH public key...\n");
    int ret = mbedtls_ecp_point_read_binary(&self->ecdh.grp, &self->ecdh.Qp, 
                                          clientPublicKey, 65);
    if (ret != 0) {
        printf("[ERROR] Invalid client public key format: -0x%04X (expected 0x04 || X || Y, 65 bytes for SECP256R1)\n", -ret);
        return false;
    }
    
    /* Verify the public key is valid (on curve) */
    ret = mbedtls_ecp_check_pubkey(&self->ecdh.grp, &self->ecdh.Qp);
    if (ret != 0) {
        printf("[ERROR] Invalid client public key (not on curve): -0x%04X\n", -ret);
        return false;
    }
    
    printf("[CRYPTO] Successfully parsed and validated client's ECDH public key\n");
    
    /* Store client's random data in the context */
    memcpy(self->R_C, clientRandom, 32);
    
    /* Generate server's random data - R_S (Controlled Station Random) */
    mbedtls_ctr_drbg_random(&self->ctr_drbg, self->R_S, 32);
    printf("[CRYPTO] Generated server random data (32 bytes)\n");
    
    /* Generate server ECDH key pair if not already generated */
    ret = mbedtls_ecdh_gen_public(&self->ecdh.grp, &self->ecdh.d, &self->ecdh.Q,
                              mbedtls_ctr_drbg_random, &self->ctr_drbg);
    if (ret != 0) {
        printf("[ERROR] Failed to generate ECDH key pair: -0x%04X\n", -ret);
        return false;
    }
    
    /* Export server's public key in uncompressed format */
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&self->ecdh.grp, &self->ecdh.Q,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                       self->localPublicKey, sizeof(self->localPublicKey));
    if (ret != 0) {
        printf("[ERROR] Failed to export server public key: -0x%04X\n", -ret);
        return false;
    }
    self->localPublicKeyLen = (int)olen;
    printf("[CRYPTO] Generated and exported server ECDH public key (%d bytes)\n", self->localPublicKeyLen);
    
    /* Compute shared secret - store in self->ecdh.z for key derivation */
    printf("[CRYPTO] Computing shared secret...\n");
    ret = mbedtls_ecdh_compute_shared(&self->ecdh.grp, &self->ecdh.z,
                                    &self->ecdh.Qp, &self->ecdh.d,
                                    mbedtls_ctr_drbg_random, &self->ctr_drbg);
    if (ret != 0) {
        printf("[ERROR] Failed to compute shared secret: -0x%04X\n", -ret);
        return false;
    }
    
    /* Also store in byte array for compatibility */
    self->sharedSecretLen = mbedtls_mpi_size(&self->ecdh.z);
    ret = mbedtls_mpi_write_binary(&self->ecdh.z, self->sharedSecret, sizeof(self->sharedSecret));
    if (ret != 0) {
        printf("[ERROR] Failed to write shared secret: -0x%04X\n", -ret);
        return false;
    }
    
    /* Derive update keys using HKDF - Call the proper function that splits K_UE and K_UA */
    printf("[CRYPTO] Deriving update keys with HKDF...\n");
    if (!AProfile_deriveUpdateKeys(self)) {
        printf("[ERROR] Failed to derive update keys\n");
        return false;
    }
    
    printf("[CRYPTO] Successfully derived update keys\n");
    
    self->state = APROFILE_STATE_ASSOC_COMPLETE;
    
    /* Server automatically sends Association Response after processing request */
    return AProfile_sendAssociationResponse(self);
}


/* Forward declarations - these functions are defined later in this file */
bool AProfile_sendAssociationResponse(AProfileContext self);
bool AProfile_sendUpdateKeyChangeResponse(AProfileContext self);
bool AProfile_sendSessionResponse(AProfileContext self);
bool AProfile_sendSessionKeyChangeResponse(AProfileContext self);

/* ============================================================================
 * IEC 62351-5:2023 Clause 8.3.10: Update Key Derivation
 * ============================================================================ */

#if !defined(APROFILE_DERIVE_UPDATE_KEYS_DEFINED)
#define APROFILE_DERIVE_UPDATE_KEYS_DEFINED

/**
 * @brief Derive Update Keys using HKDF as per IEC 62351-5:2023 Clause 8.3.10.4
 * 
 * @param self AProfile context
 * @return true on success, false on failure
 */
bool
AProfile_deriveUpdateKeys(AProfileContext self)
{
    if (!self) return false;
    
    /* IEC 62351-5:2023 Clause 8.3.10.4 */
    uint8_t salt[64];
    memcpy(salt, self->R_C, 32);
    memcpy(salt + 32, self->R_S, 32);
    
    printf("[HKDF-DEBUG] R_C (Client Random): ");
    for (int i = 0; i < 32; i++) printf("%02X ", self->R_C[i]);
    printf("\n");
    
    printf("[HKDF-DEBUG] R_S (Server Random): ");
    for (int i = 0; i < 32; i++) printf("%02X ", self->R_S[i]);
    printf("\n");
    
    /* Get shared secret */
    uint8_t shared_secret[32];
    size_t shared_secret_len = mbedtls_mpi_size(&self->ecdh.z);
    if (shared_secret_len > sizeof(shared_secret)) {
        printf("[ERROR] Shared secret too long: %zu\n", shared_secret_len);
        return false;
    }
    
    int ret = mbedtls_mpi_write_binary(&self->ecdh.z, shared_secret, shared_secret_len);
    if (ret != 0) {
        printf("[ERROR] Failed to write shared secret: -0x%04X\n", -ret);
        return false;
    }
    
    printf("[HKDF-DEBUG] Shared Secret (%zu bytes): ", shared_secret_len);
    for (size_t i = 0; i < shared_secret_len; i++) printf("%02X ", shared_secret[i]);
    printf("\n");
    
    /* HKDF-Extract */
    uint8_t prk[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = mbedtls_hkdf_extract(md_info, salt, sizeof(salt), shared_secret, shared_secret_len, prk);
    if (ret != 0) {
        printf("[ERROR] HKDF-Extract failed: -0x%04X\n", -ret);
        return false;
    }
    
    /* HKDF-Expand */
    uint8_t okm[64];
    const uint8_t info[] = "IEC62351-5-UpdateKeys";
    ret = mbedtls_hkdf_expand(md_info, prk, sizeof(prk), info, sizeof(info) - 1, okm, sizeof(okm));
    if (ret != 0) {
        printf("[ERROR] HKDF-Expand failed: -0x%04X\n", -ret);
        return false;
    }
    
    /* Split into keys */
    memcpy(self->K_UE, okm, 32);
    memcpy(self->K_UA, okm + 32, 32);
    
    /* Set K_UE as the KEK (Key Encryption Key) for AES-256-KW wrapping */
    ret = mbedtls_nist_kw_setkey(&self->kw_ctx, MBEDTLS_CIPHER_ID_AES,
                                 self->K_UE, 256, 1);  /* 1 = wrap mode */
    if (ret != 0) {
        printf("[ERROR] Failed to set KEK (K_UE) for key wrapping: -0x%04X\n", -ret);
        return false;
    }
    
    printf("[HANDSHAKE] Update keys derived successfully\n");
    return true;
}

#endif /* APROFILE_DERIVE_UPDATE_KEYS_DEFINED */

/**
 * @brief Generate random Session Keys as per IEC 62351-5:2023 Clause 8.4.2.4.3
 * 
 * @param self AProfile context
 * @return true on success, false on failure
 */
bool AProfile_generateSessionKeys(AProfileContext self) {
    if (!self) return false;
    
    // Generate random session keys
    if (mbedtls_ctr_drbg_random(&self->ctr_drbg, self->K_SC, 32) != 0 ||
        mbedtls_ctr_drbg_random(&self->ctr_drbg, self->K_SM, 32) != 0) {
        printf("[ERROR] Failed to generate random session keys\n");
        return false;
    }
    
    self->sessionKeysGenerated = true;
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
bool AProfile_wrapSessionKeys(AProfileContext self, uint8_t* wrapped_keys, size_t* wrapped_len) {
    if (!self || !wrapped_keys || !wrapped_len) return false;
    
    // Concatenate K_SC and K_SM
    uint8_t key_data[64];
    memcpy(key_data, self->K_SC, 32);
    memcpy(key_data + 32, self->K_SM, 32);
    
    // Use AES-256-KW to wrap the keys (64 bytes input + 8 bytes KW overhead = 72 bytes output)
    size_t out_len = 72;
    size_t max_out_len = *wrapped_len;  // Use provided buffer size
    if (max_out_len < 72) {
        printf("[ERROR] Output buffer too small for wrapped keys (%zu < 72)\n", max_out_len);
        return false;
    }
    
    int ret = mbedtls_nist_kw_wrap(&self->kw_ctx, 
                     MBEDTLS_KW_MODE_KW, 
                     key_data, 
                     64, 
                     wrapped_keys, 
                     &out_len,
                     max_out_len);
    
    if (ret != 0) {
        printf("[ERROR] Key wrapping failed: -0x%04X\n", -ret);
        return false;
    }
    
    *wrapped_len = out_len;
    
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
bool AProfile_calculateMACOverASDU(AProfileContext self, CS101_ASDU asdu, uint8_t* mac) {
    if (!self || !asdu || !mac) return false;
    
    /* IEC 62351-5:2023: MAC is calculated over ASDU bytes BEFORE the MAC field is added.
     * Calculate MAC directly from the received ASDU's internal buffer,
     * excluding only the MAC information object bytes at the end. */
    
    struct sCS101_ASDU* asdu_internal = (struct sCS101_ASDU*)asdu;
    if (!asdu_internal || !asdu_internal->asdu) {
        printf("[ERROR] Invalid ASDU structure\n");
        return false;
    }
    
    TypeID typeId = CS101_ASDU_getTypeID(asdu);
    int numElements = CS101_ASDU_getNumberOfElements(asdu);
    
    printf("[MAC-CALC] ASDU Type=%d, Elements=%d\n", typeId, numElements);
    
    /* For security messages with only a MAC (like S_UK_NA_1), the MAC is calculated over
     * just the ASDU header (6 bytes: Type, VSQ, COT, OA, CA). */
    int mac_calc_length;
    
    if (numElements == 1) {
        /* Only MAC present - calculate over ASDU header only */
        mac_calc_length = 6;
    } else {
        /* Data + MAC - calculate over header + all IOs except last (MAC)
         * Last IO is the MAC: IOA(3) + Length(1) + MAC(32) = 36 bytes */
        int total_payload = asdu_internal->payloadSize;
        int mac_io_size = 36;
        
        if (total_payload < mac_io_size) {
            printf("[ERROR] Payload too small to contain MAC\n");
            return false;
        }
        
        mac_calc_length = 6 + (total_payload - mac_io_size);
    }
    
    printf("[MAC-CALC] Calculating MAC over %d bytes\n", mac_calc_length);
    printf("[MAC-CALC] ASDU bytes: ");
    for (int i = 0; i < mac_calc_length && i < 50; i++) {
        printf("%02X ", asdu_internal->asdu[i]);
    }
    printf("\n");
    
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) {
        printf("[ERROR] Failed to get SHA-256 MD info\n");
        return false;
    }
    
    printf("[MAC-CALC] K_UA: ");
    for (int i = 0; i < 32; i++) printf("%02X ", self->K_UA[i]);
    printf("\n");
    
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32,
                             asdu_internal->asdu, mac_calc_length, mac);
    
    printf("[MAC-CALC] Calculated MAC: ");
    for (int i = 0; i < 32; i++) printf("%02X ", mac[i]);
    printf("\n");
    
    if (ret != 0) {
        printf("[ERROR] HMAC calculation failed: %d\n", ret);
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
    int ret = 0;
   /* Generate random data for this station - IEC 62351-5:2023 Clause 8.3.1 */
    mbedtls_ctr_drbg_random(&self->ctr_drbg, self->R_C, 32);
    
    /* Initialize ECDH group if not already done */
    if (self->ecdh.grp.id == 0) {
        mbedtls_ecp_group_init(&self->ecdh.grp);
        ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) {
            printf("[ERROR] Failed to initialize ECDH group: -0x%04X\n", -ret);
            return false;
        }
    } else {
        /* Reset the ECDH context if it was already initialized */
        mbedtls_ecp_group_free(&self->ecdh.grp);
        mbedtls_ecdh_free(&self->ecdh);
        mbedtls_ecdh_init(&self->ecdh);
        
        ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) {
            printf("[ERROR] Failed to reinitialize ECDH group: -0x%04X\n", -ret);
            return false;
        }
    }
    
    /* Generate ECDH key pair */
    printf("[CRYPTO] Generating ECDH key pair...\n");
    ret = mbedtls_ecdh_gen_public(&self->ecdh.grp, &self->ecdh.d, &self->ecdh.Q,
                                    mbedtls_ctr_drbg_random, &self->ctr_drbg);
    if (ret != 0) {
        printf("[ERROR] Failed to generate ECDH key pair: -0x%04X\n", -ret);
        return false;
    }
    
    /* Export public key in uncompressed format (0x04 || X || Y) */
    printf("[CRYPTO] Exporting public key in uncompressed format...\n");
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&self->ecdh.grp, &self->ecdh.Q,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                       self->localPublicKey, sizeof(self->localPublicKey));
    if (ret != 0) {
        printf("[ERROR] Failed to export public key: -0x%04X\n", -ret);
        return false;
    }
    
    self->localPublicKeyLen = (int)olen;
    
    /* Verify the exported public key format */
    if (self->localPublicKey[0] != 0x04) {
        printf("[ERROR] Invalid public key format. First byte: 0x%02X (expected 0x04)\n", 
               self->localPublicKey[0]);
        return false;
    }
    
    printf("[CRYPTO] Generated ECDH key pair and exported public key (%d bytes)\n", self->localPublicKeyLen);
    
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
    /* Override the type to match the ASDU type S_AR_NA_1.
     * This is safe because: (1) spk_random is a local variable that will be destroyed after encoding,
     * (2) CS101_ASDU_addInformationObject encodes the data into the ASDU buffer and doesn't keep a reference,
     * (3) The library requires all information objects in an ASDU to have the same type as the ASDU itself. */
    ((struct sInformationObject*)spk_random)->type = S_AR_NA_1;
    bool added1 = CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_random);
    printf("[HANDSHAKE] Added random data (IOA 1) to Association Request: %s\n", added1 ? "SUCCESS" : "FAILED");
    printf("[DEBUG] ASDU element count after adding random: %d\n", CS101_ASDU_getNumberOfElements(asdu));

    /* Add ECDH public key as second information object */
    SecurityPublicKey spk_key = SecurityPublicKey_create(NULL, 2, self->localPublicKeyLen, self->localPublicKey);
    if (!spk_key) {
        SecurityPublicKey_destroy(spk_random);
        CS101_ASDU_destroy(asdu);
        return false;
    }
    /* Override the type to match the ASDU type S_AR_NA_1 */
    ((struct sInformationObject*)spk_key)->type = S_AR_NA_1;
    bool added2 = CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_key);
    printf("[HANDSHAKE] Added public key (IOA 2) to Association Request: %s\n", added2 ? "SUCCESS" : "FAILED");
    printf("[DEBUG] ASDU element count after adding key: %d\n", CS101_ASDU_getNumberOfElements(asdu));

    if (self->sendAsdu) {
        uint8_t final_vsq = CS101_ASDU_getNumberOfElements(asdu);
        printf("[HANDSHAKE] Sending Association Request with VSQ=%d\n", final_vsq);
        self->sendAsdu(self->connection, asdu);
    }
    
    SecurityPublicKey_destroy(spk_random);
    SecurityPublicKey_destroy(spk_key);
    CS101_ASDU_destroy(asdu);
    
    self->state = APROFILE_STATE_ASSOC_PENDING;
    printf("[CRYPTO] Sent: ClientRandom (32 bytes) + ECDH Public Key (65 bytes)\n");
    printf("[STATE] Waiting for Association Response...\n");
    return true;
}

/**
 * @brief Send Association Response (S_AS_NA_1) - Clause 8.3.2 (Server Side)
 */
bool
AProfile_sendAssociationResponse(AProfileContext self)
{
    printf("\n[HANDSHAKE STEP 2/8] Sending Association Response (S_AS_NA_1)\n");
    printf("[CRYPTO] Sending server's ECDH public key and random data\n");
    
    /* Create ASDU */
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_AS_NA_1);
    
    /* Add server's random data as first information object - R_S (Controlled Station Random) */
    SecurityPublicKey spk_random = SecurityPublicKey_create(NULL, 1, 32, self->R_S);
    if (!spk_random) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    ((struct sInformationObject*)spk_random)->type = S_AS_NA_1;
    bool added1 = CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_random);
    printf("[HANDSHAKE] Added server random data (IOA 1) to Association Response: %s\n", added1 ? "SUCCESS" : "FAILED");

    /* Add server's ECDH public key as second information object */
    SecurityPublicKey spk_key = SecurityPublicKey_create(NULL, 2, self->localPublicKeyLen, self->localPublicKey);
    if (!spk_key) {
        SecurityPublicKey_destroy(spk_random);
        CS101_ASDU_destroy(asdu);
        return false;
    }
    ((struct sInformationObject*)spk_key)->type = S_AS_NA_1;
    bool added2 = CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_key);
    printf("[HANDSHAKE] Added server public key (IOA 2) to Association Response: %s\n", added2 ? "SUCCESS" : "FAILED");

    if (self->sendAsdu) {
        uint8_t final_vsq = CS101_ASDU_getNumberOfElements(asdu);
        printf("[HANDSHAKE] Sending Association Response with VSQ=%d\n", final_vsq);
        self->sendAsdu(self->connection, asdu);
    }
    
    SecurityPublicKey_destroy(spk_random);
    SecurityPublicKey_destroy(spk_key);
    CS101_ASDU_destroy(asdu);
    
    printf("[CRYPTO] Sent: ServerRandom (32 bytes) + ECDH Public Key (65 bytes)\n");
    printf("[STATE] Waiting for Update Key Change Request...\n");
    return true;
}

/**
 * @brief Handle Association Response (S_AS_NA_1) - Clause 8.3.2 (Client Side)
 */
bool
AProfile_handleAssociationResponse(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Received Association Response (S_AS_NA_1)\n");
    
    /* Extract peer's random data and public key (now in two separate IOs) */
    SecurityPublicKey spk_random = (SecurityPublicKey)CS101_ASDU_getElement(asdu, 0);
    if (!spk_random) return false;
    
    if (InformationObject_getObjectAddress((InformationObject)spk_random) != 1) {
        printf("[ERROR] Expected random data at IOA 1, got %d\n", InformationObject_getObjectAddress((InformationObject)spk_random));
        return false;
    }

    const uint8_t* peer_random = SecurityPublicKey_getKeyValue(spk_random);
    int random_len = SecurityPublicKey_getKeyLength(spk_random);
    if (random_len != 32) return false;
    
    /* Copy peer's random data - R_S (Controlled Station Random) */
    memcpy(self->R_S, peer_random, 32);
    
    /* Get second information object (ECDH public key, 65 bytes) */
    SecurityPublicKey spk_key = (SecurityPublicKey)CS101_ASDU_getElement(asdu, 1);
    if (!spk_key) return false;
    
    if (InformationObject_getObjectAddress((InformationObject)spk_key) != 2) {
        printf("[ERROR] Expected public key at IOA 2, got %d\n", InformationObject_getObjectAddress((InformationObject)spk_key));
        return false;
    }

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
    if (!AProfile_deriveUpdateKeys(self)) {
        return false;
    }
    
    self->state = APROFILE_STATE_ASSOC_COMPLETE;
    
    /* Automatically send Update Key Change Request */
    return AProfile_sendUpdateKeyChangeRequest(self);
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
    
    /* IEC 62351-5:2023: Calculate MAC over ASDU header with VSQ=1 */
    /* First, create a temporary ASDU header to calculate the MAC */
    uint8_t asdu_header[6];
    asdu_header[0] = S_UK_NA_1;  /* Type ID */
    asdu_header[1] = 0x01;        /* VSQ = 1 (one element: the MAC) */
    asdu_header[2] = CS101_COT_AUTHENTICATION;  /* COT */
    asdu_header[3] = 0x00;        /* Originator Address */
    asdu_header[4] = 0x00;        /* Common Address (low byte) */
    asdu_header[5] = 0x00;        /* Common Address (high byte) */
    
    /* Calculate MAC over ASDU header only (6 bytes) */
    printf("[CLIENT-MAC] ASDU header (6 bytes): ");
    for (int i = 0; i < 6; i++) printf("%02X ", asdu_header[i]);
    printf("\n");
    
    printf("[CLIENT-MAC] K_UA: ");
    for (int i = 0; i < 32; i++) printf("%02X ", self->K_UA[i]);
    printf("\n");
    
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, asdu_header, 6, mac);
    
    printf("[CLIENT-MAC] Calculated MAC: ");
    for (int i = 0; i < 32; i++) printf("%02X ", mac[i]);
    printf("\n");
    
    if (ret != 0) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    
    /* Now add the MAC as information object */
    SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, 32, mac);
    if (!spk) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    ((struct sInformationObject*)spk)->type = S_UK_NA_1;
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    
    /* Send the ASDU with the correct MAC */
    if (self->sendAsdu) {
        self->sendAsdu(self->connection, asdu);
    }
    
    InformationObject_destroy((InformationObject)spk);
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
    
    /* Debug: Check ASDU structure */
    int numElements = CS101_ASDU_getNumberOfElements(asdu);
    TypeID typeId = CS101_ASDU_getTypeID(asdu);
    printf("[DEBUG] ASDU Type=%d, Number of elements=%d\n", typeId, numElements);
    
    /* For security messages, we need to extract the MAC directly from the payload
     * because CS101_ASDU_getElement() doesn't work for SecurityPublicKey with non-standard types */
    struct sCS101_ASDU* asduInternal = (struct sCS101_ASDU*)asdu;
    
    if (!asduInternal || !asduInternal->payload) {
        printf("[ERROR] Invalid ASDU structure or NULL payload\n");
        return false;
    }
    
    /* S_UK_NA_1 format: IOA (3 bytes) + Length (1 byte) + MAC (32 bytes) = 36 bytes minimum
     * The payload starts after the ASDU header */
    uint8_t* payload = asduInternal->payload;
    int payloadSize = asduInternal->payloadSize;
    
    printf("[DEBUG] Payload size: %d bytes\n", payloadSize);
    printf("[DEBUG] Full payload dump: ");
    for (int i = 0; i < payloadSize; i++) printf("%02X ", payload[i]);
    printf("\n");
    
    /* Extract MAC from payload
     * Format: IOA (3 bytes) + Length (1 byte) + MAC data (32 bytes) */
    if (payloadSize < 36) {
        printf("[ERROR] Payload too small for MAC: %d bytes (need at least 36)\n", payloadSize);
        return false;
    }
    
    /* Skip IOA (3 bytes) and length (1 byte) to get to MAC data */
    const uint8_t* received_mac = payload + 4;
    int mac_len = payload[3]; /* Length byte */
    
    printf("[CRYPTO] Received MAC length: %d bytes\n", mac_len);
    printf("[CRYPTO] Received MAC: ");
    for (int i = 0; i < mac_len && i < 32; i++) printf("%02X ", received_mac[i]);
    printf("\n");
    
    if (mac_len != 32) {
        printf("[ERROR] Invalid MAC length: %d (expected 32)\n", mac_len);
        return false;
    }
    
    /* IEC 62351-5:2023 Clause 8.3.10.5: Verify MAC over ASDU bytes using K_UA */
    printf("[CRYPTO] Verifying MAC using Authentication Update Key (K_UA)...\n");
    if (!AProfile_verifyMACOverASDU(self, asdu, received_mac)) {
        printf("[ERROR] MAC verification failed for Update Key Change Request\n");
        return false;
    }
    
    printf("[CRYPTO] MAC verification successful - Update Keys confirmed\n");
    
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
    
    /* Ensure DRBG is seeded */
    if (self->ctr_drbg.reseed_counter == 0) {
        int ret = mbedtls_ctr_drbg_seed(&self->ctr_drbg, mbedtls_entropy_func, &self->entropy,
                                        (const unsigned char*)"lib60870", 8);
        if (ret != 0) {
            printf("[CRYPTO ERROR] Failed to seed DRBG: -0x%04X\n", -ret);
            return false;
        }
    }
    
    /* Create ASDU */
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) return false;
    
    CS101_ASDU_setTypeID(asdu, S_UR_NA_1);
    
    /* IEC 62351-5:2023 Clause 8.3.10: Calculate MAC over 6-byte ASDU header with VSQ=1
     * The header format is: Type (1) | VSQ (1) | COT (1) | OA (1) | CA (2)
     * We must use VSQ=1 because the final ASDU will have 1 element (the MAC itself) */
    uint8_t asdu_header[6];
    asdu_header[0] = S_UR_NA_1;  /* Type ID */
    asdu_header[1] = 1;           /* VSQ = 1 element (the MAC that will be added) */
    asdu_header[2] = CS101_COT_AUTHENTICATION;  /* COT */
    asdu_header[3] = 0;           /* Originator Address */
    asdu_header[4] = 0;           /* Common Address (LSB) */
    asdu_header[5] = 0;           /* Common Address (MSB) */
    
    printf("[SERVER-UR-MAC] ASDU header for MAC calculation (6 bytes): ");
    for (int i = 0; i < 6; i++) printf("%02X ", asdu_header[i]);
    printf("\n");
    printf("[SERVER-UR-MAC] K_UA: ");
    for (int i = 0; i < 32; i++) printf("%02X ", self->K_UA[i]);
    printf("\n");
    fflush(stdout);
    
    /* Calculate MAC over 6-byte ASDU header using K_UA */
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, asdu_header, 6, mac);
    
    printf("[SERVER-UR-MAC] Calculated MAC: ");
    for (int i = 0; i < 32; i++) printf("%02X ", mac[i]);
    printf("\n");
    fflush(stdout);
    
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
    ((struct sInformationObject*)spk)->type = S_UR_NA_1;  /* Match ASDU type */
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    
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
    printf("*** DEBUG: NEW CODE IS RUNNING - TIMESTAMP 2025-11-11 16:05 ***\n");
    fflush(stdout);
    
    /* Verify MAC */
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElement(asdu, 0);
    
    printf("[UR-DEBUG] CS101_ASDU_getElement returned: %p\n", (void*)spk);
    fflush(stdout);
    
    if (!spk) {
        printf("[UR-DEBUG] ERROR: CS101_ASDU_getElement returned NULL - no MAC element found!\n");
        fflush(stdout);
        return false;
    }
    
    const uint8_t* received_mac = SecurityPublicKey_getKeyValue(spk);
    
    /* IEC 62351-5:2023: Server computes MAC over 6-byte ASDU header (Type, VSQ, COT, OA, CA).
     * Deterministically verify against that header first, then fall back to generic verifier. */
    bool header_ok = false;
    {
        printf("[UR-DEBUG] Starting header-based verification...\n");
        fflush(stdout);
        
        Frame tf = (Frame)T104Frame_create();
        if (!tf) {
            printf("[UR-DEBUG] ERROR: T104Frame_create() returned NULL\n");
            fflush(stdout);
        } else {
            printf("[UR-DEBUG] Frame created successfully\n");
            fflush(stdout);
            
            CS101_ASDU_encode(asdu, tf);
            uint8_t* buf = Frame_getBuffer(tf);
            int sz = Frame_getMsgSize(tf);
            
            printf("[UR-DEBUG] Frame size: %d bytes (need >= 12)\n", sz);
            fflush(stdout);
            
            if (sz >= 12) {
                const uint8_t* hdr = buf + 6; /* 6-byte ASDU header starts after 6-byte APCI */
                uint8_t calc_mac[32];
                const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
                
                printf("[UR-DEBUG] Calling mbedtls_md_hmac...\n");
                fflush(stdout);
                
                int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, hdr, 6, calc_mac);
                
                printf("[UR-DEBUG] mbedtls_md_hmac returned: %d\n", ret);
                fflush(stdout);
                
                if (ret == 0) {
                    /* Diagnostics */
                    printf("[UR-VERIFY] Header: ");
                    for (int i = 0; i < 6; i++) printf("%02X ", hdr[i]);
                    printf("\n");
                    printf("[UR-VERIFY] K_UA: ");
                    for (int i = 0; i < 32; i++) printf("%02X ", self->K_UA[i]);
                    printf("\n");
                    printf("[UR-VERIFY] Calc MAC: ");
                    for (int i = 0; i < 32; i++) printf("%02X ", calc_mac[i]);
                    printf("\n");
                    printf("[UR-VERIFY] Recv MAC: ");
                    for (int i = 0; i < 32; i++) printf("%02X ", received_mac[i]);
                    printf("\n");

                    int diff = 0;
                    for (int i = 0; i < 32; i++) diff |= (calc_mac[i] ^ received_mac[i]);
                    header_ok = (diff == 0);
                    
                    printf("[UR-DEBUG] header_ok = %s\n", header_ok ? "TRUE" : "FALSE");
                    fflush(stdout);
                } else {
                    printf("[UR-DEBUG] ERROR: mbedtls_md_hmac failed with code %d\n", ret);
                    fflush(stdout);
                }
            } else {
                printf("[UR-DEBUG] ERROR: Frame size too small (%d < 12)\n", sz);
                fflush(stdout);
            }
            T104Frame_destroy(tf);
        }
    }

    bool generic_ok = false;
    if (!header_ok) {
        /* Fallback to generic verifier (calculates per numElements and payload) */
        generic_ok = AProfile_verifyMACOverASDU(self, asdu, received_mac);
    }

    if (!(header_ok || generic_ok)) {
        printf("APROFILE: MAC verification failed for Update Key Change Response\n");
        return false;
    }

    printf("APROFILE: MAC verification successful - Update Keys confirmed by both parties\n");
    self->state = APROFILE_STATE_UPDATE_KEY_COMPLETE;
    /* Automatically send Session Request */
    return AProfile_sendSessionRequest(self);
}

/**
 * @brief Send Session Request (S_SR_NA_1) - Clause 8.4.1
 */
bool
AProfile_sendSessionRequest(AProfileContext self)
{
    printf("\n[HANDSHAKE STEP 5/8] Sending Session Request (S_SR_NA_1)\n");
    printf("[SESSION] Requesting new session establishment\n");
    fflush(stdout);
    
    if (!self) {
        printf("[ERROR] Session Request: self is NULL\n");
        fflush(stdout);
        return false;
    }
    
    if (!self->parameters) {
        printf("[ERROR] Session Request: parameters is NULL\n");
        fflush(stdout);
        return false;
    }
    
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) {
        printf("[ERROR] Session Request: Failed to create ASDU\n");
        fflush(stdout);
        return false;
    }
    
    CS101_ASDU_setTypeID(asdu, S_SR_NA_1);
    
    /* Add placeholder information object */
    SecurityPublicKey spk = SecurityPublicKey_create(NULL, 65535, 1, (uint8_t*)"\x00");
    if (!spk) {
        CS101_ASDU_destroy(asdu);
        return false;
    }
    ((struct sInformationObject*)spk)->type = S_SR_NA_1;  /* Match ASDU type */
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    
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
    
    /* IEC 62351-5:2023 Clause 8.4.1: Calculate MAC over 6-byte ASDU header with VSQ=1 */
    uint8_t asdu_header[6];
    asdu_header[0] = S_SS_NA_1;  /* Type ID */
    asdu_header[1] = 1;           /* VSQ = 1 element (the MAC that will be added) */
    asdu_header[2] = CS101_COT_AUTHENTICATION;  /* COT */
    asdu_header[3] = 0;           /* Originator Address */
    asdu_header[4] = 0;           /* Common Address (LSB) */
    asdu_header[5] = 0;           /* Common Address (MSB) */
    
    /* Calculate MAC over 6-byte ASDU header using K_UA */
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, asdu_header, 6, mac);
    
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
    ((struct sInformationObject*)spk)->type = S_SS_NA_1;  /* Match ASDU type */
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    
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
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElement(asdu, 0);
    
    if (!spk) return false;
    
    if (InformationObject_getObjectAddress((InformationObject)spk) != 65535) {
        printf("[ERROR] Expected MAC at IOA 65535, got %d\n", InformationObject_getObjectAddress((InformationObject)spk));
        return false;
    }

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
bool AProfile_sendSessionKeyChangeRequest(AProfileContext self) {   
    if (!self) return false;
    
    // Generate session keys if not done
    if (!self->sessionKeysGenerated) {
        if (!AProfile_generateSessionKeys(self)) {
            printf("[ERROR] Failed to generate session keys\n");
            return false;
        }
    }

    printf("\n[HANDSHAKE STEP 7/8] Sending Session Key Change Request (S_SK_NA_1)\n");
    
    // Wrap session keys
    uint8_t wrapped_keys[72];
    size_t wrapped_len = sizeof(wrapped_keys);  // Must be set to buffer size for AProfile_wrapSessionKeys
    
    if (!AProfile_wrapSessionKeys(self, wrapped_keys, &wrapped_len) || wrapped_len == 0) {
        printf("[ERROR] Failed to wrap session keys\n");
        return false;
    }

    // Create ASDU
    CS101_ASDU asdu = CS101_ASDU_create(self->parameters, false, 
                                       CS101_COT_AUTHENTICATION, 0, 0, false, false);
    if (!asdu) {
        printf("[ERROR] Failed to create ASDU\n");
        return false;
    }
    
    CS101_ASDU_setTypeID(asdu, S_SK_NA_1);
    
    // Add wrapped keys (IOA=1)
    SecurityPublicKey spk_keys = SecurityPublicKey_create(NULL, 1, (int)wrapped_len, wrapped_keys);
    if (!spk_keys) {
        printf("[ERROR] Failed to create keys information object\n");
        CS101_ASDU_destroy(asdu);
        return false;
    }
    ((struct sInformationObject*)spk_keys)->type = S_SK_NA_1;  /* Match ASDU type */
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_keys);

    /* IEC 62351-5:2023 Clause 8.4.2: Calculate MAC over 6-byte ASDU header with VSQ=2
     * S_SK_NA_1 has 2 elements: wrapped keys (IOA=1) + MAC (IOA=2) */
    uint8_t asdu_header[6];
    asdu_header[0] = S_SK_NA_1;  /* Type ID */
    asdu_header[1] = 2;           /* VSQ = 2 elements (wrapped keys + MAC) */
    asdu_header[2] = CS101_COT_AUTHENTICATION;  /* COT */
    asdu_header[3] = 0;           /* Originator Address */
    asdu_header[4] = 0;           /* Common Address (LSB) */
    asdu_header[5] = 0;           /* Common Address (MSB) */
    
    uint8_t mac[32];
    printf("[CRYPTO] Calculating HMAC-SHA256 MAC...\n");
    
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, asdu_header, 6, mac);
    
    if (ret != 0) {
        printf("[ERROR] HMAC calculation failed: -0x%04X\n", -ret);
        return false;
    }
    
    // Add MAC (IOA=2)
    SecurityPublicKey spk_mac = SecurityPublicKey_create(NULL, 2, 32, mac);
    if (!spk_mac) {
        printf("[ERROR] Failed to create MAC information object\n");
        SecurityPublicKey_destroy(spk_keys);
        CS101_ASDU_destroy(asdu);
        return false;
    }
    ((struct sInformationObject*)spk_mac)->type = S_SK_NA_1;  /* Match ASDU type */
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk_mac);
    
    // Send ASDU
    bool sendResult = false;
    if (self->sendAsdu) {
        sendResult = self->sendAsdu(self->connection, asdu);
        if (sendResult) {
            printf("[INFO] Session Key Change Request sent successfully\n");
            // Update state
            self->state = APROFILE_STATE_SESSION_KEY_PENDING;
            // Start timer for response
            self->lastActivityTime = Hal_getTimeInMs();
        } else {
            printf("[ERROR] Failed to send Session Key Change Request\n");
        }
    }

    // Cleanup
    SecurityPublicKey_destroy(spk_keys);
    SecurityPublicKey_destroy(spk_mac);
    CS101_ASDU_destroy(asdu);
    
    return sendResult;
}

/**
 * @brief Handle Session Key Change Request (S_SK_NA_1) - Server side - Clause 8.4.2
 */
bool
AProfile_handleSessionKeyChangeRequest(AProfileContext self, CS101_ASDU asdu)
{
    printf("APROFILE: Server received Session Key Change Request (S_SK_NA_1)\n");
    
    /* Extract wrapped keys (first information object) */
    SecurityPublicKey spk_keys = (SecurityPublicKey)CS101_ASDU_getElement(asdu, 0);
    
    if (!spk_keys) return false;
    
    if (InformationObject_getObjectAddress((InformationObject)spk_keys) != 1) {
        printf("[ERROR] Expected wrapped keys at IOA 1, got %d\n", InformationObject_getObjectAddress((InformationObject)spk_keys));
        return false;
    }

    const uint8_t* wrapped_keys = SecurityPublicKey_getKeyValue(spk_keys);
    int wrapped_keys_len = SecurityPublicKey_getKeyLength(spk_keys);
    
    /* Extract MAC (second information object) */
    SecurityPublicKey spk_mac = (SecurityPublicKey)CS101_ASDU_getElement(asdu, 1);
    
    if (!spk_mac) return false;
    
    if (InformationObject_getObjectAddress((InformationObject)spk_mac) != 2) {
        printf("[ERROR] Expected MAC at IOA 2, got %d\n", InformationObject_getObjectAddress((InformationObject)spk_mac));
        return false;
    }

    const uint8_t* received_mac = SecurityPublicKey_getKeyValue(spk_mac);
    
    /* IEC 62351-5:2023 Clause 8.4.2: Verify MAC over 6-byte ASDU header with VSQ=2
     * S_SK_NA_1 has 2 elements: wrapped keys (IOA=1) + MAC (IOA=2) */
    uint8_t asdu_header[6];
    asdu_header[0] = S_SK_NA_1;  /* Type ID */
    asdu_header[1] = 2;           /* VSQ = 2 elements (wrapped keys + MAC) */
    asdu_header[2] = CS101_COT_AUTHENTICATION;  /* COT */
    asdu_header[3] = 0;           /* Originator Address */
    asdu_header[4] = 0;           /* Common Address (LSB) */
    asdu_header[5] = 0;           /* Common Address (MSB) */
    
    /* Calculate expected MAC */
    uint8_t calculated_mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, asdu_header, 6, calculated_mac);
    
    if (ret != 0) {
        printf("APROFILE: Failed to calculate MAC: -0x%04X\n", -ret);
        return false;
    }
    
    /* Compare MACs */
    if (memcmp(calculated_mac, received_mac, 32) != 0) {
        printf("APROFILE: MAC verification failed for Session Key Change Request\n");
        return false;
    }
    
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
    
    /* IEC 62351-5:2023 Clause 8.4.2: Calculate MAC over 6-byte ASDU header with VSQ=1 */
    uint8_t asdu_header[6];
    asdu_header[0] = S_SQ_NA_1;  /* Type ID */
    asdu_header[1] = 1;           /* VSQ = 1 element (the MAC that will be added) */
    asdu_header[2] = CS101_COT_AUTHENTICATION;  /* COT */
    asdu_header[3] = 0;           /* Originator Address */
    asdu_header[4] = 0;           /* Common Address (LSB) */
    asdu_header[5] = 0;           /* Common Address (MSB) */
    
    /* Calculate MAC over 6-byte ASDU header using K_UA */
    uint8_t mac[32];
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(md_info, self->K_UA, 32, asdu_header, 6, mac);
    
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
    ((struct sInformationObject*)spk)->type = S_SQ_NA_1;  /* Match ASDU type */
    
    CS101_ASDU_addInformationObject(asdu, (InformationObject)spk);
    
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
    printf("[DEBUG] SERVER security_active flag set to: %s\n", self->security_active ? "TRUE" : "FALSE");
    printf("[DEBUG] SERVER isControllingStation: %s\n", self->isControllingStation ? "TRUE" : "FALSE");
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
    SecurityPublicKey spk = (SecurityPublicKey)CS101_ASDU_getElement(asdu, 0);
    
    if (!spk) return false;
    
    if (InformationObject_getObjectAddress((InformationObject)spk) != 65535) {
        printf("[ERROR] Expected MAC at IOA 65535, got %d\n", InformationObject_getObjectAddress((InformationObject)spk));
        return false;
    }

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
    printf("[DEBUG] CLIENT security_active flag set to: %s\n", self->security_active ? "TRUE" : "FALSE");
    printf("[DEBUG] CLIENT isControllingStation: %s\n", self->isControllingStation ? "TRUE" : "FALSE");
    return true;
}

#endif /* CONFIG_CS104_APROFILE */

AProfileContext
AProfileContext_create(CS101_AppLayerParameters parameters, bool isControllingStation)
{
    AProfileContext self = (AProfileContext)calloc(1, sizeof(struct sAProfileContext));
    
    if (self) {
        /* Initialize ECDH context */
        mbedtls_ecdh_init(&self->ecdh);
        
        /* Initialize ECDH group with SECP256R1 curve */
        mbedtls_ecp_group_init(&self->ecdh.grp);
        int ret = mbedtls_ecp_group_load(&self->ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret != 0) {
            printf("[ERROR] Failed to load curve: -0x%04X\n", -ret);
            free(self);
            return NULL;
        }
        
        /* Initialize cryptographic components */
        mbedtls_ctr_drbg_init(&self->ctr_drbg);
        mbedtls_entropy_init(&self->entropy);
        mbedtls_nist_kw_init(&self->kw_ctx);
        
        /* Initialize DRBG */
        ret = mbedtls_ctr_drbg_seed(&self->ctr_drbg, mbedtls_entropy_func, &self->entropy,
                                    (const unsigned char*)"lib60870", 8);
        if (ret != 0) {
            printf("[CRYPTO ERROR] Failed to seed DRBG: -0x%04X\n", -ret);
            mbedtls_ecdh_free(&self->ecdh);
            free(self);
            return NULL;
        }
        
        /* Rest of initialization code */
    }
    
    return self;
}

void
AProfileContext_destroy(AProfileContext self)
{
    if (self) {
        /* Clean up ECDH context */
        mbedtls_ecdh_free(&self->ecdh);
        
        /* Rest of cleanup code */
        mbedtls_entropy_free(&self->entropy);
        mbedtls_ctr_drbg_free(&self->ctr_drbg);
        mbedtls_nist_kw_free(&self->kw_ctx);
        free(self);
    }
}
