/*
 * IEC 62351-5:2023 Application Layer Security Message Definitions
 * 
 * This file defines all message structures for the A-Profile security protocol
 */

#ifndef APROFILE_MESSAGES_H_
#define APROFILE_MESSAGES_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Session Key Wrap Algorithms */
typedef enum {
    KWA_AES256_WRAP = 0x01  /* AES-256 Key Wrap (RFC 3394) */
} SessionKeyWrapAlgorithm;

/* MAC Algorithms */
typedef enum {
    MAL_HMAC_SHA256 = 0x01,  /* HMAC-SHA-256 */
    MAL_HMAC_SHA384 = 0x02,  /* HMAC-SHA-384 */
    MAL_HMAC_SHA512 = 0x03   /* HMAC-SHA-512 */
} MACAlgorithm;

/* Data Protection Algorithms */
typedef enum {
    DPA_AES256_GCM = 0x01,      /* AES-256-GCM */
    DPA_HMAC_SHA256_ONLY = 0x02 /* MAC only (no encryption) */
} DataProtectionAlgorithm;

/* Association Request Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    uint16_t protocol_info;          /* Protocol information */
    uint16_t cert_data_length;       /* Certificate data length */
    uint8_t* cert_data;              /* Certificate data (X.509 DER) */
} AssociationRequest;

/* Association Response Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    uint16_t cert_data_length;       /* Certificate data length */
    uint16_t random_data_length;     /* Random data length */
    uint8_t* cert_data;              /* Certificate data (X.509 DER) */
    uint8_t* random_data;            /* Random data for HKDF */
} AssociationResponse;

/* Update Key Change Request Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    SessionKeyWrapAlgorithm kwa;     /* Session key wrap algorithm */
    MACAlgorithm mal;                /* MAC algorithm */
    uint16_t random_data_length;     /* Controlling station random data length */
    uint8_t* random_data;            /* Controlling station random data */
    uint8_t mac[32];                 /* Message authentication code (HMAC-SHA256) */
} UpdateKeyChangeRequest;

/* Update Key Change Response Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    uint8_t mac[32];                 /* Message authentication code */
} UpdateKeyChangeResponse;

/* Session Request Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    uint16_t protocol_info;          /* Protocol information */
    uint16_t random_data_length;     /* Controlling station random data length */
    uint8_t* random_data;            /* Controlling station random data */
} SessionRequest;

/* Session Response Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    uint16_t random_data_length;     /* Controlled station random data length */
    uint8_t* random_data;            /* Controlled station random data */
    uint8_t mac[32];                 /* Message authentication code */
} SessionResponse;

/* Session Key Change Request Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    DataProtectionAlgorithm dpa;     /* Data protection algorithm */
    uint16_t wrapped_key_length;     /* Wrapped key data length */
    uint8_t* wrapped_key_data;       /* Wrapped session keys (AES-256 wrapped) */
    uint8_t mac[32];                 /* Message authentication code */
} SessionKeyChangeRequest;

/* Session Key Change Response Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    uint8_t mac[32];                 /* Message authentication code */
} SessionKeyChangeResponse;

/* Secure Data Message Structure */
typedef struct {
    uint16_t aim;                    /* Controlling station association ID */
    uint16_t ais;                    /* Controlled station association ID */
    uint32_t sequence_number;        /* Data sequence number */
    uint16_t app_data_length;        /* Application data length */
    uint8_t* secure_payload;         /* Encrypted ASDU + MAC or ASDU + MAC */
} SecureDataMessage;

#ifdef __cplusplus
}
#endif

#endif /* APROFILE_MESSAGES_H_ */
