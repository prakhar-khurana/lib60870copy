/*
 * IEC 62351-5:2023 Message Encoding/Decoding Functions
 */

#include "aprofile_messages.h"
#include "aprofile_internal.h"
#include "cs101_asdu_internal.h"
#include <string.h>
#include <stdlib.h>

#if (CONFIG_CS104_APROFILE == 1)

/* Helper: Write uint16 in little-endian */
static void write_uint16_le(uint8_t* buf, uint16_t value) {
    buf[0] = value & 0xFF;
    buf[1] = (value >> 8) & 0xFF;
}

/* Helper: Read uint16 in little-endian */
static uint16_t read_uint16_le(const uint8_t* buf) {
    return (uint16_t)(buf[0] | (buf[1] << 8));
}

/* Helper: Write uint32 in little-endian */
static void write_uint32_le(uint8_t* buf, uint32_t value) {
    buf[0] = value & 0xFF;
    buf[1] = (value >> 8) & 0xFF;
    buf[2] = (value >> 16) & 0xFF;
    buf[3] = (value >> 24) & 0xFF;
}

/* Helper: Read uint32 in little-endian */
static uint32_t read_uint32_le(const uint8_t* buf) {
    return (uint32_t)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
}

/*=============================================================================
 * Association Request Encoding/Decoding
 *===========================================================================*/

int AProfile_encodeAssociationRequest(
    const AssociationRequest* msg,
    uint8_t* buffer,
    int bufferSize)
{
    if (!msg || !buffer) return -1;
    
    int required = 8 + msg->cert_data_length;
    if (bufferSize < required) return -1;
    
    int pos = 0;
    write_uint16_le(buffer + pos, msg->aim); pos += 2;
    write_uint16_le(buffer + pos, msg->ais); pos += 2;
    write_uint16_le(buffer + pos, msg->protocol_info); pos += 2;
    write_uint16_le(buffer + pos, msg->cert_data_length); pos += 2;
    
    if (msg->cert_data && msg->cert_data_length > 0) {
        memcpy(buffer + pos, msg->cert_data, msg->cert_data_length);
        pos += msg->cert_data_length;
    }
    
    return pos;
}

int AProfile_decodeAssociationRequest(
    const uint8_t* buffer,
    int bufferSize,
    AssociationRequest* msg)
{
    if (!buffer || !msg || bufferSize < 8) return -1;
    
    int pos = 0;
    msg->aim = read_uint16_le(buffer + pos); pos += 2;
    msg->ais = read_uint16_le(buffer + pos); pos += 2;
    msg->protocol_info = read_uint16_le(buffer + pos); pos += 2;
    msg->cert_data_length = read_uint16_le(buffer + pos); pos += 2;
    
    if (bufferSize < pos + msg->cert_data_length) return -1;
    
    msg->cert_data = (uint8_t*)malloc(msg->cert_data_length);
    if (!msg->cert_data) return -1;
    
    memcpy(msg->cert_data, buffer + pos, msg->cert_data_length);
    pos += msg->cert_data_length;
    
    return pos;
}

/*=============================================================================
 * Association Response Encoding/Decoding
 *===========================================================================*/

int AProfile_encodeAssociationResponse(
    const AssociationResponse* msg,
    uint8_t* buffer,
    int bufferSize)
{
    if (!msg || !buffer) return -1;
    
    int required = 8 + msg->cert_data_length + msg->random_data_length;
    if (bufferSize < required) return -1;
    
    int pos = 0;
    write_uint16_le(buffer + pos, msg->aim); pos += 2;
    write_uint16_le(buffer + pos, msg->ais); pos += 2;
    write_uint16_le(buffer + pos, msg->cert_data_length); pos += 2;
    write_uint16_le(buffer + pos, msg->random_data_length); pos += 2;
    
    if (msg->cert_data && msg->cert_data_length > 0) {
        memcpy(buffer + pos, msg->cert_data, msg->cert_data_length);
        pos += msg->cert_data_length;
    }
    
    if (msg->random_data && msg->random_data_length > 0) {
        memcpy(buffer + pos, msg->random_data, msg->random_data_length);
        pos += msg->random_data_length;
    }
    
    return pos;
}

int AProfile_decodeAssociationResponse(
    const uint8_t* buffer,
    int bufferSize,
    AssociationResponse* msg)
{
    if (!buffer || !msg || bufferSize < 8) return -1;
    
    int pos = 0;
    msg->aim = read_uint16_le(buffer + pos); pos += 2;
    msg->ais = read_uint16_le(buffer + pos); pos += 2;
    msg->cert_data_length = read_uint16_le(buffer + pos); pos += 2;
    msg->random_data_length = read_uint16_le(buffer + pos); pos += 2;
    
    if (bufferSize < pos + msg->cert_data_length + msg->random_data_length) return -1;
    
    msg->cert_data = (uint8_t*)malloc(msg->cert_data_length);
    if (!msg->cert_data) return -1;
    memcpy(msg->cert_data, buffer + pos, msg->cert_data_length);
    pos += msg->cert_data_length;
    
    msg->random_data = (uint8_t*)malloc(msg->random_data_length);
    if (!msg->random_data) {
        free(msg->cert_data);
        return -1;
    }
    memcpy(msg->random_data, buffer + pos, msg->random_data_length);
    pos += msg->random_data_length;
    
    return pos;
}

/*=============================================================================
 * Update Key Change Request Encoding/Decoding
 *===========================================================================*/

int AProfile_encodeUpdateKeyChangeRequest(
    const UpdateKeyChangeRequest* msg,
    uint8_t* buffer,
    int bufferSize)
{
    if (!msg || !buffer) return -1;
    
    int required = 8 + msg->random_data_length + 32;
    if (bufferSize < required) return -1;
    
    int pos = 0;
    write_uint16_le(buffer + pos, msg->aim); pos += 2;
    write_uint16_le(buffer + pos, msg->ais); pos += 2;
    buffer[pos++] = (uint8_t)msg->kwa;
    buffer[pos++] = (uint8_t)msg->mal;
    write_uint16_le(buffer + pos, msg->random_data_length); pos += 2;
    
    if (msg->random_data && msg->random_data_length > 0) {
        memcpy(buffer + pos, msg->random_data, msg->random_data_length);
        pos += msg->random_data_length;
    }
    
    memcpy(buffer + pos, msg->mac, 32);
    pos += 32;
    
    return pos;
}

int AProfile_decodeUpdateKeyChangeRequest(
    const uint8_t* buffer,
    int bufferSize,
    UpdateKeyChangeRequest* msg)
{
    if (!buffer || !msg || bufferSize < 8) return -1;
    
    int pos = 0;
    msg->aim = read_uint16_le(buffer + pos); pos += 2;
    msg->ais = read_uint16_le(buffer + pos); pos += 2;
    msg->kwa = (SessionKeyWrapAlgorithm)buffer[pos++];
    msg->mal = (MACAlgorithm)buffer[pos++];
    msg->random_data_length = read_uint16_le(buffer + pos); pos += 2;
    
    if (bufferSize < pos + msg->random_data_length + 32) return -1;
    
    msg->random_data = (uint8_t*)malloc(msg->random_data_length);
    if (!msg->random_data) return -1;
    memcpy(msg->random_data, buffer + pos, msg->random_data_length);
    pos += msg->random_data_length;
    
    memcpy(msg->mac, buffer + pos, 32);
    pos += 32;
    
    return pos;
}

/*=============================================================================
 * Session Key Change Request Encoding/Decoding
 *===========================================================================*/

int AProfile_encodeSessionKeyChangeRequest(
    const SessionKeyChangeRequest* msg,
    uint8_t* buffer,
    int bufferSize)
{
    if (!msg || !buffer) return -1;
    
    int required = 7 + msg->wrapped_key_length + 32;
    if (bufferSize < required) return -1;
    
    int pos = 0;
    write_uint16_le(buffer + pos, msg->aim); pos += 2;
    write_uint16_le(buffer + pos, msg->ais); pos += 2;
    buffer[pos++] = (uint8_t)msg->dpa;
    write_uint16_le(buffer + pos, msg->wrapped_key_length); pos += 2;
    
    if (msg->wrapped_key_data && msg->wrapped_key_length > 0) {
        memcpy(buffer + pos, msg->wrapped_key_data, msg->wrapped_key_length);
        pos += msg->wrapped_key_length;
    }
    
    memcpy(buffer + pos, msg->mac, 32);
    pos += 32;
    
    return pos;
}

int AProfile_decodeSessionKeyChangeRequest(
    const uint8_t* buffer,
    int bufferSize,
    SessionKeyChangeRequest* msg)
{
    if (!buffer || !msg || bufferSize < 7) return -1;
    
    int pos = 0;
    msg->aim = read_uint16_le(buffer + pos); pos += 2;
    msg->ais = read_uint16_le(buffer + pos); pos += 2;
    msg->dpa = (DataProtectionAlgorithm)buffer[pos++];
    msg->wrapped_key_length = read_uint16_le(buffer + pos); pos += 2;
    
    if (bufferSize < pos + msg->wrapped_key_length + 32) return -1;
    
    msg->wrapped_key_data = (uint8_t*)malloc(msg->wrapped_key_length);
    if (!msg->wrapped_key_data) return -1;
    memcpy(msg->wrapped_key_data, buffer + pos, msg->wrapped_key_length);
    pos += msg->wrapped_key_length;
    
    memcpy(msg->mac, buffer + pos, 32);
    pos += 32;
    
    return pos;
}

/*=============================================================================
 * Secure Data Message Encoding/Decoding
 *===========================================================================*/

int AProfile_encodeSecureData(
    const SecureDataMessage* msg,
    uint8_t* buffer,
    int bufferSize)
{
    if (!msg || !buffer) return -1;
    
    int required = 12 + msg->app_data_length;
    if (bufferSize < required) return -1;
    
    int pos = 0;
    write_uint16_le(buffer + pos, msg->aim); pos += 2;
    write_uint16_le(buffer + pos, msg->ais); pos += 2;
    write_uint32_le(buffer + pos, msg->sequence_number); pos += 4;
    write_uint16_le(buffer + pos, msg->app_data_length); pos += 2;
    
    if (msg->secure_payload && msg->app_data_length > 0) {
        memcpy(buffer + pos, msg->secure_payload, msg->app_data_length);
        pos += msg->app_data_length;
    }
    
    return pos;
}

int AProfile_decodeSecureData(
    const uint8_t* buffer,
    int bufferSize,
    SecureDataMessage* msg)
{
    if (!buffer || !msg || bufferSize < 12) return -1;
    
    int pos = 0;
    msg->aim = read_uint16_le(buffer + pos); pos += 2;
    msg->ais = read_uint16_le(buffer + pos); pos += 2;
    msg->sequence_number = read_uint32_le(buffer + pos); pos += 4;
    msg->app_data_length = read_uint16_le(buffer + pos); pos += 2;
    
    if (bufferSize < pos + msg->app_data_length) return -1;
    
    msg->secure_payload = (uint8_t*)malloc(msg->app_data_length);
    if (!msg->secure_payload) return -1;
    memcpy(msg->secure_payload, buffer + pos, msg->app_data_length);
    pos += msg->app_data_length;
    
    return pos;
}

#endif /* CONFIG_CS104_APROFILE */
