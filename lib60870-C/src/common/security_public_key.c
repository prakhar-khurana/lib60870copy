#include "security_public_key.h"
#include "internal/information_objects_internal.h"
#include <stdlib.h>  // For malloc/free
#include <string.h>  // For memcpy

/* Forward declaration of the VFT and initialize function from cs101_information_objects.c */
extern struct sInformationObjectVFT securityPublicKeyVFT;
extern void SecurityPublicKey_initialize(SecurityPublicKey self);

const uint8_t* SecurityPublicKey_getKeyValue(SecurityPublicKey self) {
    if (!self) return NULL;
    return self->keyValue;
}

int SecurityPublicKey_getKeyLength(SecurityPublicKey self) {
    if (!self) return 0;
    return self->keyLength;
}

SecurityPublicKey SecurityPublicKey_create(SecurityPublicKey self, int ioa, int keyLength, const uint8_t* keyValue) {
    if (!self) {
        self = (SecurityPublicKey)malloc(sizeof(struct sSecurityPublicKey));
        if (!self) return NULL;
    }
    
    SecurityPublicKey_initialize(self);
    self->objectAddress = ioa;
    self->keyLength = keyLength;
    if (keyValue && keyLength > 0) {
        memcpy(self->keyValue, keyValue, keyLength > 2048 ? 2048 : keyLength);
    }
    /* Note: self->type is set to S_RP_NA_1 by SecurityPublicKey_initialize().
     * For security ASDUs, the caller must override this to match the ASDU type
     * (e.g., S_AR_NA_1, S_AS_NA_1, etc.) before adding to the ASDU. */
    return self;
}

void SecurityPublicKey_destroy(SecurityPublicKey self) {
    if (self) {
        free(self);
    }
}
