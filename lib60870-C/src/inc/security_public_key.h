#ifndef SECURITY_PUBLIC_KEY_H
#define SECURITY_PUBLIC_KEY_H

#include "inc/api/cs101_information_objects.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

SecurityPublicKey SecurityPublicKey_create(SecurityPublicKey self, int ioa, int keyLength, const uint8_t* keyValue);
void SecurityPublicKey_destroy(SecurityPublicKey self);
const uint8_t* SecurityPublicKey_getKeyValue(SecurityPublicKey self);
int SecurityPublicKey_getKeyLength(SecurityPublicKey self);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_PUBLIC_KEY_H */