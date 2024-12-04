#ifndef __Hacl_Curve25519_H
#define __Hacl_Curve25519_H


#include "kremlib.h"

void Hacl_Curve25519_crypto_scalarmult(uint8_t *mypublic, uint8_t *secret, uint8_t *basepoint);

#define __Hacl_Curve25519_H_DEFINED
#endif
