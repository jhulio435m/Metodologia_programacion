
#ifndef PSA_CRYPTO_BUILTIN_PRIMITIVES_H
#define PSA_CRYPTO_BUILTIN_PRIMITIVES_H
#include "mbedtls/private_access.h"

#include <psa/crypto_driver_common.h>

/*
 * Hash multi-part operation definitions.
 */

#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#if defined(MBEDTLS_PSA_BUILTIN_ALG_MD5) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_1) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_224) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_256) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_384) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_512)
#define MBEDTLS_PSA_BUILTIN_HASH
#endif

typedef struct
{
    psa_algorithm_t MBEDTLS_PRIVATE(alg);
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_MD5)
        mbedtls_md5_context md5;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160)
        mbedtls_ripemd160_context ripemd160;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_1)
        mbedtls_sha1_context sha1;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_256) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_224)
        mbedtls_sha256_context sha256;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_512) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_384)
        mbedtls_sha512_context sha512;
#endif
    } MBEDTLS_PRIVATE(ctx);
} mbedtls_psa_hash_operation_t;

#define MBEDTLS_PSA_HASH_OPERATION_INIT {0, {0}}

/*
 * Cipher multi-part operation definitions.
 */

#include "mbedtls/cipher.h"

#if defined(MBEDTLS_PSA_BUILTIN_ALG_STREAM_CIPHER) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CTR) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CFB) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_OFB) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECB_NO_PADDING) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7)
#define MBEDTLS_PSA_BUILTIN_CIPHER  1
#endif

typedef struct {
    /* Context structure for the Mbed TLS cipher implementation. */
    psa_algorithm_t MBEDTLS_PRIVATE(alg);
    uint8_t MBEDTLS_PRIVATE(iv_length);
    uint8_t MBEDTLS_PRIVATE(block_length);
    union {
        unsigned int MBEDTLS_PRIVATE(dummy);
        mbedtls_cipher_context_t MBEDTLS_PRIVATE(cipher);
    } MBEDTLS_PRIVATE(ctx);
} mbedtls_psa_cipher_operation_t;

#define MBEDTLS_PSA_CIPHER_OPERATION_INIT {0, 0, 0, {0}}

#endif /* PSA_CRYPTO_BUILTIN_PRIMITIVES_H */
