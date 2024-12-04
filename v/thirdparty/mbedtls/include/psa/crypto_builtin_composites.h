

#ifndef PSA_CRYPTO_BUILTIN_COMPOSITES_H
#define PSA_CRYPTO_BUILTIN_COMPOSITES_H
#include "mbedtls/private_access.h"

#include <psa/crypto_driver_common.h>

/*
 * MAC multi-part operation definitions.
 */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CMAC) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_HMAC)
#define MBEDTLS_PSA_BUILTIN_MAC
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_HMAC) || defined(PSA_CRYPTO_DRIVER_TEST)
typedef struct
{
    /** The HMAC algorithm in use */
    psa_algorithm_t MBEDTLS_PRIVATE(alg);
    /** The hash context. */
    struct psa_hash_operation_s hash_ctx;
    /** The HMAC part of the context. */
    uint8_t MBEDTLS_PRIVATE(opad)[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
} mbedtls_psa_hmac_operation_t;

#define MBEDTLS_PSA_HMAC_OPERATION_INIT {0, PSA_HASH_OPERATION_INIT, {0}}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HMAC */

#include "mbedtls/cmac.h"

typedef struct
{
    psa_algorithm_t MBEDTLS_PRIVATE(alg);
    union
    {
        unsigned MBEDTLS_PRIVATE(dummy); /* Make the union non-empty even with no supported algorithms. */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HMAC) || defined(PSA_CRYPTO_DRIVER_TEST)
        mbedtls_psa_hmac_operation_t MBEDTLS_PRIVATE(hmac);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_HMAC */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CMAC) || defined(PSA_CRYPTO_DRIVER_TEST)
        mbedtls_cipher_context_t MBEDTLS_PRIVATE(cmac);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CMAC */
    } MBEDTLS_PRIVATE(ctx);
} mbedtls_psa_mac_operation_t;

#define MBEDTLS_PSA_MAC_OPERATION_INIT {0, {0}}

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CCM) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
#define MBEDTLS_PSA_BUILTIN_AEAD  1
#endif

/* Context structure for the Mbed TLS AEAD implementation. */
typedef struct
{
    psa_algorithm_t MBEDTLS_PRIVATE(alg);
    psa_key_type_t MBEDTLS_PRIVATE(key_type);

    unsigned int MBEDTLS_PRIVATE(is_encrypt) : 1;

    uint8_t MBEDTLS_PRIVATE(tag_length);

    union
    {
        unsigned dummy; /* Enable easier initializing of the union. */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
        mbedtls_ccm_context MBEDTLS_PRIVATE(ccm);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
        mbedtls_gcm_context MBEDTLS_PRIVATE(gcm);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        mbedtls_chachapoly_context MBEDTLS_PRIVATE(chachapoly);
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */

    } ctx;

} mbedtls_psa_aead_operation_t;

#define MBEDTLS_PSA_AEAD_OPERATION_INIT {0, 0, 0, 0, {0}}

#endif /* PSA_CRYPTO_BUILTIN_COMPOSITES_H */
