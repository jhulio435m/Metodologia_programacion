

#ifndef MBEDTLS_OR_PSA_HELPERS_H
#define MBEDTLS_OR_PSA_HELPERS_H

#include "mbedtls/build_info.h"
#if defined(MBEDTLS_PSA_CRYPTO_C)
#include "psa/crypto.h"
#endif /* MBEDTLS_PSA_CRYPTO_C */

/*
 * Hashes
 */

/* Hashes using low-level or PSA based on availability */
#if defined(MBEDTLS_MD5_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_MD5) )
#define MBEDTLS_HAS_ALG_MD5_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_RIPEMD160_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_RIPEMD160) )
#define MBEDTLS_HAS_ALG_RIPEMD160_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA1_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_1) )
#define MBEDTLS_HAS_ALG_SHA_1_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA224_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_224) )
#define MBEDTLS_HAS_ALG_SHA_224_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA256_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256) )
#define MBEDTLS_HAS_ALG_SHA_256_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA384_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_384) )
#define MBEDTLS_HAS_ALG_SHA_384_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA512_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_512) )
#define MBEDTLS_HAS_ALG_SHA_512_VIA_LOWLEVEL_OR_PSA
#endif

/* Hashes using MD or PSA based on availability */
#if ( defined(MBEDTLS_MD_C) && defined(MBEDTLS_MD5_C) ) || \
    ( !defined(MBEDTLS_MD_C) && \
        defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_MD5) )
#define MBEDTLS_HAS_ALG_MD5_VIA_MD_OR_PSA
#endif
#if ( defined(MBEDTLS_MD_C) && defined(MBEDTLS_RIPEMD160_C) ) || \
    ( !defined(MBEDTLS_MD_C) && \
        defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_RIPEMD160) )
#define MBEDTLS_HAS_ALG_RIPEMD160_VIA_MD_OR_PSA
#endif
#if ( defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA1_C) ) || \
    ( !defined(MBEDTLS_MD_C) && \
        defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_1) )
#define MBEDTLS_HAS_ALG_SHA_1_VIA_MD_OR_PSA
#endif
#if ( defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA224_C) ) || \
    ( !defined(MBEDTLS_MD_C) && \
        defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_224) )
#define MBEDTLS_HAS_ALG_SHA_224_VIA_MD_OR_PSA
#endif
#if ( defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA256_C) ) || \
    ( !defined(MBEDTLS_MD_C) && \
        defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256) )
#define MBEDTLS_HAS_ALG_SHA_256_VIA_MD_OR_PSA
#endif
#if ( defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA384_C) ) || \
    ( !defined(MBEDTLS_MD_C) && \
        defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_384) )
#define MBEDTLS_HAS_ALG_SHA_384_VIA_MD_OR_PSA
#endif
#if ( defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA512_C) ) || \
    ( !defined(MBEDTLS_MD_C) && \
        defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_512) )
#define MBEDTLS_HAS_ALG_SHA_512_VIA_MD_OR_PSA
#endif

/* Hashes using MD or PSA based on MBEDTLS_USE_PSA_CRYPTO */
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && \
        defined(MBEDTLS_MD_C) && defined(MBEDTLS_MD5_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_MD5) )
#define MBEDTLS_HAS_ALG_MD5_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && \
        defined(MBEDTLS_MD_C) && defined(MBEDTLS_RIPEMD160_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_RIPEMD160) )
#define MBEDTLS_HAS_ALG_RIPEMD160_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && \
        defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA1_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_1) )
#define MBEDTLS_HAS_ALG_SHA_1_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && \
        defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA224_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_224) )
#define MBEDTLS_HAS_ALG_SHA_224_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && \
        defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA256_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_256) )
#define MBEDTLS_HAS_ALG_SHA_256_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && \
        defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA384_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_384) )
#define MBEDTLS_HAS_ALG_SHA_384_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && \
        defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA512_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_512) )
#define MBEDTLS_HAS_ALG_SHA_512_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif

#endif /* MBEDTLS_OR_PSA_HELPERS_H */
