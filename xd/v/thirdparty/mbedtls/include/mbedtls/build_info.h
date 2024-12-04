

#ifndef MBEDTLS_BUILD_INFO_H
#define MBEDTLS_BUILD_INFO_H

#define MBEDTLS_VERSION_MAJOR  3
#define MBEDTLS_VERSION_MINOR  3
#define MBEDTLS_VERSION_PATCH  0

#define MBEDTLS_VERSION_NUMBER         0x03030000
#define MBEDTLS_VERSION_STRING         "3.3.0"
#define MBEDTLS_VERSION_STRING_FULL    "mbed TLS 3.3.0"

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

/* Define `inline` on some non-C99-compliant compilers. */
#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CONFIG_VERSION) && ( \
    MBEDTLS_CONFIG_VERSION < 0x03000000 || \
    MBEDTLS_CONFIG_VERSION > MBEDTLS_VERSION_NUMBER )
#error "Invalid config version, defined value of MBEDTLS_CONFIG_VERSION is unsupported"
#endif

/* Target and application specific configurations
 *
 * Allow user to override any previous default.
 *
 */
#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

/* The PK wrappers need pk_write functions to format RSA key objects
 * when they are dispatching to the PSA API. This happens under USE_PSA_CRYPTO,
 * and also even without USE_PSA_CRYPTO for mbedtls_pk_sign_ext().
 * PSA crypto also needs pk_write to export RSA keys (otherwise the build
 * goes through but psa_export_key() and psa_export_public_key() fail on
 * RSA keys), and pk_parse to work with RSA keys in almost any way.
 */
#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_RSA_C)
#define MBEDTLS_PK_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_PARSE_C
#endif

/* Under MBEDTLS_USE_PSA_CRYPTO, the pk module needs pk_write functions
 * to pass ECC keys to PSA. */
#if defined(MBEDTLS_PK_C) &&                                    \
    defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_ECP_C)
#define MBEDTLS_PK_WRITE_C
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_2)
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
#endif

#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_EARLY_DATA
#endif

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED
#endif

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED) || \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_EPHEMERAL_ENABLED
#endif

/* Make sure all configuration symbols are set before including check_config.h,
 * even the ones that are calculated programmatically. */
#if defined(MBEDTLS_PSA_CRYPTO_CONFIG) /* PSA_WANT_xxx influences MBEDTLS_xxx */ || \
    defined(MBEDTLS_PSA_CRYPTO_C) /* MBEDTLS_xxx influences PSA_WANT_xxx */
#include "mbedtls/config_psa.h"
#endif

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_BUILD_INFO_H */
