
#ifndef MBEDTLS_HASH_INFO_H
#define MBEDTLS_HASH_INFO_H

#include "common.h"

#include "mbedtls/md.h"
#include "psa/crypto.h"

/** \def MBEDTLS_HASH_MAX_SIZE
 *
 * Maximum size of a hash based on configuration.
 */
#if defined(MBEDTLS_MD_C) && ( \
    !defined(MBEDTLS_PSA_CRYPTO_C) || \
    MBEDTLS_MD_MAX_SIZE >= PSA_HASH_MAX_SIZE )
#define MBEDTLS_HASH_MAX_SIZE MBEDTLS_MD_MAX_SIZE
#elif defined(MBEDTLS_PSA_CRYPTO_C) && ( \
    !defined(MBEDTLS_MD_C) || \
    PSA_HASH_MAX_SIZE >= MBEDTLS_MD_MAX_SIZE )
#define MBEDTLS_HASH_MAX_SIZE PSA_HASH_MAX_SIZE
#endif

/** Get the output length of the given hash type from its MD type.
 *
 * \note To get the output length from the PSA alg, use \c PSA_HASH_LENGTH().
 *
 * \param md_type   The hash MD type.
 *
 * \return          The output length in bytes, or 0 if not known.
 */
unsigned char mbedtls_hash_info_get_size( mbedtls_md_type_t md_type );

/** Get the block size of the given hash type from its MD type.
 *
 * \note To get the output length from the PSA alg, use
 *       \c PSA_HASH_BLOCK_LENGTH().
 *
 * \param md_type   The hash MD type.
 *
 * \return          The block size in bytes, or 0 if not known.
 */
unsigned char mbedtls_hash_info_get_block_size( mbedtls_md_type_t md_type );

/** Get the PSA alg from the MD type.
 *
 * \param md_type   The hash MD type.
 *
 * \return          The corresponding PSA algorithm identifier,
 *                  or PSA_ALG_NONE if not known.
 */
psa_algorithm_t mbedtls_hash_info_psa_from_md( mbedtls_md_type_t md_type );

/** Get the MD type alg from the PSA algorithm identifier.
 *
 * \param psa_alg   The PSA hash algorithm.
 *
 * \return          The corresponding MD type,
 *                  or MBEDTLS_MD_NONE if not known.
 */
mbedtls_md_type_t mbedtls_hash_info_md_from_psa( psa_algorithm_t psa_alg );

/** Convert PSA status to MD error code.
 *
 * \param status    PSA status.
 *
 * \return          The corresponding MD error code,
 */
int mbedtls_md_error_from_psa( psa_status_t status );

#endif
