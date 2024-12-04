


#include "hash_info.h"
#include "mbedtls/legacy_or_psa.h"
#include "mbedtls/error.h"

typedef struct
{
    psa_algorithm_t psa_alg;
    mbedtls_md_type_t md_type;
    unsigned char size;
    unsigned char block_size;
} hash_entry;

static const hash_entry hash_table[] = {
#if defined(MBEDTLS_HAS_ALG_MD5_VIA_LOWLEVEL_OR_PSA)
    { PSA_ALG_MD5, MBEDTLS_MD_MD5, 16, 64 },
#endif
#if defined(MBEDTLS_HAS_ALG_RIPEMD160_VIA_LOWLEVEL_OR_PSA)
    { PSA_ALG_RIPEMD160, MBEDTLS_MD_RIPEMD160, 20, 64 },
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_1_VIA_LOWLEVEL_OR_PSA)
    { PSA_ALG_SHA_1, MBEDTLS_MD_SHA1, 20, 64 },
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_224_VIA_LOWLEVEL_OR_PSA)
    { PSA_ALG_SHA_224, MBEDTLS_MD_SHA224, 28, 64 },
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_256_VIA_LOWLEVEL_OR_PSA)
    { PSA_ALG_SHA_256, MBEDTLS_MD_SHA256, 32, 64 },
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_384_VIA_LOWLEVEL_OR_PSA)
    { PSA_ALG_SHA_384, MBEDTLS_MD_SHA384, 48, 128 },
#endif
#if defined(MBEDTLS_HAS_ALG_SHA_512_VIA_LOWLEVEL_OR_PSA)
    { PSA_ALG_SHA_512, MBEDTLS_MD_SHA512, 64, 128 },
#endif
    { PSA_ALG_NONE, MBEDTLS_MD_NONE, 0, 0 },
};


unsigned char mbedtls_hash_info_get_size( mbedtls_md_type_t md_type )
{
    const hash_entry *entry = hash_table;
    while( entry->md_type != MBEDTLS_MD_NONE &&
           entry->md_type != md_type )
    {
        entry++;
    }

    return entry->size;
}


unsigned char mbedtls_hash_info_get_block_size( mbedtls_md_type_t md_type )
{
    const hash_entry *entry = hash_table;
    while( entry->md_type != MBEDTLS_MD_NONE &&
           entry->md_type != md_type )
    {
        entry++;
    }

    return entry->block_size;
}


psa_algorithm_t mbedtls_hash_info_psa_from_md( mbedtls_md_type_t md_type )
{
    const hash_entry *entry = hash_table;
    while( entry->md_type != MBEDTLS_MD_NONE &&
           entry->md_type != md_type )
    {
        entry++;
    }

    return entry->psa_alg;
}


mbedtls_md_type_t mbedtls_hash_info_md_from_psa( psa_algorithm_t psa_alg )
{
    const hash_entry *entry = hash_table;
    while( entry->md_type != MBEDTLS_MD_NONE &&
           entry->psa_alg != psa_alg )
    {
        entry++;
    }

    return entry->md_type;
}

int mbedtls_md_error_from_psa( psa_status_t status )
{
    switch( status )
    {
        case PSA_SUCCESS:
            return( 0 );
        case PSA_ERROR_NOT_SUPPORTED:
            return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );
        case PSA_ERROR_INVALID_ARGUMENT:
            return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
        case PSA_ERROR_INSUFFICIENT_MEMORY:
            return( MBEDTLS_ERR_MD_ALLOC_FAILED );
        default:
            return( MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED );
    }
}
