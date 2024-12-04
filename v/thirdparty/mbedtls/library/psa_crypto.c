


#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)
#include "check_crypto_config.h"
#endif

#include "psa/crypto.h"
#include "psa/crypto_values.h"

#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "psa_crypto_invasive.h"
#include "psa_crypto_driver_wrappers.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_hash.h"
#include "psa_crypto_mac.h"
#include "psa_crypto_rsa.h"
#include "psa_crypto_ecp.h"
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
#include "psa_crypto_se.h"
#endif
#include "psa_crypto_slot_management.h"

#include "psa_crypto_storage.h"

#include "psa_crypto_random_impl.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform.h"

#include "mbedtls/aes.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/camellia.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md5.h"
#include "mbedtls/md.h"
#include "md_wrap.h"
#include "mbedtls/pk.h"
#include "pk_wrap.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#define ARRAY_LENGTH( array ) ( sizeof( array ) / sizeof( *( array ) ) )

#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF) ||          \
    defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT) ||  \
    defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
#define BUILTIN_ALG_ANY_HKDF 1
#endif

/****************************************************************/

/****************************************************************/

static int key_type_is_raw_bytes( psa_key_type_t type )
{
    return( PSA_KEY_TYPE_IS_UNSTRUCTURED( type ) );
}


#define RNG_NOT_INITIALIZED 0
#define RNG_INITIALIZED 1
#define RNG_SEEDED 2

typedef struct
{
    unsigned initialized : 1;
    unsigned rng_state : 2;
    mbedtls_psa_random_context_t rng;
} psa_global_data_t;

static psa_global_data_t global_data;

#if !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
mbedtls_psa_drbg_context_t *const mbedtls_psa_random_state =
    &global_data.rng.drbg;
#endif

#define GUARD_MODULE_INITIALIZED        \
    if( global_data.initialized == 0 )  \
        return( PSA_ERROR_BAD_STATE );

psa_status_t mbedtls_to_psa_error( int ret )
{
   
    int low_level_ret = - ( -ret & 0x007f );
    switch( low_level_ret != 0 ? low_level_ret : ret )
    {
        case 0:
            return( PSA_SUCCESS );

        case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
        case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_ASN1_OUT_OF_DATA:
        case MBEDTLS_ERR_ASN1_UNEXPECTED_TAG:
        case MBEDTLS_ERR_ASN1_INVALID_LENGTH:
        case MBEDTLS_ERR_ASN1_LENGTH_MISMATCH:
        case MBEDTLS_ERR_ASN1_INVALID_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_ASN1_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA)
        case MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA:
#endif
        case MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );

        case MBEDTLS_ERR_CCM_BAD_INPUT:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_CCM_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );

        case MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );

        case MBEDTLS_ERR_CHACHAPOLY_BAD_STATE:
            return( PSA_ERROR_BAD_STATE );
        case MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );

        case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_CIPHER_INVALID_PADDING:
            return( PSA_ERROR_INVALID_PADDING );
        case MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_CIPHER_INVALID_CONTEXT:
            return( PSA_ERROR_CORRUPTION_DETECTED );

#if !( defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) ||      \
       defined(MBEDTLS_PSA_HMAC_DRBG_MD_TYPE) )
       
        case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );
        case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
        case MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );
#endif

        case MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );

        case MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED:
        case MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE:
        case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );

        case MBEDTLS_ERR_GCM_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_GCM_BAD_INPUT:
            return( PSA_ERROR_INVALID_ARGUMENT );

#if !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) &&        \
    defined(MBEDTLS_PSA_HMAC_DRBG_MD_TYPE)
       
        case MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );
        case MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG:
        case MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );
#endif

        case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MD_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_MD_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );

        case MBEDTLS_ERR_MPI_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );
        case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_INVALID_CHARACTER:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_MPI_NEGATIVE_VALUE:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        case MBEDTLS_ERR_PK_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_PK_TYPE_MISMATCH:
        case MBEDTLS_ERR_PK_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );
        case MBEDTLS_ERR_PK_KEY_INVALID_VERSION:
        case MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
        case MBEDTLS_ERR_PK_PASSWORD_MISMATCH:
            return( PSA_ERROR_NOT_PERMITTED );
        case MBEDTLS_ERR_PK_INVALID_PUBKEY:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_INVALID_ALG:
        case MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE:
        case MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_PK_SIG_LEN_MISMATCH:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_PK_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        case MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED:
            return( PSA_ERROR_NOT_SUPPORTED );

        case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_RSA_INVALID_PADDING:
            return( PSA_ERROR_INVALID_PADDING );
        case MBEDTLS_ERR_RSA_KEY_GEN_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case MBEDTLS_ERR_RSA_KEY_CHECK_FAILED:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_RSA_PUBLIC_FAILED:
        case MBEDTLS_ERR_RSA_PRIVATE_FAILED:
            return( PSA_ERROR_CORRUPTION_DETECTED );
        case MBEDTLS_ERR_RSA_VERIFY_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_RSA_RNG_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );

        case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
        case MBEDTLS_ERR_ECP_INVALID_KEY:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH:
        case MBEDTLS_ERR_ECP_VERIFY_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_ECP_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_ECP_RANDOM_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );

        case MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED:
            return( PSA_ERROR_CORRUPTION_DETECTED );

        default:
            return( PSA_ERROR_GENERIC_ERROR );
    }
}




/****************************************************************/

/****************************************************************/

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECDH)
mbedtls_ecp_group_id mbedtls_ecc_group_of_psa( psa_ecc_family_t curve,
                                               size_t bits,
                                               int bits_is_sloppy )
{
    switch( curve )
    {
        case PSA_ECC_FAMILY_SECP_R1:
            switch( bits )
            {
#if defined(PSA_WANT_ECC_SECP_R1_192)
                case 192:
                    return( MBEDTLS_ECP_DP_SECP192R1 );
#endif
#if defined(PSA_WANT_ECC_SECP_R1_224)
                case 224:
                    return( MBEDTLS_ECP_DP_SECP224R1 );
#endif
#if defined(PSA_WANT_ECC_SECP_R1_256)
                case 256:
                    return( MBEDTLS_ECP_DP_SECP256R1 );
#endif
#if defined(PSA_WANT_ECC_SECP_R1_384)
                case 384:
                    return( MBEDTLS_ECP_DP_SECP384R1 );
#endif
#if defined(PSA_WANT_ECC_SECP_R1_521)
                case 521:
                    return( MBEDTLS_ECP_DP_SECP521R1 );
                case 528:
                    if( bits_is_sloppy )
                        return( MBEDTLS_ECP_DP_SECP521R1 );
                    break;
#endif
            }
            break;

        case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
            switch( bits )
            {
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
                case 256:
                    return( MBEDTLS_ECP_DP_BP256R1 );
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
                case 384:
                    return( MBEDTLS_ECP_DP_BP384R1 );
#endif
#if defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
                case 512:
                    return( MBEDTLS_ECP_DP_BP512R1 );
#endif
            }
            break;

        case PSA_ECC_FAMILY_MONTGOMERY:
            switch( bits )
            {
#if defined(PSA_WANT_ECC_MONTGOMERY_255)
                case 255:
                    return( MBEDTLS_ECP_DP_CURVE25519 );
                case 256:
                    if( bits_is_sloppy )
                        return( MBEDTLS_ECP_DP_CURVE25519 );
                    break;
#endif
#if defined(PSA_WANT_ECC_MONTGOMERY_448)
                case 448:
                    return( MBEDTLS_ECP_DP_CURVE448 );
#endif
            }
            break;

        case PSA_ECC_FAMILY_SECP_K1:
            switch( bits )
            {
#if defined(PSA_WANT_ECC_SECP_K1_192)
                case 192:
                    return( MBEDTLS_ECP_DP_SECP192K1 );
#endif
#if defined(PSA_WANT_ECC_SECP_K1_224)
                case 224:
                    return( MBEDTLS_ECP_DP_SECP224K1 );
#endif
#if defined(PSA_WANT_ECC_SECP_K1_256)
                case 256:
                    return( MBEDTLS_ECP_DP_SECP256K1 );
#endif
            }
            break;
    }

    (void) bits_is_sloppy;
    return( MBEDTLS_ECP_DP_NONE );
}
#endif

psa_status_t psa_validate_unstructured_key_bit_size( psa_key_type_t type,
                                                     size_t bits )
{
   
    switch( type )
    {
        case PSA_KEY_TYPE_RAW_DATA:
        case PSA_KEY_TYPE_HMAC:
        case PSA_KEY_TYPE_DERIVE:
        case PSA_KEY_TYPE_PASSWORD:
        case PSA_KEY_TYPE_PASSWORD_HASH:
            break;
#if defined(PSA_WANT_KEY_TYPE_AES)
        case PSA_KEY_TYPE_AES:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_ARIA)
        case PSA_KEY_TYPE_ARIA:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_CAMELLIA)
        case PSA_KEY_TYPE_CAMELLIA:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_DES)
        case PSA_KEY_TYPE_DES:
            if( bits != 64 && bits != 128 && bits != 192 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_CHACHA20)
        case PSA_KEY_TYPE_CHACHA20:
            if( bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
    if( bits % 8 != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}

/** Check whether a given key type is valid for use with a given MAC algorithm
 *
 * Upon successful return of this function, the behavior of #PSA_MAC_LENGTH
 * when called with the validated \p algorithm and \p key_type is well-defined.
 *
 * \param[in] algorithm     The specific MAC algorithm (can be wildcard).
 * \param[in] key_type      The key type of the key to be used with the
 *                          \p algorithm.
 *
 * \retval #PSA_SUCCESS
 *         The \p key_type is valid for use with the \p algorithm
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The \p key_type is not valid for use with the \p algorithm
 */
MBEDTLS_STATIC_TESTABLE psa_status_t psa_mac_key_can_do(
    psa_algorithm_t algorithm,
    psa_key_type_t key_type )
{
    if( PSA_ALG_IS_HMAC( algorithm ) )
    {
        if( key_type == PSA_KEY_TYPE_HMAC )
            return( PSA_SUCCESS );
    }

    if( PSA_ALG_IS_BLOCK_CIPHER_MAC( algorithm ) )
    {
       
        if( ( key_type & PSA_KEY_TYPE_CATEGORY_MASK ) ==
            PSA_KEY_TYPE_CATEGORY_SYMMETRIC )
        {
           
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( key_type ) > 1 )
                return( PSA_SUCCESS );
        }
    }

    return( PSA_ERROR_INVALID_ARGUMENT );
}

psa_status_t psa_allocate_buffer_to_slot( psa_key_slot_t *slot,
                                          size_t buffer_length )
{
    if( slot->key.data != NULL )
        return( PSA_ERROR_ALREADY_EXISTS );

    slot->key.data = mbedtls_calloc( 1, buffer_length );
    if( slot->key.data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    slot->key.bytes = buffer_length;
    return( PSA_SUCCESS );
}

psa_status_t psa_copy_key_material_into_slot( psa_key_slot_t *slot,
                                              const uint8_t* data,
                                              size_t data_length )
{
    psa_status_t status = psa_allocate_buffer_to_slot( slot,
                                                       data_length );
    if( status != PSA_SUCCESS )
        return( status );

    memcpy( slot->key.data, data, data_length );
    return( PSA_SUCCESS );
}

psa_status_t psa_import_key_into_slot(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = attributes->core.type;

   
    if( data_length == 0 )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( key_type_is_raw_bytes( type ) )
    {
        *bits = PSA_BYTES_TO_BITS( data_length );

        status = psa_validate_unstructured_key_bit_size( attributes->core.type,
                                                         *bits );
        if( status != PSA_SUCCESS )
            return( status );

       
        memcpy( key_buffer, data, data_length );
        *key_buffer_length = data_length;
        (void)key_buffer_size;

        return( PSA_SUCCESS );
    }
    else if( PSA_KEY_TYPE_IS_ASYMMETRIC( type ) )
    {
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY)
        if( PSA_KEY_TYPE_IS_ECC( type ) )
        {
            return( mbedtls_psa_ecp_import_key( attributes,
                                                data, data_length,
                                                key_buffer, key_buffer_size,
                                                key_buffer_length,
                                                bits ) );
        }
#endif
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
        if( PSA_KEY_TYPE_IS_RSA( type ) )
        {
            return( mbedtls_psa_rsa_import_key( attributes,
                                                data, data_length,
                                                key_buffer, key_buffer_size,
                                                key_buffer_length,
                                                bits ) );
        }
#endif
    }

    return( PSA_ERROR_NOT_SUPPORTED );
}

/** Calculate the intersection of two algorithm usage policies.
 *
 * Return 0 (which allows no operation) on incompatibility.
 */
static psa_algorithm_t psa_key_policy_algorithm_intersection(
    psa_key_type_t key_type,
    psa_algorithm_t alg1,
    psa_algorithm_t alg2 )
{
   
    if( alg1 == alg2 )
        return( alg1 );
   
    if( PSA_ALG_IS_SIGN_HASH( alg1 ) &&
        PSA_ALG_IS_SIGN_HASH( alg2 ) &&
        ( alg1 & ~PSA_ALG_HASH_MASK ) == ( alg2 & ~PSA_ALG_HASH_MASK ) )
    {
        if( PSA_ALG_SIGN_GET_HASH( alg1 ) == PSA_ALG_ANY_HASH )
            return( alg2 );
        if( PSA_ALG_SIGN_GET_HASH( alg2 ) == PSA_ALG_ANY_HASH )
            return( alg1 );
    }
   
    if( PSA_ALG_IS_AEAD( alg1 ) && PSA_ALG_IS_AEAD( alg2 ) &&
        ( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg1, 0 ) ==
          PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg2, 0 ) ) )
    {
        size_t alg1_len = PSA_ALG_AEAD_GET_TAG_LENGTH( alg1 );
        size_t alg2_len = PSA_ALG_AEAD_GET_TAG_LENGTH( alg2 );
        size_t restricted_len = alg1_len > alg2_len ? alg1_len : alg2_len;

       
        if( ( ( alg1 & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG ) != 0 ) &&
            ( ( alg2 & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG ) != 0 ) )
        {
            return( PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                        alg1, restricted_len ) );
        }
       
        if( ( ( alg1 & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG ) != 0 ) &&
            ( alg1_len <= alg2_len ) )
        {
            return( alg2 );
        }
        if( ( ( alg2 & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG ) != 0 ) &&
            ( alg2_len <= alg1_len ) )
        {
            return( alg1 );
        }
    }
   
    if( PSA_ALG_IS_MAC( alg1 ) && PSA_ALG_IS_MAC( alg2 ) &&
        ( PSA_ALG_FULL_LENGTH_MAC( alg1 ) ==
          PSA_ALG_FULL_LENGTH_MAC( alg2 ) ) )
    {
       
        if( PSA_SUCCESS != psa_mac_key_can_do( alg1, key_type ) )
            return( 0 );

       
        size_t alg1_len = PSA_MAC_LENGTH( key_type, 0, alg1 );
        size_t alg2_len = PSA_MAC_LENGTH( key_type, 0, alg2 );
        size_t restricted_len = alg1_len > alg2_len ? alg1_len : alg2_len;

       
        if( ( ( alg1 & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG ) != 0 ) &&
            ( ( alg2 & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG ) != 0 ) )
        {
            return( PSA_ALG_AT_LEAST_THIS_LENGTH_MAC( alg1, restricted_len ) );
        }

       
        if( ( alg1 & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG ) != 0 )
        {
            return( ( alg1_len <= alg2_len ) ? alg2 : 0 );
        }
        if( ( alg2 & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG ) != 0 )
        {
            return( ( alg2_len <= alg1_len ) ? alg1 : 0 );
        }

       
        if( alg1_len == alg2_len )
            return( PSA_ALG_TRUNCATED_MAC( alg1, alg1_len ) );
    }
   
    return( 0 );
}

static int psa_key_algorithm_permits( psa_key_type_t key_type,
                                      psa_algorithm_t policy_alg,
                                      psa_algorithm_t requested_alg )
{
   
    if( requested_alg == policy_alg )
        return( 1 );
   
    if( PSA_ALG_IS_SIGN_HASH( requested_alg ) &&
        PSA_ALG_SIGN_GET_HASH( policy_alg ) == PSA_ALG_ANY_HASH )
    {
        return( ( policy_alg & ~PSA_ALG_HASH_MASK ) ==
                ( requested_alg & ~PSA_ALG_HASH_MASK ) );
    }
   
    if( PSA_ALG_IS_AEAD( policy_alg ) &&
        PSA_ALG_IS_AEAD( requested_alg ) &&
        ( PSA_ALG_AEAD_WITH_SHORTENED_TAG( policy_alg, 0 ) ==
          PSA_ALG_AEAD_WITH_SHORTENED_TAG( requested_alg, 0 ) ) &&
        ( ( policy_alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG ) != 0 ) )
    {
        return( PSA_ALG_AEAD_GET_TAG_LENGTH( policy_alg ) <=
                PSA_ALG_AEAD_GET_TAG_LENGTH( requested_alg ) );
    }
   
    if( PSA_ALG_IS_MAC( policy_alg ) &&
        PSA_ALG_IS_MAC( requested_alg ) &&
        ( PSA_ALG_FULL_LENGTH_MAC( policy_alg ) ==
          PSA_ALG_FULL_LENGTH_MAC( requested_alg ) ) )
    {
       
        if( PSA_SUCCESS != psa_mac_key_can_do( policy_alg, key_type ) )
            return( 0 );

       
        size_t requested_output_length = PSA_MAC_LENGTH(
                                            key_type, 0, requested_alg );
        size_t default_output_length = PSA_MAC_LENGTH(
                                        key_type, 0,
                                        PSA_ALG_FULL_LENGTH_MAC( requested_alg ) );

       
        if( PSA_MAC_TRUNCATED_LENGTH( policy_alg ) == 0 )
            return( requested_output_length == default_output_length );

       
        if( PSA_MAC_TRUNCATED_LENGTH( requested_alg ) == 0 &&
            PSA_MAC_TRUNCATED_LENGTH( policy_alg ) == default_output_length )
        {
            return( 1 );
        }

       
        if( ( policy_alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG ) != 0 )
        {
            return( PSA_MAC_TRUNCATED_LENGTH( policy_alg ) <=
                    requested_output_length );
        }
    }
   
    if( PSA_ALG_IS_RAW_KEY_AGREEMENT( policy_alg ) &&
        PSA_ALG_IS_KEY_AGREEMENT( requested_alg ) )
    {
        return( PSA_ALG_KEY_AGREEMENT_GET_BASE( requested_alg ) ==
                policy_alg );
    }
   
    return( 0 );
}

/** Test whether a policy permits an algorithm.
 *
 * The caller must test usage flags separately.
 *
 * \note This function requires providing the key type for which the policy is
 *       being validated, since some algorithm policy definitions (e.g. MAC)
 *       have different properties depending on what kind of cipher it is
 *       combined with.
 *
 * \retval PSA_SUCCESS                  When \p alg is a specific algorithm
 *                                      allowed by the \p policy.
 * \retval PSA_ERROR_INVALID_ARGUMENT   When \p alg is not a specific algorithm
 * \retval PSA_ERROR_NOT_PERMITTED      When \p alg is a specific algorithm, but
 *                                      the \p policy does not allow it.
 */
static psa_status_t psa_key_policy_permits( const psa_key_policy_t *policy,
                                            psa_key_type_t key_type,
                                            psa_algorithm_t alg )
{
   
    if( alg == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

   
    if( PSA_ALG_IS_WILDCARD( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( psa_key_algorithm_permits( key_type, policy->alg, alg ) ||
        psa_key_algorithm_permits( key_type, policy->alg2, alg ) )
        return( PSA_SUCCESS );
    else
        return( PSA_ERROR_NOT_PERMITTED );
}

/** Restrict a key policy based on a constraint.
 *
 * \note This function requires providing the key type for which the policy is
 *       being restricted, since some algorithm policy definitions (e.g. MAC)
 *       have different properties depending on what kind of cipher it is
 *       combined with.
 *
 * \param[in] key_type      The key type for which to restrict the policy
 * \param[in,out] policy    The policy to restrict.
 * \param[in] constraint    The policy constraint to apply.
 *
 * \retval #PSA_SUCCESS
 *         \c *policy contains the intersection of the original value of
 *         \c *policy and \c *constraint.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \c key_type, \c *policy and \c *constraint are incompatible.
 *         \c *policy is unchanged.
 */
static psa_status_t psa_restrict_key_policy(
    psa_key_type_t key_type,
    psa_key_policy_t *policy,
    const psa_key_policy_t *constraint )
{
    psa_algorithm_t intersection_alg =
        psa_key_policy_algorithm_intersection( key_type, policy->alg,
                                               constraint->alg );
    psa_algorithm_t intersection_alg2 =
        psa_key_policy_algorithm_intersection( key_type, policy->alg2,
                                               constraint->alg2 );
    if( intersection_alg == 0 && policy->alg != 0 && constraint->alg != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );
    if( intersection_alg2 == 0 && policy->alg2 != 0 && constraint->alg2 != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );
    policy->usage &= constraint->usage;
    policy->alg = intersection_alg;
    policy->alg2 = intersection_alg2;
    return( PSA_SUCCESS );
}

psa_status_t psa_get_and_lock_key_slot_with_policy(
    mbedtls_svc_key_id_t key,
    psa_key_slot_t **p_slot,
    psa_key_usage_t usage,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    status = psa_get_and_lock_key_slot( key, p_slot );
    if( status != PSA_SUCCESS )
        return( status );
    slot = *p_slot;

   
    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->attr.type ) )
        usage &= ~PSA_KEY_USAGE_EXPORT;

    if( ( slot->attr.policy.usage & usage ) != usage )
    {
        status = PSA_ERROR_NOT_PERMITTED;
        goto error;
    }

   
    if( alg != 0 )
    {
        status = psa_key_policy_permits( &slot->attr.policy,
                                         slot->attr.type,
                                         alg );
        if( status != PSA_SUCCESS )
            goto error;
    }

    return( PSA_SUCCESS );

error:
    *p_slot = NULL;
    psa_unlock_key_slot( slot );

    return( status );
}

/** Get a key slot containing a transparent key and lock it.
 *
 * A transparent key is a key for which the key material is directly
 * available, as opposed to a key in a secure element and/or to be used
 * by a secure element.
 *
 * This is a temporary function that may be used instead of
 * psa_get_and_lock_key_slot_with_policy() when there is no opaque key support
 * for a cryptographic operation.
 *
 * On success, the returned key slot is locked. It is the responsibility of the
 * caller to unlock the key slot when it does not access it anymore.
 */
static psa_status_t psa_get_and_lock_transparent_key_slot_with_policy(
    mbedtls_svc_key_id_t key,
    psa_key_slot_t **p_slot,
    psa_key_usage_t usage,
    psa_algorithm_t alg )
{
    psa_status_t status = psa_get_and_lock_key_slot_with_policy( key, p_slot,
                                                                 usage, alg );
    if( status != PSA_SUCCESS )
        return( status );

    if( psa_key_lifetime_is_external( (*p_slot)->attr.lifetime ) )
    {
        psa_unlock_key_slot( *p_slot );
        *p_slot = NULL;
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_remove_key_data_from_memory( psa_key_slot_t *slot )
{
   
    if( slot->key.data != NULL )
        mbedtls_platform_zeroize( slot->key.data, slot->key.bytes);

    mbedtls_free( slot->key.data );
    slot->key.data = NULL;
    slot->key.bytes = 0;

    return( PSA_SUCCESS );
}

/** Completely wipe a slot in memory, including its policy.
 * Persistent storage is not affected. */
psa_status_t psa_wipe_key_slot( psa_key_slot_t *slot )
{
    psa_status_t status = psa_remove_key_data_from_memory( slot );

  
    if( slot->lock_count != 1 )
    {
        MBEDTLS_TEST_HOOK_TEST_ASSERT( slot->lock_count == 1 );
        status = PSA_ERROR_CORRUPTION_DETECTED;
    }

   
   
    memset( slot, 0, sizeof( *slot ) );
    return( status );
}

psa_status_t psa_destroy_key( mbedtls_svc_key_id_t key )
{
    psa_key_slot_t *slot;
    psa_status_t status;
    psa_status_t overall_status = PSA_SUCCESS;
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    psa_se_drv_table_entry_t *driver;
#endif

    if( mbedtls_svc_key_id_is_null( key ) )
        return( PSA_SUCCESS );

   
    status = psa_get_and_lock_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

   
    if( slot->lock_count > 1 )
    {
       psa_unlock_key_slot( slot );
       return( PSA_ERROR_GENERIC_ERROR );
    }

    if( PSA_KEY_LIFETIME_IS_READ_ONLY( slot->attr.lifetime ) )
    {
       
        overall_status = PSA_ERROR_NOT_PERMITTED;
        goto exit;
    }

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    driver = psa_get_se_driver_entry( slot->attr.lifetime );
    if( driver != NULL )
    {
       
        psa_crypto_prepare_transaction( PSA_CRYPTO_TRANSACTION_DESTROY_KEY );
        psa_crypto_transaction.key.lifetime = slot->attr.lifetime;
        psa_crypto_transaction.key.slot = psa_key_slot_get_slot_number( slot );
        psa_crypto_transaction.key.id = slot->attr.id;
        status = psa_crypto_save_transaction( );
        if( status != PSA_SUCCESS )
        {
            (void) psa_crypto_stop_transaction( );
           
            overall_status = status;
            goto exit;
        }

        status = psa_destroy_se_key( driver,
                                     psa_key_slot_get_slot_number( slot ) );
        if( overall_status == PSA_SUCCESS )
            overall_status = status;
    }
#endif

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if( ! PSA_KEY_LIFETIME_IS_VOLATILE( slot->attr.lifetime ) )
    {
        status = psa_destroy_persistent_key( slot->attr.id );
        if( overall_status == PSA_SUCCESS )
            overall_status = status;

       
    }
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( driver != NULL )
    {
        status = psa_save_se_persistent_data( driver );
        if( overall_status == PSA_SUCCESS )
            overall_status = status;
        status = psa_crypto_stop_transaction( );
        if( overall_status == PSA_SUCCESS )
            overall_status = status;
    }
#endif

exit:
    status = psa_wipe_key_slot( slot );
   
    if( status != PSA_SUCCESS )
        overall_status = status;
    return( overall_status );
}

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
static psa_status_t psa_get_rsa_public_exponent(
    const mbedtls_rsa_context *rsa,
    psa_key_attributes_t *attributes )
{
    mbedtls_mpi mpi;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t *buffer = NULL;
    size_t buflen;
    mbedtls_mpi_init( &mpi );

    ret = mbedtls_rsa_export( rsa, NULL, NULL, NULL, NULL, &mpi );
    if( ret != 0 )
        goto exit;
    if( mbedtls_mpi_cmp_int( &mpi, 65537 ) == 0 )
    {
       
        goto exit;
    }

    buflen = mbedtls_mpi_size( &mpi );
    buffer = mbedtls_calloc( 1, buflen );
    if( buffer == NULL )
    {
        ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto exit;
    }
    ret = mbedtls_mpi_write_binary( &mpi, buffer, buflen );
    if( ret != 0 )
        goto exit;
    attributes->domain_parameters = buffer;
    attributes->domain_parameters_size = buflen;

exit:
    mbedtls_mpi_free( &mpi );
    if( ret != 0 )
        mbedtls_free( buffer );
    return( mbedtls_to_psa_error( ret ) );
}
#endif

/** Retrieve all the publicly-accessible attributes of a key.
 */
psa_status_t psa_get_key_attributes( mbedtls_svc_key_id_t key,
                                     psa_key_attributes_t *attributes )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    psa_reset_key_attributes( attributes );

    status = psa_get_and_lock_key_slot_with_policy( key, &slot, 0, 0 );
    if( status != PSA_SUCCESS )
        return( status );

    attributes->core = slot->attr;
    attributes->core.flags &= ( MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY |
                                MBEDTLS_PSA_KA_MASK_DUAL_USE );

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( psa_get_se_driver_entry( slot->attr.lifetime ) != NULL )
        psa_set_key_slot_number( attributes,
                                 psa_key_slot_get_slot_number( slot ) );
#endif

    switch( slot->attr.type )
    {
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
        case PSA_KEY_TYPE_RSA_KEY_PAIR:
        case PSA_KEY_TYPE_RSA_PUBLIC_KEY:
           
            if( ! psa_key_lifetime_is_external( slot->attr.lifetime ) )
            {
                mbedtls_rsa_context *rsa = NULL;

                status = mbedtls_psa_rsa_load_representation(
                             slot->attr.type,
                             slot->key.data,
                             slot->key.bytes,
                             &rsa );
                if( status != PSA_SUCCESS )
                    break;

                status = psa_get_rsa_public_exponent( rsa,
                                                      attributes );
                mbedtls_rsa_free( rsa );
                mbedtls_free( rsa );
            }
            break;
#endif
        default:
           
            break;
    }

    if( status != PSA_SUCCESS )
        psa_reset_key_attributes( attributes );

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
psa_status_t psa_get_key_slot_number(
    const psa_key_attributes_t *attributes,
    psa_key_slot_number_t *slot_number )
{
    if( attributes->core.flags & MBEDTLS_PSA_KA_FLAG_HAS_SLOT_NUMBER )
    {
        *slot_number = attributes->slot_number;
        return( PSA_SUCCESS );
    }
    else
        return( PSA_ERROR_INVALID_ARGUMENT );
}
#endif

static psa_status_t psa_export_key_buffer_internal( const uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    uint8_t *data,
                                                    size_t data_size,
                                                    size_t *data_length )
{
    if( key_buffer_size > data_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    memcpy( data, key_buffer, key_buffer_size );
    memset( data + key_buffer_size, 0,
            data_size - key_buffer_size );
    *data_length = key_buffer_size;
    return( PSA_SUCCESS );
}

psa_status_t psa_export_key_internal(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    psa_key_type_t type = attributes->core.type;

    if( key_type_is_raw_bytes( type ) ||
        PSA_KEY_TYPE_IS_RSA( type )   ||
        PSA_KEY_TYPE_IS_ECC( type )      )
    {
        return( psa_export_key_buffer_internal(
                    key_buffer, key_buffer_size,
                    data, data_size, data_length ) );
    }
    else
    {
       
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t psa_export_key( mbedtls_svc_key_id_t key,
                             uint8_t *data,
                             size_t data_size,
                             size_t *data_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

   
    if( data_size == 0 )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

   
    *data_length = 0;

   
    status = psa_get_and_lock_key_slot_with_policy( key, &slot,
                                                    PSA_KEY_USAGE_EXPORT, 0 );
    if( status != PSA_SUCCESS )
        return( status );

    psa_key_attributes_t attributes = {
        .core = slot->attr
    };
    status = psa_driver_wrapper_export_key( &attributes,
                 slot->key.data, slot->key.bytes,
                 data, data_size, data_length );

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

psa_status_t psa_export_public_key_internal(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length )
{
    psa_key_type_t type = attributes->core.type;

    if( PSA_KEY_TYPE_IS_RSA( type ) || PSA_KEY_TYPE_IS_ECC( type ) )
    {
        if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
        {
           
            return( psa_export_key_buffer_internal(
                        key_buffer, key_buffer_size,
                        data, data_size, data_length ) );
        }

        if( PSA_KEY_TYPE_IS_RSA( type ) )
        {
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
            return( mbedtls_psa_rsa_export_public_key( attributes,
                                                       key_buffer,
                                                       key_buffer_size,
                                                       data,
                                                       data_size,
                                                       data_length ) );
#else
           
            return( PSA_ERROR_NOT_SUPPORTED );
#endif
        }
        else
        {
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY)
            return( mbedtls_psa_ecp_export_public_key( attributes,
                                                       key_buffer,
                                                       key_buffer_size,
                                                       data,
                                                       data_size,
                                                       data_length ) );
#else
           
            return( PSA_ERROR_NOT_SUPPORTED );
#endif
        }
    }
    else
    {
       
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t psa_export_public_key( mbedtls_svc_key_id_t key,
                                    uint8_t *data,
                                    size_t data_size,
                                    size_t *data_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

   
    if( data_size == 0 )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

   
    *data_length = 0;

   
    status = psa_get_and_lock_key_slot_with_policy( key, &slot, 0, 0 );
    if( status != PSA_SUCCESS )
        return( status );

    if( ! PSA_KEY_TYPE_IS_ASYMMETRIC( slot->attr.type ) )
    {
         status = PSA_ERROR_INVALID_ARGUMENT;
         goto exit;
    }

    psa_key_attributes_t attributes = {
        .core = slot->attr
    };
    status = psa_driver_wrapper_export_public_key(
        &attributes, slot->key.data, slot->key.bytes,
        data, data_size, data_length );

exit:
    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

#if defined(static_assert)
static_assert( ( MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY & MBEDTLS_PSA_KA_MASK_DUAL_USE ) == 0,
               "One or more key attribute flag is listed as both external-only and dual-use" );
static_assert( ( PSA_KA_MASK_INTERNAL_ONLY & MBEDTLS_PSA_KA_MASK_DUAL_USE ) == 0,
               "One or more key attribute flag is listed as both internal-only and dual-use" );
static_assert( ( PSA_KA_MASK_INTERNAL_ONLY & MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY ) == 0,
               "One or more key attribute flag is listed as both internal-only and external-only" );
#endif

/** Validate that a key policy is internally well-formed.
 *
 * This function only rejects invalid policies. It does not validate the
 * consistency of the policy with respect to other attributes of the key
 * such as the key type.
 */
static psa_status_t psa_validate_key_policy( const psa_key_policy_t *policy )
{
    if( ( policy->usage & ~( PSA_KEY_USAGE_EXPORT |
                             PSA_KEY_USAGE_COPY |
                             PSA_KEY_USAGE_ENCRYPT |
                             PSA_KEY_USAGE_DECRYPT |
                             PSA_KEY_USAGE_SIGN_MESSAGE |
                             PSA_KEY_USAGE_VERIFY_MESSAGE |
                             PSA_KEY_USAGE_SIGN_HASH |
                             PSA_KEY_USAGE_VERIFY_HASH |
                             PSA_KEY_USAGE_VERIFY_DERIVATION |
                             PSA_KEY_USAGE_DERIVE ) ) != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}

/** Validate the internal consistency of key attributes.
 *
 * This function only rejects invalid attribute values. If does not
 * validate the consistency of the attributes with any key data that may
 * be involved in the creation of the key.
 *
 * Call this function early in the key creation process.
 *
 * \param[in] attributes    Key attributes for the new key.
 * \param[out] p_drv        On any return, the driver for the key, if any.
 *                          NULL for a transparent key.
 *
 */
static psa_status_t psa_validate_key_attributes(
    const psa_key_attributes_t *attributes,
    psa_se_drv_table_entry_t **p_drv )
{
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_lifetime_t lifetime = psa_get_key_lifetime( attributes );
    mbedtls_svc_key_id_t key = psa_get_key_id( attributes );

    status = psa_validate_key_location( lifetime, p_drv );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_validate_key_persistence( lifetime );
    if( status != PSA_SUCCESS )
        return( status );

    if ( PSA_KEY_LIFETIME_IS_VOLATILE( lifetime ) )
    {
        if( MBEDTLS_SVC_KEY_ID_GET_KEY_ID( key ) != 0 )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
    else
    {
        if( !psa_is_valid_key_id( psa_get_key_id( attributes ), 0 ) )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }

    status = psa_validate_key_policy( &attributes->core.policy );
    if( status != PSA_SUCCESS )
        return( status );

   
    if( psa_get_key_bits( attributes ) > PSA_MAX_KEY_BITS )
        return( PSA_ERROR_NOT_SUPPORTED );

   
    if( attributes->core.flags & ~ ( MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY |
                                     MBEDTLS_PSA_KA_MASK_DUAL_USE ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}

/** Prepare a key slot to receive key material.
 *
 * This function allocates a key slot and sets its metadata.
 *
 * If this function fails, call psa_fail_key_creation().
 *
 * This function is intended to be used as follows:
 * -# Call psa_start_key_creation() to allocate a key slot, prepare
 *    it with the specified attributes, and in case of a volatile key assign it
 *    a volatile key identifier.
 * -# Populate the slot with the key material.
 * -# Call psa_finish_key_creation() to finalize the creation of the slot.
 * In case of failure at any step, stop the sequence and call
 * psa_fail_key_creation().
 *
 * On success, the key slot is locked. It is the responsibility of the caller
 * to unlock the key slot when it does not access it anymore.
 *
 * \param method            An identification of the calling function.
 * \param[in] attributes    Key attributes for the new key.
 * \param[out] p_slot       On success, a pointer to the prepared slot.
 * \param[out] p_drv        On any return, the driver for the key, if any.
 *                          NULL for a transparent key.
 *
 * \retval #PSA_SUCCESS
 *         The key slot is ready to receive key material.
 * \return If this function fails, the key slot is an invalid state.
 *         You must call psa_fail_key_creation() to wipe and free the slot.
 */
static psa_status_t psa_start_key_creation(
    psa_key_creation_method_t method,
    const psa_key_attributes_t *attributes,
    psa_key_slot_t **p_slot,
    psa_se_drv_table_entry_t **p_drv )
{
    psa_status_t status;
    psa_key_id_t volatile_key_id;
    psa_key_slot_t *slot;

    (void) method;
    *p_drv = NULL;

    status = psa_validate_key_attributes( attributes, p_drv );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_get_empty_key_slot( &volatile_key_id, p_slot );
    if( status != PSA_SUCCESS )
        return( status );
    slot = *p_slot;

   

    slot->attr = attributes->core;
    if( PSA_KEY_LIFETIME_IS_VOLATILE( slot->attr.lifetime ) )
    {
#if !defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
        slot->attr.id = volatile_key_id;
#else
        slot->attr.id.key_id = volatile_key_id;
#endif
    }

   
    slot->attr.flags &= ~MBEDTLS_PSA_KA_MASK_EXTERNAL_ONLY;

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
   
   
    if( *p_drv != NULL )
    {
        psa_key_slot_number_t slot_number;
        status = psa_find_se_slot_for_key( attributes, method, *p_drv,
                                           &slot_number );
        if( status != PSA_SUCCESS )
            return( status );

        if( ! PSA_KEY_LIFETIME_IS_VOLATILE( attributes->core.lifetime ) )
        {
            psa_crypto_prepare_transaction( PSA_CRYPTO_TRANSACTION_CREATE_KEY );
            psa_crypto_transaction.key.lifetime = slot->attr.lifetime;
            psa_crypto_transaction.key.slot = slot_number;
            psa_crypto_transaction.key.id = slot->attr.id;
            status = psa_crypto_save_transaction( );
            if( status != PSA_SUCCESS )
            {
                (void) psa_crypto_stop_transaction( );
                return( status );
            }
        }

        status = psa_copy_key_material_into_slot(
            slot, (uint8_t *)( &slot_number ), sizeof( slot_number ) );
    }

    if( *p_drv == NULL && method == PSA_KEY_CREATION_REGISTER )
    {
       
        return( PSA_ERROR_INVALID_ARGUMENT );
    }
#endif

    return( PSA_SUCCESS );
}

/** Finalize the creation of a key once its key material has been set.
 *
 * This entails writing the key to persistent storage.
 *
 * If this function fails, call psa_fail_key_creation().
 * See the documentation of psa_start_key_creation() for the intended use
 * of this function.
 *
 * If the finalization succeeds, the function unlocks the key slot (it was
 * locked by psa_start_key_creation()) and the key slot cannot be accessed
 * anymore as part of the key creation process.
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 * \param[in] driver    The secure element driver for the key,
 *                      or NULL for a transparent key.
 * \param[out] key      On success, identifier of the key. Note that the
 *                      key identifier is also stored in the key slot.
 *
 * \retval #PSA_SUCCESS
 *         The key was successfully created.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval #PSA_ERROR_ALREADY_EXISTS
 * \retval #PSA_ERROR_DATA_INVALID
 * \retval #PSA_ERROR_DATA_CORRUPT
 * \retval #PSA_ERROR_STORAGE_FAILURE
 *
 * \return If this function fails, the key slot is an invalid state.
 *         You must call psa_fail_key_creation() to wipe and free the slot.
 */
static psa_status_t psa_finish_key_creation(
    psa_key_slot_t *slot,
    psa_se_drv_table_entry_t *driver,
    mbedtls_svc_key_id_t *key)
{
    psa_status_t status = PSA_SUCCESS;
    (void) slot;
    (void) driver;

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if( ! PSA_KEY_LIFETIME_IS_VOLATILE( slot->attr.lifetime ) )
    {
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
        if( driver != NULL )
        {
            psa_se_key_data_storage_t data;
            psa_key_slot_number_t slot_number =
                psa_key_slot_get_slot_number( slot ) ;

#if defined(static_assert)
            static_assert( sizeof( slot_number ) ==
                           sizeof( data.slot_number ),
                           "Slot number size does not match psa_se_key_data_storage_t" );
#endif
            memcpy( &data.slot_number, &slot_number, sizeof( slot_number ) );
            status = psa_save_persistent_key( &slot->attr,
                                              (uint8_t*) &data,
                                              sizeof( data ) );
        }
        else
#endif
        {
           
            status = psa_save_persistent_key( &slot->attr,
                                              slot->key.data,
                                              slot->key.bytes );
        }
    }
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
   
    if( driver != NULL &&
        psa_crypto_transaction.unknown.type == PSA_CRYPTO_TRANSACTION_CREATE_KEY )
    {
        status = psa_save_se_persistent_data( driver );
        if( status != PSA_SUCCESS )
        {
            psa_destroy_persistent_key( slot->attr.id );
            return( status );
        }
        status = psa_crypto_stop_transaction( );
    }
#endif

    if( status == PSA_SUCCESS )
    {
        *key = slot->attr.id;
        status = psa_unlock_key_slot( slot );
        if( status != PSA_SUCCESS )
            *key = MBEDTLS_SVC_KEY_ID_INIT;
    }

    return( status );
}

/** Abort the creation of a key.
 *
 * You may call this function after calling psa_start_key_creation(),
 * or after psa_finish_key_creation() fails. In other circumstances, this
 * function may not clean up persistent storage.
 * See the documentation of psa_start_key_creation() for the intended use
 * of this function.
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 * \param[in] driver    The secure element driver for the key,
 *                      or NULL for a transparent key.
 */
static void psa_fail_key_creation( psa_key_slot_t *slot,
                                   psa_se_drv_table_entry_t *driver )
{
    (void) driver;

    if( slot == NULL )
        return;

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
   

   
    (void) psa_crypto_stop_transaction( );
#endif

    psa_wipe_key_slot( slot );
}

/** Validate optional attributes during key creation.
 *
 * Some key attributes are optional during key creation. If they are
 * specified in the attributes structure, check that they are consistent
 * with the data in the slot.
 *
 * This function should be called near the end of key creation, after
 * the slot in memory is fully populated but before saving persistent data.
 */
static psa_status_t psa_validate_optional_attributes(
    const psa_key_slot_t *slot,
    const psa_key_attributes_t *attributes )
{
    if( attributes->core.type != 0 )
    {
        if( attributes->core.type != slot->attr.type )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }

    if( attributes->domain_parameters_size != 0 )
    {
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)
        if( PSA_KEY_TYPE_IS_RSA( slot->attr.type ) )
        {
            mbedtls_rsa_context *rsa = NULL;
            mbedtls_mpi actual, required;
            int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

            psa_status_t status = mbedtls_psa_rsa_load_representation(
                                      slot->attr.type,
                                      slot->key.data,
                                      slot->key.bytes,
                                      &rsa );
            if( status != PSA_SUCCESS )
                return( status );

            mbedtls_mpi_init( &actual );
            mbedtls_mpi_init( &required );
            ret = mbedtls_rsa_export( rsa,
                                      NULL, NULL, NULL, NULL, &actual );
            mbedtls_rsa_free( rsa );
            mbedtls_free( rsa );
            if( ret != 0 )
                goto rsa_exit;
            ret = mbedtls_mpi_read_binary( &required,
                                           attributes->domain_parameters,
                                           attributes->domain_parameters_size );
            if( ret != 0 )
                goto rsa_exit;
            if( mbedtls_mpi_cmp_mpi( &actual, &required ) != 0 )
                ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        rsa_exit:
            mbedtls_mpi_free( &actual );
            mbedtls_mpi_free( &required );
            if( ret != 0)
                return( mbedtls_to_psa_error( ret ) );
        }
        else
#endif
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }

    if( attributes->core.bits != 0 )
    {
        if( attributes->core.bits != slot->attr.bits )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_import_key( const psa_key_attributes_t *attributes,
                             const uint8_t *data,
                             size_t data_length,
                             mbedtls_svc_key_id_t *key )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    size_t bits;
    size_t storage_size = data_length;

    *key = MBEDTLS_SVC_KEY_ID_INIT;

   
    if( data_length == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

   
    if( data_length > SIZE_MAX / 8 )
        return( PSA_ERROR_NOT_SUPPORTED );

    status = psa_start_key_creation( PSA_KEY_CREATION_IMPORT, attributes,
                                     &slot, &driver );
    if( status != PSA_SUCCESS )
        goto exit;

   
    if( slot->key.data == NULL )
    {
        if( psa_key_lifetime_is_external( attributes->core.lifetime ) )
        {
            status = psa_driver_wrapper_get_key_buffer_size_from_key_data(
                         attributes, data, data_length, &storage_size );
            if( status != PSA_SUCCESS )
                goto exit;
        }
        status = psa_allocate_buffer_to_slot( slot, storage_size );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    bits = slot->attr.bits;
    status = psa_driver_wrapper_import_key( attributes,
                                            data, data_length,
                                            slot->key.data,
                                            slot->key.bytes,
                                            &slot->key.bytes, &bits );
    if( status != PSA_SUCCESS )
        goto exit;

    if( slot->attr.bits == 0 )
        slot->attr.bits = (psa_key_bits_t) bits;
    else if( bits != slot->attr.bits )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

   
    if( bits > PSA_MAX_KEY_BITS )
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = psa_validate_optional_attributes( slot, attributes );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_finish_key_creation( slot, driver, key );
exit:
    if( status != PSA_SUCCESS )
        psa_fail_key_creation( slot, driver );

    return( status );
}

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
psa_status_t mbedtls_psa_register_se_key(
    const psa_key_attributes_t *attributes )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;

   
    if( psa_get_key_type( attributes ) == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_NOT_SUPPORTED );
    if( psa_get_key_bits( attributes ) == 0 )
        return( PSA_ERROR_NOT_SUPPORTED );

    status = psa_start_key_creation( PSA_KEY_CREATION_REGISTER, attributes,
                                     &slot, &driver );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_finish_key_creation( slot, driver, &key );

exit:
    if( status != PSA_SUCCESS )
        psa_fail_key_creation( slot, driver );

   
    psa_close_key( key );
    return( status );
}
#endif

psa_status_t psa_copy_key( mbedtls_svc_key_id_t source_key,
                           const psa_key_attributes_t *specified_attributes,
                           mbedtls_svc_key_id_t *target_key )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *source_slot = NULL;
    psa_key_slot_t *target_slot = NULL;
    psa_key_attributes_t actual_attributes = *specified_attributes;
    psa_se_drv_table_entry_t *driver = NULL;
    size_t storage_size = 0;

    *target_key = MBEDTLS_SVC_KEY_ID_INIT;

    status = psa_get_and_lock_key_slot_with_policy(
                 source_key, &source_slot, PSA_KEY_USAGE_COPY, 0 );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_validate_optional_attributes( source_slot,
                                               specified_attributes );
    if( status != PSA_SUCCESS )
        goto exit;

   
    actual_attributes.core.bits = source_slot->attr.bits;
    actual_attributes.core.type = source_slot->attr.type;


    status = psa_restrict_key_policy( source_slot->attr.type,
                                      &actual_attributes.core.policy,
                                      &source_slot->attr.policy );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_start_key_creation( PSA_KEY_CREATION_COPY, &actual_attributes,
                                     &target_slot, &driver );
    if( status != PSA_SUCCESS )
        goto exit;
    if( PSA_KEY_LIFETIME_GET_LOCATION( target_slot->attr.lifetime ) !=
        PSA_KEY_LIFETIME_GET_LOCATION( source_slot->attr.lifetime ) )
    {
       
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
   
    if( psa_key_lifetime_is_external( actual_attributes.core.lifetime ) )
    {
        status = psa_driver_wrapper_get_key_buffer_size( &actual_attributes,
                                                         &storage_size );
        if( status != PSA_SUCCESS )
            goto exit;

        status = psa_allocate_buffer_to_slot( target_slot, storage_size );
        if( status != PSA_SUCCESS )
            goto exit;

        status = psa_driver_wrapper_copy_key( &actual_attributes,
                                              source_slot->key.data,
                                              source_slot->key.bytes,
                                              target_slot->key.data,
                                              target_slot->key.bytes,
                                              &target_slot->key.bytes );
        if( status != PSA_SUCCESS )
            goto exit;
    }
    else
    {
       status = psa_copy_key_material_into_slot( target_slot,
                                                 source_slot->key.data,
                                                 source_slot->key.bytes );
        if( status != PSA_SUCCESS )
            goto exit;
    }
    status = psa_finish_key_creation( target_slot, driver, target_key );
exit:
    if( status != PSA_SUCCESS )
        psa_fail_key_creation( target_slot, driver );

    unlock_status = psa_unlock_key_slot( source_slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}



/****************************************************************/

/****************************************************************/

psa_status_t psa_hash_abort( psa_hash_operation_t *operation )
{
   
    if( operation->id == 0 )
        return( PSA_SUCCESS );

    psa_status_t status = psa_driver_wrapper_hash_abort( operation );
    operation->id = 0;

    return( status );
}

psa_status_t psa_hash_setup( psa_hash_operation_t *operation,
                             psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

   
    if( operation->id != 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( !PSA_ALG_IS_HASH( alg ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

   
    memset( &operation->ctx, 0, sizeof( operation->ctx ) );

    status = psa_driver_wrapper_hash_setup( operation, alg );

exit:
    if( status != PSA_SUCCESS )
        psa_hash_abort( operation );

    return status;
}

psa_status_t psa_hash_update( psa_hash_operation_t *operation,
                              const uint8_t *input,
                              size_t input_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

   
    if( input_length == 0 )
        return( PSA_SUCCESS );

    status = psa_driver_wrapper_hash_update( operation, input, input_length );

exit:
    if( status != PSA_SUCCESS )
        psa_hash_abort( operation );

    return( status );
}

psa_status_t psa_hash_finish( psa_hash_operation_t *operation,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length )
{
    *hash_length = 0;
    if( operation->id == 0 )
        return( PSA_ERROR_BAD_STATE );

    psa_status_t status = psa_driver_wrapper_hash_finish(
                            operation, hash, hash_size, hash_length );
    psa_hash_abort( operation );
    return( status );
}

psa_status_t psa_hash_verify( psa_hash_operation_t *operation,
                              const uint8_t *hash,
                              size_t hash_length )
{
    uint8_t actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;
    psa_status_t status = psa_hash_finish(
                            operation,
                            actual_hash, sizeof( actual_hash ),
                            &actual_hash_length );

    if( status != PSA_SUCCESS )
        goto exit;

    if( actual_hash_length != hash_length )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    if( mbedtls_psa_safer_memcmp( hash, actual_hash, actual_hash_length ) != 0 )
        status = PSA_ERROR_INVALID_SIGNATURE;

exit:
    mbedtls_platform_zeroize( actual_hash, sizeof( actual_hash ) );
    if( status != PSA_SUCCESS )
        psa_hash_abort(operation);

    return( status );
}

psa_status_t psa_hash_compute( psa_algorithm_t alg,
                               const uint8_t *input, size_t input_length,
                               uint8_t *hash, size_t hash_size,
                               size_t *hash_length )
{
    *hash_length = 0;
    if( !PSA_ALG_IS_HASH( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( psa_driver_wrapper_hash_compute( alg, input, input_length,
                                             hash, hash_size, hash_length ) );
}

psa_status_t psa_hash_compare( psa_algorithm_t alg,
                               const uint8_t *input, size_t input_length,
                               const uint8_t *hash, size_t hash_length )
{
    uint8_t actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;

    if( !PSA_ALG_IS_HASH( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    psa_status_t status = psa_driver_wrapper_hash_compute(
                            alg, input, input_length,
                            actual_hash, sizeof(actual_hash),
                            &actual_hash_length );
    if( status != PSA_SUCCESS )
        goto exit;
    if( actual_hash_length != hash_length )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }
    if( mbedtls_psa_safer_memcmp( hash, actual_hash, actual_hash_length ) != 0 )
        status = PSA_ERROR_INVALID_SIGNATURE;

exit:
    mbedtls_platform_zeroize( actual_hash, sizeof( actual_hash ) );
    return( status );
}

psa_status_t psa_hash_clone( const psa_hash_operation_t *source_operation,
                             psa_hash_operation_t *target_operation )
{
    if( source_operation->id == 0 ||
        target_operation->id != 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    psa_status_t status = psa_driver_wrapper_hash_clone( source_operation,
                                                         target_operation );
    if( status != PSA_SUCCESS )
        psa_hash_abort( target_operation );

    return( status );
}


/****************************************************************/

/****************************************************************/

psa_status_t psa_mac_abort( psa_mac_operation_t *operation )
{
   
    if( operation->id == 0 )
        return( PSA_SUCCESS );

    psa_status_t status = psa_driver_wrapper_mac_abort( operation );
    operation->mac_size = 0;
    operation->is_sign = 0;
    operation->id = 0;

    return( status );
}

static psa_status_t psa_mac_finalize_alg_and_key_validation(
    psa_algorithm_t alg,
    const psa_key_attributes_t *attributes,
    uint8_t *mac_size )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type( attributes );
    size_t key_bits = psa_get_key_bits( attributes );

    if( ! PSA_ALG_IS_MAC( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

   
    status = psa_mac_key_can_do( alg, key_type );
    if( status != PSA_SUCCESS )
        return( status );

   
    *mac_size = PSA_MAC_LENGTH( key_type, key_bits, alg );

    if( *mac_size < 4 )
    {
       
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( *mac_size > PSA_MAC_LENGTH( key_type, key_bits,
                                    PSA_ALG_FULL_LENGTH_MAC( alg ) ) )
    {
       
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    if( *mac_size > PSA_MAC_MAX_SIZE )
    {
       
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    return( PSA_SUCCESS );
}

static psa_status_t psa_mac_setup( psa_mac_operation_t *operation,
                                   mbedtls_svc_key_id_t key,
                                   psa_algorithm_t alg,
                                   int is_sign )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

   
    if( operation->id != 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy(
                 key,
                 &slot,
                 is_sign ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_VERIFY_MESSAGE,
                 alg );
    if( status != PSA_SUCCESS )
        goto exit;

    psa_key_attributes_t attributes = {
        .core = slot->attr
    };

    status = psa_mac_finalize_alg_and_key_validation( alg, &attributes,
                                                      &operation->mac_size );
    if( status != PSA_SUCCESS )
        goto exit;

    operation->is_sign = is_sign;
   
    if( is_sign )
    {
        status = psa_driver_wrapper_mac_sign_setup( operation,
                                                    &attributes,
                                                    slot->key.data,
                                                    slot->key.bytes,
                                                    alg );
    }
    else
    {
        status = psa_driver_wrapper_mac_verify_setup( operation,
                                                      &attributes,
                                                      slot->key.data,
                                                      slot->key.bytes,
                                                      alg );
    }

exit:
    if( status != PSA_SUCCESS )
        psa_mac_abort( operation );

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

psa_status_t psa_mac_sign_setup( psa_mac_operation_t *operation,
                                 mbedtls_svc_key_id_t key,
                                 psa_algorithm_t alg )
{
    return( psa_mac_setup( operation, key, alg, 1 ) );
}

psa_status_t psa_mac_verify_setup( psa_mac_operation_t *operation,
                                   mbedtls_svc_key_id_t key,
                                   psa_algorithm_t alg )
{
    return( psa_mac_setup( operation, key, alg, 0 ) );
}

psa_status_t psa_mac_update( psa_mac_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length )
{
    if( operation->id == 0 )
        return( PSA_ERROR_BAD_STATE );

   
    if( input_length == 0 )
        return( PSA_SUCCESS );

    psa_status_t status = psa_driver_wrapper_mac_update( operation,
                                                         input, input_length );
    if( status != PSA_SUCCESS )
        psa_mac_abort( operation );

    return( status );
}

psa_status_t psa_mac_sign_finish( psa_mac_operation_t *operation,
                                  uint8_t *mac,
                                  size_t mac_size,
                                  size_t *mac_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t abort_status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( ! operation->is_sign )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

   
    if( operation->mac_size == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( mac_size < operation->mac_size )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = psa_driver_wrapper_mac_sign_finish( operation,
                                                 mac, operation->mac_size,
                                                 mac_length );

exit:
   
    if( status != PSA_SUCCESS )
    {
        *mac_length = mac_size;
        operation->mac_size = 0;
    }

    if( mac_size > operation->mac_size )
        memset( &mac[operation->mac_size], '!',
                mac_size - operation->mac_size );

    abort_status = psa_mac_abort( operation );

    return( status == PSA_SUCCESS ? abort_status : status );
}

psa_status_t psa_mac_verify_finish( psa_mac_operation_t *operation,
                                    const uint8_t *mac,
                                    size_t mac_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t abort_status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->is_sign )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->mac_size != mac_length )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    status = psa_driver_wrapper_mac_verify_finish( operation,
                                                   mac, mac_length );

exit:
    abort_status = psa_mac_abort( operation );

    return( status == PSA_SUCCESS ? abort_status : status );
}

static psa_status_t psa_mac_compute_internal( mbedtls_svc_key_id_t key,
                                              psa_algorithm_t alg,
                                              const uint8_t *input,
                                              size_t input_length,
                                              uint8_t *mac,
                                              size_t mac_size,
                                              size_t *mac_length,
                                              int is_sign )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;
    uint8_t operation_mac_size = 0;

    status = psa_get_and_lock_key_slot_with_policy(
                 key,
                 &slot,
                 is_sign ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_VERIFY_MESSAGE,
                 alg );
    if( status != PSA_SUCCESS )
        goto exit;

    psa_key_attributes_t attributes = {
        .core = slot->attr
    };

    status = psa_mac_finalize_alg_and_key_validation( alg, &attributes,
                                                      &operation_mac_size );
    if( status != PSA_SUCCESS )
        goto exit;

    if( mac_size < operation_mac_size )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = psa_driver_wrapper_mac_compute(
                 &attributes,
                 slot->key.data, slot->key.bytes,
                 alg,
                 input, input_length,
                 mac, operation_mac_size, mac_length );

exit:
   
    if( status != PSA_SUCCESS )
    {
        *mac_length = mac_size;
        operation_mac_size = 0;
    }
    if( mac_size > operation_mac_size )
        memset( &mac[operation_mac_size], '!', mac_size - operation_mac_size );

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

psa_status_t psa_mac_compute( mbedtls_svc_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *mac,
                              size_t mac_size,
                              size_t *mac_length)
{
    return( psa_mac_compute_internal( key, alg,
                                      input, input_length,
                                      mac, mac_size, mac_length, 1 ) );
}

psa_status_t psa_mac_verify( mbedtls_svc_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             const uint8_t *mac,
                             size_t mac_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t actual_mac[PSA_MAC_MAX_SIZE];
    size_t actual_mac_length;

    status = psa_mac_compute_internal( key, alg,
                                       input, input_length,
                                       actual_mac, sizeof( actual_mac ),
                                       &actual_mac_length, 0 );
    if( status != PSA_SUCCESS )
        goto exit;

    if( mac_length != actual_mac_length )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }
    if( mbedtls_psa_safer_memcmp( mac, actual_mac, actual_mac_length ) != 0 )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

exit:
    mbedtls_platform_zeroize( actual_mac, sizeof( actual_mac ) );

    return ( status );
}

/****************************************************************/

/****************************************************************/

static psa_status_t psa_sign_verify_check_alg( int input_is_message,
                                               psa_algorithm_t alg )
{
    if( input_is_message )
    {
        if( ! PSA_ALG_IS_SIGN_MESSAGE( alg ) )
            return( PSA_ERROR_INVALID_ARGUMENT );

        if ( PSA_ALG_IS_SIGN_HASH( alg ) )
        {
            if( ! PSA_ALG_IS_HASH( PSA_ALG_SIGN_GET_HASH( alg ) ) )
                return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }
    else
    {
        if( ! PSA_ALG_IS_SIGN_HASH( alg ) )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }

    return( PSA_SUCCESS );
}

static psa_status_t psa_sign_internal( mbedtls_svc_key_id_t key,
                                       int input_is_message,
                                       psa_algorithm_t alg,
                                       const uint8_t * input,
                                       size_t input_length,
                                       uint8_t * signature,
                                       size_t signature_size,
                                       size_t * signature_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    *signature_length = 0;

    status = psa_sign_verify_check_alg( input_is_message, alg );
    if( status != PSA_SUCCESS )
        return status;

   
    if( signature_size == 0 )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    status = psa_get_and_lock_key_slot_with_policy(
                key, &slot,
                input_is_message ? PSA_KEY_USAGE_SIGN_MESSAGE :
                                   PSA_KEY_USAGE_SIGN_HASH,
                alg );

    if( status != PSA_SUCCESS )
        goto exit;

    if( ! PSA_KEY_TYPE_IS_KEY_PAIR( slot->attr.type ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    if( input_is_message )
    {
        status = psa_driver_wrapper_sign_message(
            &attributes, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_size, signature_length );
    }
    else
    {

        status = psa_driver_wrapper_sign_hash(
            &attributes, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_size, signature_length );
    }


exit:
   
    if( status == PSA_SUCCESS )
        memset( signature + *signature_length, '!',
                signature_size - *signature_length );
    else
        memset( signature, '!', signature_size );
   

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

static psa_status_t psa_verify_internal( mbedtls_svc_key_id_t key,
                                         int input_is_message,
                                         psa_algorithm_t alg,
                                         const uint8_t * input,
                                         size_t input_length,
                                         const uint8_t * signature,
                                         size_t signature_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    status = psa_sign_verify_check_alg( input_is_message, alg );
    if( status != PSA_SUCCESS )
        return status;

    status = psa_get_and_lock_key_slot_with_policy(
                key, &slot,
                input_is_message ? PSA_KEY_USAGE_VERIFY_MESSAGE :
                                   PSA_KEY_USAGE_VERIFY_HASH,
                alg );

    if( status != PSA_SUCCESS )
        return( status );

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    if( input_is_message )
    {
        status = psa_driver_wrapper_verify_message(
            &attributes, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_length );
    }
    else
    {
        status = psa_driver_wrapper_verify_hash(
            &attributes, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_length );
    }

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );

}

psa_status_t psa_sign_message_builtin(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if ( PSA_ALG_IS_SIGN_HASH( alg ) )
    {
        size_t hash_length;
        uint8_t hash[PSA_HASH_MAX_SIZE];

        status = psa_driver_wrapper_hash_compute(
                    PSA_ALG_SIGN_GET_HASH( alg ),
                    input, input_length,
                    hash, sizeof( hash ), &hash_length );

        if( status != PSA_SUCCESS )
            return status;

        return psa_driver_wrapper_sign_hash(
                    attributes, key_buffer, key_buffer_size,
                    alg, hash, hash_length,
                    signature, signature_size, signature_length );
    }

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t psa_sign_message( mbedtls_svc_key_id_t key,
                               psa_algorithm_t alg,
                               const uint8_t * input,
                               size_t input_length,
                               uint8_t * signature,
                               size_t signature_size,
                               size_t * signature_length )
{
    return psa_sign_internal(
        key, 1, alg, input, input_length,
        signature, signature_size, signature_length );
}

psa_status_t psa_verify_message_builtin(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *signature,
    size_t signature_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if ( PSA_ALG_IS_SIGN_HASH( alg ) )
    {
        size_t hash_length;
        uint8_t hash[PSA_HASH_MAX_SIZE];

        status = psa_driver_wrapper_hash_compute(
                    PSA_ALG_SIGN_GET_HASH( alg ),
                    input, input_length,
                    hash, sizeof( hash ), &hash_length );

        if( status != PSA_SUCCESS )
            return status;

        return psa_driver_wrapper_verify_hash(
                    attributes, key_buffer, key_buffer_size,
                    alg, hash, hash_length,
                    signature, signature_length );
    }

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t psa_verify_message( mbedtls_svc_key_id_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t * input,
                                 size_t input_length,
                                 const uint8_t * signature,
                                 size_t signature_length )
{
    return psa_verify_internal(
        key, 1, alg, input, input_length,
        signature, signature_length );
}

psa_status_t psa_sign_hash_builtin(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    if( attributes->core.type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
        if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) ||
            PSA_ALG_IS_RSA_PSS( alg) )
        {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
            return( mbedtls_psa_rsa_sign_hash(
                        attributes,
                        key_buffer, key_buffer_size,
                        alg, hash, hash_length,
                        signature, signature_size, signature_length ) );
#endif
        }
        else
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }
    else if( PSA_KEY_TYPE_IS_ECC( attributes->core.type ) )
    {
        if( PSA_ALG_IS_ECDSA( alg ) )
        {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
            return( mbedtls_psa_ecdsa_sign_hash(
                        attributes,
                        key_buffer, key_buffer_size,
                        alg, hash, hash_length,
                        signature, signature_size, signature_length ) );
#endif
        }
        else
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }

    (void)key_buffer;
    (void)key_buffer_size;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_size;
    (void)signature_length;

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t psa_sign_hash( mbedtls_svc_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t *hash,
                            size_t hash_length,
                            uint8_t *signature,
                            size_t signature_size,
                            size_t *signature_length )
{
    return psa_sign_internal(
        key, 0, alg, hash, hash_length,
        signature, signature_size, signature_length );
}

psa_status_t psa_verify_hash_builtin(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    if( PSA_KEY_TYPE_IS_RSA( attributes->core.type ) )
    {
        if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) ||
            PSA_ALG_IS_RSA_PSS( alg) )
        {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
            return( mbedtls_psa_rsa_verify_hash(
                        attributes,
                        key_buffer, key_buffer_size,
                        alg, hash, hash_length,
                        signature, signature_length ) );
#endif
        }
        else
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }
    else if( PSA_KEY_TYPE_IS_ECC( attributes->core.type ) )
    {
        if( PSA_ALG_IS_ECDSA( alg ) )
        {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
            return( mbedtls_psa_ecdsa_verify_hash(
                        attributes,
                        key_buffer, key_buffer_size,
                        alg, hash, hash_length,
                        signature, signature_length ) );
#endif
        }
        else
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }

    (void)key_buffer;
    (void)key_buffer_size;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_length;

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t psa_verify_hash( mbedtls_svc_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *hash,
                              size_t hash_length,
                              const uint8_t *signature,
                              size_t signature_length )
{
    return psa_verify_internal(
        key, 0, alg, hash, hash_length,
        signature, signature_length );
}

psa_status_t psa_asymmetric_encrypt( mbedtls_svc_key_id_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     const uint8_t *salt,
                                     size_t salt_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if( ! PSA_ALG_IS_RSA_OAEP( alg ) && salt_length != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_and_lock_transparent_key_slot_with_policy(
                 key, &slot, PSA_KEY_USAGE_ENCRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( ! ( PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->attr.type ) ||
            PSA_KEY_TYPE_IS_KEY_PAIR( slot->attr.type ) ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    status = psa_driver_wrapper_asymmetric_encrypt(
        &attributes, slot->key.data, slot->key.bytes,
        alg, input, input_length, salt, salt_length,
        output, output_size, output_length );
exit:
    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

psa_status_t psa_asymmetric_decrypt( mbedtls_svc_key_id_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     const uint8_t *salt,
                                     size_t salt_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if( ! PSA_ALG_IS_RSA_OAEP( alg ) && salt_length != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_and_lock_transparent_key_slot_with_policy(
                 key, &slot, PSA_KEY_USAGE_DECRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( ! PSA_KEY_TYPE_IS_KEY_PAIR( slot->attr.type ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    status = psa_driver_wrapper_asymmetric_decrypt(
        &attributes, slot->key.data, slot->key.bytes,
        alg, input, input_length, salt, salt_length,
        output, output_size, output_length );

exit:
    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}



/****************************************************************/

/****************************************************************/

static psa_status_t psa_cipher_setup( psa_cipher_operation_t *operation,
                                      mbedtls_svc_key_id_t key,
                                      psa_algorithm_t alg,
                                      mbedtls_operation_t cipher_operation )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;
    psa_key_usage_t usage = ( cipher_operation == MBEDTLS_ENCRYPT ?
                              PSA_KEY_USAGE_ENCRYPT :
                              PSA_KEY_USAGE_DECRYPT );

   
    if( operation->id != 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( ! PSA_ALG_IS_CIPHER( alg ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy( key, &slot, usage, alg );
    if( status != PSA_SUCCESS )
        goto exit;

   
    operation->iv_set = 0;
    if( alg == PSA_ALG_ECB_NO_PADDING )
        operation->iv_required = 0;
    else
        operation->iv_required = 1;
    operation->default_iv_length = PSA_CIPHER_IV_LENGTH( slot->attr.type, alg );

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

   
    if( cipher_operation == MBEDTLS_ENCRYPT )
        status = psa_driver_wrapper_cipher_encrypt_setup( operation,
                                                          &attributes,
                                                          slot->key.data,
                                                          slot->key.bytes,
                                                          alg );
    else
        status = psa_driver_wrapper_cipher_decrypt_setup( operation,
                                                          &attributes,
                                                          slot->key.data,
                                                          slot->key.bytes,
                                                          alg );

exit:
    if( status != PSA_SUCCESS )
        psa_cipher_abort( operation );

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

psa_status_t psa_cipher_encrypt_setup( psa_cipher_operation_t *operation,
                                       mbedtls_svc_key_id_t key,
                                       psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, key, alg, MBEDTLS_ENCRYPT ) );
}

psa_status_t psa_cipher_decrypt_setup( psa_cipher_operation_t *operation,
                                       mbedtls_svc_key_id_t key,
                                       psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, key, alg, MBEDTLS_DECRYPT ) );
}

psa_status_t psa_cipher_generate_iv( psa_cipher_operation_t *operation,
                                     uint8_t *iv,
                                     size_t iv_size,
                                     size_t *iv_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t local_iv[PSA_CIPHER_IV_MAX_SIZE];
    size_t default_iv_length;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->iv_set || ! operation->iv_required )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    default_iv_length = operation->default_iv_length;
    if( iv_size < default_iv_length )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if( default_iv_length > PSA_CIPHER_IV_MAX_SIZE )
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    status = psa_generate_random( local_iv, default_iv_length );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_driver_wrapper_cipher_set_iv( operation,
                                               local_iv, default_iv_length );

exit:
    if( status == PSA_SUCCESS )
    {
        memcpy( iv, local_iv, default_iv_length );
        *iv_length = default_iv_length;
        operation->iv_set = 1;
    }
    else
    {
        *iv_length = 0;
        psa_cipher_abort( operation );
    }

    return( status );
}

psa_status_t psa_cipher_set_iv( psa_cipher_operation_t *operation,
                                const uint8_t *iv,
                                size_t iv_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->iv_set || ! operation->iv_required )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( iv_length > PSA_CIPHER_IV_MAX_SIZE )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_cipher_set_iv( operation,
                                               iv,
                                               iv_length );

exit:
    if( status == PSA_SUCCESS )
        operation->iv_set = 1;
    else
        psa_cipher_abort( operation );
    return( status );
}

psa_status_t psa_cipher_update( psa_cipher_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->iv_required && ! operation->iv_set )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_cipher_update( operation,
                                               input,
                                               input_length,
                                               output,
                                               output_size,
                                               output_length );

exit:
    if( status != PSA_SUCCESS )
        psa_cipher_abort( operation );

    return( status );
}

psa_status_t psa_cipher_finish( psa_cipher_operation_t *operation,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->iv_required && ! operation->iv_set )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_cipher_finish( operation,
                                               output,
                                               output_size,
                                               output_length );

exit:
    if( status == PSA_SUCCESS )
        return( psa_cipher_abort( operation ) );
    else
    {
        *output_length = 0;
        (void) psa_cipher_abort( operation );

        return( status );
    }
}

psa_status_t psa_cipher_abort( psa_cipher_operation_t *operation )
{
    if( operation->id == 0 )
    {
       
        return( PSA_SUCCESS );
    }

    psa_driver_wrapper_cipher_abort( operation );

    operation->id = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;

    return( PSA_SUCCESS );
}

psa_status_t psa_cipher_encrypt( mbedtls_svc_key_id_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t *input,
                                 size_t input_length,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;
    uint8_t local_iv[PSA_CIPHER_IV_MAX_SIZE];
    size_t default_iv_length = 0;

    if( ! PSA_ALG_IS_CIPHER( alg ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy( key, &slot,
                                                    PSA_KEY_USAGE_ENCRYPT,
                                                    alg );
    if( status != PSA_SUCCESS )
        goto exit;

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    default_iv_length = PSA_CIPHER_IV_LENGTH( slot->attr.type, alg );
    if( default_iv_length > PSA_CIPHER_IV_MAX_SIZE )
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if( default_iv_length > 0 )
    {
        if( output_size < default_iv_length )
        {
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            goto exit;
        }

        status = psa_generate_random( local_iv, default_iv_length );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    status = psa_driver_wrapper_cipher_encrypt(
        &attributes, slot->key.data, slot->key.bytes,
        alg, local_iv, default_iv_length, input, input_length,
        mbedtls_buffer_offset( output, default_iv_length ),
        output_size - default_iv_length, output_length );

exit:
    unlock_status = psa_unlock_key_slot( slot );
    if( status == PSA_SUCCESS )
        status = unlock_status;

    if( status == PSA_SUCCESS )
    {
        if( default_iv_length > 0 )
            memcpy( output, local_iv, default_iv_length );
        *output_length += default_iv_length;
    }
    else
        *output_length = 0;

    return( status );
}

psa_status_t psa_cipher_decrypt( mbedtls_svc_key_id_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t *input,
                                 size_t input_length,
                                 uint8_t *output,
                                 size_t output_size,
                                 size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    if( ! PSA_ALG_IS_CIPHER( alg ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy( key, &slot,
                                                    PSA_KEY_USAGE_DECRYPT,
                                                    alg );
    if( status != PSA_SUCCESS )
        goto exit;

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    if( alg == PSA_ALG_CCM_STAR_NO_TAG && input_length < PSA_BLOCK_CIPHER_BLOCK_LENGTH( slot->attr.type ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    else if ( input_length < PSA_CIPHER_IV_LENGTH( slot->attr.type, alg ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_cipher_decrypt(
        &attributes, slot->key.data, slot->key.bytes,
        alg, input, input_length,
        output, output_size, output_length );

exit:
    unlock_status = psa_unlock_key_slot( slot );
    if( status == PSA_SUCCESS )
        status = unlock_status;

    if( status != PSA_SUCCESS )
        *output_length = 0;

    return( status );
}


/****************************************************************/

/****************************************************************/


static psa_algorithm_t psa_aead_get_base_algorithm( psa_algorithm_t alg )
{
    return PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG( alg );
}


static psa_status_t psa_aead_check_nonce_length( psa_algorithm_t alg,
                                                 size_t nonce_length )
{
    psa_algorithm_t base_alg = psa_aead_get_base_algorithm( alg );

    switch(base_alg)
    {
#if defined(PSA_WANT_ALG_GCM)
        case PSA_ALG_GCM:
           
            if( nonce_length != 0 )
                return( PSA_SUCCESS );
            break;
#endif
#if defined(PSA_WANT_ALG_CCM)
        case PSA_ALG_CCM:
            if( nonce_length >= 7 && nonce_length <= 13 )
                return( PSA_SUCCESS );
            break;
#endif
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
        case PSA_ALG_CHACHA20_POLY1305:
            if( nonce_length == 12 )
                return( PSA_SUCCESS );
            else if( nonce_length == 8 )
                return( PSA_ERROR_NOT_SUPPORTED );
            break;
#endif
        default:
            (void) nonce_length;
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    return( PSA_ERROR_INVALID_ARGUMENT );
}

static psa_status_t psa_aead_check_algorithm( psa_algorithm_t alg )
{
    if( !PSA_ALG_IS_AEAD( alg ) || PSA_ALG_IS_WILDCARD( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}

psa_status_t psa_aead_encrypt( mbedtls_svc_key_id_t key,
                               psa_algorithm_t alg,
                               const uint8_t *nonce,
                               size_t nonce_length,
                               const uint8_t *additional_data,
                               size_t additional_data_length,
                               const uint8_t *plaintext,
                               size_t plaintext_length,
                               uint8_t *ciphertext,
                               size_t ciphertext_size,
                               size_t *ciphertext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    *ciphertext_length = 0;

    status = psa_aead_check_algorithm( alg );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_get_and_lock_key_slot_with_policy(
                 key, &slot, PSA_KEY_USAGE_ENCRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    status = psa_aead_check_nonce_length( alg, nonce_length );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_driver_wrapper_aead_encrypt(
        &attributes, slot->key.data, slot->key.bytes,
        alg,
        nonce, nonce_length,
        additional_data, additional_data_length,
        plaintext, plaintext_length,
        ciphertext, ciphertext_size, ciphertext_length );

    if( status != PSA_SUCCESS && ciphertext_size != 0 )
        memset( ciphertext, 0, ciphertext_size );

exit:
    psa_unlock_key_slot( slot );

    return( status );
}

psa_status_t psa_aead_decrypt( mbedtls_svc_key_id_t key,
                               psa_algorithm_t alg,
                               const uint8_t *nonce,
                               size_t nonce_length,
                               const uint8_t *additional_data,
                               size_t additional_data_length,
                               const uint8_t *ciphertext,
                               size_t ciphertext_length,
                               uint8_t *plaintext,
                               size_t plaintext_size,
                               size_t *plaintext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    *plaintext_length = 0;

    status = psa_aead_check_algorithm( alg );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_get_and_lock_key_slot_with_policy(
                 key, &slot, PSA_KEY_USAGE_DECRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );

    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    status = psa_aead_check_nonce_length( alg, nonce_length );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_driver_wrapper_aead_decrypt(
        &attributes, slot->key.data, slot->key.bytes,
        alg,
        nonce, nonce_length,
        additional_data, additional_data_length,
        ciphertext, ciphertext_length,
        plaintext, plaintext_size, plaintext_length );

    if( status != PSA_SUCCESS && plaintext_size != 0 )
        memset( plaintext, 0, plaintext_size );

exit:
    psa_unlock_key_slot( slot );

    return( status );
}

static psa_status_t psa_validate_tag_length( psa_algorithm_t alg ) {
    const uint8_t tag_len = PSA_ALG_AEAD_GET_TAG_LENGTH( alg );

    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(PSA_WANT_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
           
            if( tag_len < 4 || tag_len > 16 || tag_len % 2 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif

#if defined(PSA_WANT_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
           
            if( tag_len != 4 && tag_len != 8 && ( tag_len < 12 || tag_len > 16 ) )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif

#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
           
            if( tag_len != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif

        default:
            (void) tag_len;
            return( PSA_ERROR_NOT_SUPPORTED );
    }
    return( PSA_SUCCESS );
}


static psa_status_t psa_aead_setup( psa_aead_operation_t *operation,
                                    int is_encrypt,
                                    mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;
    psa_key_usage_t key_usage = 0;

    status = psa_aead_check_algorithm( alg );
    if( status != PSA_SUCCESS )
        goto exit;

    if( operation->id != 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->nonce_set || operation->lengths_set ||
        operation->ad_started || operation->body_started )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( is_encrypt )
        key_usage = PSA_KEY_USAGE_ENCRYPT;
    else
        key_usage = PSA_KEY_USAGE_DECRYPT;

    status = psa_get_and_lock_key_slot_with_policy( key, &slot, key_usage,
                                                    alg );
    if( status != PSA_SUCCESS )
        goto exit;

    psa_key_attributes_t attributes = {
        .core = slot->attr
    };

    if( ( status = psa_validate_tag_length( alg ) ) != PSA_SUCCESS )
        goto exit;

    if( is_encrypt )
        status = psa_driver_wrapper_aead_encrypt_setup( operation,
                                                        &attributes,
                                                        slot->key.data,
                                                        slot->key.bytes,
                                                        alg );
    else
        status = psa_driver_wrapper_aead_decrypt_setup( operation,
                                                        &attributes,
                                                        slot->key.data,
                                                        slot->key.bytes,
                                                        alg );
    if( status != PSA_SUCCESS )
        goto exit;

    operation->key_type = psa_get_key_type( &attributes );

exit:
    unlock_status = psa_unlock_key_slot( slot );

    if( status == PSA_SUCCESS )
    {
        status = unlock_status;
        operation->alg = psa_aead_get_base_algorithm( alg );
        operation->is_encrypt = is_encrypt;
    }
    else
        psa_aead_abort( operation );

    return( status );
}


psa_status_t psa_aead_encrypt_setup( psa_aead_operation_t *operation,
                                     mbedtls_svc_key_id_t key,
                                     psa_algorithm_t alg )
{
    return( psa_aead_setup( operation, 1, key, alg ) );
}


psa_status_t psa_aead_decrypt_setup( psa_aead_operation_t *operation,
                                     mbedtls_svc_key_id_t key,
                                     psa_algorithm_t alg )
{
    return( psa_aead_setup( operation, 0, key, alg ) );
}


psa_status_t psa_aead_generate_nonce( psa_aead_operation_t *operation,
                                      uint8_t *nonce,
                                      size_t nonce_size,
                                      size_t *nonce_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t local_nonce[PSA_AEAD_NONCE_MAX_SIZE];
    size_t required_nonce_size;

    *nonce_length = 0;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->nonce_set || !operation->is_encrypt )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

   
    required_nonce_size = PSA_AEAD_NONCE_LENGTH( operation->key_type,
                                                 operation->alg );
    if( nonce_size < required_nonce_size )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = psa_generate_random( local_nonce, required_nonce_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_aead_set_nonce( operation, local_nonce, required_nonce_size );

exit:
    if( status == PSA_SUCCESS )
    {
        memcpy( nonce, local_nonce, required_nonce_size );
        *nonce_length = required_nonce_size;
    }
    else
        psa_aead_abort( operation );

    return( status );
}


psa_status_t psa_aead_set_nonce( psa_aead_operation_t *operation,
                                 const uint8_t *nonce,
                                 size_t nonce_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->nonce_set )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_aead_check_nonce_length( operation->alg, nonce_length );
    if( status != PSA_SUCCESS )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_aead_set_nonce( operation, nonce,
                                                nonce_length );

exit:
    if( status == PSA_SUCCESS )
        operation->nonce_set = 1;
    else
        psa_aead_abort( operation );

    return( status );
}


psa_status_t psa_aead_set_lengths( psa_aead_operation_t *operation,
                                   size_t ad_length,
                                   size_t plaintext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->lengths_set || operation->ad_started ||
        operation->body_started )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    switch(operation->alg)
    {
#if defined(PSA_WANT_ALG_GCM)
        case PSA_ALG_GCM:
           
#if SIZE_MAX > UINT32_MAX
            if( (( uint64_t ) ad_length ) >> 61 != 0 ||
                (( uint64_t ) plaintext_length ) > 0xFFFFFFFE0ull )
            {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
#endif
            break;
#endif
#if defined(PSA_WANT_ALG_CCM)
        case PSA_ALG_CCM:
            if( ad_length > 0xFF00 )
            {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
            break;
#endif
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
        case PSA_ALG_CHACHA20_POLY1305:
           
            break;
#endif
        default:
            break;
    }

    status = psa_driver_wrapper_aead_set_lengths( operation, ad_length,
                                                  plaintext_length );

exit:
    if( status == PSA_SUCCESS )
    {
        operation->ad_remaining = ad_length;
        operation->body_remaining = plaintext_length;
        operation->lengths_set = 1;
    }
    else
        psa_aead_abort( operation );

    return( status );
}


psa_status_t psa_aead_update_ad( psa_aead_operation_t *operation,
                                 const uint8_t *input,
                                 size_t input_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( !operation->nonce_set || operation->body_started )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->lengths_set )
    {
        if( operation->ad_remaining < input_length )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        operation->ad_remaining -= input_length;
    }
#if defined(PSA_WANT_ALG_CCM)
    else if( operation->alg == PSA_ALG_CCM )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }
#endif

    status = psa_driver_wrapper_aead_update_ad( operation, input,
                                                input_length );

exit:
    if( status == PSA_SUCCESS )
        operation->ad_started = 1;
    else
        psa_aead_abort( operation );

    return( status );
}


psa_status_t psa_aead_update( psa_aead_operation_t *operation,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *output,
                              size_t output_size,
                              size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *output_length = 0;

    if( operation->id == 0 )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( !operation->nonce_set )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if( operation->lengths_set )
    {
       
        if( operation->ad_remaining != 0 )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

       
        if( operation->body_remaining < input_length )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        operation->body_remaining -= input_length;
    }
#if defined(PSA_WANT_ALG_CCM)
    else if( operation->alg == PSA_ALG_CCM )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }
#endif

    status = psa_driver_wrapper_aead_update( operation, input, input_length,
                                             output, output_size,
                                             output_length );

exit:
    if( status == PSA_SUCCESS )
        operation->body_started = 1;
    else
        psa_aead_abort( operation );

    return( status );
}

static psa_status_t psa_aead_final_checks( const psa_aead_operation_t *operation )
{
    if( operation->id == 0 || !operation->nonce_set )
        return( PSA_ERROR_BAD_STATE );

    if( operation->lengths_set && ( operation->ad_remaining != 0 ||
                                   operation->body_remaining != 0 ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}


psa_status_t psa_aead_finish( psa_aead_operation_t *operation,
                              uint8_t *ciphertext,
                              size_t ciphertext_size,
                              size_t *ciphertext_length,
                              uint8_t *tag,
                              size_t tag_size,
                              size_t *tag_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *ciphertext_length = 0;
    *tag_length = tag_size;

    status = psa_aead_final_checks( operation );
    if( status != PSA_SUCCESS )
        goto exit;

    if( !operation->is_encrypt )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_aead_finish( operation, ciphertext,
                                             ciphertext_size,
                                             ciphertext_length,
                                             tag, tag_size, tag_length );

exit:
   
    if( tag != NULL )
    {
        if( status != PSA_SUCCESS )
            memset( tag, '!', tag_size );
        else if( *tag_length < tag_size )
            memset( tag + *tag_length, '!', ( tag_size - *tag_length ) );
    }

    psa_aead_abort( operation );

    return( status );
}


psa_status_t psa_aead_verify( psa_aead_operation_t *operation,
                              uint8_t *plaintext,
                              size_t plaintext_size,
                              size_t *plaintext_length,
                              const uint8_t *tag,
                              size_t tag_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *plaintext_length = 0;

    status = psa_aead_final_checks( operation );
    if( status != PSA_SUCCESS )
        goto exit;

    if( operation->is_encrypt )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_aead_verify( operation, plaintext,
                                             plaintext_size,
                                             plaintext_length,
                                             tag, tag_length );

exit:
    psa_aead_abort( operation );

    return( status );
}


psa_status_t psa_aead_abort( psa_aead_operation_t *operation )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->id == 0 )
    {
       
        return( PSA_SUCCESS );
    }

    status = psa_driver_wrapper_aead_abort( operation );

    memset( operation, 0, sizeof( *operation ) );

    return( status );
}

/****************************************************************/

/****************************************************************/

#if defined(BUILTIN_ALG_ANY_HKDF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
#define AT_LEAST_ONE_BUILTIN_KDF
#endif

#if defined(BUILTIN_ALG_ANY_HKDF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
static psa_status_t psa_key_derivation_start_hmac(
    psa_mac_operation_t *operation,
    psa_algorithm_t hash_alg,
    const uint8_t *hmac_key,
    size_t hmac_key_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type( &attributes, PSA_KEY_TYPE_HMAC );
    psa_set_key_bits( &attributes, PSA_BYTES_TO_BITS( hmac_key_length ) );
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_SIGN_HASH );

    operation->is_sign = 1;
    operation->mac_size = PSA_HASH_LENGTH( hash_alg );

    status = psa_driver_wrapper_mac_sign_setup( operation,
                                                &attributes,
                                                hmac_key, hmac_key_length,
                                                PSA_ALG_HMAC( hash_alg ) );

    psa_reset_key_attributes( &attributes );
    return( status );
}
#endif

#define HKDF_STATE_INIT 0
#define HKDF_STATE_STARTED 1
#define HKDF_STATE_KEYED 2
#define HKDF_STATE_OUTPUT 3

static psa_algorithm_t psa_key_derivation_get_kdf_alg(
    const psa_key_derivation_operation_t *operation )
{
    if ( PSA_ALG_IS_KEY_AGREEMENT( operation->alg ) )
        return( PSA_ALG_KEY_AGREEMENT_GET_KDF( operation->alg ) );
    else
        return( operation->alg );
}

psa_status_t psa_key_derivation_abort( psa_key_derivation_operation_t *operation )
{
    psa_status_t status = PSA_SUCCESS;
    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg( operation );
    if( kdf_alg == 0 )
    {
       
    }
    else
#if defined(BUILTIN_ALG_ANY_HKDF)
    if( PSA_ALG_IS_ANY_HKDF( kdf_alg ) )
    {
        mbedtls_free( operation->ctx.hkdf.info );
        status = psa_mac_abort( &operation->ctx.hkdf.hmac );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    if( PSA_ALG_IS_TLS12_PRF( kdf_alg ) ||
            
             PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) )
    {
        if( operation->ctx.tls12_prf.secret != NULL )
        {
            mbedtls_platform_zeroize( operation->ctx.tls12_prf.secret,
                                      operation->ctx.tls12_prf.secret_length );
            mbedtls_free( operation->ctx.tls12_prf.secret );
        }

        if( operation->ctx.tls12_prf.seed != NULL )
        {
            mbedtls_platform_zeroize( operation->ctx.tls12_prf.seed,
                                      operation->ctx.tls12_prf.seed_length );
            mbedtls_free( operation->ctx.tls12_prf.seed );
        }

        if( operation->ctx.tls12_prf.label != NULL )
        {
            mbedtls_platform_zeroize( operation->ctx.tls12_prf.label,
                                      operation->ctx.tls12_prf.label_length );
            mbedtls_free( operation->ctx.tls12_prf.label );
        }

        if( operation->ctx.tls12_prf.other_secret != NULL )
        {
            mbedtls_platform_zeroize( operation->ctx.tls12_prf.other_secret,
                                      operation->ctx.tls12_prf.other_secret_length );
            mbedtls_free( operation->ctx.tls12_prf.other_secret );
        }

        status = PSA_SUCCESS;

       
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if( kdf_alg == PSA_ALG_TLS12_ECJPAKE_TO_PMS )
    {
        mbedtls_platform_zeroize( operation->ctx.tls12_ecjpake_to_pms.data,
            sizeof( operation->ctx.tls12_ecjpake_to_pms.data ) );
    }
    else
#endif
    {
        status = PSA_ERROR_BAD_STATE;
    }
    mbedtls_platform_zeroize( operation, sizeof( *operation ) );
    return( status );
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
                                        size_t *capacity)
{
    if( operation->alg == 0 )
    {
       
        return( PSA_ERROR_BAD_STATE );
    }

    *capacity = operation->capacity;
    return( PSA_SUCCESS );
}

psa_status_t psa_key_derivation_set_capacity( psa_key_derivation_operation_t *operation,
                                         size_t capacity )
{
    if( operation->alg == 0 )
        return( PSA_ERROR_BAD_STATE );
    if( capacity > operation->capacity )
        return( PSA_ERROR_INVALID_ARGUMENT );
    operation->capacity = capacity;
    return( PSA_SUCCESS );
}

#if defined(BUILTIN_ALG_ANY_HKDF)

static psa_status_t psa_key_derivation_hkdf_read( psa_hkdf_key_derivation_t *hkdf,
                                                  psa_algorithm_t kdf_alg,
                                                  uint8_t *output,
                                                  size_t output_length )
{
    psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( kdf_alg );
    uint8_t hash_length = PSA_HASH_LENGTH( hash_alg );
    size_t hmac_output_length;
    psa_status_t status;
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
    const uint8_t last_block = PSA_ALG_IS_HKDF_EXTRACT( kdf_alg ) ? 0 : 0xff;
#else
    const uint8_t last_block = 0xff;
#endif

    if( hkdf->state < HKDF_STATE_KEYED ||
        ( !hkdf->info_set
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
         && !PSA_ALG_IS_HKDF_EXTRACT( kdf_alg )
#endif
    ) )
        return( PSA_ERROR_BAD_STATE );
    hkdf->state = HKDF_STATE_OUTPUT;

    while( output_length != 0 )
    {
       
        uint8_t n = hash_length - hkdf->offset_in_block;
        if( n > output_length )
            n = (uint8_t) output_length;
        memcpy( output, hkdf->output_block + hkdf->offset_in_block, n );
        output += n;
        output_length -= n;
        hkdf->offset_in_block += n;
        if( output_length == 0 )
            break;
       
        if( hkdf->block_number == last_block )
            return( PSA_ERROR_BAD_STATE );

       
        ++hkdf->block_number;
        hkdf->offset_in_block = 0;

        status = psa_key_derivation_start_hmac( &hkdf->hmac,
                                                hash_alg,
                                                hkdf->prk,
                                                hash_length );
        if( status != PSA_SUCCESS )
            return( status );

        if( hkdf->block_number != 1 )
        {
            status = psa_mac_update( &hkdf->hmac,
                                     hkdf->output_block,
                                     hash_length );
            if( status != PSA_SUCCESS )
                return( status );
        }
        status = psa_mac_update( &hkdf->hmac,
                                 hkdf->info,
                                 hkdf->info_length );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_mac_update( &hkdf->hmac,
                                 &hkdf->block_number, 1 );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_mac_sign_finish( &hkdf->hmac,
                                      hkdf->output_block,
                                      sizeof( hkdf->output_block ),
                                      &hmac_output_length );
        if( status != PSA_SUCCESS )
            return( status );
    }

    return( PSA_SUCCESS );
}
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
static psa_status_t psa_key_derivation_tls12_prf_generate_next_block(
    psa_tls12_prf_key_derivation_t *tls12_prf,
    psa_algorithm_t alg )
{
    psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( alg );
    uint8_t hash_length = PSA_HASH_LENGTH( hash_alg );
    psa_mac_operation_t hmac = PSA_MAC_OPERATION_INIT;
    size_t hmac_output_length;
    psa_status_t status, cleanup_status;

   
    if( tls12_prf->block_number == 0xff )
        return( PSA_ERROR_CORRUPTION_DETECTED );

   
    ++tls12_prf->block_number;
    tls12_prf->left_in_block = hash_length;

   

    status = psa_key_derivation_start_hmac( &hmac,
                                            hash_alg,
                                            tls12_prf->secret,
                                            tls12_prf->secret_length );
    if( status != PSA_SUCCESS )
        goto cleanup;

   
    if( tls12_prf->block_number == 1 )
    {
       
        status = psa_mac_update( &hmac,
                                 tls12_prf->label,
                                 tls12_prf->label_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
        status = psa_mac_update( &hmac,
                                 tls12_prf->seed,
                                 tls12_prf->seed_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
    }
    else
    {
       
        status = psa_mac_update( &hmac, tls12_prf->Ai, hash_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
    }

    status = psa_mac_sign_finish( &hmac,
                                  tls12_prf->Ai, hash_length,
                                  &hmac_output_length );
    if( hmac_output_length != hash_length )
        status = PSA_ERROR_CORRUPTION_DETECTED;
    if( status != PSA_SUCCESS )
        goto cleanup;

   
    status = psa_key_derivation_start_hmac( &hmac,
                                            hash_alg,
                                            tls12_prf->secret,
                                            tls12_prf->secret_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_mac_update( &hmac, tls12_prf->Ai, hash_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_mac_update( &hmac, tls12_prf->label, tls12_prf->label_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_mac_update( &hmac, tls12_prf->seed, tls12_prf->seed_length );
    if( status != PSA_SUCCESS )
        goto cleanup;
    status = psa_mac_sign_finish( &hmac,
                                  tls12_prf->output_block, hash_length,
                                  &hmac_output_length );
    if( status != PSA_SUCCESS )
        goto cleanup;


cleanup:
    cleanup_status = psa_mac_abort( &hmac );
    if( status == PSA_SUCCESS && cleanup_status != PSA_SUCCESS )
        status = cleanup_status;

    return( status );
}

static psa_status_t psa_key_derivation_tls12_prf_read(
    psa_tls12_prf_key_derivation_t *tls12_prf,
    psa_algorithm_t alg,
    uint8_t *output,
    size_t output_length )
{
    psa_algorithm_t hash_alg = PSA_ALG_TLS12_PRF_GET_HASH( alg );
    uint8_t hash_length = PSA_HASH_LENGTH( hash_alg );
    psa_status_t status;
    uint8_t offset, length;

    switch( tls12_prf->state )
    {
        case PSA_TLS12_PRF_STATE_LABEL_SET:
            tls12_prf->state = PSA_TLS12_PRF_STATE_OUTPUT;
            break;
        case PSA_TLS12_PRF_STATE_OUTPUT:
            break;
        default:
            return( PSA_ERROR_BAD_STATE );
    }

    while( output_length != 0 )
    {
       
        if( tls12_prf->left_in_block == 0 )
        {
            status = psa_key_derivation_tls12_prf_generate_next_block( tls12_prf,
                                                                       alg );
            if( status != PSA_SUCCESS )
                return( status );

            continue;
        }

        if( tls12_prf->left_in_block > output_length )
            length = (uint8_t) output_length;
        else
            length = tls12_prf->left_in_block;

        offset = hash_length - tls12_prf->left_in_block;
        memcpy( output, tls12_prf->output_block + offset, length );
        output += length;
        output_length -= length;
        tls12_prf->left_in_block -= length;
    }

    return( PSA_SUCCESS );
}
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
static psa_status_t psa_key_derivation_tls12_ecjpake_to_pms_read(
    psa_tls12_ecjpake_to_pms_t *ecjpake,
    uint8_t *output,
    size_t output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t output_size = 0;

    if( output_length != 32 )
        return ( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_hash_compute( PSA_ALG_SHA_256, ecjpake->data,
        PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE, output, output_length,
        &output_size );
    if( status != PSA_SUCCESS )
        return ( status );

    if( output_size != output_length )
        return ( PSA_ERROR_GENERIC_ERROR );

    return ( PSA_SUCCESS );
}
#endif

psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t *operation,
    uint8_t *output,
    size_t output_length )
{
    psa_status_t status;
    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg( operation );

    if( operation->alg == 0 )
    {
       
        return( PSA_ERROR_BAD_STATE );
    }

    if( output_length > operation->capacity )
    {
        operation->capacity = 0;
       
        status = PSA_ERROR_INSUFFICIENT_DATA;
        goto exit;
    }
    if( output_length == 0 && operation->capacity == 0 )
    {
       
        return( PSA_ERROR_INSUFFICIENT_DATA );
    }
    operation->capacity -= output_length;

#if defined(BUILTIN_ALG_ANY_HKDF)
    if( PSA_ALG_IS_ANY_HKDF( kdf_alg ) )
    {
        status = psa_key_derivation_hkdf_read( &operation->ctx.hkdf, kdf_alg,
                                          output, output_length );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    if( PSA_ALG_IS_TLS12_PRF( kdf_alg ) ||
        PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) )
    {
        status = psa_key_derivation_tls12_prf_read( &operation->ctx.tls12_prf,
                                                    kdf_alg, output,
                                                    output_length );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if( kdf_alg == PSA_ALG_TLS12_ECJPAKE_TO_PMS )
    {
        status = psa_key_derivation_tls12_ecjpake_to_pms_read(
            &operation->ctx.tls12_ecjpake_to_pms, output, output_length );
    }
    else
#endif

    {
        (void) kdf_alg;
        return( PSA_ERROR_BAD_STATE );
    }

exit:
    if( status != PSA_SUCCESS )
    {
       
        psa_algorithm_t alg = operation->alg;
        psa_key_derivation_abort( operation );
        operation->alg = alg;
        memset( output, '!', output_length );
    }
    return( status );
}

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
static void psa_des_set_key_parity( uint8_t *data, size_t data_size )
{
    if( data_size >= 8 )
        mbedtls_des_key_set_parity( data );
    if( data_size >= 16 )
        mbedtls_des_key_set_parity( data + 8 );
    if( data_size >= 24 )
        mbedtls_des_key_set_parity( data + 16 );
}
#endif


#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECDH)
static psa_status_t psa_generate_derived_ecc_key_weierstrass_helper(
    psa_key_slot_t *slot,
    size_t bits,
    psa_key_derivation_operation_t *operation,
    uint8_t **data
    )
{
    unsigned key_out_of_range = 1;
    mbedtls_mpi k;
    mbedtls_mpi diff_N_2;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    mbedtls_mpi_init( &k );
    mbedtls_mpi_init( &diff_N_2 );

    psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY(
                                slot->attr.type );
    mbedtls_ecp_group_id grp_id =
        mbedtls_ecc_group_of_psa( curve, bits, 0 );

    if( grp_id == MBEDTLS_ECP_DP_NONE )
    {
        ret = MBEDTLS_ERR_ASN1_INVALID_DATA;
        goto cleanup;
    }

    mbedtls_ecp_group ecp_group;
    mbedtls_ecp_group_init( &ecp_group );

    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ecp_group, grp_id ) );

   
   
    size_t m = ecp_group.nbits;

    size_t m_bytes = PSA_BITS_TO_BYTES( m );

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &diff_N_2, &ecp_group.N, 2 ) );

   
    *data = mbedtls_calloc( 1, m_bytes );
    if( *data == NULL )
    {
        ret = MBEDTLS_ERR_ASN1_ALLOC_FAILED;
        goto cleanup;
    }

    while( key_out_of_range )
    {
       
        if( ( status = psa_key_derivation_output_bytes( operation, *data, m_bytes ) ) != 0 )
            goto cleanup;

       
        if( m % 8 != 0 )
        {
           
            uint8_t clear_bit_mask = ( 1 << ( m % 8 ) ) - 1;
            (*data)[0] &= clear_bit_mask;
        }

       
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &k, *data, m_bytes ) );

       
        MBEDTLS_MPI_CHK( mbedtls_mpi_lt_mpi_ct( &diff_N_2, &k, &key_out_of_range ) );
    }

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &k, &k, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &k, *data, m_bytes ) );
cleanup:
    if( ret != 0 )
        status = mbedtls_to_psa_error( ret );
    if( status != PSA_SUCCESS  ) {
        mbedtls_free( *data );
        *data = NULL;
    }
    mbedtls_mpi_free( &k );
    mbedtls_mpi_free( &diff_N_2 );
    return( status );
}



static psa_status_t psa_generate_derived_ecc_key_montgomery_helper(
    size_t bits,
    psa_key_derivation_operation_t *operation,
    uint8_t **data
    )
{
    size_t output_length;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    switch( bits )
    {
        case 255:
            output_length = 32;
            break;
        case 448:
            output_length = 56;
            break;
        default:
            return( PSA_ERROR_INVALID_ARGUMENT );
            break;
    }

    *data = mbedtls_calloc( 1, output_length );

    if( *data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    status = psa_key_derivation_output_bytes( operation, *data, output_length );

    if( status != PSA_SUCCESS )
        return status;

    switch( bits )
    {
        case 255:
            (*data)[0] &= 248;
            (*data)[31] &= 127;
            (*data)[31] |= 64;
            break;
        case 448:
            (*data)[0] &= 252;
            (*data)[55] |= 128;
            break;
        default:
            return( PSA_ERROR_CORRUPTION_DETECTED );
            break;
    }

    return status;
}
#endif

static psa_status_t psa_generate_derived_key_internal(
    psa_key_slot_t *slot,
    size_t bits,
    psa_key_derivation_operation_t *operation )
{
    uint8_t *data = NULL;
    size_t bytes = PSA_BITS_TO_BYTES( bits );
    size_t storage_size = bytes;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->attr.type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_ECDH)
    if( PSA_KEY_TYPE_IS_ECC( slot->attr.type ) )
    {
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY( slot->attr.type );
        if( PSA_ECC_FAMILY_IS_WEIERSTRASS( curve ) )
        {
           
            status = psa_generate_derived_ecc_key_weierstrass_helper( slot, bits, operation, &data );
            if( status != PSA_SUCCESS )
                goto exit;
        }
        else
        {
           
            status = psa_generate_derived_ecc_key_montgomery_helper( bits, operation, &data );
            if( status != PSA_SUCCESS )
                goto exit;
        }
    } else
#endif
    if( key_type_is_raw_bytes( slot->attr.type ) )
    {
        if( bits % 8 != 0 )
            return( PSA_ERROR_INVALID_ARGUMENT );
        data = mbedtls_calloc( 1, bytes );
        if( data == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        status = psa_key_derivation_output_bytes( operation, data, bytes );
        if( status != PSA_SUCCESS )
            goto exit;
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
        if( slot->attr.type == PSA_KEY_TYPE_DES )
            psa_des_set_key_parity( data, bytes );
#endif
    }
    else
        return( PSA_ERROR_NOT_SUPPORTED );

    slot->attr.bits = (psa_key_bits_t) bits;
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    if( psa_key_lifetime_is_external( attributes.core.lifetime ) )
    {
        status = psa_driver_wrapper_get_key_buffer_size( &attributes,
                                                         &storage_size );
        if( status != PSA_SUCCESS )
            goto exit;
    }
    status = psa_allocate_buffer_to_slot( slot, storage_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_driver_wrapper_import_key( &attributes,
                                            data, bytes,
                                            slot->key.data,
                                            slot->key.bytes,
                                            &slot->key.bytes, &bits );
    if( bits != slot->attr.bits )
        status = PSA_ERROR_INVALID_ARGUMENT;

exit:
    mbedtls_free( data );
    return( status );
}

psa_status_t psa_key_derivation_output_key( const psa_key_attributes_t *attributes,
                                       psa_key_derivation_operation_t *operation,
                                       mbedtls_svc_key_id_t *key )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;

    *key = MBEDTLS_SVC_KEY_ID_INIT;

   
    if( psa_get_key_bits( attributes ) == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( operation->alg == PSA_ALG_NONE )
        return( PSA_ERROR_BAD_STATE );

    if( ! operation->can_output_key )
        return( PSA_ERROR_NOT_PERMITTED );

    status = psa_start_key_creation( PSA_KEY_CREATION_DERIVE, attributes,
                                     &slot, &driver );
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    if( driver != NULL )
    {
       
        status = PSA_ERROR_NOT_SUPPORTED;
    }
#endif
    if( status == PSA_SUCCESS )
    {
        status = psa_generate_derived_key_internal( slot,
                                                    attributes->core.bits,
                                                    operation );
    }
    if( status == PSA_SUCCESS )
        status = psa_finish_key_creation( slot, driver, key );
    if( status != PSA_SUCCESS )
        psa_fail_key_creation( slot, driver );

    return( status );
}



/****************************************************************/

/****************************************************************/

#if defined(AT_LEAST_ONE_BUILTIN_KDF)
static int is_kdf_alg_supported( psa_algorithm_t kdf_alg )
{
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF)
    if( PSA_ALG_IS_HKDF( kdf_alg ) )
        return( 1 );
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
    if( PSA_ALG_IS_HKDF_EXTRACT( kdf_alg ) )
        return( 1 );
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
    if( PSA_ALG_IS_HKDF_EXPAND( kdf_alg ) )
        return( 1 );
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF)
    if( PSA_ALG_IS_TLS12_PRF( kdf_alg ) )
        return( 1 );
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    if( PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) )
        return( 1 );
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if( kdf_alg == PSA_ALG_TLS12_ECJPAKE_TO_PMS )
        return( 1 );
#endif
    return( 0 );
}

static psa_status_t psa_hash_try_support( psa_algorithm_t alg )
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status = psa_hash_setup( &operation, alg );
    psa_hash_abort( &operation );
    return( status );
}

static psa_status_t psa_key_derivation_setup_kdf(
    psa_key_derivation_operation_t *operation,
    psa_algorithm_t kdf_alg )
{
   
    memset( &operation->ctx, 0, sizeof( operation->ctx ) );

   
    if( ! is_kdf_alg_supported( kdf_alg ) )
        return( PSA_ERROR_NOT_SUPPORTED );

   
    psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( kdf_alg );
    size_t hash_size = PSA_HASH_LENGTH( hash_alg );
    if( kdf_alg != PSA_ALG_TLS12_ECJPAKE_TO_PMS )
    {
        if( hash_size == 0 )
            return( PSA_ERROR_NOT_SUPPORTED );

       
        psa_status_t status = psa_hash_try_support( hash_alg );
        if( status != PSA_SUCCESS )
            return( status );
    }
    else
    {
        hash_size = PSA_HASH_LENGTH( PSA_ALG_SHA_256 );
    }

    if( ( PSA_ALG_IS_TLS12_PRF( kdf_alg ) ||
          PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) ) &&
        ! ( hash_alg == PSA_ALG_SHA_256 || hash_alg == PSA_ALG_SHA_384 ) )
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if( PSA_ALG_IS_HKDF_EXTRACT( kdf_alg ) ||
        ( kdf_alg == PSA_ALG_TLS12_ECJPAKE_TO_PMS ) )
        operation->capacity = hash_size;
    else
#endif
        operation->capacity = 255 * hash_size;
    return( PSA_SUCCESS );
}

static psa_status_t psa_key_agreement_try_support( psa_algorithm_t alg )
{
#if defined(PSA_WANT_ALG_ECDH)
    if( alg == PSA_ALG_ECDH )
        return( PSA_SUCCESS );
#endif
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}
#endif

psa_status_t psa_key_derivation_setup( psa_key_derivation_operation_t *operation,
                                       psa_algorithm_t alg )
{
    psa_status_t status;

    if( operation->alg != 0 )
        return( PSA_ERROR_BAD_STATE );

    if( PSA_ALG_IS_RAW_KEY_AGREEMENT( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    else if( PSA_ALG_IS_KEY_AGREEMENT( alg ) )
    {
#if defined(AT_LEAST_ONE_BUILTIN_KDF)
        psa_algorithm_t kdf_alg = PSA_ALG_KEY_AGREEMENT_GET_KDF( alg );
        psa_algorithm_t ka_alg = PSA_ALG_KEY_AGREEMENT_GET_BASE( alg );
        status = psa_key_agreement_try_support( ka_alg );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_key_derivation_setup_kdf( operation, kdf_alg );
#else
        return( PSA_ERROR_NOT_SUPPORTED );
#endif
    }
    else if( PSA_ALG_IS_KEY_DERIVATION( alg ) )
    {
#if defined(AT_LEAST_ONE_BUILTIN_KDF)
        status = psa_key_derivation_setup_kdf( operation, alg );
#else
        return( PSA_ERROR_NOT_SUPPORTED );
#endif
    }
    else
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( status == PSA_SUCCESS )
        operation->alg = alg;
    return( status );
}

#if defined(BUILTIN_ALG_ANY_HKDF)
static psa_status_t psa_hkdf_input( psa_hkdf_key_derivation_t *hkdf,
                                    psa_algorithm_t kdf_alg,
                                    psa_key_derivation_step_t step,
                                    const uint8_t *data,
                                    size_t data_length )
{
    psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( kdf_alg );
    psa_status_t status;
    switch( step )
    {
        case PSA_KEY_DERIVATION_INPUT_SALT:
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
            if( PSA_ALG_IS_HKDF_EXPAND( kdf_alg ) )
                return( PSA_ERROR_INVALID_ARGUMENT );
#endif
            if( hkdf->state != HKDF_STATE_INIT )
                return( PSA_ERROR_BAD_STATE );
            else
            {
                status = psa_key_derivation_start_hmac( &hkdf->hmac,
                                                        hash_alg,
                                                        data, data_length );
                if( status != PSA_SUCCESS )
                    return( status );
                hkdf->state = HKDF_STATE_STARTED;
                return( PSA_SUCCESS );
            }
        case PSA_KEY_DERIVATION_INPUT_SECRET:
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
            if( PSA_ALG_IS_HKDF_EXPAND( kdf_alg ) )
            {
               
                if( hkdf->state != HKDF_STATE_INIT )
                    return( PSA_ERROR_BAD_STATE );

               
                if( data_length != PSA_HASH_LENGTH( hash_alg ) )
                    return( PSA_ERROR_INVALID_ARGUMENT );

                memcpy( hkdf->prk, data, data_length );
            }
            else
#endif
            {
               
                if( hkdf->state == HKDF_STATE_INIT )
                {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
                    if( PSA_ALG_IS_HKDF_EXTRACT( kdf_alg ) )
                        return( PSA_ERROR_BAD_STATE );
#endif
                    status = psa_key_derivation_start_hmac( &hkdf->hmac,
                                                            hash_alg,
                                                            NULL, 0 );
                    if( status != PSA_SUCCESS )
                        return( status );
                    hkdf->state = HKDF_STATE_STARTED;
                }
                if( hkdf->state != HKDF_STATE_STARTED )
                    return( PSA_ERROR_BAD_STATE );
                status = psa_mac_update( &hkdf->hmac,
                                        data, data_length );
                if( status != PSA_SUCCESS )
                    return( status );
                status = psa_mac_sign_finish( &hkdf->hmac,
                                            hkdf->prk,
                                            sizeof( hkdf->prk ),
                                            &data_length );
                if( status != PSA_SUCCESS )
                    return( status );
            }

            hkdf->state = HKDF_STATE_KEYED;
            hkdf->block_number = 0;
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
            if( PSA_ALG_IS_HKDF_EXTRACT( kdf_alg ) )
            {
               
                memcpy( hkdf->output_block, hkdf->prk, PSA_HASH_LENGTH( hash_alg ) );
                hkdf->offset_in_block = 0;
            }
            else
#endif
            {
               
                hkdf->offset_in_block = PSA_HASH_LENGTH( hash_alg );
            }

            return( PSA_SUCCESS );
        case PSA_KEY_DERIVATION_INPUT_INFO:
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT)
            if( PSA_ALG_IS_HKDF_EXTRACT( kdf_alg ) )
                return( PSA_ERROR_INVALID_ARGUMENT );
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
            if( PSA_ALG_IS_HKDF_EXPAND( kdf_alg ) &&
                hkdf->state == HKDF_STATE_INIT )
                return( PSA_ERROR_BAD_STATE );
#endif
            if( hkdf->state == HKDF_STATE_OUTPUT )
                return( PSA_ERROR_BAD_STATE );
            if( hkdf->info_set )
                return( PSA_ERROR_BAD_STATE );
            hkdf->info_length = data_length;
            if( data_length != 0 )
            {
                hkdf->info = mbedtls_calloc( 1, data_length );
                if( hkdf->info == NULL )
                    return( PSA_ERROR_INSUFFICIENT_MEMORY );
                memcpy( hkdf->info, data, data_length );
            }
            hkdf->info_set = 1;
            return( PSA_SUCCESS );
        default:
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
}
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
static psa_status_t psa_tls12_prf_set_seed( psa_tls12_prf_key_derivation_t *prf,
                                            const uint8_t *data,
                                            size_t data_length )
{
    if( prf->state != PSA_TLS12_PRF_STATE_INIT )
        return( PSA_ERROR_BAD_STATE );

    if( data_length != 0 )
    {
        prf->seed = mbedtls_calloc( 1, data_length );
        if( prf->seed == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        memcpy( prf->seed, data, data_length );
        prf->seed_length = data_length;
    }

    prf->state = PSA_TLS12_PRF_STATE_SEED_SET;

    return( PSA_SUCCESS );
}

static psa_status_t psa_tls12_prf_set_key( psa_tls12_prf_key_derivation_t *prf,
                                           const uint8_t *data,
                                           size_t data_length )
{
    if( prf->state != PSA_TLS12_PRF_STATE_SEED_SET &&
        prf->state != PSA_TLS12_PRF_STATE_OTHER_KEY_SET )
        return( PSA_ERROR_BAD_STATE );

    if( data_length != 0 )
    {
        prf->secret = mbedtls_calloc( 1, data_length );
        if( prf->secret == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        memcpy( prf->secret, data, data_length );
        prf->secret_length = data_length;
    }

    prf->state = PSA_TLS12_PRF_STATE_KEY_SET;

    return( PSA_SUCCESS );
}

static psa_status_t psa_tls12_prf_set_label( psa_tls12_prf_key_derivation_t *prf,
                                             const uint8_t *data,
                                             size_t data_length )
{
    if( prf->state != PSA_TLS12_PRF_STATE_KEY_SET )
        return( PSA_ERROR_BAD_STATE );

    if( data_length != 0 )
    {
        prf->label = mbedtls_calloc( 1, data_length );
        if( prf->label == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        memcpy( prf->label, data, data_length );
        prf->label_length = data_length;
    }

    prf->state = PSA_TLS12_PRF_STATE_LABEL_SET;

    return( PSA_SUCCESS );
}

static psa_status_t psa_tls12_prf_input( psa_tls12_prf_key_derivation_t *prf,
                                         psa_key_derivation_step_t step,
                                         const uint8_t *data,
                                         size_t data_length )
{
    switch( step )
    {
        case PSA_KEY_DERIVATION_INPUT_SEED:
            return( psa_tls12_prf_set_seed( prf, data, data_length ) );
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            return( psa_tls12_prf_set_key( prf, data, data_length ) );
        case PSA_KEY_DERIVATION_INPUT_LABEL:
            return( psa_tls12_prf_set_label( prf, data, data_length ) );
        default:
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
}
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
static psa_status_t psa_tls12_prf_psk_to_ms_set_key(
    psa_tls12_prf_key_derivation_t *prf,
    const uint8_t *data,
    size_t data_length )
{
    psa_status_t status;
    const size_t pms_len = ( prf->state == PSA_TLS12_PRF_STATE_OTHER_KEY_SET ?
        4 + data_length + prf->other_secret_length :
        4 + 2 * data_length );

    if( data_length > PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE )
        return( PSA_ERROR_INVALID_ARGUMENT );

    uint8_t *pms = mbedtls_calloc( 1, pms_len );
    if( pms == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    uint8_t *cur = pms;

   

    if( prf->state == PSA_TLS12_PRF_STATE_OTHER_KEY_SET )
    {
        *cur++ = MBEDTLS_BYTE_1( prf->other_secret_length );
        *cur++ = MBEDTLS_BYTE_0( prf->other_secret_length );
        if( prf->other_secret_length != 0 )
        {
            memcpy( cur, prf->other_secret, prf->other_secret_length );
            mbedtls_platform_zeroize( prf->other_secret, prf->other_secret_length );
            cur += prf->other_secret_length;
        }
    }
    else
    {
        *cur++ = MBEDTLS_BYTE_1( data_length );
        *cur++ = MBEDTLS_BYTE_0( data_length );
        memset( cur, 0, data_length );
        cur += data_length;
    }

    *cur++ = MBEDTLS_BYTE_1( data_length );
    *cur++ = MBEDTLS_BYTE_0( data_length );
    memcpy( cur, data, data_length );
    cur += data_length;

    status = psa_tls12_prf_set_key( prf, pms, cur - pms );

    mbedtls_platform_zeroize( pms, pms_len );
    mbedtls_free( pms );
    return( status );
}

static psa_status_t psa_tls12_prf_psk_to_ms_set_other_key(
    psa_tls12_prf_key_derivation_t *prf,
    const uint8_t *data,
    size_t data_length )
{
    if( prf->state != PSA_TLS12_PRF_STATE_SEED_SET )
        return( PSA_ERROR_BAD_STATE );

    if( data_length != 0 )
    {
        prf->other_secret = mbedtls_calloc( 1, data_length );
        if( prf->other_secret == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        memcpy( prf->other_secret, data, data_length );
        prf->other_secret_length = data_length;
    }
    else
    {
        prf->other_secret_length = 0;
    }

    prf->state = PSA_TLS12_PRF_STATE_OTHER_KEY_SET;

    return( PSA_SUCCESS );
}

static psa_status_t psa_tls12_prf_psk_to_ms_input(
    psa_tls12_prf_key_derivation_t *prf,
    psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length )
{
    switch( step )
    {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            return( psa_tls12_prf_psk_to_ms_set_key( prf,
                                                     data, data_length ) );
            break;
        case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            return( psa_tls12_prf_psk_to_ms_set_other_key( prf,
                                                           data,
                                                           data_length ) );
            break;
        default:
            return( psa_tls12_prf_input( prf, step, data, data_length ) );
            break;

    }
}
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
static psa_status_t psa_tls12_ecjpake_to_pms_input(
    psa_tls12_ecjpake_to_pms_t *ecjpake,
    psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length )
{
    if( data_length != PSA_TLS12_ECJPAKE_TO_PMS_INPUT_SIZE ||
        step != PSA_KEY_DERIVATION_INPUT_SECRET )
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

   
    if( data[0] != 0x04 )
        return( PSA_ERROR_INVALID_ARGUMENT );

   
    memcpy( ecjpake->data, data + 1, PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE );

    return( PSA_SUCCESS );
}
#endif
/** Check whether the given key type is acceptable for the given
 * input step of a key derivation.
 *
 * Secret inputs must have the type #PSA_KEY_TYPE_DERIVE.
 * Non-secret inputs must have the type #PSA_KEY_TYPE_RAW_DATA.
 * Both secret and non-secret inputs can alternatively have the type
 * #PSA_KEY_TYPE_NONE, which is never the type of a key object, meaning
 * that the input was passed as a buffer rather than via a key object.
 */
static int psa_key_derivation_check_input_type(
    psa_key_derivation_step_t step,
    psa_key_type_t key_type )
{
    switch( step )
    {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            if( key_type == PSA_KEY_TYPE_DERIVE )
                return( PSA_SUCCESS );
            if( key_type == PSA_KEY_TYPE_NONE )
                return( PSA_SUCCESS );
            break;
        case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            if( key_type == PSA_KEY_TYPE_DERIVE )
                return( PSA_SUCCESS );
            if( key_type == PSA_KEY_TYPE_NONE )
                return( PSA_SUCCESS );
            break;
        case PSA_KEY_DERIVATION_INPUT_LABEL:
        case PSA_KEY_DERIVATION_INPUT_SALT:
        case PSA_KEY_DERIVATION_INPUT_INFO:
        case PSA_KEY_DERIVATION_INPUT_SEED:
            if( key_type == PSA_KEY_TYPE_RAW_DATA )
                return( PSA_SUCCESS );
            if( key_type == PSA_KEY_TYPE_NONE )
                return( PSA_SUCCESS );
            break;
    }
    return( PSA_ERROR_INVALID_ARGUMENT );
}

static psa_status_t psa_key_derivation_input_internal(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_type_t key_type,
    const uint8_t *data,
    size_t data_length )
{
    psa_status_t status;
    psa_algorithm_t kdf_alg = psa_key_derivation_get_kdf_alg( operation );

    status = psa_key_derivation_check_input_type( step, key_type );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(BUILTIN_ALG_ANY_HKDF)
    if( PSA_ALG_IS_ANY_HKDF( kdf_alg ) )
    {
        status = psa_hkdf_input( &operation->ctx.hkdf, kdf_alg,
                                 step, data, data_length );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF)
    if( PSA_ALG_IS_TLS12_PRF( kdf_alg ) )
    {
        status = psa_tls12_prf_input( &operation->ctx.tls12_prf,
                                      step, data, data_length );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    if( PSA_ALG_IS_TLS12_PSK_TO_MS( kdf_alg ) )
    {
        status = psa_tls12_prf_psk_to_ms_input( &operation->ctx.tls12_prf,
                                                step, data, data_length );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    if( kdf_alg == PSA_ALG_TLS12_ECJPAKE_TO_PMS )
    {
        status = psa_tls12_ecjpake_to_pms_input(
            &operation->ctx.tls12_ecjpake_to_pms, step, data, data_length );
    }
    else
#endif
    {
       
        (void) data;
        (void) data_length;
        (void) kdf_alg;
        return( PSA_ERROR_BAD_STATE );
    }

exit:
    if( status != PSA_SUCCESS )
        psa_key_derivation_abort( operation );
    return( status );
}

psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length )
{
    return( psa_key_derivation_input_internal( operation, step,
                                               PSA_KEY_TYPE_NONE,
                                               data, data_length ) );
}

psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    mbedtls_svc_key_id_t key )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    status = psa_get_and_lock_transparent_key_slot_with_policy(
                 key, &slot, PSA_KEY_USAGE_DERIVE, operation->alg );
    if( status != PSA_SUCCESS )
    {
        psa_key_derivation_abort( operation );
        return( status );
    }

   
    if( step == PSA_KEY_DERIVATION_INPUT_SECRET )
        operation->can_output_key = 1;

    status = psa_key_derivation_input_internal( operation,
                                                step, slot->attr.type,
                                                slot->key.data,
                                                slot->key.bytes );

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}



/****************************************************************/

/****************************************************************/

psa_status_t psa_key_agreement_raw_builtin( const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t *peer_key,
                                            size_t peer_key_length,
                                            uint8_t *shared_secret,
                                            size_t shared_secret_size,
                                            size_t *shared_secret_length )
{
    switch( alg )
    {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_ECDH)
        case PSA_ALG_ECDH:
            return( mbedtls_psa_key_agreement_ecdh( attributes, key_buffer,
                                                    key_buffer_size, alg,
                                                    peer_key, peer_key_length,
                                                    shared_secret,
                                                    shared_secret_size,
                                                    shared_secret_length ) );
#endif
        default:
            (void) attributes;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) peer_key;
            (void) peer_key_length;
            (void) shared_secret;
            (void) shared_secret_size;
            (void) shared_secret_length;
            return( PSA_ERROR_NOT_SUPPORTED );
    }
}

/** Internal function for raw key agreement
 *  Calls the driver wrapper which will hand off key agreement task
 *  to the driver's implementation if a driver is present.
 *  Fallback specified in the driver wrapper is built-in raw key agreement
 *  (psa_key_agreement_raw_builtin).
 */
static psa_status_t psa_key_agreement_raw_internal( psa_algorithm_t alg,
                                                    psa_key_slot_t *private_key,
                                                    const uint8_t *peer_key,
                                                    size_t peer_key_length,
                                                    uint8_t *shared_secret,
                                                    size_t shared_secret_size,
                                                    size_t *shared_secret_length )
{
    if( !PSA_ALG_IS_RAW_KEY_AGREEMENT( alg ) )
        return( PSA_ERROR_NOT_SUPPORTED );

    psa_key_attributes_t attributes = {
      .core = private_key->attr
    };

    return( psa_driver_wrapper_key_agreement( &attributes,
                                              private_key->key.data,
                                              private_key->key.bytes, alg,
                                              peer_key, peer_key_length,
                                              shared_secret,
                                              shared_secret_size,
                                              shared_secret_length ) );
}


static psa_status_t psa_key_agreement_internal( psa_key_derivation_operation_t *operation,
                                                psa_key_derivation_step_t step,
                                                psa_key_slot_t *private_key,
                                                const uint8_t *peer_key,
                                                size_t peer_key_length )
{
    psa_status_t status;
    uint8_t shared_secret[PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE];
    size_t shared_secret_length = 0;
    psa_algorithm_t ka_alg = PSA_ALG_KEY_AGREEMENT_GET_BASE( operation->alg );

   
    status = psa_key_agreement_raw_internal( ka_alg,
                                             private_key,
                                             peer_key, peer_key_length,
                                             shared_secret,
                                             sizeof( shared_secret ),
                                             &shared_secret_length );
    if( status != PSA_SUCCESS )
        goto exit;

   
    status = psa_key_derivation_input_internal( operation, step,
                                                PSA_KEY_TYPE_DERIVE,
                                                shared_secret,
                                                shared_secret_length );
exit:
    mbedtls_platform_zeroize( shared_secret, shared_secret_length );
    return( status );
}

psa_status_t psa_key_derivation_key_agreement( psa_key_derivation_operation_t *operation,
                                               psa_key_derivation_step_t step,
                                               mbedtls_svc_key_id_t private_key,
                                               const uint8_t *peer_key,
                                               size_t peer_key_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    if( ! PSA_ALG_IS_KEY_AGREEMENT( operation->alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    status = psa_get_and_lock_transparent_key_slot_with_policy(
                 private_key, &slot, PSA_KEY_USAGE_DERIVE, operation->alg );
    if( status != PSA_SUCCESS )
        return( status );
    status = psa_key_agreement_internal( operation, step,
                                         slot,
                                         peer_key, peer_key_length );
    if( status != PSA_SUCCESS )
        psa_key_derivation_abort( operation );
    else
    {
       
        if( step == PSA_KEY_DERIVATION_INPUT_SECRET )
            operation->can_output_key = 1;
    }

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}

psa_status_t psa_raw_key_agreement( psa_algorithm_t alg,
                                    mbedtls_svc_key_id_t private_key,
                                    const uint8_t *peer_key,
                                    size_t peer_key_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    if( ! PSA_ALG_IS_KEY_AGREEMENT( alg ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    status = psa_get_and_lock_transparent_key_slot_with_policy(
                 private_key, &slot, PSA_KEY_USAGE_DERIVE, alg );
    if( status != PSA_SUCCESS )
        goto exit;

   
    size_t expected_length =
        PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE( slot->attr.type, slot->attr.bits );
    if( output_size < expected_length )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = psa_key_agreement_raw_internal( alg, slot,
                                             peer_key, peer_key_length,
                                             output, output_size,
                                             output_length );

exit:
    if( status != PSA_SUCCESS )
    {
       
        psa_generate_random( output, output_size );
        *output_length = output_size;
    }

    unlock_status = psa_unlock_key_slot( slot );

    return( ( status == PSA_SUCCESS ) ? unlock_status : status );
}



/****************************************************************/

/****************************************************************/

/** Initialize the PSA random generator.
 */
static void mbedtls_psa_random_init( mbedtls_psa_random_context_t *rng )
{
#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    memset( rng, 0, sizeof( *rng ) );
#else

   
    if( rng->entropy_init == NULL )
        rng->entropy_init = mbedtls_entropy_init;
    if( rng->entropy_free == NULL )
        rng->entropy_free = mbedtls_entropy_free;

    rng->entropy_init( &rng->entropy );
#if defined(MBEDTLS_PSA_INJECT_ENTROPY) && \
    defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
   
    mbedtls_entropy_add_source( &rng->entropy,
                                mbedtls_nv_seed_poll, NULL,
                                MBEDTLS_ENTROPY_BLOCK_SIZE,
                                MBEDTLS_ENTROPY_SOURCE_STRONG );
#endif

    mbedtls_psa_drbg_init( MBEDTLS_PSA_RANDOM_STATE );
#endif
}

/** Deinitialize the PSA random generator.
 */
static void mbedtls_psa_random_free( mbedtls_psa_random_context_t *rng )
{
#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    memset( rng, 0, sizeof( *rng ) );
#else
    mbedtls_psa_drbg_free( MBEDTLS_PSA_RANDOM_STATE );
    rng->entropy_free( &rng->entropy );
#endif
}

/** Seed the PSA random generator.
 */
static psa_status_t mbedtls_psa_random_seed( mbedtls_psa_random_context_t *rng )
{
#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
   
    (void) rng;
    return( PSA_SUCCESS );
#else
    const unsigned char drbg_seed[] = "PSA";
    int ret = mbedtls_psa_drbg_seed( &rng->entropy,
                                     drbg_seed, sizeof( drbg_seed ) - 1 );
    return mbedtls_to_psa_error( ret );
#endif
}

psa_status_t psa_generate_random( uint8_t *output,
                                  size_t output_size )
{
    GUARD_MODULE_INITIALIZED;

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

    size_t output_length = 0;
    psa_status_t status = mbedtls_psa_external_get_random( &global_data.rng,
                                                           output, output_size,
                                                           &output_length );
    if( status != PSA_SUCCESS )
        return( status );
   
    if( output_length != output_size )
        return( PSA_ERROR_INSUFFICIENT_ENTROPY );
    return( PSA_SUCCESS );

#else

    while( output_size > 0 )
    {
        size_t request_size =
            ( output_size > MBEDTLS_PSA_RANDOM_MAX_REQUEST ?
              MBEDTLS_PSA_RANDOM_MAX_REQUEST :
              output_size );
        int ret = mbedtls_psa_get_random( MBEDTLS_PSA_RANDOM_STATE,
                                          output, request_size );
        if( ret != 0 )
            return( mbedtls_to_psa_error( ret ) );
        output_size -= request_size;
        output += request_size;
    }
    return( PSA_SUCCESS );
#endif
}


#if defined (MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
int mbedtls_psa_get_random( void *p_rng,
                            unsigned char *output,
                            size_t output_size )
{
   
    (void) p_rng;
    psa_status_t status = psa_generate_random( output, output_size );
    if( status == PSA_SUCCESS )
        return( 0 );
    else
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
}
#endif

#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
#include "entropy_poll.h"

psa_status_t mbedtls_psa_inject_entropy( const uint8_t *seed,
                                         size_t seed_size )
{
    if( global_data.initialized )
        return( PSA_ERROR_NOT_PERMITTED );

    if( ( ( seed_size < MBEDTLS_ENTROPY_MIN_PLATFORM ) ||
          ( seed_size < MBEDTLS_ENTROPY_BLOCK_SIZE ) ) ||
          ( seed_size > MBEDTLS_ENTROPY_MAX_SEED_SIZE ) )
            return( PSA_ERROR_INVALID_ARGUMENT );

    return( mbedtls_psa_storage_inject_entropy( seed, seed_size ) );
}
#endif

/** Validate the key type and size for key generation
 *
 * \param  type  The key type
 * \param  bits  The number of bits of the key
 *
 * \retval #PSA_SUCCESS
 *         The key type and size are valid.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The size in bits of the key is not valid.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The type and/or the size in bits of the key or the combination of
 *         the two is not supported.
 */
static psa_status_t psa_validate_key_type_and_size_for_key_generation(
    psa_key_type_t type, size_t bits )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( key_type_is_raw_bytes( type ) )
    {
        status = psa_validate_unstructured_key_bit_size( type, bits );
        if( status != PSA_SUCCESS )
            return( status );
    }
    else
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
    if( PSA_KEY_TYPE_IS_RSA( type ) && PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
    {
        if( bits > PSA_VENDOR_RSA_MAX_KEY_BITS )
            return( PSA_ERROR_NOT_SUPPORTED );

       
        if( bits % 8 != 0 )
            return( PSA_ERROR_NOT_SUPPORTED );
    }
    else
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR)
    if( PSA_KEY_TYPE_IS_ECC( type ) && PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
    {
       
        return( PSA_SUCCESS );
    }
    else
#endif
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_generate_key_internal(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = attributes->core.type;

    if( ( attributes->domain_parameters == NULL ) &&
        ( attributes->domain_parameters_size != 0 ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( key_type_is_raw_bytes( type ) )
    {
        status = psa_generate_random( key_buffer, key_buffer_size );
        if( status != PSA_SUCCESS )
            return( status );

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
        if( type == PSA_KEY_TYPE_DES )
            psa_des_set_key_parity( key_buffer, key_buffer_size );
#endif
    }
    else

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) && \
    defined(MBEDTLS_GENPRIME)
    if ( type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
        return( mbedtls_psa_rsa_generate_key( attributes,
                                              key_buffer,
                                              key_buffer_size,
                                              key_buffer_length ) );
    }
    else
#endif

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR)
    if ( PSA_KEY_TYPE_IS_ECC( type ) && PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
    {
        return( mbedtls_psa_ecp_generate_key( attributes,
                                              key_buffer,
                                              key_buffer_size,
                                              key_buffer_length ) );
    }
    else
#endif
    {
        (void)key_buffer_length;
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_generate_key( const psa_key_attributes_t *attributes,
                               mbedtls_svc_key_id_t *key )
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    size_t key_buffer_size;

    *key = MBEDTLS_SVC_KEY_ID_INIT;

   
    if( psa_get_key_bits( attributes ) == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

   
    if( PSA_KEY_TYPE_IS_PUBLIC_KEY(attributes->core.type) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_start_key_creation( PSA_KEY_CREATION_GENERATE, attributes,
                                     &slot, &driver );
    if( status != PSA_SUCCESS )
        goto exit;

   
    if( slot->key.data == NULL )
    {
        if ( PSA_KEY_LIFETIME_GET_LOCATION( attributes->core.lifetime ) ==
             PSA_KEY_LOCATION_LOCAL_STORAGE )
        {
            status = psa_validate_key_type_and_size_for_key_generation(
                attributes->core.type, attributes->core.bits );
            if( status != PSA_SUCCESS )
                goto exit;

            key_buffer_size = PSA_EXPORT_KEY_OUTPUT_SIZE(
                                  attributes->core.type,
                                  attributes->core.bits );
        }
        else
        {
            status = psa_driver_wrapper_get_key_buffer_size(
                         attributes, &key_buffer_size );
            if( status != PSA_SUCCESS )
                goto exit;
        }

        status = psa_allocate_buffer_to_slot( slot, key_buffer_size );
        if( status != PSA_SUCCESS )
            goto exit;
    }

    status = psa_driver_wrapper_generate_key( attributes,
        slot->key.data, slot->key.bytes, &slot->key.bytes );

    if( status != PSA_SUCCESS )
        psa_remove_key_data_from_memory( slot );

exit:
    if( status == PSA_SUCCESS )
        status = psa_finish_key_creation( slot, driver, key );
    if( status != PSA_SUCCESS )
        psa_fail_key_creation( slot, driver );

    return( status );
}

/****************************************************************/

/****************************************************************/

#if !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
psa_status_t mbedtls_psa_crypto_configure_entropy_sources(
    void (* entropy_init )( mbedtls_entropy_context *ctx ),
    void (* entropy_free )( mbedtls_entropy_context *ctx ) )
{
    if( global_data.rng_state != RNG_NOT_INITIALIZED )
        return( PSA_ERROR_BAD_STATE );
    global_data.rng.entropy_init = entropy_init;
    global_data.rng.entropy_free = entropy_free;
    return( PSA_SUCCESS );
}
#endif

void mbedtls_psa_crypto_free( void )
{
    psa_wipe_all_key_slots( );
    if( global_data.rng_state != RNG_NOT_INITIALIZED )
    {
        mbedtls_psa_random_free( &global_data.rng );
    }
   
    mbedtls_platform_zeroize( &global_data, sizeof( global_data ) );

   
    psa_driver_wrapper_free( );
}

#if defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
/** Recover a transaction that was interrupted by a power failure.
 *
 * This function is called during initialization, before psa_crypto_init()
 * returns. If this function returns a failure status, the initialization
 * fails.
 */
static psa_status_t psa_crypto_recover_transaction(
    const psa_crypto_transaction_t *transaction )
{
    switch( transaction->unknown.type )
    {
        case PSA_CRYPTO_TRANSACTION_CREATE_KEY:
        case PSA_CRYPTO_TRANSACTION_DESTROY_KEY:
           
        default:
           
            return( PSA_ERROR_DATA_INVALID );
    }
}
#endif

psa_status_t psa_crypto_init( void )
{
    psa_status_t status;

   
    if( global_data.initialized != 0 )
        return( PSA_SUCCESS );

   
    mbedtls_psa_random_init( &global_data.rng );
    global_data.rng_state = RNG_INITIALIZED;
    status = mbedtls_psa_random_seed( &global_data.rng );
    if( status != PSA_SUCCESS )
        goto exit;
    global_data.rng_state = RNG_SEEDED;

    status = psa_initialize_key_slots( );
    if( status != PSA_SUCCESS )
        goto exit;

   
    status = psa_driver_wrapper_init( );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
    status = psa_crypto_load_transaction( );
    if( status == PSA_SUCCESS )
    {
        status = psa_crypto_recover_transaction( &psa_crypto_transaction );
        if( status != PSA_SUCCESS )
            goto exit;
        status = psa_crypto_stop_transaction( );
    }
    else if( status == PSA_ERROR_DOES_NOT_EXIST )
    {
       
        status = PSA_SUCCESS;
    }
#endif

   
    global_data.initialized = 1;

exit:
    if( status != PSA_SUCCESS )
        mbedtls_psa_crypto_free( );
    return( status );
}

#endif
