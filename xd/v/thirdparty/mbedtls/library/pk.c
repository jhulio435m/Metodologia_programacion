

#include "common.h"

#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#include "pk_wrap.h"
#include "pkwrite.h"

#include "hash_info.h"

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C)
#include "mbedtls/psa_util.h"
#endif

#include <limits.h>
#include <stdint.h>


void mbedtls_pk_init( mbedtls_pk_context *ctx )
{
    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}


void mbedtls_pk_free( mbedtls_pk_context *ctx )
{
    if( ctx == NULL )
        return;

    if ( ctx->pk_info != NULL )
        ctx->pk_info->ctx_free_func( ctx->pk_ctx );

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_pk_context ) );
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)

void mbedtls_pk_restart_init( mbedtls_pk_restart_ctx *ctx )
{
    ctx->pk_info = NULL;
    ctx->rs_ctx = NULL;
}


void mbedtls_pk_restart_free( mbedtls_pk_restart_ctx *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        ctx->pk_info->rs_free_func == NULL )
    {
        return;
    }

    ctx->pk_info->rs_free_func( ctx->rs_ctx );

    ctx->pk_info = NULL;
    ctx->rs_ctx = NULL;
}
#endif


const mbedtls_pk_info_t * mbedtls_pk_info_from_type( mbedtls_pk_type_t pk_type )
{
    switch( pk_type ) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_PK_RSA:
            return( &mbedtls_rsa_info );
#endif
#if defined(MBEDTLS_ECP_C)
        case MBEDTLS_PK_ECKEY:
            return( &mbedtls_eckey_info );
        case MBEDTLS_PK_ECKEY_DH:
            return( &mbedtls_eckeydh_info );
#endif
#if defined(MBEDTLS_ECDSA_C)
        case MBEDTLS_PK_ECDSA:
            return( &mbedtls_ecdsa_info );
#endif
       
        default:
            return( NULL );
    }
}


int mbedtls_pk_setup( mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info )
{
    if( info == NULL || ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    return( 0 );
}

#if defined(MBEDTLS_USE_PSA_CRYPTO)

int mbedtls_pk_setup_opaque( mbedtls_pk_context *ctx,
                             const mbedtls_svc_key_id_t key )
{
    const mbedtls_pk_info_t *info = NULL;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t *pk_ctx;
    psa_key_type_t type;

    if( ctx == NULL || ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( PSA_SUCCESS != psa_get_key_attributes( key, &attributes ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    type = psa_get_key_type( &attributes );
    psa_reset_key_attributes( &attributes );

    if( PSA_KEY_TYPE_IS_ECC_KEY_PAIR( type ) )
        info = &mbedtls_pk_ecdsa_opaque_info;
    else if( type == PSA_KEY_TYPE_RSA_KEY_PAIR )
        info = &mbedtls_pk_rsa_opaque_info;
    else
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    pk_ctx = (mbedtls_svc_key_id_t *) ctx->pk_ctx;
    *pk_ctx = key;

    return( 0 );
}
#endif

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)

int mbedtls_pk_setup_rsa_alt( mbedtls_pk_context *ctx, void * key,
                         mbedtls_pk_rsa_alt_decrypt_func decrypt_func,
                         mbedtls_pk_rsa_alt_sign_func sign_func,
                         mbedtls_pk_rsa_alt_key_len_func key_len_func )
{
    mbedtls_rsa_alt_context *rsa_alt;
    const mbedtls_pk_info_t *info = &mbedtls_rsa_alt_info;

    if( ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    rsa_alt = (mbedtls_rsa_alt_context *) ctx->pk_ctx;

    rsa_alt->key = key;
    rsa_alt->decrypt_func = decrypt_func;
    rsa_alt->sign_func = sign_func;
    rsa_alt->key_len_func = key_len_func;

    return( 0 );
}
#endif


int mbedtls_pk_can_do( const mbedtls_pk_context *ctx, mbedtls_pk_type_t type )
{
   
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->can_do( type ) );
}

#if defined(MBEDTLS_USE_PSA_CRYPTO)

int mbedtls_pk_can_do_ext( const mbedtls_pk_context *ctx, psa_algorithm_t alg,
                           psa_key_usage_t usage )
{
    psa_key_usage_t key_usage;

   
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

   
    if( PSA_ALG_IS_ECDSA( alg ) == 0 &&
        PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) == 0 &&
        PSA_ALG_IS_RSA_PSS( alg ) == 0 &&
        alg != PSA_ALG_RSA_PKCS1V15_CRYPT &&
        PSA_ALG_IS_ECDH( alg ) == 0 )
        return( 0 );

   
    if( usage == 0 ||
        ( usage & ~( PSA_KEY_USAGE_SIGN_HASH |
                     PSA_KEY_USAGE_DECRYPT |
                     PSA_KEY_USAGE_DERIVE ) ) != 0 )
        return( 0 );

   
    if( PSA_ALG_IS_SIGN_HASH( alg ) &&
        PSA_ALG_SIGN_GET_HASH( alg ) == PSA_ALG_ANY_HASH )
        return( 0 );

    if( mbedtls_pk_get_type( ctx ) != MBEDTLS_PK_OPAQUE )
    {
        mbedtls_pk_type_t type;

        if( PSA_ALG_IS_ECDSA( alg ) || PSA_ALG_IS_ECDH( alg ) )
            type = MBEDTLS_PK_ECKEY;
        else if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) ||
                 alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
            type = MBEDTLS_PK_RSA;
        else if( PSA_ALG_IS_RSA_PSS( alg ) )
            type = MBEDTLS_PK_RSASSA_PSS;
        else
            return( 0 );

        if( ctx->pk_info->can_do( type ) == 0 )
            return( 0 );

        switch( type )
        {
            case MBEDTLS_PK_ECKEY:
                key_usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DERIVE;
                break;
            case MBEDTLS_PK_RSA:
            case MBEDTLS_PK_RSASSA_PSS:
                key_usage = PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_DECRYPT;
                break;
            default:
               
                return( 0 );
        }

        return( ( key_usage & usage ) == usage );
    }

    const mbedtls_svc_key_id_t *key = (const mbedtls_svc_key_id_t *) ctx->pk_ctx;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t key_alg, key_alg2;
    psa_status_t status;

    status = psa_get_key_attributes( *key, &attributes );
    if( status != PSA_SUCCESS )
        return( 0 );

    key_alg = psa_get_key_algorithm( &attributes );
    key_alg2 = psa_get_key_enrollment_algorithm( &attributes );
    key_usage = psa_get_key_usage_flags( &attributes );
    psa_reset_key_attributes( &attributes );

    if( ( key_usage & usage ) != usage )
        return( 0 );

   
    if( alg == key_alg || alg == key_alg2 )
            return( 1 );

   
    if( PSA_ALG_IS_SIGN_HASH( alg ) )
    {

        if( PSA_ALG_IS_SIGN_HASH( key_alg ) &&
            PSA_ALG_SIGN_GET_HASH( key_alg ) == PSA_ALG_ANY_HASH &&
            ( alg & ~PSA_ALG_HASH_MASK ) == ( key_alg & ~PSA_ALG_HASH_MASK ) )
            return( 1 );

        if( PSA_ALG_IS_SIGN_HASH( key_alg2 ) &&
            PSA_ALG_SIGN_GET_HASH( key_alg2 ) == PSA_ALG_ANY_HASH &&
            ( alg & ~PSA_ALG_HASH_MASK ) == ( key_alg2 & ~PSA_ALG_HASH_MASK ) )
            return( 1 );
    }

    return( 0 );
}
#endif


static inline int pk_hashlen_helper( mbedtls_md_type_t md_alg, size_t *hash_len )
{
    if( *hash_len != 0 )
        return( 0 );

    *hash_len = mbedtls_hash_info_get_size( md_alg );

    if( *hash_len == 0 )
        return( -1 );

    return( 0 );
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)

static int pk_restart_setup( mbedtls_pk_restart_ctx *ctx,
                             const mbedtls_pk_info_t *info )
{
   
    if( ctx == NULL || ctx->pk_info != NULL )
        return( 0 );

   
    if( info->rs_alloc_func == NULL || info->rs_free_func == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->rs_ctx = info->rs_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    return( 0 );
}
#endif


int mbedtls_pk_verify_restartable( mbedtls_pk_context *ctx,
               mbedtls_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len,
               mbedtls_pk_restart_ctx *rs_ctx )
{
    if( ( md_alg != MBEDTLS_MD_NONE || hash_len != 0 ) && hash == NULL )
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    if( ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
   
    if( rs_ctx != NULL &&
        mbedtls_ecp_restart_is_enabled() &&
        ctx->pk_info->verify_rs_func != NULL )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if( ( ret = pk_restart_setup( rs_ctx, ctx->pk_info ) ) != 0 )
            return( ret );

        ret = ctx->pk_info->verify_rs_func( ctx->pk_ctx,
                   md_alg, hash, hash_len, sig, sig_len, rs_ctx->rs_ctx );

        if( ret != MBEDTLS_ERR_ECP_IN_PROGRESS )
            mbedtls_pk_restart_free( rs_ctx );

        return( ret );
    }
#else
    (void) rs_ctx;
#endif

    if( ctx->pk_info->verify_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->verify_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                       sig, sig_len ) );
}


int mbedtls_pk_verify( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len )
{
    return( mbedtls_pk_verify_restartable( ctx, md_alg, hash, hash_len,
                                           sig, sig_len, NULL ) );
}


int mbedtls_pk_verify_ext( mbedtls_pk_type_t type, const void *options,
                   mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    if( ( md_alg != MBEDTLS_MD_NONE || hash_len != 0 ) && hash == NULL )
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    if( ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ! mbedtls_pk_can_do( ctx, type ) )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    if( type != MBEDTLS_PK_RSASSA_PSS )
    {
       
        if( options != NULL )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

        return( mbedtls_pk_verify( ctx, md_alg, hash, hash_len, sig, sig_len ) );
    }

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21)
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_pk_rsassa_pss_options *pss_opts;

#if SIZE_MAX > UINT_MAX
    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif

    if( options == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    pss_opts = (const mbedtls_pk_rsassa_pss_options *) options;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if( pss_opts->mgf1_hash_id == md_alg &&
        ( (size_t) pss_opts->expected_salt_len == hash_len ||
            pss_opts->expected_salt_len  == MBEDTLS_RSA_SALT_LEN_ANY ) )
    {
       
        unsigned char buf[ 38 + 2 * MBEDTLS_MPI_MAX_SIZE ];
        unsigned char *p;
        int key_len;
        size_t signature_length;
        psa_status_t status = PSA_ERROR_DATA_CORRUPT;
        psa_status_t destruction_status = PSA_ERROR_DATA_CORRUPT;

        psa_algorithm_t psa_md_alg = mbedtls_hash_info_psa_from_md( md_alg );
        mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_algorithm_t psa_sig_alg =
            ( pss_opts->expected_salt_len == MBEDTLS_RSA_SALT_LEN_ANY ?
                                 PSA_ALG_RSA_PSS_ANY_SALT(psa_md_alg) :
                                 PSA_ALG_RSA_PSS(psa_md_alg) );
        p = buf + sizeof( buf );
        key_len = mbedtls_pk_write_pubkey( &p, buf, ctx );

        if( key_len < 0 )
            return( key_len );

        psa_set_key_type( &attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY );
        psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_VERIFY_HASH );
        psa_set_key_algorithm( &attributes, psa_sig_alg );

        status = psa_import_key( &attributes,
                                 buf + sizeof( buf ) - key_len, key_len,
                                 &key_id );
        if( status != PSA_SUCCESS )
        {
            psa_destroy_key( key_id );
            return( mbedtls_pk_error_from_psa( status ) );
        }

       
        signature_length = sig_len > mbedtls_pk_get_len( ctx ) ?
                                     mbedtls_pk_get_len( ctx ) : sig_len;
        status = psa_verify_hash( key_id, psa_sig_alg, hash,
                                  hash_len, sig, signature_length );
        destruction_status = psa_destroy_key( key_id );

        if( status == PSA_SUCCESS && sig_len > mbedtls_pk_get_len( ctx ) )
            return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

        if( status == PSA_SUCCESS )
            status = destruction_status;

        return( mbedtls_pk_error_from_psa_rsa( status ) );
    }
    else
#endif
    {
        if( sig_len < mbedtls_pk_get_len( ctx ) )
            return( MBEDTLS_ERR_RSA_VERIFY_FAILED );

        ret = mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_pk_rsa( *ctx ),
                                                 md_alg, (unsigned int) hash_len, hash,
                                                 pss_opts->mgf1_hash_id,
                                                 pss_opts->expected_salt_len,
                                                 sig );
        if( ret != 0 )
            return( ret );

        if( sig_len > mbedtls_pk_get_len( ctx ) )
            return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

        return( 0 );
    }
#else
    return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
#endif
}


int mbedtls_pk_sign_restartable( mbedtls_pk_context *ctx,
             mbedtls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t sig_size, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
             mbedtls_pk_restart_ctx *rs_ctx )
{
    if( ( md_alg != MBEDTLS_MD_NONE || hash_len != 0 ) && hash == NULL )
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    if( ctx->pk_info == NULL || pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
   
    if( rs_ctx != NULL &&
        mbedtls_ecp_restart_is_enabled() &&
        ctx->pk_info->sign_rs_func != NULL )
    {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if( ( ret = pk_restart_setup( rs_ctx, ctx->pk_info ) ) != 0 )
            return( ret );

        ret = ctx->pk_info->sign_rs_func( ctx->pk_ctx, md_alg,
                                          hash, hash_len,
                                          sig, sig_size, sig_len,
                                          f_rng, p_rng, rs_ctx->rs_ctx );

        if( ret != MBEDTLS_ERR_ECP_IN_PROGRESS )
            mbedtls_pk_restart_free( rs_ctx );

        return( ret );
    }
#else
    (void) rs_ctx;
#endif

    if( ctx->pk_info->sign_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->sign_func( ctx->pk_ctx, md_alg,
                                     hash, hash_len,
                                     sig, sig_size, sig_len,
                                     f_rng, p_rng ) );
}


int mbedtls_pk_sign( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t sig_size, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( mbedtls_pk_sign_restartable( ctx, md_alg, hash, hash_len,
                                         sig, sig_size, sig_len,
                                         f_rng, p_rng, NULL ) );
}

#if defined(MBEDTLS_PSA_CRYPTO_C)

int mbedtls_pk_sign_ext( mbedtls_pk_type_t pk_type,
                         mbedtls_pk_context *ctx,
                         mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
#if defined(MBEDTLS_RSA_C)
    psa_algorithm_t psa_md_alg;
#endif
    *sig_len = 0;

    if( ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ! mbedtls_pk_can_do( ctx, pk_type ) )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    if( pk_type != MBEDTLS_PK_RSASSA_PSS )
    {
        return( mbedtls_pk_sign( ctx, md_alg, hash, hash_len,
                                 sig, sig_size, sig_len, f_rng, p_rng ) );
    }

#if defined(MBEDTLS_RSA_C)
    psa_md_alg = mbedtls_hash_info_psa_from_md( md_alg );
    if( psa_md_alg == 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( mbedtls_pk_get_type( ctx ) == MBEDTLS_PK_OPAQUE )
    {
        const mbedtls_svc_key_id_t *key = (const mbedtls_svc_key_id_t *) ctx->pk_ctx;
        psa_status_t status;

        status = psa_sign_hash( *key, PSA_ALG_RSA_PSS( psa_md_alg ),
                                hash, hash_len,
                                sig, sig_size, sig_len );
        return( mbedtls_pk_error_from_psa_rsa( status ) );
    }

    return( mbedtls_pk_psa_rsa_sign_ext( PSA_ALG_RSA_PSS( psa_md_alg ),
                                         ctx->pk_ctx, hash, hash_len,
                                         sig, sig_size, sig_len ) );
#else
    return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
#endif

}
#endif


int mbedtls_pk_decrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->decrypt_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->decrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}


int mbedtls_pk_encrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->encrypt_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->encrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}


int mbedtls_pk_check_pair( const mbedtls_pk_context *pub,
                           const mbedtls_pk_context *prv,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng )
{
    if( pub->pk_info == NULL ||
        prv->pk_info == NULL )
    {
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    }

    if( f_rng == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( prv->pk_info->check_pair_func == NULL )
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );

    if( prv->pk_info->type == MBEDTLS_PK_RSA_ALT )
    {
        if( pub->pk_info->type != MBEDTLS_PK_RSA )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    }
    else
    {
        if( pub->pk_info != prv->pk_info )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    }

    return( prv->pk_info->check_pair_func( pub->pk_ctx, prv->pk_ctx, f_rng, p_rng ) );
}


size_t mbedtls_pk_get_bitlen( const mbedtls_pk_context *ctx )
{
   
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->get_bitlen( ctx->pk_ctx ) );
}


int mbedtls_pk_debug( const mbedtls_pk_context *ctx, mbedtls_pk_debug_item *items )
{
    if( ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->debug_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    ctx->pk_info->debug_func( ctx->pk_ctx, items );
    return( 0 );
}


const char *mbedtls_pk_get_name( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( "invalid PK" );

    return( ctx->pk_info->name );
}


mbedtls_pk_type_t mbedtls_pk_get_type( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_PK_NONE );

    return( ctx->pk_info->type );
}

#if defined(MBEDTLS_USE_PSA_CRYPTO)

int mbedtls_pk_wrap_as_opaque( mbedtls_pk_context *pk,
                               mbedtls_svc_key_id_t *key,
                               psa_algorithm_t alg,
                               psa_key_usage_t usage,
                               psa_algorithm_t alg2 )
{
#if !defined(MBEDTLS_ECP_C) && !defined(MBEDTLS_RSA_C)
    ((void) pk);
    ((void) key);
    ((void) alg);
    ((void) usage);
    ((void) alg2);
#else
#if defined(MBEDTLS_ECP_C)
    if( mbedtls_pk_get_type( pk ) == MBEDTLS_PK_ECKEY )
    {
        const mbedtls_ecp_keypair *ec;
        unsigned char d[MBEDTLS_ECP_MAX_BYTES];
        size_t d_len;
        psa_ecc_family_t curve_id;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_key_type_t key_type;
        size_t bits;
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        psa_status_t status;

       
        ec = mbedtls_pk_ec( *pk );
        d_len = PSA_BITS_TO_BYTES( ec->grp.nbits );
        if( ( ret = mbedtls_mpi_write_binary( &ec->d, d, d_len ) ) != 0 )
            return( ret );

        curve_id = mbedtls_ecc_group_to_psa( ec->grp.id, &bits );
        key_type = PSA_KEY_TYPE_ECC_KEY_PAIR( curve_id );

       
        psa_set_key_type( &attributes, key_type );
        psa_set_key_bits( &attributes, bits );
        psa_set_key_usage_flags( &attributes, usage );
        psa_set_key_algorithm( &attributes, alg );
        if( alg2 != PSA_ALG_NONE )
            psa_set_key_enrollment_algorithm( &attributes, alg2 );

       
        status = psa_import_key( &attributes, d, d_len, key );
        if( status != PSA_SUCCESS )
            return( mbedtls_pk_error_from_psa( status ) );

       
        mbedtls_pk_free( pk );
        mbedtls_pk_init( pk );

        return( mbedtls_pk_setup_opaque( pk, *key ) );
    }
    else
#endif
#if defined(MBEDTLS_RSA_C)
    if( mbedtls_pk_get_type( pk ) == MBEDTLS_PK_RSA )
    {
        unsigned char buf[MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES];
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        int key_len;
        psa_status_t status;

       
        key_len = mbedtls_pk_write_key_der( pk, buf, sizeof( buf ) );
        if( key_len <= 0 )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

       
        psa_set_key_type( &attributes, PSA_KEY_TYPE_RSA_KEY_PAIR );
        psa_set_key_bits( &attributes, mbedtls_pk_get_bitlen( pk ) );
        psa_set_key_usage_flags( &attributes, usage );
        psa_set_key_algorithm( &attributes, alg );
        if( alg2 != PSA_ALG_NONE )
            psa_set_key_enrollment_algorithm( &attributes, alg2 );

       
        status = psa_import_key( &attributes,
                                 buf + sizeof( buf ) - key_len,
                                 key_len, key);

        mbedtls_platform_zeroize( buf, sizeof( buf ) );

        if( status != PSA_SUCCESS )
            return( mbedtls_pk_error_from_psa( status ) );

       
        mbedtls_pk_free( pk );
        mbedtls_pk_init( pk );

        return( mbedtls_pk_setup_opaque( pk, *key ) );
    }
    else
#endif
#endif
    return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
}
#endif
#endif
