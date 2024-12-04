



#include "common.h"

#if defined(MBEDTLS_RSA_C)

#include "mbedtls/rsa.h"
#include "rsa_alt_helpers.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include "hash_info.h"

#include <string.h>

#if defined(MBEDTLS_PKCS1_V15) && !defined(__OpenBSD__) && !defined(__NetBSD__)
#include <stdlib.h>
#endif


#if defined(MBEDTLS_PKCS1_V21)
#if !defined(MBEDTLS_MD_C)
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"
#endif
#endif

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_RSA_ALT)

int mbedtls_rsa_import( mbedtls_rsa_context *ctx,
                        const mbedtls_mpi *N,
                        const mbedtls_mpi *P, const mbedtls_mpi *Q,
                        const mbedtls_mpi *D, const mbedtls_mpi *E )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ( N != NULL && ( ret = mbedtls_mpi_copy( &ctx->N, N ) ) != 0 ) ||
        ( P != NULL && ( ret = mbedtls_mpi_copy( &ctx->P, P ) ) != 0 ) ||
        ( Q != NULL && ( ret = mbedtls_mpi_copy( &ctx->Q, Q ) ) != 0 ) ||
        ( D != NULL && ( ret = mbedtls_mpi_copy( &ctx->D, D ) ) != 0 ) ||
        ( E != NULL && ( ret = mbedtls_mpi_copy( &ctx->E, E ) ) != 0 ) )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
    }

    if( N != NULL )
        ctx->len = mbedtls_mpi_size( &ctx->N );

    return( 0 );
}

int mbedtls_rsa_import_raw( mbedtls_rsa_context *ctx,
                            unsigned char const *N, size_t N_len,
                            unsigned char const *P, size_t P_len,
                            unsigned char const *Q, size_t Q_len,
                            unsigned char const *D, size_t D_len,
                            unsigned char const *E, size_t E_len )
{
    int ret = 0;

    if( N != NULL )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->N, N, N_len ) );
        ctx->len = mbedtls_mpi_size( &ctx->N );
    }

    if( P != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->P, P, P_len ) );

    if( Q != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->Q, Q, Q_len ) );

    if( D != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->D, D, D_len ) );

    if( E != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->E, E, E_len ) );

cleanup:

    if( ret != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );

    return( 0 );
}


static int rsa_check_context( mbedtls_rsa_context const *ctx, int is_priv,
                              int blinding_needed )
{
#if !defined(MBEDTLS_RSA_NO_CRT)
   
    ((void) blinding_needed);
#endif

    if( ctx->len != mbedtls_mpi_size( &ctx->N ) ||
        ctx->len > MBEDTLS_MPI_MAX_SIZE )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

   

   
    if( mbedtls_mpi_cmp_int( &ctx->N, 0 ) <= 0 ||
        mbedtls_mpi_get_bit( &ctx->N, 0 ) == 0  )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
   
    if( is_priv &&
        ( mbedtls_mpi_cmp_int( &ctx->P, 0 ) <= 0 ||
          mbedtls_mpi_get_bit( &ctx->P, 0 ) == 0 ||
          mbedtls_mpi_cmp_int( &ctx->Q, 0 ) <= 0 ||
          mbedtls_mpi_get_bit( &ctx->Q, 0 ) == 0  ) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
#endif

   

   
    if( mbedtls_mpi_cmp_int( &ctx->E, 0 ) <= 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

#if defined(MBEDTLS_RSA_NO_CRT)
   
    if( is_priv && mbedtls_mpi_cmp_int( &ctx->D, 0 ) <= 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
#else
    if( is_priv &&
        ( mbedtls_mpi_cmp_int( &ctx->DP, 0 ) <= 0 ||
          mbedtls_mpi_cmp_int( &ctx->DQ, 0 ) <= 0  ) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
#endif

   
#if defined(MBEDTLS_RSA_NO_CRT)
    if( is_priv && blinding_needed &&
        ( mbedtls_mpi_cmp_int( &ctx->P, 0 ) <= 0 ||
          mbedtls_mpi_cmp_int( &ctx->Q, 0 ) <= 0 ) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
#endif

   
#if !defined(MBEDTLS_RSA_NO_CRT)
    if( is_priv &&
        mbedtls_mpi_cmp_int( &ctx->QP, 0 ) <= 0 )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
#endif

    return( 0 );
}

int mbedtls_rsa_complete( mbedtls_rsa_context *ctx )
{
    int ret = 0;
    int have_N, have_P, have_Q, have_D, have_E;
#if !defined(MBEDTLS_RSA_NO_CRT)
    int have_DP, have_DQ, have_QP;
#endif
    int n_missing, pq_missing, d_missing, is_pub, is_priv;

    have_N = ( mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 );
    have_P = ( mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 );
    have_Q = ( mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 );
    have_D = ( mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 );
    have_E = ( mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0 );

#if !defined(MBEDTLS_RSA_NO_CRT)
    have_DP = ( mbedtls_mpi_cmp_int( &ctx->DP, 0 ) != 0 );
    have_DQ = ( mbedtls_mpi_cmp_int( &ctx->DQ, 0 ) != 0 );
    have_QP = ( mbedtls_mpi_cmp_int( &ctx->QP, 0 ) != 0 );
#endif

   

    n_missing  =              have_P &&  have_Q &&  have_D && have_E;
    pq_missing =   have_N && !have_P && !have_Q &&  have_D && have_E;
    d_missing  =              have_P &&  have_Q && !have_D && have_E;
    is_pub     =   have_N && !have_P && !have_Q && !have_D && have_E;

   
    is_priv = n_missing || pq_missing || d_missing;

    if( !is_priv && !is_pub )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

   

    if( !have_N && have_P && have_Q )
    {
        if( ( ret = mbedtls_mpi_mul_mpi( &ctx->N, &ctx->P,
                                         &ctx->Q ) ) != 0 )
        {
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
        }

        ctx->len = mbedtls_mpi_size( &ctx->N );
    }

   

    if( pq_missing )
    {
        ret = mbedtls_rsa_deduce_primes( &ctx->N, &ctx->E, &ctx->D,
                                         &ctx->P, &ctx->Q );
        if( ret != 0 )
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );

    }
    else if( d_missing )
    {
        if( ( ret = mbedtls_rsa_deduce_private_exponent( &ctx->P,
                                                         &ctx->Q,
                                                         &ctx->E,
                                                         &ctx->D ) ) != 0 )
        {
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
        }
    }

   

#if !defined(MBEDTLS_RSA_NO_CRT)
    if( is_priv && ! ( have_DP && have_DQ && have_QP ) )
    {
        ret = mbedtls_rsa_deduce_crt( &ctx->P,  &ctx->Q,  &ctx->D,
                                      &ctx->DP, &ctx->DQ, &ctx->QP );
        if( ret != 0 )
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
    }
#endif

   

    return( rsa_check_context( ctx, is_priv, 1 ) );
}

int mbedtls_rsa_export_raw( const mbedtls_rsa_context *ctx,
                            unsigned char *N, size_t N_len,
                            unsigned char *P, size_t P_len,
                            unsigned char *Q, size_t Q_len,
                            unsigned char *D, size_t D_len,
                            unsigned char *E, size_t E_len )
{
    int ret = 0;
    int is_priv;

   
    is_priv =
        mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

    if( !is_priv )
    {
       
        if( P != NULL || Q != NULL || D != NULL )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    }

    if( N != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->N, N, N_len ) );

    if( P != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->P, P, P_len ) );

    if( Q != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->Q, Q, Q_len ) );

    if( D != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->D, D, D_len ) );

    if( E != NULL )
        MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &ctx->E, E, E_len ) );

cleanup:

    return( ret );
}

int mbedtls_rsa_export( const mbedtls_rsa_context *ctx,
                        mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q,
                        mbedtls_mpi *D, mbedtls_mpi *E )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int is_priv;

   
    is_priv =
        mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

    if( !is_priv )
    {
       
        if( P != NULL || Q != NULL || D != NULL )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    }

   

    if( ( N != NULL && ( ret = mbedtls_mpi_copy( N, &ctx->N ) ) != 0 ) ||
        ( P != NULL && ( ret = mbedtls_mpi_copy( P, &ctx->P ) ) != 0 ) ||
        ( Q != NULL && ( ret = mbedtls_mpi_copy( Q, &ctx->Q ) ) != 0 ) ||
        ( D != NULL && ( ret = mbedtls_mpi_copy( D, &ctx->D ) ) != 0 ) ||
        ( E != NULL && ( ret = mbedtls_mpi_copy( E, &ctx->E ) ) != 0 ) )
    {
        return( ret );
    }

    return( 0 );
}


int mbedtls_rsa_export_crt( const mbedtls_rsa_context *ctx,
                            mbedtls_mpi *DP, mbedtls_mpi *DQ, mbedtls_mpi *QP )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int is_priv;

   
    is_priv =
        mbedtls_mpi_cmp_int( &ctx->N, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->P, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->Q, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->D, 0 ) != 0 &&
        mbedtls_mpi_cmp_int( &ctx->E, 0 ) != 0;

    if( !is_priv )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

#if !defined(MBEDTLS_RSA_NO_CRT)
   
    if( ( DP != NULL && ( ret = mbedtls_mpi_copy( DP, &ctx->DP ) ) != 0 ) ||
        ( DQ != NULL && ( ret = mbedtls_mpi_copy( DQ, &ctx->DQ ) ) != 0 ) ||
        ( QP != NULL && ( ret = mbedtls_mpi_copy( QP, &ctx->QP ) ) != 0 ) )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
    }
#else
    if( ( ret = mbedtls_rsa_deduce_crt( &ctx->P, &ctx->Q, &ctx->D,
                                        DP, DQ, QP ) ) != 0 )
    {
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_BAD_INPUT_DATA, ret ) );
    }
#endif

    return( 0 );
}


void mbedtls_rsa_init( mbedtls_rsa_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_rsa_context ) );

    ctx->padding = MBEDTLS_RSA_PKCS_V15;
    ctx->hash_id = MBEDTLS_MD_NONE;

#if defined(MBEDTLS_THREADING_C)
   
    ctx->ver = 1;
    mbedtls_mutex_init( &ctx->mutex );
#endif
}


int mbedtls_rsa_set_padding( mbedtls_rsa_context *ctx, int padding,
                             mbedtls_md_type_t hash_id )
{
    switch( padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            break;
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            break;
#endif
        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }

#if defined(MBEDTLS_PKCS1_V21)
    if( ( padding == MBEDTLS_RSA_PKCS_V21 ) &&
        ( hash_id != MBEDTLS_MD_NONE ) )
    {
       
        if( mbedtls_hash_info_psa_from_md( hash_id ) == PSA_ALG_NONE )
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
#endif

    ctx->padding = padding;
    ctx->hash_id = hash_id;

    return( 0 );
}



size_t mbedtls_rsa_get_len( const mbedtls_rsa_context *ctx )
{
    return( ctx->len );
}


#if defined(MBEDTLS_GENPRIME)


int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi H, G, L;
    int prime_quality = 0;

   
    if( nbits > 1024 )
        prime_quality = MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR;

    mbedtls_mpi_init( &H );
    mbedtls_mpi_init( &G );
    mbedtls_mpi_init( &L );

    if( nbits < 128 || exponent < 3 || nbits % 2 != 0 )
    {
        ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &ctx->E, exponent ) );

    do
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->P, nbits >> 1,
                                                prime_quality, f_rng, p_rng ) );

        MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->Q, nbits >> 1,
                                                prime_quality, f_rng, p_rng ) );

       
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &H, &ctx->P, &ctx->Q ) );
        if( mbedtls_mpi_bitlen( &H ) <= ( ( nbits >= 200 ) ? ( ( nbits >> 1 ) - 99 ) : 0 ) )
            continue;

       
        if( H.s < 0 )
            mbedtls_mpi_swap( &ctx->P, &ctx->Q );

       
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &ctx->P, &ctx->P, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &ctx->Q, &ctx->Q, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &H, &ctx->P, &ctx->Q ) );

       
        MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G, &ctx->E, &H  ) );
        if( mbedtls_mpi_cmp_int( &G, 1 ) != 0 )
            continue;

       
        MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G, &ctx->P, &ctx->Q ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_div_mpi( &L, NULL, &H, &G ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &ctx->D, &ctx->E, &L ) );

        if( mbedtls_mpi_bitlen( &ctx->D ) <= ( ( nbits + 1 ) / 2 ) ) // (FIPS 186-4 §B.3.1 criterion 3(a))
            continue;

        break;
    }
    while( 1 );

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &ctx->P,  &ctx->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &ctx->Q,  &ctx->Q, 1 ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );

    ctx->len = mbedtls_mpi_size( &ctx->N );

#if !defined(MBEDTLS_RSA_NO_CRT)
   
    MBEDTLS_MPI_CHK( mbedtls_rsa_deduce_crt( &ctx->P, &ctx->Q, &ctx->D,
                                             &ctx->DP, &ctx->DQ, &ctx->QP ) );
#endif

   
    MBEDTLS_MPI_CHK( mbedtls_rsa_check_privkey( ctx ) );

cleanup:

    mbedtls_mpi_free( &H );
    mbedtls_mpi_free( &G );
    mbedtls_mpi_free( &L );

    if( ret != 0 )
    {
        mbedtls_rsa_free( ctx );

        if( ( -ret & ~0x7f ) == 0 )
            ret = MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_KEY_GEN_FAILED, ret );
        return( ret );
    }

    return( 0 );
}

#endif


int mbedtls_rsa_check_pubkey( const mbedtls_rsa_context *ctx )
{
    if( rsa_check_context( ctx, 0, 0 ) != 0 )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    if( mbedtls_mpi_bitlen( &ctx->N ) < 128 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_get_bit( &ctx->E, 0 ) == 0 ||
        mbedtls_mpi_bitlen( &ctx->E )     < 2  ||
        mbedtls_mpi_cmp_mpi( &ctx->E, &ctx->N ) >= 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}


int mbedtls_rsa_check_privkey( const mbedtls_rsa_context *ctx )
{
    if( mbedtls_rsa_check_pubkey( ctx ) != 0 ||
        rsa_check_context( ctx, 1, 1 ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_rsa_validate_params( &ctx->N, &ctx->P, &ctx->Q,
                                     &ctx->D, &ctx->E, NULL, NULL ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

#if !defined(MBEDTLS_RSA_NO_CRT)
    else if( mbedtls_rsa_validate_crt( &ctx->P, &ctx->Q, &ctx->D,
                                       &ctx->DP, &ctx->DQ, &ctx->QP ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }
#endif

    return( 0 );
}


int mbedtls_rsa_check_pub_priv( const mbedtls_rsa_context *pub,
                                const mbedtls_rsa_context *prv )
{
    if( mbedtls_rsa_check_pubkey( pub )  != 0 ||
        mbedtls_rsa_check_privkey( prv ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_cmp_mpi( &pub->N, &prv->N ) != 0 ||
        mbedtls_mpi_cmp_mpi( &pub->E, &prv->E ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}


int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;
    mbedtls_mpi T;

    if( rsa_check_context( ctx, 0, 0 ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_mpi_init( &T );

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );

    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    mbedtls_mpi_free( &T );

    if( ret != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_PUBLIC_FAILED, ret ) );

    return( 0 );
}


static int rsa_prepare_blinding( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, count = 0;
    mbedtls_mpi R;

    mbedtls_mpi_init( &R );

    if( ctx->Vf.p != NULL )
    {
       
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &ctx->Vi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vf, &ctx->Vf, &ctx->Vf ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vf, &ctx->Vf, &ctx->N ) );

        goto cleanup;
    }

   
    do {
        if( count++ > 10 )
        {
            ret = MBEDTLS_ERR_RSA_RNG_FAILED;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &ctx->Vf, ctx->len - 1, f_rng, p_rng ) );

       
        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, ctx->len - 1, f_rng, p_rng ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vi, &ctx->Vf, &R ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );

       
        ret = mbedtls_mpi_inv_mod( &ctx->Vi, &ctx->Vi, &ctx->N );
        if( ret != 0 && ret != MBEDTLS_ERR_MPI_NOT_ACCEPTABLE )
            goto cleanup;

    } while( ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE );

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, &ctx->RN ) );


cleanup:
    mbedtls_mpi_free( &R );

    return( ret );
}


#define RSA_EXPONENT_BLINDING 28


int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;

   
    mbedtls_mpi T;

   
    mbedtls_mpi P1, Q1, R;

#if !defined(MBEDTLS_RSA_NO_CRT)
   
    mbedtls_mpi TP, TQ;

   
    mbedtls_mpi DP_blind, DQ_blind;

   
    mbedtls_mpi *DP = &ctx->DP;
    mbedtls_mpi *DQ = &ctx->DQ;
#else
   
    mbedtls_mpi D_blind;

   
    mbedtls_mpi *D = &ctx->D;
#endif

   
    mbedtls_mpi I, C;

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( rsa_check_context( ctx, 1,
                                1 ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

   
    mbedtls_mpi_init( &T );

    mbedtls_mpi_init( &P1 );
    mbedtls_mpi_init( &Q1 );
    mbedtls_mpi_init( &R );

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init( &D_blind );
#else
    mbedtls_mpi_init( &DP_blind );
    mbedtls_mpi_init( &DQ_blind );
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init( &TP ); mbedtls_mpi_init( &TQ );
#endif

    mbedtls_mpi_init( &I );
    mbedtls_mpi_init( &C );

   

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );
    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &I, &T ) );

   
    MBEDTLS_MPI_CHK( rsa_prepare_blinding( ctx, f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &T, &ctx->Vi ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T, &ctx->N ) );

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &P1, &ctx->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &Q1, &ctx->Q, 1 ) );

#if defined(MBEDTLS_RSA_NO_CRT)
   
    MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                     f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &D_blind, &P1, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &D_blind, &D_blind, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &D_blind, &D_blind, &ctx->D ) );

    D = &D_blind;
#else
   
    MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                     f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DP_blind, &P1, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &DP_blind, &DP_blind,
                &ctx->DP ) );

    DP = &DP_blind;

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                     f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DQ_blind, &Q1, &R ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &DQ_blind, &DQ_blind,
                &ctx->DQ ) );

    DQ = &DQ_blind;
#endif

#if defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &T, D, &ctx->N, &ctx->RN ) );
#else
   

    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &TP, &T, DP, &ctx->P, &ctx->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &TQ, &T, DQ, &ctx->Q, &ctx->RQ ) );

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T, &TP, &TQ ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &TP, &T, &ctx->QP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &TP, &ctx->P ) );

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &TP, &T, &ctx->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &T, &TQ, &TP ) );
#endif

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &T, &ctx->Vf ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T, &ctx->N ) );

   
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &C, &T, &ctx->E,
                                          &ctx->N, &ctx->RN ) );
    if( mbedtls_mpi_cmp_mpi( &C, &I ) != 0 )
    {
        ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
        goto cleanup;
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    mbedtls_mpi_free( &P1 );
    mbedtls_mpi_free( &Q1 );
    mbedtls_mpi_free( &R );

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free( &D_blind );
#else
    mbedtls_mpi_free( &DP_blind );
    mbedtls_mpi_free( &DQ_blind );
#endif

    mbedtls_mpi_free( &T );

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free( &TP ); mbedtls_mpi_free( &TQ );
#endif

    mbedtls_mpi_free( &C );
    mbedtls_mpi_free( &I );

    if( ret != 0 && ret >= -0x007f )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret ) );

    return( ret );
}

#if defined(MBEDTLS_PKCS1_V21)
/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
 * \param dlen      length of destination buffer
 * \param src       source of the mask generation
 * \param slen      length of the source buffer
 * \param md_alg    message digest to use
 */
static int mgf_mask( unsigned char *dst, size_t dlen, unsigned char *src,
                      size_t slen, mbedtls_md_type_t md_alg )
{
    unsigned char counter[4];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;
    unsigned char mask[MBEDTLS_HASH_MAX_SIZE];
#if defined(MBEDTLS_MD_C)
    int ret = 0;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init( &md_ctx );
    md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_md_init( &md_ctx );
    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 0 ) ) != 0 )
        goto exit;

    hlen = mbedtls_md_get_size( md_info );
#else
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_algorithm_t alg = mbedtls_psa_translate_md( md_alg );
    psa_status_t status = PSA_SUCCESS;
    size_t out_len;

    hlen = PSA_HASH_LENGTH( alg );
#endif

    memset( mask, 0, sizeof( mask ) );
    memset( counter, 0, 4 );

   
    p = dst;

    while( dlen > 0 )
    {
        use_len = hlen;
        if( dlen < hlen )
            use_len = dlen;

#if defined(MBEDTLS_MD_C)
        if( ( ret = mbedtls_md_starts( &md_ctx ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_update( &md_ctx, src, slen ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_update( &md_ctx, counter, 4 ) ) != 0 )
            goto exit;
        if( ( ret = mbedtls_md_finish( &md_ctx, mask ) ) != 0 )
            goto exit;
#else
        if( ( status = psa_hash_setup( &op, alg ) ) != PSA_SUCCESS )
            goto exit;
        if( ( status = psa_hash_update( &op, src, slen ) ) != PSA_SUCCESS )
            goto exit;
        if( ( status = psa_hash_update( &op, counter, 4 ) ) != PSA_SUCCESS )
            goto exit;
        status = psa_hash_finish( &op, mask, sizeof( mask ), &out_len );
        if( status != PSA_SUCCESS )
            goto exit;
#endif

        for( i = 0; i < use_len; ++i )
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }

exit:
    mbedtls_platform_zeroize( mask, sizeof( mask ) );
#if defined(MBEDTLS_MD_C)
    mbedtls_md_free( &md_ctx );

    return( ret );
#else
    psa_hash_abort( &op );

    return( mbedtls_md_error_from_psa( status ) );
#endif
}

/**
 * Generate Hash(M') as in RFC 8017 page 43 points 5 and 6.
 *
 * \param hash      the input hash
 * \param hlen      length of the input hash
 * \param salt      the input salt
 * \param slen      length of the input salt
 * \param out       the output buffer - must be large enough for \p md_alg
 * \param md_alg    message digest to use
 */
static int hash_mprime( const unsigned char *hash, size_t hlen,
                        const unsigned char *salt, size_t slen,
                        unsigned char *out, mbedtls_md_type_t md_alg )
{
    const unsigned char zeros[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

#if defined(MBEDTLS_MD_C)
    mbedtls_md_context_t md_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_md_init( &md_ctx );
    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 0 ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_starts( &md_ctx ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_update( &md_ctx, zeros, sizeof( zeros ) ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_update( &md_ctx, hash, hlen ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_update( &md_ctx, salt, slen ) ) != 0 )
        goto exit;
    if( ( ret = mbedtls_md_finish( &md_ctx, out ) ) != 0 )
        goto exit;

exit:
    mbedtls_md_free( &md_ctx );

    return( ret );
#else
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_algorithm_t alg = mbedtls_psa_translate_md( md_alg );
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED ;
    size_t out_size = PSA_HASH_LENGTH( alg );
    size_t out_len;

    if( ( status = psa_hash_setup( &op, alg ) ) != PSA_SUCCESS )
        goto exit;
    if( ( status = psa_hash_update( &op, zeros, sizeof( zeros ) ) ) != PSA_SUCCESS )
        goto exit;
    if( ( status = psa_hash_update( &op, hash, hlen ) ) != PSA_SUCCESS )
        goto exit;
    if( ( status = psa_hash_update( &op, salt, slen ) ) != PSA_SUCCESS )
        goto exit;
    status = psa_hash_finish( &op, out, out_size, &out_len );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    psa_hash_abort( &op );

    return( mbedtls_md_error_from_psa( status ) );
#endif
}

/**
 * Compute a hash.
 *
 * \param md_alg    algorithm to use
 * \param input     input message to hash
 * \param ilen      input length
 * \param output    the output buffer - must be large enough for \p md_alg
 */
static int compute_hash( mbedtls_md_type_t md_alg,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output )
{
#if defined(MBEDTLS_MD_C)
    const mbedtls_md_info_t *md_info;

    md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    return( mbedtls_md( md_info, input, ilen, output ) );
#else
    psa_algorithm_t alg = mbedtls_psa_translate_md( md_alg );
    psa_status_t status;
    size_t out_size = PSA_HASH_LENGTH( alg );
    size_t out_len;

    status = psa_hash_compute( alg, input, ilen, output, out_size, &out_len );

    return( mbedtls_md_error_from_psa( status ) );
#endif
}
#endif

#if defined(MBEDTLS_PKCS1_V21)

int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
    size_t olen;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = output;
    unsigned int hlen;

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    hlen = mbedtls_hash_info_get_size( (mbedtls_md_type_t) ctx->hash_id );
    if( hlen == 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

   
    if( ilen + 2 * hlen + 2 < ilen || olen < ilen + 2 * hlen + 2 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    memset( output, 0, olen );

    *p++ = 0;

   
    if( ( ret = f_rng( p_rng, p, hlen ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_RNG_FAILED, ret ) );

    p += hlen;

   
    ret = compute_hash( (mbedtls_md_type_t) ctx->hash_id, label, label_len, p );
    if( ret != 0 )
        return( ret );
    p += hlen;
    p += olen - 2 * hlen - 2 - ilen;
    *p++ = 1;
    if( ilen != 0 )
        memcpy( p, input, ilen );

   
    if( ( ret = mgf_mask( output + hlen + 1, olen - hlen - 1, output + 1, hlen,
                          ctx->hash_id ) ) != 0 )
        return( ret );

   
    if( ( ret = mgf_mask( output + 1, hlen, output + hlen + 1, olen - hlen - 1,
                          ctx->hash_id ) ) != 0 )
        return( ret );

    return( mbedtls_rsa_public(  ctx, output, output ) );
}
#endif

#if defined(MBEDTLS_PKCS1_V15)

int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng, size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    size_t nb_pad, olen;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = output;

    olen = ctx->len;

   
    if( ilen + 11 < ilen || olen < ilen + 11 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    nb_pad = olen - 3 - ilen;

    *p++ = 0;

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    *p++ = MBEDTLS_RSA_CRYPT;

    while( nb_pad-- > 0 )
    {
        int rng_dl = 100;

        do {
            ret = f_rng( p_rng, p, 1 );
        } while( *p == 0 && --rng_dl && ret == 0 );

       
        if( rng_dl == 0 || ret != 0 )
            return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_RNG_FAILED, ret ) );

        p++;
    }

    *p++ = 0;
    if( ilen != 0 )
        memcpy( p, input, ilen );

    return( mbedtls_rsa_public(  ctx, output, output ) );
}
#endif


int mbedtls_rsa_pkcs1_encrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsaes_pkcs1_v15_encrypt( ctx, f_rng, p_rng,
                                                        ilen, input, output );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsaes_oaep_encrypt( ctx, f_rng, p_rng, NULL, 0,
                                                   ilen, input, output );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)

int mbedtls_rsa_rsaes_oaep_decrypt( mbedtls_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t ilen, i, pad_len;
    unsigned char *p, bad, pad_done;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    unsigned char lhash[MBEDTLS_HASH_MAX_SIZE];
    unsigned int hlen;

   
    if( ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    ilen = ctx->len;

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    hlen = mbedtls_hash_info_get_size( (mbedtls_md_type_t) ctx->hash_id );
    if( hlen == 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    // checking for integer underflow
    if( 2 * hlen + 2 > ilen )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

   
    ret = mbedtls_rsa_private( ctx, f_rng, p_rng, input, buf );

    if( ret != 0 )
        goto cleanup;

   
   
    if( ( ret = mgf_mask( buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
                          ctx->hash_id ) ) != 0 ||
   
        ( ret = mgf_mask( buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
                          ctx->hash_id ) ) != 0 )
    {
        goto cleanup;
    }

   
    ret = compute_hash( (mbedtls_md_type_t) ctx->hash_id,
                        label, label_len, lhash );
    if( ret != 0 )
        goto cleanup;

   
    p = buf;
    bad = 0;

    bad |= *p++;

    p += hlen;

   
    for( i = 0; i < hlen; i++ )
        bad |= lhash[i] ^ *p++;

   
    pad_len = 0;
    pad_done = 0;
    for( i = 0; i < ilen - 2 * hlen - 2; i++ )
    {
        pad_done |= p[i];
        pad_len += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
    }

    p += pad_len;
    bad |= *p++ ^ 0x01;

   
    if( bad != 0 )
    {
        ret = MBEDTLS_ERR_RSA_INVALID_PADDING;
        goto cleanup;
    }

    if( ilen - ( p - buf ) > output_max_len )
    {
        ret = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
        goto cleanup;
    }

    *olen = ilen - (p - buf);
    if( *olen != 0 )
        memcpy( output, p, *olen );
    ret = 0;

cleanup:
    mbedtls_platform_zeroize( buf, sizeof( buf ) );
    mbedtls_platform_zeroize( lhash, sizeof( lhash ) );

    return( ret );
}
#endif

#if defined(MBEDTLS_PKCS1_V15)

int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t ilen;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

    ilen = ctx->len;

    if( ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( ilen < 16 || ilen > sizeof( buf ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    ret = mbedtls_rsa_private( ctx, f_rng, p_rng, input, buf );

    if( ret != 0 )
        goto cleanup;

    ret = mbedtls_ct_rsaes_pkcs1_v15_unpadding( buf, ilen,
                                                output, output_max_len, olen );

cleanup:
    mbedtls_platform_zeroize( buf, sizeof( buf ) );

    return( ret );
}
#endif


int mbedtls_rsa_pkcs1_decrypt( mbedtls_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len)
{
    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsaes_pkcs1_v15_decrypt( ctx, f_rng, p_rng, olen,
                                                input, output, output_max_len );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsaes_oaep_decrypt( ctx, f_rng, p_rng, NULL, 0,
                                           olen, input, output,
                                           output_max_len );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)
static int rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         int saltlen,
                         unsigned char *sig )
{
    size_t olen;
    unsigned char *p = sig;
    unsigned char *salt = NULL;
    size_t slen, min_slen, hlen, offset = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t msb;

    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if( ctx->padding != MBEDTLS_RSA_PKCS_V21 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( f_rng == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    olen = ctx->len;

    if( md_alg != MBEDTLS_MD_NONE )
    {
       
        size_t exp_hashlen = mbedtls_hash_info_get_size( md_alg );
        if( exp_hashlen == 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( hashlen != exp_hashlen )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    hlen = mbedtls_hash_info_get_size( (mbedtls_md_type_t) ctx->hash_id );
    if( hlen == 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if (saltlen == MBEDTLS_RSA_SALT_LEN_ANY)
    {
      
        min_slen = hlen - 2;
        if( olen < hlen + min_slen + 2 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        else if( olen >= hlen + hlen + 2 )
            slen = hlen;
        else
            slen = olen - hlen - 2;
    }
    else if ( (saltlen < 0) || (saltlen + hlen + 2 > olen) )
    {
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }
    else
    {
        slen = (size_t) saltlen;
    }

    memset( sig, 0, olen );

   
    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;
    p += olen - hlen - slen - 2;
    *p++ = 0x01;

   
    salt = p;
    if( ( ret = f_rng( p_rng, salt, slen ) ) != 0 )
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_RSA_RNG_FAILED, ret ) );

    p += slen;

   
    ret = hash_mprime( hash, hashlen, salt, slen, p, ctx->hash_id );
    if( ret != 0 )
        return( ret );

   
    if( msb % 8 == 0 )
        offset = 1;

   
    ret = mgf_mask( sig + offset, olen - hlen - 1 - offset, p, hlen,
                    ctx->hash_id );
    if( ret != 0 )
        return( ret );

    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;
    sig[0] &= 0xFF >> ( olen * 8 - msb );

    p += hlen;
    *p++ = 0xBC;

    return mbedtls_rsa_private( ctx, f_rng, p_rng, sig, sig );
}


int mbedtls_rsa_rsassa_pss_sign_ext( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         int saltlen,
                         unsigned char *sig )
{
    return rsa_rsassa_pss_sign( ctx, f_rng, p_rng, md_alg,
                                hashlen, hash, saltlen, sig );
}



int mbedtls_rsa_rsassa_pss_sign( mbedtls_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         mbedtls_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig )
{
    return rsa_rsassa_pss_sign( ctx, f_rng, p_rng, md_alg,
                                hashlen, hash, MBEDTLS_RSA_SALT_LEN_ANY, sig );
}
#endif

#if defined(MBEDTLS_PKCS1_V15)



static int rsa_rsassa_pkcs1_v15_encode( mbedtls_md_type_t md_alg,
                                        unsigned int hashlen,
                                        const unsigned char *hash,
                                        size_t dst_len,
                                        unsigned char *dst )
{
    size_t oid_size  = 0;
    size_t nb_pad    = dst_len;
    unsigned char *p = dst;
    const char *oid  = NULL;

   
    if( md_alg != MBEDTLS_MD_NONE )
    {
        unsigned char md_size = mbedtls_hash_info_get_size( md_alg );
        if( md_size == 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( mbedtls_oid_get_oid_by_md( md_alg, &oid, &oid_size ) != 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( hashlen != md_size )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

       
        if( 8 + hashlen + oid_size  >= 0x80         ||
            10 + hashlen            <  hashlen      ||
            10 + hashlen + oid_size <  10 + hashlen )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

       
        if( nb_pad < 10 + hashlen + oid_size )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
        nb_pad -= 10 + hashlen + oid_size;
    }
    else
    {
        if( nb_pad < hashlen )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        nb_pad -= hashlen;
    }

   
    if( nb_pad < 3 + 8 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    nb_pad -= 3;

   

   
    *p++ = 0;
    *p++ = MBEDTLS_RSA_SIGN;
    memset( p, 0xFF, nb_pad );
    p += nb_pad;
    *p++ = 0;

   
    if( md_alg == MBEDTLS_MD_NONE )
    {
        memcpy( p, hash, hashlen );
        return( 0 );
    }

   
    *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
    *p++ = (unsigned char)( 0x08 + oid_size + hashlen );
    *p++ = MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED;
    *p++ = (unsigned char)( 0x04 + oid_size );
    *p++ = MBEDTLS_ASN1_OID;
    *p++ = (unsigned char) oid_size;
    memcpy( p, oid, oid_size );
    p += oid_size;
    *p++ = MBEDTLS_ASN1_NULL;
    *p++ = 0x00;
    *p++ = MBEDTLS_ASN1_OCTET_STRING;
    *p++ = (unsigned char) hashlen;
    memcpy( p, hash, hashlen );
    p += hashlen;

   
    if( p != dst + dst_len )
    {
        mbedtls_platform_zeroize( dst, dst_len );
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    return( 0 );
}


int mbedtls_rsa_rsassa_pkcs1_v15_sign( mbedtls_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *sig_try = NULL, *verif = NULL;

    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    if( ctx->padding != MBEDTLS_RSA_PKCS_V15 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

   

    if( ( ret = rsa_rsassa_pkcs1_v15_encode( md_alg, hashlen, hash,
                                             ctx->len, sig ) ) != 0 )
        return( ret );

   

    sig_try = mbedtls_calloc( 1, ctx->len );
    if( sig_try == NULL )
        return( MBEDTLS_ERR_MPI_ALLOC_FAILED );

    verif = mbedtls_calloc( 1, ctx->len );
    if( verif == NULL )
    {
        mbedtls_free( sig_try );
        return( MBEDTLS_ERR_MPI_ALLOC_FAILED );
    }

    MBEDTLS_MPI_CHK( mbedtls_rsa_private( ctx, f_rng, p_rng, sig, sig_try ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_public( ctx, sig_try, verif ) );

    if( mbedtls_ct_memcmp( verif, sig, ctx->len ) != 0 )
    {
        ret = MBEDTLS_ERR_RSA_PRIVATE_FAILED;
        goto cleanup;
    }

    memcpy( sig, sig_try, ctx->len );

cleanup:
    mbedtls_platform_zeroize( sig_try, ctx->len );
    mbedtls_platform_zeroize( verif, ctx->len );
    mbedtls_free( sig_try );
    mbedtls_free( verif );

    if( ret != 0 )
        memset( sig, '!', ctx->len );
    return( ret );
}
#endif


int mbedtls_rsa_pkcs1_sign( mbedtls_rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    mbedtls_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsassa_pkcs1_v15_sign( ctx, f_rng, p_rng,
                                                      md_alg, hashlen, hash, sig );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsassa_pss_sign( ctx, f_rng, p_rng, md_alg,
                                                hashlen, hash, sig );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}

#if defined(MBEDTLS_PKCS1_V21)

int mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_rsa_context *ctx,
                               mbedtls_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               mbedtls_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t siglen;
    unsigned char *p;
    unsigned char *hash_start;
    unsigned char result[MBEDTLS_HASH_MAX_SIZE];
    unsigned int hlen;
    size_t observed_salt_len, msb;
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE] = {0};

    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    siglen = ctx->len;

    if( siglen < 16 || siglen > sizeof( buf ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    ret = mbedtls_rsa_public(  ctx, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    if( buf[siglen - 1] != 0xBC )
        return( MBEDTLS_ERR_RSA_INVALID_PADDING );

    if( md_alg != MBEDTLS_MD_NONE )
    {
       
        size_t exp_hashlen = mbedtls_hash_info_get_size( md_alg );
        if( exp_hashlen == 0 )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

        if( hashlen != exp_hashlen )
            return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    }

    hlen = mbedtls_hash_info_get_size( mgf1_hash_id );
    if( hlen == 0 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

   
    msb = mbedtls_mpi_bitlen( &ctx->N ) - 1;

    if( buf[0] >> ( 8 - siglen * 8 + msb ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

   
    if( msb % 8 == 0 )
    {
        p++;
        siglen -= 1;
    }

    if( siglen < hlen + 2 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );
    hash_start = p + siglen - hlen - 1;

    ret = mgf_mask( p, siglen - hlen - 1, hash_start, hlen, mgf1_hash_id );
    if( ret != 0 )
        return( ret );

    buf[0] &= 0xFF >> ( siglen * 8 - msb );

    while( p < hash_start - 1 && *p == 0 )
        p++;

    if( *p++ != 0x01 )
        return( MBEDTLS_ERR_RSA_INVALID_PADDING );

    observed_salt_len = hash_start - p;

    if( expected_salt_len != MBEDTLS_RSA_SALT_LEN_ANY &&
        observed_salt_len != (size_t) expected_salt_len )
    {
        return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }

   
    ret = hash_mprime( hash, hashlen, p, observed_salt_len,
                       result, mgf1_hash_id );
    if( ret != 0 )
        return( ret );

    if( memcmp( hash_start, result, hlen ) != 0 )
        return( MBEDTLS_ERR_RSA_VERIFY_FAILED );

    return( 0 );
}


int mbedtls_rsa_rsassa_pss_verify( mbedtls_rsa_context *ctx,
                           mbedtls_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig )
{
    mbedtls_md_type_t mgf1_hash_id;
    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    mgf1_hash_id = ( ctx->hash_id != MBEDTLS_MD_NONE )
                             ? (mbedtls_md_type_t) ctx->hash_id
                             : md_alg;

    return( mbedtls_rsa_rsassa_pss_verify_ext( ctx,
                                               md_alg, hashlen, hash,
                                               mgf1_hash_id,
                                               MBEDTLS_RSA_SALT_LEN_ANY,
                                               sig ) );

}
#endif

#if defined(MBEDTLS_PKCS1_V15)

int mbedtls_rsa_rsassa_pkcs1_v15_verify( mbedtls_rsa_context *ctx,
                                 mbedtls_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig )
{
    int ret = 0;
    size_t sig_len;
    unsigned char *encoded = NULL, *encoded_expected = NULL;

    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    sig_len = ctx->len;

   

    if( ( encoded          = mbedtls_calloc( 1, sig_len ) ) == NULL ||
        ( encoded_expected = mbedtls_calloc( 1, sig_len ) ) == NULL )
    {
        ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto cleanup;
    }

    if( ( ret = rsa_rsassa_pkcs1_v15_encode( md_alg, hashlen, hash, sig_len,
                                             encoded_expected ) ) != 0 )
        goto cleanup;

   

    ret = mbedtls_rsa_public( ctx, sig, encoded );
    if( ret != 0 )
        goto cleanup;

   

    if( ( ret = mbedtls_ct_memcmp( encoded, encoded_expected,
                                              sig_len ) ) != 0 )
    {
        ret = MBEDTLS_ERR_RSA_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:

    if( encoded != NULL )
    {
        mbedtls_platform_zeroize( encoded, sig_len );
        mbedtls_free( encoded );
    }

    if( encoded_expected != NULL )
    {
        mbedtls_platform_zeroize( encoded_expected, sig_len );
        mbedtls_free( encoded_expected );
    }

    return( ret );
}
#endif


int mbedtls_rsa_pkcs1_verify( mbedtls_rsa_context *ctx,
                      mbedtls_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig )
{
    if( ( md_alg != MBEDTLS_MD_NONE || hashlen != 0 ) && hash == NULL )
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    switch( ctx->padding )
    {
#if defined(MBEDTLS_PKCS1_V15)
        case MBEDTLS_RSA_PKCS_V15:
            return mbedtls_rsa_rsassa_pkcs1_v15_verify( ctx, md_alg,
                                                        hashlen, hash, sig );
#endif

#if defined(MBEDTLS_PKCS1_V21)
        case MBEDTLS_RSA_PKCS_V21:
            return mbedtls_rsa_rsassa_pss_verify( ctx, md_alg,
                                                  hashlen, hash, sig );
#endif

        default:
            return( MBEDTLS_ERR_RSA_INVALID_PADDING );
    }
}


int mbedtls_rsa_copy( mbedtls_rsa_context *dst, const mbedtls_rsa_context *src )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    dst->len = src->len;

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->N, &src->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->E, &src->E ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->D, &src->D ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->P, &src->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Q, &src->Q ) );

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->DP, &src->DP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->DQ, &src->DQ ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->QP, &src->QP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RP, &src->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RQ, &src->RQ ) );
#endif

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RN, &src->RN ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Vi, &src->Vi ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Vf, &src->Vf ) );

    dst->padding = src->padding;
    dst->hash_id = src->hash_id;

cleanup:
    if( ret != 0 )
        mbedtls_rsa_free( dst );

    return( ret );
}


void mbedtls_rsa_free( mbedtls_rsa_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_mpi_free( &ctx->Vi );
    mbedtls_mpi_free( &ctx->Vf );
    mbedtls_mpi_free( &ctx->RN );
    mbedtls_mpi_free( &ctx->D  );
    mbedtls_mpi_free( &ctx->Q  );
    mbedtls_mpi_free( &ctx->P  );
    mbedtls_mpi_free( &ctx->E  );
    mbedtls_mpi_free( &ctx->N  );

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free( &ctx->RQ );
    mbedtls_mpi_free( &ctx->RP );
    mbedtls_mpi_free( &ctx->QP );
    mbedtls_mpi_free( &ctx->DQ );
    mbedtls_mpi_free( &ctx->DP );
#endif

#if defined(MBEDTLS_THREADING_C)
   
    if( ctx->ver != 0 )
    {
        mbedtls_mutex_free( &ctx->mutex );
        ctx->ver = 0;
    }
#endif
}

#endif

#if defined(MBEDTLS_SELF_TEST)

#include "mbedtls/sha1.h"


#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

#if defined(MBEDTLS_PKCS1_V15)
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__) && !defined(__NetBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif

    return( 0 );
}
#endif


int mbedtls_rsa_self_test( int verbose )
{
    int ret = 0;
#if defined(MBEDTLS_PKCS1_V15)
    size_t len;
    mbedtls_rsa_context rsa;
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];
#if defined(MBEDTLS_SHA1_C)
    unsigned char sha1sum[20];
#endif

    mbedtls_mpi K;

    mbedtls_mpi_init( &K );
    mbedtls_rsa_init( &rsa );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_N  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, &K, NULL, NULL, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_P  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, &K, NULL, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_Q  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, &K, NULL, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_D  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, NULL, &K, NULL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &K, 16, RSA_E  ) );
    MBEDTLS_MPI_CHK( mbedtls_rsa_import( &rsa, NULL, NULL, NULL, NULL, &K ) );

    MBEDTLS_MPI_CHK( mbedtls_rsa_complete( &rsa ) );

    if( verbose != 0 )
        mbedtls_printf( "  RSA key validation: " );

    if( mbedtls_rsa_check_pubkey(  &rsa ) != 0 ||
        mbedtls_rsa_check_privkey( &rsa ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    if( mbedtls_rsa_pkcs1_encrypt( &rsa, myrand, NULL,
                                   PT_LEN, rsa_plaintext,
                                   rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 decryption : " );

    if( mbedtls_rsa_pkcs1_decrypt( &rsa, myrand, NULL,
                                   &len, rsa_ciphertext, rsa_decrypted,
                                   sizeof(rsa_decrypted) ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

#if defined(MBEDTLS_SHA1_C)
    if( verbose != 0 )
        mbedtls_printf( "  PKCS#1 data sign  : " );

    if( mbedtls_sha1( rsa_plaintext, PT_LEN, sha1sum ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        return( 1 );
    }

    if( mbedtls_rsa_pkcs1_sign( &rsa, myrand, NULL,
                                MBEDTLS_MD_SHA1, 20,
                                sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n  PKCS#1 sig. verify: " );

    if( mbedtls_rsa_pkcs1_verify( &rsa, MBEDTLS_MD_SHA1, 20,
                                  sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );
#endif

    if( verbose != 0 )
        mbedtls_printf( "\n" );

cleanup:
    mbedtls_mpi_free( &K );
    mbedtls_rsa_free( &rsa );
#else
    ((void) verbose);
#endif
    return( ret );
}

#endif

#endif
