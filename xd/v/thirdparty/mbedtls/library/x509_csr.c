


#include "common.h"

#if defined(MBEDTLS_X509_CSR_PARSE_C)

#include "mbedtls/x509_csr.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#include "mbedtls/platform.h"

#if defined(MBEDTLS_FS_IO) || defined(EFIX64) || defined(EFI32)
#include <stdio.h>
#endif


static int x509_csr_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_X509_INVALID_VERSION, ret ) );
    }

    return( 0 );
}


int mbedtls_x509_csr_parse_der( mbedtls_x509_csr *csr,
                        const unsigned char *buf, size_t buflen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *p, *end;
    mbedtls_x509_buf sig_params;

    memset( &sig_params, 0, sizeof( mbedtls_x509_buf ) );

   
    if( csr == NULL || buf == NULL || buflen == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    mbedtls_x509_csr_init( csr );

   
    p = mbedtls_calloc( 1, len = buflen );

    if( p == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    memcpy( p, buf, buflen );

    csr->raw.p = p;
    csr->raw.len = len;
    end = p + len;

   
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_X509_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH ) );
    }

   
    csr->cri.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_X509_INVALID_FORMAT, ret ) );
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

   
    if( ( ret = x509_csr_get_version( &p, end, &csr->version ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( csr->version != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
    }

    csr->version++;

   
    csr->subject_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_X509_INVALID_FORMAT, ret ) );
    }

    if( ( ret = mbedtls_x509_get_name( &p, p + len, &csr->subject ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    csr->subject_raw.len = p - csr->subject_raw.p;

   
    if( ( ret = mbedtls_pk_parse_subpubkey( &p, end, &csr->pk ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

   
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_X509_INVALID_FORMAT, ret ) );
    }

    p += len;

    end = csr->raw.p + csr->raw.len;

   
    if( ( ret = mbedtls_x509_get_alg( &p, end, &csr->sig_oid, &sig_params ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( ( ret = mbedtls_x509_get_sig_alg( &csr->sig_oid, &sig_params,
                                  &csr->sig_md, &csr->sig_pk,
                                  &csr->sig_opts ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG );
    }

    if( ( ret = mbedtls_x509_get_sig( &p, end, &csr->sig ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( p != end )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERROR_ADD( MBEDTLS_ERR_X509_INVALID_FORMAT,
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH ) );
    }

    return( 0 );
}


int mbedtls_x509_csr_parse( mbedtls_x509_csr *csr, const unsigned char *buf, size_t buflen )
{
#if defined(MBEDTLS_PEM_PARSE_C)
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t use_len;
    mbedtls_pem_context pem;
#endif

   
    if( csr == NULL || buf == NULL || buflen == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

#if defined(MBEDTLS_PEM_PARSE_C)
   
    if( buf[buflen - 1] == '\0' )
    {
        mbedtls_pem_init( &pem );
        ret = mbedtls_pem_read_buffer( &pem,
                                       "-----BEGIN CERTIFICATE REQUEST-----",
                                       "-----END CERTIFICATE REQUEST-----",
                                       buf, NULL, 0, &use_len );
        if( ret == MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        {
            ret = mbedtls_pem_read_buffer( &pem,
                                           "-----BEGIN NEW CERTIFICATE REQUEST-----",
                                           "-----END NEW CERTIFICATE REQUEST-----",
                                           buf, NULL, 0, &use_len );
        }

        if( ret == 0 )
        {
           
            ret = mbedtls_x509_csr_parse_der( csr, pem.buf, pem.buflen );
        }

        mbedtls_pem_free( &pem );
        if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
            return( ret );
    }
#endif
    return( mbedtls_x509_csr_parse_der( csr, buf, buflen ) );
}

#if defined(MBEDTLS_FS_IO)

int mbedtls_x509_csr_parse_file( mbedtls_x509_csr *csr, const char *path )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_csr_parse( csr, buf, n );

    mbedtls_platform_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
#endif

#if !defined(MBEDTLS_X509_REMOVE_INFO)
#define BEFORE_COLON    14
#define BC              "14"

int mbedtls_x509_csr_info( char *buf, size_t size, const char *prefix,
                   const mbedtls_x509_csr *csr )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    char *p;
    char key_size_str[BEFORE_COLON];

    p = buf;
    n = size;

    ret = mbedtls_snprintf( p, n, "%sCSR version   : %d",
                               prefix, csr->version );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssubject name  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets( p, n, &csr->subject );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssigned using  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_sig_alg_gets( p, n, &csr->sig_oid, csr->sig_pk, csr->sig_md,
                             csr->sig_opts );
    MBEDTLS_X509_SAFE_SNPRINTF;

    if( ( ret = mbedtls_x509_key_size_helper( key_size_str, BEFORE_COLON,
                                      mbedtls_pk_get_name( &csr->pk ) ) ) != 0 )
    {
        return( ret );
    }

    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: %d bits\n", prefix, key_size_str,
                          (int) mbedtls_pk_get_bitlen( &csr->pk ) );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int) ( size - n ) );
}
#endif


void mbedtls_x509_csr_init( mbedtls_x509_csr *csr )
{
    memset( csr, 0, sizeof(mbedtls_x509_csr) );
}


void mbedtls_x509_csr_free( mbedtls_x509_csr *csr )
{
    if( csr == NULL )
        return;

    mbedtls_pk_free( &csr->pk );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_free( csr->sig_opts );
#endif

    mbedtls_asn1_free_named_data_list_shallow( csr->subject.next );

    if( csr->raw.p != NULL )
    {
        mbedtls_platform_zeroize( csr->raw.p, csr->raw.len );
        mbedtls_free( csr->raw.p );
    }

    mbedtls_platform_zeroize( csr, sizeof( mbedtls_x509_csr ) );
}

#endif
