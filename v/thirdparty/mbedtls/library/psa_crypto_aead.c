


#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa_crypto_aead.h"
#include "psa_crypto_core.h"
#include "psa_crypto_cipher.h"

#include <string.h>
#include "mbedtls/platform.h"

#include "mbedtls/ccm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"
#include "mbedtls/error.h"

static psa_status_t psa_aead_setup(
    mbedtls_psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_id_t cipher_id;

    ( void ) key_buffer_size;

    key_bits = attributes->core.bits;

    cipher_info = mbedtls_cipher_info_from_psa( alg,
                                                attributes->core.type, key_bits,
                                                &cipher_id );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            operation->alg = PSA_ALG_CCM;
           
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( attributes->core.type ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );

            mbedtls_ccm_init( &operation->ctx.ccm );
            status = mbedtls_to_psa_error(
                mbedtls_ccm_setkey( &operation->ctx.ccm, cipher_id,
                                    key_buffer, (unsigned int) key_bits ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            operation->alg = PSA_ALG_GCM;
           
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( attributes->core.type ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );

            mbedtls_gcm_init( &operation->ctx.gcm );
            status = mbedtls_to_psa_error(
                mbedtls_gcm_setkey( &operation->ctx.gcm, cipher_id,
                                    key_buffer, (unsigned int) key_bits ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            operation->alg = PSA_ALG_CHACHA20_POLY1305;
           
            if( alg != PSA_ALG_CHACHA20_POLY1305 )
                return( PSA_ERROR_NOT_SUPPORTED );

            mbedtls_chachapoly_init( &operation->ctx.chachapoly );
            status = mbedtls_to_psa_error(
                mbedtls_chachapoly_setkey( &operation->ctx.chachapoly,
                                           key_buffer ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif

        default:
            (void) status;
            (void) key_buffer;
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    operation->key_type = psa_get_key_type( attributes );

    operation->tag_length = PSA_ALG_AEAD_GET_TAG_LENGTH( alg );

    return( PSA_SUCCESS );
}

psa_status_t mbedtls_psa_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_psa_aead_operation_t operation = MBEDTLS_PSA_AEAD_OPERATION_INIT;
    uint8_t *tag;

    status = psa_aead_setup( &operation, attributes, key_buffer,
                             key_buffer_size, alg );

    if( status != PSA_SUCCESS )
        goto exit;

   
    if( ciphertext_size < ( plaintext_length + operation.tag_length ) )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    tag = ciphertext + plaintext_length;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation.alg == PSA_ALG_CCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_ccm_encrypt_and_tag( &operation.ctx.ccm,
                                         plaintext_length,
                                         nonce, nonce_length,
                                         additional_data,
                                         additional_data_length,
                                         plaintext, ciphertext,
                                         tag, operation.tag_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation.alg == PSA_ALG_GCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_gcm_crypt_and_tag( &operation.ctx.gcm,
                                       MBEDTLS_GCM_ENCRYPT,
                                       plaintext_length,
                                       nonce, nonce_length,
                                       additional_data, additional_data_length,
                                       plaintext, ciphertext,
                                       operation.tag_length, tag ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation.alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( operation.tag_length != 16 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = mbedtls_to_psa_error(
            mbedtls_chachapoly_encrypt_and_tag( &operation.ctx.chachapoly,
                                                plaintext_length,
                                                nonce,
                                                additional_data,
                                                additional_data_length,
                                                plaintext,
                                                ciphertext,
                                                tag ) );
    }
    else
#endif
    {
        (void) tag;
        (void) nonce;
        (void) nonce_length;
        (void) additional_data;
        (void) additional_data_length;
        (void) plaintext;
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
        *ciphertext_length = plaintext_length + operation.tag_length;

exit:
    mbedtls_psa_aead_abort( &operation );

    return( status );
}


static psa_status_t psa_aead_unpadded_locate_tag( size_t tag_length,
                                                  const uint8_t *ciphertext,
                                                  size_t ciphertext_length,
                                                  size_t plaintext_size,
                                                  const uint8_t **p_tag )
{
    size_t payload_length;
    if( tag_length > ciphertext_length )
        return( PSA_ERROR_INVALID_ARGUMENT );
    payload_length = ciphertext_length - tag_length;
    if( payload_length > plaintext_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    *p_tag = ciphertext + payload_length;
    return( PSA_SUCCESS );
}

psa_status_t mbedtls_psa_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_psa_aead_operation_t operation = MBEDTLS_PSA_AEAD_OPERATION_INIT;
    const uint8_t *tag = NULL;

    status = psa_aead_setup( &operation, attributes, key_buffer,
                             key_buffer_size, alg );

    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_aead_unpadded_locate_tag( operation.tag_length,
                                           ciphertext, ciphertext_length,
                                           plaintext_size, &tag );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation.alg == PSA_ALG_CCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_ccm_auth_decrypt( &operation.ctx.ccm,
                                      ciphertext_length - operation.tag_length,
                                      nonce, nonce_length,
                                      additional_data,
                                      additional_data_length,
                                      ciphertext, plaintext,
                                      tag, operation.tag_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation.alg == PSA_ALG_GCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_gcm_auth_decrypt( &operation.ctx.gcm,
                                      ciphertext_length - operation.tag_length,
                                      nonce, nonce_length,
                                      additional_data,
                                      additional_data_length,
                                      tag, operation.tag_length,
                                      ciphertext, plaintext ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation.alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( operation.tag_length != 16 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = mbedtls_to_psa_error(
            mbedtls_chachapoly_auth_decrypt( &operation.ctx.chachapoly,
                                             ciphertext_length - operation.tag_length,
                                             nonce,
                                             additional_data,
                                             additional_data_length,
                                             tag,
                                             ciphertext,
                                             plaintext ) );
    }
    else
#endif
    {
        (void) nonce;
        (void) nonce_length;
        (void) additional_data;
        (void) additional_data_length;
        (void) plaintext;
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
        *plaintext_length = ciphertext_length - operation.tag_length;

exit:
    mbedtls_psa_aead_abort( &operation );

    if( status == PSA_SUCCESS )
        *plaintext_length = ciphertext_length - operation.tag_length;
    return( status );
}


psa_status_t mbedtls_psa_aead_encrypt_setup(
    mbedtls_psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_aead_setup( operation, attributes, key_buffer,
                             key_buffer_size, alg );

    if( status == PSA_SUCCESS )
        operation->is_encrypt = 1;

    return ( status );
}


psa_status_t mbedtls_psa_aead_decrypt_setup(
    mbedtls_psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_aead_setup( operation, attributes, key_buffer,
                             key_buffer_size, alg );

    if( status == PSA_SUCCESS )
        operation->is_encrypt = 0;

    return ( status );
}


psa_status_t mbedtls_psa_aead_set_nonce(
    mbedtls_psa_aead_operation_t *operation,
    const uint8_t *nonce,
    size_t nonce_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        status = mbedtls_to_psa_error(
                 mbedtls_gcm_starts( &operation->ctx.gcm,
                                     operation->is_encrypt ?
                                     MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
                                     nonce,
                                     nonce_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        status = mbedtls_to_psa_error(
                   mbedtls_ccm_starts( &operation->ctx.ccm,
                                       operation->is_encrypt ?
                                       MBEDTLS_CCM_ENCRYPT : MBEDTLS_CCM_DECRYPT,
                                       nonce,
                                       nonce_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
       
        if( nonce_length != 12 )
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }

        status = mbedtls_to_psa_error(
           mbedtls_chachapoly_starts( &operation->ctx.chachapoly,
                                      nonce,
                                      operation->is_encrypt ?
                                      MBEDTLS_CHACHAPOLY_ENCRYPT :
                                      MBEDTLS_CHACHAPOLY_DECRYPT ) );
    }
    else
#endif
    {
        ( void ) operation;
        ( void ) nonce;
        ( void ) nonce_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    return( status );
}


psa_status_t mbedtls_psa_aead_set_lengths(
    mbedtls_psa_aead_operation_t *operation,
    size_t ad_length,
    size_t plaintext_length )
{
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        return( mbedtls_to_psa_error(
                         mbedtls_ccm_set_lengths( &operation->ctx.ccm,
                                                 ad_length,
                                                 plaintext_length,
                                                 operation->tag_length ) ) );

    }
#else
    ( void ) operation;
    ( void ) ad_length;
    ( void ) plaintext_length;
#endif

    return ( PSA_SUCCESS );
}


psa_status_t mbedtls_psa_aead_update_ad(
    mbedtls_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_gcm_update_ad( &operation->ctx.gcm, input, input_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_ccm_update_ad( &operation->ctx.ccm, input, input_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        status = mbedtls_to_psa_error(
           mbedtls_chachapoly_update_aad( &operation->ctx.chachapoly,
                                          input,
                                          input_length ) );
    }
    else
#endif
    {
        ( void ) operation;
        ( void ) input;
        ( void ) input_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    return ( status );
}


psa_status_t mbedtls_psa_aead_update(
    mbedtls_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
    size_t update_output_length;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    update_output_length = input_length;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        status =  mbedtls_to_psa_error(
            mbedtls_gcm_update( &operation->ctx.gcm,
                                input, input_length,
                                output, output_size,
                                &update_output_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        if( output_size < input_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = mbedtls_to_psa_error(
           mbedtls_ccm_update( &operation->ctx.ccm,
                               input, input_length,
                               output, output_size,
                               &update_output_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( output_size < input_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = mbedtls_to_psa_error(
           mbedtls_chachapoly_update( &operation->ctx.chachapoly,
                                      input_length,
                                      input,
                                      output ) );
    }
    else
#endif
    {
        ( void ) operation;
        ( void ) input;
        ( void ) output;
        ( void ) output_size;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
        *output_length = update_output_length;

    return( status );
}


psa_status_t mbedtls_psa_aead_finish(
    mbedtls_psa_aead_operation_t *operation,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *tag,
    size_t tag_size,
    size_t *tag_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t finish_output_size = 0;

    if( tag_size < operation->tag_length )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        status =  mbedtls_to_psa_error(
            mbedtls_gcm_finish( &operation->ctx.gcm,
                                ciphertext, ciphertext_size, ciphertext_length,
                                tag, operation->tag_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
       
        if( tag_size < operation->tag_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = mbedtls_to_psa_error(
                           mbedtls_ccm_finish( &operation->ctx.ccm,
                                               tag, operation->tag_length ) );
    }
    else
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
       
        if( tag_size < 16 )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        status = mbedtls_to_psa_error(
            mbedtls_chachapoly_finish( &operation->ctx.chachapoly,
                                       tag ) );
    }
    else
#endif
    {
        ( void ) ciphertext;
        ( void ) ciphertext_size;
        ( void ) ciphertext_length;
        ( void ) tag;
        ( void ) tag_size;
        ( void ) tag_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
    {
       
        *ciphertext_length = finish_output_size;
        *tag_length = operation->tag_length;
    }

    return ( status );
}


psa_status_t mbedtls_psa_aead_abort(
   mbedtls_psa_aead_operation_t *operation )
{
    switch( operation->alg )
    {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
        case PSA_ALG_CCM:
            mbedtls_ccm_free( &operation->ctx.ccm );
            break;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
        case PSA_ALG_GCM:
            mbedtls_gcm_free( &operation->ctx.gcm );
            break;
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_CHACHA20_POLY1305:
            mbedtls_chachapoly_free( &operation->ctx.chachapoly );
            break;
#endif
    }

    operation->is_encrypt = 0;

    return( PSA_SUCCESS );
}

#endif

