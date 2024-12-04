


#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_slot_management.h"

#include <mbedtls/ecjpake.h>
#include <mbedtls/psa_util.h>

#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <string.h>



enum psa_pake_step
{
    PSA_PAKE_STEP_INVALID       = 0,
    PSA_PAKE_STEP_X1_X2         = 1,
    PSA_PAKE_STEP_X2S           = 2,
    PSA_PAKE_STEP_DERIVE        = 3,
};

enum psa_pake_state
{
    PSA_PAKE_STATE_INVALID      = 0,
    PSA_PAKE_STATE_SETUP        = 1,
    PSA_PAKE_STATE_READY        = 2,
    PSA_PAKE_OUTPUT_X1_X2       = 3,
    PSA_PAKE_OUTPUT_X2S         = 4,
    PSA_PAKE_INPUT_X1_X2        = 5,
    PSA_PAKE_INPUT_X4S          = 6,
};


enum psa_pake_sequence
{
    PSA_PAKE_SEQ_INVALID        = 0,
    PSA_PAKE_X1_STEP_KEY_SHARE  = 1,   
    PSA_PAKE_X1_STEP_ZK_PUBLIC  = 2,   
    PSA_PAKE_X1_STEP_ZK_PROOF   = 3,   
    PSA_PAKE_X2_STEP_KEY_SHARE  = 4,
    PSA_PAKE_X2_STEP_ZK_PUBLIC  = 5,
    PSA_PAKE_X2_STEP_ZK_PROOF   = 6,
    PSA_PAKE_SEQ_END            = 7,
};

#if defined(MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
static psa_status_t mbedtls_ecjpake_to_psa_error( int ret )
{
    switch( ret )
    {
        case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
        case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
        case MBEDTLS_ERR_ECP_INVALID_KEY:
        case MBEDTLS_ERR_ECP_VERIFY_FAILED:
            return( PSA_ERROR_DATA_INVALID );
        case MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
        case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED:
            return( PSA_ERROR_CORRUPTION_DETECTED );
        default:
            return( PSA_ERROR_GENERIC_ERROR );
    }
}
#endif

#if defined(MBEDTLS_PSA_BUILTIN_PAKE)
psa_status_t psa_pake_setup( psa_pake_operation_t *operation,
                             const psa_pake_cipher_suite_t *cipher_suite)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

   
    if( operation->alg != PSA_ALG_NONE )
    {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }

    if( cipher_suite == NULL ||
        PSA_ALG_IS_PAKE(cipher_suite->algorithm ) == 0 ||
        ( cipher_suite->type != PSA_PAKE_PRIMITIVE_TYPE_ECC &&
          cipher_suite->type != PSA_PAKE_PRIMITIVE_TYPE_DH ) ||
        PSA_ALG_IS_HASH( cipher_suite->hash ) == 0 )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto error;
    }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    if( cipher_suite->algorithm == PSA_ALG_JPAKE )
    {
        if( cipher_suite->type != PSA_PAKE_PRIMITIVE_TYPE_ECC ||
            cipher_suite->family != PSA_ECC_FAMILY_SECP_R1 ||
            cipher_suite->bits != 256 ||
            cipher_suite->hash != PSA_ALG_SHA_256 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto error;
        }

        operation->alg = cipher_suite->algorithm;

        mbedtls_ecjpake_init( &operation->ctx.ecjpake );

        operation->state = PSA_PAKE_STATE_SETUP;
        operation->sequence = PSA_PAKE_SEQ_INVALID;
        operation->input_step = PSA_PAKE_STEP_X1_X2;
        operation->output_step = PSA_PAKE_STEP_X1_X2;

        mbedtls_platform_zeroize( operation->buffer, MBEDTLS_PSA_PAKE_BUFFER_SIZE );
        operation->buffer_length = 0;
        operation->buffer_offset = 0;

        return( PSA_SUCCESS );
    }
    else
#endif
    status = PSA_ERROR_NOT_SUPPORTED;

error:
    psa_pake_abort( operation );
    return status;
}

psa_status_t psa_pake_set_password_key( psa_pake_operation_t *operation,
                                        mbedtls_svc_key_id_t password )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = psa_key_attributes_init();
    psa_key_type_t type;
    psa_key_usage_t usage;
    psa_key_slot_t *slot = NULL;

    if( operation->alg == PSA_ALG_NONE ||
        operation->state != PSA_PAKE_STATE_SETUP )
    {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }

    status = psa_get_key_attributes( password, &attributes );
    if( status != PSA_SUCCESS )
        goto error;

    type = psa_get_key_type( &attributes );
    usage = psa_get_key_usage_flags( &attributes );

    psa_reset_key_attributes( &attributes );

    if( type != PSA_KEY_TYPE_PASSWORD &&
        type != PSA_KEY_TYPE_PASSWORD_HASH )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    if( ( usage & PSA_KEY_USAGE_DERIVE ) == 0 ) {
        status = PSA_ERROR_NOT_PERMITTED;
        goto error;
    }

    if( operation->password != NULL )
        return( PSA_ERROR_BAD_STATE );

    status = psa_get_and_lock_key_slot_with_policy( password, &slot,
                                                    PSA_KEY_USAGE_DERIVE,
                                                    PSA_ALG_JPAKE );
    if( status != PSA_SUCCESS )
        return( status );

    operation->password = mbedtls_calloc( 1, slot->key.bytes );
    if( operation->password == NULL )
    {
        psa_unlock_key_slot( slot );
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    }
    memcpy( operation->password, slot->key.data, slot->key.bytes );
    operation->password_len = slot->key.bytes;

    status = psa_unlock_key_slot( slot );
    if( status != PSA_SUCCESS )
        return( status );

    return( PSA_SUCCESS );

error:
    psa_pake_abort(operation);
    return( status );
}

psa_status_t psa_pake_set_user( psa_pake_operation_t *operation,
                                const uint8_t *user_id,
                                size_t user_id_len )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->alg == PSA_ALG_NONE ||
        operation->state != PSA_PAKE_STATE_SETUP )
    {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }

    if( user_id_len == 0 || user_id == NULL )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    status = PSA_ERROR_NOT_SUPPORTED;

error:
    psa_pake_abort(operation);
    return( status );
}

psa_status_t psa_pake_set_peer( psa_pake_operation_t *operation,
                                const uint8_t *peer_id,
                                size_t peer_id_len )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->alg == PSA_ALG_NONE ||
        operation->state != PSA_PAKE_STATE_SETUP )
    {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }

    if( peer_id_len == 0 || peer_id == NULL )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto error;
    }

    status = PSA_ERROR_NOT_SUPPORTED;

error:
    psa_pake_abort(operation);
    return( status );
}

psa_status_t psa_pake_set_role( psa_pake_operation_t *operation,
                                psa_pake_role_t role )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->alg == PSA_ALG_NONE ||
        operation->state != PSA_PAKE_STATE_SETUP )
    {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }

    if( role != PSA_PAKE_ROLE_NONE &&
        role != PSA_PAKE_ROLE_FIRST &&
        role != PSA_PAKE_ROLE_SECOND &&
        role != PSA_PAKE_ROLE_CLIENT &&
        role != PSA_PAKE_ROLE_SERVER )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto error;
    }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    if( operation->alg == PSA_ALG_JPAKE )
    {
        if( role != PSA_PAKE_ROLE_CLIENT &&
            role != PSA_PAKE_ROLE_SERVER )
            return( PSA_ERROR_NOT_SUPPORTED );

        operation->role = role;

        return( PSA_SUCCESS );
    }
    else
#endif
        status = PSA_ERROR_NOT_SUPPORTED;

error:
    psa_pake_abort(operation);
    return( status );
}

#if defined(MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
static psa_status_t psa_pake_ecjpake_setup( psa_pake_operation_t *operation )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecjpake_role role;

    if( operation->role == PSA_PAKE_ROLE_CLIENT )
        role = MBEDTLS_ECJPAKE_CLIENT;
    else if( operation->role == PSA_PAKE_ROLE_SERVER )
        role = MBEDTLS_ECJPAKE_SERVER;
    else
        return( PSA_ERROR_BAD_STATE );

    if( operation->password_len == 0 )
        return( PSA_ERROR_BAD_STATE );

    ret = mbedtls_ecjpake_setup( &operation->ctx.ecjpake,
                                 role,
                                 MBEDTLS_MD_SHA256,
                                 MBEDTLS_ECP_DP_SECP256R1,
                                 operation->password,
                                 operation->password_len );

    mbedtls_platform_zeroize( operation->password, operation->password_len );
    mbedtls_free( operation->password );
    operation->password = NULL;
    operation->password_len = 0;

    if( ret != 0 )
        return( mbedtls_ecjpake_to_psa_error( ret ) );

    operation->state = PSA_PAKE_STATE_READY;

    return( PSA_SUCCESS );
}
#endif

static psa_status_t psa_pake_output_internal(
                              psa_pake_operation_t *operation,
                              psa_pake_step_t step,
                              uint8_t *output,
                              size_t output_size,
                              size_t *output_length )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t length;

    if( operation->alg == PSA_ALG_NONE ||
        operation->state == PSA_PAKE_STATE_INVALID )
        return( PSA_ERROR_BAD_STATE );

    if( output == NULL || output_size == 0 || output_length == NULL )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
   
    if( operation->alg == PSA_ALG_JPAKE )
    {
        if( step != PSA_PAKE_STEP_KEY_SHARE &&
            step != PSA_PAKE_STEP_ZK_PUBLIC &&
            step != PSA_PAKE_STEP_ZK_PROOF )
            return( PSA_ERROR_INVALID_ARGUMENT );

        if( operation->state == PSA_PAKE_STATE_SETUP ) {
            status = psa_pake_ecjpake_setup( operation );
            if( status != PSA_SUCCESS )
                return( status );
        }

        if( operation->state != PSA_PAKE_STATE_READY &&
            operation->state != PSA_PAKE_OUTPUT_X1_X2 &&
            operation->state != PSA_PAKE_OUTPUT_X2S )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        if( operation->state == PSA_PAKE_STATE_READY )
        {
            if( step != PSA_PAKE_STEP_KEY_SHARE )
                return( PSA_ERROR_BAD_STATE );

            switch( operation->output_step )
            {
                case PSA_PAKE_STEP_X1_X2:
                    operation->state = PSA_PAKE_OUTPUT_X1_X2;
                    break;
                case PSA_PAKE_STEP_X2S:
                    operation->state = PSA_PAKE_OUTPUT_X2S;
                    break;
                default:
                    return( PSA_ERROR_BAD_STATE );
            }

            operation->sequence = PSA_PAKE_X1_STEP_KEY_SHARE;
        }

       
        switch( operation->sequence )
        {
            case PSA_PAKE_X1_STEP_KEY_SHARE:
            case PSA_PAKE_X2_STEP_KEY_SHARE:
                if( step != PSA_PAKE_STEP_KEY_SHARE )
                    return( PSA_ERROR_BAD_STATE );
                break;

            case PSA_PAKE_X1_STEP_ZK_PUBLIC:
            case PSA_PAKE_X2_STEP_ZK_PUBLIC:
                if( step != PSA_PAKE_STEP_ZK_PUBLIC )
                    return( PSA_ERROR_BAD_STATE );
                break;

            case PSA_PAKE_X1_STEP_ZK_PROOF:
            case PSA_PAKE_X2_STEP_ZK_PROOF:
                if( step != PSA_PAKE_STEP_ZK_PROOF )
                    return( PSA_ERROR_BAD_STATE );
                break;

            default:
                return( PSA_ERROR_BAD_STATE );
        }

       
        if( operation->state == PSA_PAKE_OUTPUT_X1_X2 &&
            operation->sequence == PSA_PAKE_X1_STEP_KEY_SHARE )
        {
            ret = mbedtls_ecjpake_write_round_one( &operation->ctx.ecjpake,
                                                   operation->buffer,
                                                   MBEDTLS_PSA_PAKE_BUFFER_SIZE,
                                                   &operation->buffer_length,
                                                   mbedtls_psa_get_random,
                                                   MBEDTLS_PSA_RANDOM_STATE );
            if( ret != 0 )
                return( mbedtls_ecjpake_to_psa_error( ret ) );

            operation->buffer_offset = 0;
        }
        else if( operation->state == PSA_PAKE_OUTPUT_X2S &&
                 operation->sequence == PSA_PAKE_X1_STEP_KEY_SHARE )
        {
            ret = mbedtls_ecjpake_write_round_two( &operation->ctx.ecjpake,
                                                   operation->buffer,
                                                   MBEDTLS_PSA_PAKE_BUFFER_SIZE,
                                                   &operation->buffer_length,
                                                   mbedtls_psa_get_random,
                                                   MBEDTLS_PSA_RANDOM_STATE );
            if( ret != 0 )
                return( mbedtls_ecjpake_to_psa_error( ret ) );

            operation->buffer_offset = 0;
        }

       
        if( operation->state == PSA_PAKE_OUTPUT_X2S &&
            operation->sequence == PSA_PAKE_X1_STEP_KEY_SHARE &&
            operation->role == PSA_PAKE_ROLE_SERVER )
        {
           
            operation->buffer_offset += 3;
        }

       
        length = operation->buffer[operation->buffer_offset];
        operation->buffer_offset += 1;

        if( operation->buffer_offset + length > operation->buffer_length )
            return( PSA_ERROR_DATA_CORRUPT );

        if( output_size < length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        memcpy( output,
                operation->buffer + operation->buffer_offset,
                length );
        *output_length = length;

        operation->buffer_offset += length;

       
        if( ( operation->state == PSA_PAKE_OUTPUT_X1_X2 &&
              operation->sequence == PSA_PAKE_X2_STEP_ZK_PROOF ) ||
            ( operation->state == PSA_PAKE_OUTPUT_X2S &&
              operation->sequence == PSA_PAKE_X1_STEP_ZK_PROOF ) )
        {
            mbedtls_platform_zeroize( operation->buffer, MBEDTLS_PSA_PAKE_BUFFER_SIZE );
            operation->buffer_length = 0;
            operation->buffer_offset = 0;

            operation->state = PSA_PAKE_STATE_READY;
            operation->output_step++;
            operation->sequence = PSA_PAKE_SEQ_INVALID;
        }
        else
            operation->sequence++;

        return( PSA_SUCCESS );
    }
    else
#endif
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t psa_pake_output( psa_pake_operation_t *operation,
                              psa_pake_step_t step,
                              uint8_t *output,
                              size_t output_size,
                              size_t *output_length )
{
    psa_status_t status = psa_pake_output_internal(
            operation, step, output, output_size, output_length );

    if( status != PSA_SUCCESS )
        psa_pake_abort( operation );

    return( status );
}

static psa_status_t psa_pake_input_internal(
                             psa_pake_operation_t *operation,
                             psa_pake_step_t step,
                             const uint8_t *input,
                             size_t input_length )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->alg == PSA_ALG_NONE ||
        operation->state == PSA_PAKE_STATE_INVALID )
        return( PSA_ERROR_BAD_STATE );

    if( input == NULL || input_length == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
   
    if( operation->alg == PSA_ALG_JPAKE )
    {
        if( step != PSA_PAKE_STEP_KEY_SHARE &&
            step != PSA_PAKE_STEP_ZK_PUBLIC &&
            step != PSA_PAKE_STEP_ZK_PROOF )
            return( PSA_ERROR_INVALID_ARGUMENT );

        const psa_pake_primitive_t prim = PSA_PAKE_PRIMITIVE(
                PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256 );
        if( input_length > (size_t) PSA_PAKE_INPUT_SIZE( PSA_ALG_JPAKE, prim, step ) )
            return( PSA_ERROR_INVALID_ARGUMENT );

        if( operation->state == PSA_PAKE_STATE_SETUP )
        {
            status = psa_pake_ecjpake_setup( operation );
            if( status != PSA_SUCCESS )
                return( status );
        }

        if( operation->state != PSA_PAKE_STATE_READY &&
            operation->state != PSA_PAKE_INPUT_X1_X2 &&
            operation->state != PSA_PAKE_INPUT_X4S )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        if( operation->state == PSA_PAKE_STATE_READY )
        {
            if( step != PSA_PAKE_STEP_KEY_SHARE )
                return( PSA_ERROR_BAD_STATE );

            switch( operation->input_step )
            {
                case PSA_PAKE_STEP_X1_X2:
                    operation->state = PSA_PAKE_INPUT_X1_X2;
                    break;
                case PSA_PAKE_STEP_X2S:
                    operation->state = PSA_PAKE_INPUT_X4S;
                    break;
                default:
                    return( PSA_ERROR_BAD_STATE );
            }

            operation->sequence = PSA_PAKE_X1_STEP_KEY_SHARE;
        }

       
        switch( operation->sequence )
        {
            case PSA_PAKE_X1_STEP_KEY_SHARE:
            case PSA_PAKE_X2_STEP_KEY_SHARE:
                if( step != PSA_PAKE_STEP_KEY_SHARE )
                    return( PSA_ERROR_BAD_STATE );
                break;

            case PSA_PAKE_X1_STEP_ZK_PUBLIC:
            case PSA_PAKE_X2_STEP_ZK_PUBLIC:
                if( step != PSA_PAKE_STEP_ZK_PUBLIC )
                    return( PSA_ERROR_BAD_STATE );
                break;

            case PSA_PAKE_X1_STEP_ZK_PROOF:
            case PSA_PAKE_X2_STEP_ZK_PROOF:
                if( step != PSA_PAKE_STEP_ZK_PROOF )
                    return( PSA_ERROR_BAD_STATE );
                break;

            default:
                return( PSA_ERROR_BAD_STATE );
        }

       
        if( operation->state == PSA_PAKE_INPUT_X4S &&
            operation->sequence == PSA_PAKE_X1_STEP_KEY_SHARE &&
            operation->role == PSA_PAKE_ROLE_CLIENT )
        {
           
           
            unsigned char ecparameters[3] = {
                3,
                0, 23
            };
            memcpy( operation->buffer + operation->buffer_length,
                    ecparameters, sizeof( ecparameters ) );
            operation->buffer_length += sizeof( ecparameters );
        }

       
        operation->buffer[operation->buffer_length] = (uint8_t) input_length;
        operation->buffer_length += 1;

       
        memcpy( operation->buffer + operation->buffer_length,
                input, input_length );
        operation->buffer_length += input_length;

       
        if( operation->state == PSA_PAKE_INPUT_X1_X2 &&
            operation->sequence == PSA_PAKE_X2_STEP_ZK_PROOF )
        {
            ret = mbedtls_ecjpake_read_round_one( &operation->ctx.ecjpake,
                                                  operation->buffer,
                                                  operation->buffer_length );

            mbedtls_platform_zeroize( operation->buffer, MBEDTLS_PSA_PAKE_BUFFER_SIZE );
            operation->buffer_length = 0;

            if( ret != 0 )
                return( mbedtls_ecjpake_to_psa_error( ret ) );
        }
        else if( operation->state == PSA_PAKE_INPUT_X4S &&
                 operation->sequence == PSA_PAKE_X1_STEP_ZK_PROOF )
        {
            ret = mbedtls_ecjpake_read_round_two( &operation->ctx.ecjpake,
                                                  operation->buffer,
                                                  operation->buffer_length );

            mbedtls_platform_zeroize( operation->buffer, MBEDTLS_PSA_PAKE_BUFFER_SIZE );
            operation->buffer_length = 0;

            if( ret != 0 )
                return( mbedtls_ecjpake_to_psa_error( ret ) );
        }

        if( ( operation->state == PSA_PAKE_INPUT_X1_X2 &&
              operation->sequence == PSA_PAKE_X2_STEP_ZK_PROOF ) ||
            ( operation->state == PSA_PAKE_INPUT_X4S &&
              operation->sequence == PSA_PAKE_X1_STEP_ZK_PROOF ) )
        {
            operation->state = PSA_PAKE_STATE_READY;
            operation->input_step++;
            operation->sequence = PSA_PAKE_SEQ_INVALID;
        }
        else
            operation->sequence++;

        return( PSA_SUCCESS );
    }
    else
#endif
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t psa_pake_input( psa_pake_operation_t *operation,
                             psa_pake_step_t step,
                             const uint8_t *input,
                             size_t input_length )
{
    psa_status_t status = psa_pake_input_internal(
            operation, step, input, input_length );

    if( status != PSA_SUCCESS )
        psa_pake_abort( operation );

    return( status );
}

psa_status_t psa_pake_get_implicit_key(psa_pake_operation_t *operation,
                                       psa_key_derivation_operation_t *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->alg == PSA_ALG_NONE ||
        operation->state != PSA_PAKE_STATE_READY ||
        operation->input_step != PSA_PAKE_STEP_DERIVE ||
        operation->output_step != PSA_PAKE_STEP_DERIVE )
    {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    if( operation->alg == PSA_ALG_JPAKE )
    {
        ret = mbedtls_ecjpake_write_shared_key( &operation->ctx.ecjpake,
                                                operation->buffer,
                                                MBEDTLS_PSA_PAKE_BUFFER_SIZE,
                                                &operation->buffer_length,
                                                mbedtls_psa_get_random,
                                                MBEDTLS_PSA_RANDOM_STATE );
        if( ret != 0)
        {
            psa_pake_abort( operation );
            return( mbedtls_ecjpake_to_psa_error( ret ) );
        }

        status = psa_key_derivation_input_bytes( output,
                                                 PSA_KEY_DERIVATION_INPUT_SECRET,
                                                 operation->buffer,
                                                 operation->buffer_length );

        mbedtls_platform_zeroize( operation->buffer, MBEDTLS_PSA_PAKE_BUFFER_SIZE );

        psa_pake_abort( operation );

        return( status );
    }
    else
#endif
    status = PSA_ERROR_NOT_SUPPORTED;

error:
    psa_key_derivation_abort( output );
    psa_pake_abort( operation );

    return( status );
}

psa_status_t psa_pake_abort(psa_pake_operation_t * operation)
{
    if( operation->alg == PSA_ALG_NONE )
    {
        return( PSA_SUCCESS );
    }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_JPAKE)
    if( operation->alg == PSA_ALG_JPAKE )
    {
        operation->input_step = PSA_PAKE_STEP_INVALID;
        operation->output_step = PSA_PAKE_STEP_INVALID;
        if( operation->password_len > 0 )
            mbedtls_platform_zeroize( operation->password, operation->password_len );
        mbedtls_free( operation->password );
        operation->password = NULL;
        operation->password_len = 0;
        operation->role = PSA_PAKE_ROLE_NONE;
        mbedtls_platform_zeroize( operation->buffer, MBEDTLS_PSA_PAKE_BUFFER_SIZE );
        operation->buffer_length = 0;
        operation->buffer_offset = 0;
        mbedtls_ecjpake_free( &operation->ctx.ecjpake );
    }
#endif

    operation->alg = PSA_ALG_NONE;
    operation->state = PSA_PAKE_STATE_INVALID;
    operation->sequence = PSA_PAKE_SEQ_INVALID;

    return( PSA_SUCCESS );
}

#endif

#endif
