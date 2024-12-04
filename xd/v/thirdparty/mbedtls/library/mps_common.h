

/**
 * \file mps_common.h
 *
 * \brief Common functions and macros used by MPS
 */

#ifndef MBEDTLS_MPS_COMMON_H
#define MBEDTLS_MPS_COMMON_H

#include "mps_error.h"

#include <stdio.h>

/**
 * \name SECTION:       MPS Configuration
 *
 * \{
 */


#define MBEDTLS_MPS_STATE_VALIDATION


#define MBEDTLS_MPS_ENABLE_ASSERTIONS


//#define MBEDTLS_MPS_ENABLE_TRACE

#if defined(MBEDTLS_MPS_STATE_VALIDATION)

#define MBEDTLS_MPS_STATE_VALIDATE_RAW( cond, string )                         \
    do                                                                         \
    {                                                                          \
        if( !(cond) )                                                          \
        {                                                                      \
            MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_ERROR, string );         \
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED );  \
        }                                                                      \
    } while( 0 )

#else

#define MBEDTLS_MPS_STATE_VALIDATE_RAW( cond, string )           \
    do                                                           \
    {                                                            \
        ( cond );                                                \
    } while( 0 )

#endif

#if defined(MBEDTLS_MPS_ENABLE_ASSERTIONS)

#define MBEDTLS_MPS_ASSERT_RAW( cond, string )                          \
    do                                                                  \
    {                                                                   \
        if( !(cond) )                                                   \
        {                                                               \
            MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_ERROR, string );  \
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_INTERNAL_ERROR ); \
        }                                                               \
    } while( 0 )

#else

#define MBEDTLS_MPS_ASSERT_RAW( cond, string ) do {} while( 0 )

#endif




/**
 * \name SECTION:       Common types
 *
 * Various common types used throughout MPS.
 * \{
 */

/** \brief   The type of buffer sizes and offsets used in MPS structures.
 *
 *           This is an unsigned integer type that should be large enough to
 *           hold the length of any buffer or message processed by MPS.
 *
 *           The reason to pick a value as small as possible here is
 *           to reduce the size of MPS structures.
 *
 * \warning  Care has to be taken when using a narrower type
 *           than ::mbedtls_mps_size_t here because of
 *           potential truncation during conversion.
 *
 * \warning  Handshake messages in TLS may be up to 2^24 ~ 16Mb in size.
 *           If mbedtls_mps_[opt_]stored_size_t is smaller than that, the
 *           maximum handshake message is restricted accordingly.
 *
 * For now, we use the default type of size_t throughout, and the use of
 * smaller types or different types for ::mbedtls_mps_size_t and
 * ::mbedtls_mps_stored_size_t is not yet supported.
 *
 */
typedef size_t mbedtls_mps_stored_size_t;
#define MBEDTLS_MPS_STORED_SIZE_MAX  ( (mbedtls_mps_stored_size_t) -1 )

/** \brief The type of buffer sizes and offsets used in the MPS API
 *         and implementation.
 *
 *         This must be at least as wide as ::mbedtls_stored_size_t but
 *         may be chosen to be strictly larger if more suitable for the
 *         target architecture.
 *
 *         For example, in a test build for ARM Thumb, using uint_fast16_t
 *         instead of uint16_t reduced the code size from 1060 Byte to 962 Byte,
 *         so almost 10%.
 */
typedef size_t mbedtls_mps_size_t;
#define MBEDTLS_MPS_SIZE_MAX  ( (mbedtls_mps_size_t) -1 )

#if MBEDTLS_MPS_STORED_SIZE_MAX > MBEDTLS_MPS_SIZE_MAX
#error "Misconfiguration of mbedtls_mps_size_t and mbedtls_mps_stored_size_t."
#endif




#endif
