
#ifndef MBEDTLS_ERROR_H
#define MBEDTLS_ERROR_H

#include "mbedtls/build_info.h"

#include <stddef.h>



#ifdef __cplusplus
extern "C" {
#endif

/** Generic error */
#define MBEDTLS_ERR_ERROR_GENERIC_ERROR       -0x0001
/** This is a bug in the library */
#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E

/** Hardware accelerator failed */
#define MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED     -0x0070
/** The requested feature is not supported by the platform */
#define MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED -0x0072

/**
 * \brief Combines a high-level and low-level error code together.
 *
 *        Wrapper macro for mbedtls_error_add(). See that function for
 *        more details.
 */
#define MBEDTLS_ERROR_ADD( high, low ) \
        mbedtls_error_add( high, low, __FILE__, __LINE__ )

#if defined(MBEDTLS_TEST_HOOKS)
/**
 * \brief Testing hook called before adding/combining two error codes together.
 *        Only used when invasive testing is enabled via MBEDTLS_TEST_HOOKS.
 */
extern void (*mbedtls_test_hook_error_add)( int, int, const char *, int );
#endif

/**
 * \brief Combines a high-level and low-level error code together.
 *
 *        This function can be called directly however it is usually
 *        called via the #MBEDTLS_ERROR_ADD macro.
 *
 *        While a value of zero is not a negative error code, it is still an
 *        error code (that denotes success) and can be combined with both a
 *        negative error code or another value of zero.
 *
 * \note  When invasive testing is enabled via #MBEDTLS_TEST_HOOKS, also try to
 *        call \link mbedtls_test_hook_error_add \endlink.
 *
 * \param high      high-level error code. See error.h for more details.
 * \param low       low-level error code. See error.h for more details.
 * \param file      file where this error code addition occurred.
 * \param line      line where this error code addition occurred.
 */
static inline int mbedtls_error_add( int high, int low,
                                     const char *file, int line )
{
#if defined(MBEDTLS_TEST_HOOKS)
    if( *mbedtls_test_hook_error_add != NULL )
        ( *mbedtls_test_hook_error_add )( high, low, file, line );
#endif
    (void)file;
    (void)line;

    return( high + low );
}

/**
 * \brief Translate a mbed TLS error code into a string representation,
 *        Result is truncated if necessary and always includes a terminating
 *        null byte.
 *
 * \param errnum    error code
 * \param buffer    buffer to place representation in
 * \param buflen    length of the buffer
 */
void mbedtls_strerror( int errnum, char *buffer, size_t buflen );

/**
 * \brief Translate the high-level part of an Mbed TLS error code into a string
 *        representation.
 *
 * This function returns a const pointer to an un-modifiable string. The caller
 * must not try to modify the string. It is intended to be used mostly for
 * logging purposes.
 *
 * \param error_code    error code
 *
 * \return The string representation of the error code, or \c NULL if the error
 *         code is unknown.
 */
const char * mbedtls_high_level_strerr( int error_code );

/**
 * \brief Translate the low-level part of an Mbed TLS error code into a string
 *        representation.
 *
 * This function returns a const pointer to an un-modifiable string. The caller
 * must not try to modify the string. It is intended to be used mostly for
 * logging purposes.
 *
 * \param error_code    error code
 *
 * \return The string representation of the error code, or \c NULL if the error
 *         code is unknown.
 */
const char * mbedtls_low_level_strerr( int error_code );

#ifdef __cplusplus
}
#endif

#endif /* error.h */
