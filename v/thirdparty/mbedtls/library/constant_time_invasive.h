
#ifndef MBEDTLS_CONSTANT_TIME_INVASIVE_H
#define MBEDTLS_CONSTANT_TIME_INVASIVE_H

#include "common.h"

#if defined(MBEDTLS_TEST_HOOKS)

/** Turn a value into a mask:
 * - if \p low <= \p c <= \p high,
 *   return the all-bits 1 mask, aka (unsigned) -1
 * - otherwise, return the all-bits 0 mask, aka 0
 *
 * \param low   The value to analyze.
 * \param high  The value to analyze.
 * \param c     The value to analyze.
 *
 * \return      All-bits-one if \p low <= \p c <= \p high, otherwise zero.
 */
unsigned char mbedtls_ct_uchar_mask_of_range( unsigned char low,
                                              unsigned char high,
                                              unsigned char c );

#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_CONSTANT_TIME_INVASIVE_H */
