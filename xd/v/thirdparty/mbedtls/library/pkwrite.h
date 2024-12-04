/**
 * \file pkwrite.h
 *
 * \brief Internal defines shared by the PK write module
 */


#ifndef MBEDTLS_PK_WRITE_H
#define MBEDTLS_PK_WRITE_H

#include "mbedtls/build_info.h"

#include "mbedtls/pk.h"



#if defined(MBEDTLS_RSA_C)

#define MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES    ( 38 + 2 * MBEDTLS_MPI_MAX_SIZE )


#define MBEDTLS_MPI_MAX_SIZE_2  ( MBEDTLS_MPI_MAX_SIZE / 2 + \
                                  MBEDTLS_MPI_MAX_SIZE % 2 )
#define MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES    ( 47 + 3 * MBEDTLS_MPI_MAX_SIZE \
                                              + 5 * MBEDTLS_MPI_MAX_SIZE_2 )

#else

#define MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES   0
#define MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES   0

#endif

#if defined(MBEDTLS_ECP_C)

#define MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES    ( 30 + 2 * MBEDTLS_ECP_MAX_BYTES )


#define MBEDTLS_PK_ECP_PRV_DER_MAX_BYTES    ( 29 + 3 * MBEDTLS_ECP_MAX_BYTES )

#else

#define MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES   0
#define MBEDTLS_PK_ECP_PRV_DER_MAX_BYTES   0

#endif

#endif
