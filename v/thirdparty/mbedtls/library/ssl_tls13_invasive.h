

#ifndef MBEDTLS_SSL_TLS13_INVASIVE_H
#define MBEDTLS_SSL_TLS13_INVASIVE_H

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#include "psa/crypto.h"

#if defined(MBEDTLS_TEST_HOOKS)
int mbedtls_ssl_tls13_parse_certificate( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end );
#endif

#endif

#endif
