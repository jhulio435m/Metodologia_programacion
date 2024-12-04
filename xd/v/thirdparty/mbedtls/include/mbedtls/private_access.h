

#ifndef MBEDTLS_PRIVATE_ACCESS_H
#define MBEDTLS_PRIVATE_ACCESS_H

#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_PRIVATE(member) private_##member
#else
#define MBEDTLS_PRIVATE(member) member
#endif

#endif /* MBEDTLS_PRIVATE_ACCESS_H */
