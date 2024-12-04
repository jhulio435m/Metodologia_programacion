

#if defined(__linux__) && !defined(_GNU_SOURCE)

#define _GNU_SOURCE
#endif

#include "common.h"

#include <string.h>

#if defined(MBEDTLS_ENTROPY_C)

#include "mbedtls/entropy.h"
#include "entropy_poll.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_TIMING_C)
#include "mbedtls/timing.h"
#endif
#include "mbedtls/platform.h"

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)

#if !defined(unix) && !defined(__unix__) && !defined(__unix) && \
    !defined(__APPLE__) && !defined(_WIN32) && !defined(__QNXNTO__) && \
    !defined(__HAIKU__) && !defined(__midipix__)
#error "Platform entropy sources only work on Unix and Windows, see MBEDTLS_NO_PLATFORM_ENTROPY in mbedtls_config.h"
#endif

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0400
#endif
#include <windows.h>
#include <wincrypt.h>

int mbedtls_platform_entropy_poll( void *data, unsigned char *output, size_t len,
                           size_t *olen )
{
    HCRYPTPROV provider;
    ((void) data);
    *olen = 0;

    if( CryptAcquireContext( &provider, NULL, NULL,
                              PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) == FALSE )
    {
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    if( CryptGenRandom( provider, (DWORD) len, output ) == FALSE )
    {
        CryptReleaseContext( provider, 0 );
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    CryptReleaseContext( provider, 0 );
    *olen = len;

    return( 0 );
}
#else


#if ((defined(__linux__) && defined(__GLIBC__)) || defined(__midipix__))
#include <unistd.h>
#include <sys/syscall.h>
#if defined(SYS_getrandom)
#define HAVE_GETRANDOM
#include <errno.h>

static int getrandom_wrapper( void *buf, size_t buflen, unsigned int flags )
{
   
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
    memset( buf, 0, buflen );
#endif
#endif
    return( syscall( SYS_getrandom, buf, buflen, flags ) );
}
#endif
#endif

#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/param.h>
#if (defined(__FreeBSD__) && __FreeBSD_version >= 1200000) || \
    (defined(__DragonFly__) && __DragonFly_version >= 500700)
#include <errno.h>
#include <sys/random.h>
#define HAVE_GETRANDOM
static int getrandom_wrapper( void *buf, size_t buflen, unsigned int flags )
{
    return getrandom( buf, buflen, flags );
}
#endif
#endif


#if (defined(__FreeBSD__) || defined(__NetBSD__)) && !defined(HAVE_GETRANDOM)
#include <sys/param.h>
#include <sys/sysctl.h>
#if defined(KERN_ARND)
#define HAVE_SYSCTL_ARND

static int sysctl_arnd_wrapper( unsigned char *buf, size_t buflen )
{
    int name[2];
    size_t len;

    name[0] = CTL_KERN;
    name[1] = KERN_ARND;

    while( buflen > 0 )
    {
        len = buflen > 256 ? 256 : buflen;
        if( sysctl(name, 2, buf, &len, NULL, 0) == -1 )
            return( -1 );
        buflen -= len;
        buf += len;
    }
    return( 0 );
}
#endif
#endif

#include <stdio.h>

int mbedtls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen )
{
    FILE *file;
    size_t read_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) data);

#if defined(HAVE_GETRANDOM)
    ret = getrandom_wrapper( output, len, 0 );
    if( ret >= 0 )
    {
        *olen = ret;
        return( 0 );
    }
    else if( errno != ENOSYS )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
   
#else
    ((void) ret);
#endif

#if defined(HAVE_SYSCTL_ARND)
    ((void) file);
    ((void) read_len);
    if( sysctl_arnd_wrapper( output, len ) == -1 )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    *olen = len;
    return( 0 );
#else

    *olen = 0;

    file = fopen( "/dev/urandom", "rb" );
    if( file == NULL )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

   
    mbedtls_setbuf( file, NULL );

    read_len = fread( output, 1, len, file );
    if( read_len != len )
    {
        fclose( file );
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    fclose( file );
    *olen = len;

    return( 0 );
#endif
}
#endif
#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED)
int mbedtls_nv_seed_poll( void *data,
                          unsigned char *output, size_t len, size_t *olen )
{
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];
    size_t use_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    ((void) data);

    memset( buf, 0, MBEDTLS_ENTROPY_BLOCK_SIZE );

    if( mbedtls_nv_seed_read( buf, MBEDTLS_ENTROPY_BLOCK_SIZE ) < 0 )
      return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    if( len < use_len )
      use_len = len;

    memcpy( output, buf, use_len );
    *olen = use_len;

    return( 0 );
}
#endif

#endif
