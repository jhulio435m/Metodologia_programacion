


#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include "common.h"

#include "mbedtls/platform_util.h"
#include "mbedtls/platform.h"
#include "mbedtls/threading.h"

#include <stddef.h>
#include <string.h>

#if !defined(MBEDTLS_PLATFORM_ZEROIZE_ALT)

static void * (* const volatile memset_func)( void *, int, size_t ) = memset;

void mbedtls_platform_zeroize( void *buf, size_t len )
{
    MBEDTLS_INTERNAL_VALIDATE( len == 0 || buf != NULL );

    if( len > 0 )
        memset_func( buf, 0, len );
}
#endif

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)
#define __STDC_WANT_LIB_EXT1__ 1 
#include <time.h>
#if !defined(_WIN32) && (defined(unix) || \
    defined(__unix) || defined(__unix__) || (defined(__APPLE__) && \
    defined(__MACH__)))
#include <unistd.h>
#endif

#if !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) ||     \
       ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) &&                     \
         _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L ) )

#if ! ( defined(_WIN32) && !defined(EFIX64) && !defined(EFI32) ) || \
      ( defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR) )
#define PLATFORM_UTIL_USE_GMTIME
#endif

#endif

struct tm *mbedtls_platform_gmtime_r( const mbedtls_time_t *tt,
                                      struct tm *tm_buf )
{
#if defined(_WIN32) && !defined(PLATFORM_UTIL_USE_GMTIME)
#if defined(__STDC_LIB_EXT1__)
    return( ( gmtime_s( tt, tm_buf ) == 0 ) ? NULL : tm_buf );
#else
   
    return( ( gmtime_s( tm_buf, tt ) == 0 ) ? tm_buf : NULL );
#endif
#elif !defined(PLATFORM_UTIL_USE_GMTIME)
    return( gmtime_r( tt, tm_buf ) );
#else
    struct tm *lt;

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &mbedtls_threading_gmtime_mutex ) != 0 )
        return( NULL );
#endif

    lt = gmtime( tt );

    if( lt != NULL )
    {
        memcpy( tm_buf, lt, sizeof( struct tm ) );
    }

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &mbedtls_threading_gmtime_mutex ) != 0 )
        return( NULL );
#endif

    return( ( lt == NULL ) ? NULL : tm_buf );
#endif
}
#endif

#if defined(MBEDTLS_TEST_HOOKS)
void (*mbedtls_test_hook_test_fail)( const char *, int, const char *);
#endif

