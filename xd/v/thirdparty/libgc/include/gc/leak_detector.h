

#ifndef GC_LEAK_DETECTOR_H
#define GC_LEAK_DETECTOR_H




#ifndef GC_DEBUG
# define GC_DEBUG
#endif
#include "gc.h"

#ifndef GC_DONT_INCLUDE_STDLIB
 
 
# include <stdlib.h>
# include <string.h>
#endif

#undef malloc
#define malloc(n) GC_MALLOC(n)
#undef calloc
#define calloc(m,n) GC_MALLOC((m)*(n))
#undef free
#define free(p) GC_FREE(p)
#undef realloc
#define realloc(p,n) GC_REALLOC(p,n)
#undef reallocarray
#define reallocarray(p,m,n) GC_REALLOC(p,(m)*(n))

#undef strdup
#define strdup(s) GC_STRDUP(s)
#undef strndup
#define strndup(s,n) GC_STRNDUP(s,n)

#ifdef GC_REQUIRE_WCSDUP
 
 
# include <wchar.h>
# undef wcsdup
# define wcsdup(s) GC_WCSDUP(s)
#endif






#undef aligned_alloc
#define aligned_alloc(a,n) GC_memalign(a,n)
#undef memalign
#define memalign(a,n) GC_memalign(a,n)
#undef posix_memalign
#define posix_memalign(p,a,n) GC_posix_memalign(p,a,n)

#undef _aligned_malloc
#define _aligned_malloc(n,a) GC_memalign(a,n)
#undef _aligned_free
#define _aligned_free(p) GC_free(p)

#ifndef GC_NO_VALLOC
# undef valloc
# define valloc(n) GC_valloc(n)
# undef pvalloc
# define pvalloc(n) GC_pvalloc(n)
#endif

#undef malloc_usable_size
#define malloc_usable_size(p) GC_size(p)
#undef malloc_size
#define malloc_size(p) GC_size(p)
#undef _msize
#define _msize(p) GC_size(p)

#ifndef CHECK_LEAKS
# define CHECK_LEAKS() GC_gcollect()
 
 
 
 
#endif

#endif
