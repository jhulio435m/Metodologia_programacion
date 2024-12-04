#ifndef AO_MALLOC_H
#define AO_MALLOC_H

#include "atomic_ops_stack.h"

#include <stddef.h>

#ifdef __cplusplus
  extern "C" {
#endif

#ifdef AO_STACK_IS_LOCK_FREE
# define AO_MALLOC_IS_LOCK_FREE
#endif

#ifndef AO_ATTR_MALLOC
# if AO_GNUC_PREREQ(3, 1)
#   define AO_ATTR_MALLOC __attribute__((__malloc__))
# elif defined(_MSC_VER) && (_MSC_VER >= 1900) && !defined(__EDG__)
#   define AO_ATTR_MALLOC \
                __declspec(allocator) __declspec(noalias) __declspec(restrict)
# elif defined(_MSC_VER) && _MSC_VER >= 1400
#   define AO_ATTR_MALLOC __declspec(noalias) __declspec(restrict)
# else
#   define AO_ATTR_MALLOC
# endif
#endif

#ifndef AO_ATTR_ALLOC_SIZE
# ifdef __clang__
#   if __has_attribute(__alloc_size__)
#     define AO_ATTR_ALLOC_SIZE(argnum) \
                __attribute__((__alloc_size__(argnum)))
#   else
#     define AO_ATTR_ALLOC_SIZE(argnum)
#   endif
# elif AO_GNUC_PREREQ(4, 3) && !defined(__ICC)
#   define AO_ATTR_ALLOC_SIZE(argnum) __attribute__((__alloc_size__(argnum)))
# else
#   define AO_ATTR_ALLOC_SIZE(argnum)
# endif
#endif

AO_API void AO_free(void *);

AO_API AO_ATTR_MALLOC AO_ATTR_ALLOC_SIZE(1)
void * AO_malloc(size_t);


AO_API void AO_malloc_enable_mmap(void);

#ifdef __cplusplus
  }
#endif

#endif
