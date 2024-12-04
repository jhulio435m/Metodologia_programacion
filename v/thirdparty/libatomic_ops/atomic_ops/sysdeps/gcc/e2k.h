


#define AO_GCC_FORCE_HAVE_CAS

#if (__SIZEOF_SIZE_T__ == 4) \
    || (defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16) && !defined(__clang__)) \
    || (defined(__clang__) && __iset__ >= 5 \
        && defined(AO_PREFER_BUILTIN_ATOMICS))
 
 
 
# define AO_GCC_HAVE_double_SYNC_CAS
# include "../standard_ao_double_t.h"
#endif

#include "generic.h"

#undef AO_GCC_FORCE_HAVE_CAS
#undef AO_GCC_HAVE_double_SYNC_CAS
