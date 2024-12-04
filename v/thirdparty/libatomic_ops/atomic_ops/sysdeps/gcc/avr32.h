

#include "../all_atomic_load_store.h"

#include "../ordered.h"

#include "../test_and_set_t_is_ao_t.h"

#ifndef AO_PREFER_GENERALIZED
  AO_INLINE AO_TS_VAL_t
  AO_test_and_set_full(volatile AO_TS_t *addr)
  {
        register long ret;

        __asm__ __volatile__(
                "xchg %[oldval], %[mem], %[newval]"
                : [oldval] "=&r"(ret)
                : [mem] "r"(addr), [newval] "r"(1)
                : "memory");

        return (AO_TS_VAL_t)ret;
  }
# define AO_HAVE_test_and_set_full
#endif

AO_INLINE int
AO_compare_and_swap_full(volatile AO_t *addr, AO_t old, AO_t new_val)
{
       register long ret;

       __asm__ __volatile__(
               "1: ssrf    5\n"
               "   ld.w    %[res], %[mem]\n"
               "   eor     %[res], %[oldval]\n"
               "   brne    2f\n"
               "   stcond  %[mem], %[newval]\n"
               "   brne    1b\n"
               "2:\n"
               : [res] "=&r"(ret), [mem] "=m"(*addr)
               : "m"(*addr), [newval] "r"(new_val), [oldval] "r"(old)
               : "cc", "memory");

       return (int)ret;
}
#define AO_HAVE_compare_and_swap_full



#define AO_T_IS_INT
