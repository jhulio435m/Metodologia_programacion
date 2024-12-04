



#undef AO_t
typedef unsigned long AO_t __attribute__((__aligned__(4)));


#include "../all_aligned_atomic_load_store.h"



#include "../ordered.h"

#include "../test_and_set_t_is_char.h"

AO_INLINE AO_TS_VAL_t
AO_test_and_set_full(volatile AO_TS_t *addr) {
  AO_TS_t oldval;

 
 
 
 
  __asm__ __volatile__(
                "tas %1; sne %0"
                : "=d" (oldval), "=m" (*addr)
                : "m" (*addr)
                : "memory");
 
  return (AO_TS_VAL_t)oldval;
}
#define AO_HAVE_test_and_set_full


AO_INLINE int
AO_compare_and_swap_full(volatile AO_t *addr,
                         AO_t old, AO_t new_val)
{
  char result;

  __asm__ __volatile__(
                "cas.l %3,%4,%1; seq %0"
                : "=d" (result), "=m" (*addr)
                : "m" (*addr), "d" (old), "d" (new_val)
                : "memory");
  return -result;
}
#define AO_HAVE_compare_and_swap_full



#define AO_T_IS_INT
