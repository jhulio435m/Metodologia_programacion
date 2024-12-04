

#include "../loadstore/atomic_load.h"
#include "../loadstore/atomic_store.h"

#include "../test_and_set_t_is_ao_t.h"

#define AO_NO_DD_ORDERING
       

AO_INLINE void
AO_nop_full(void)
{
  __asm__ __volatile__("mb" : : : "memory");
}
#define AO_HAVE_nop_full

AO_INLINE void
AO_nop_write(void)
{
  __asm__ __volatile__("wmb" : : : "memory");
}
#define AO_HAVE_nop_write






AO_INLINE int
AO_compare_and_swap(volatile AO_t *addr,
                    AO_t old, AO_t new_val)
{
  unsigned long was_equal;
  unsigned long temp;

  __asm__ __volatile__(
                     "1:     ldq_l %0,%1\n"
                     "       cmpeq %0,%4,%2\n"
                     "       mov %3,%0\n"
                     "       beq %2,2f\n"
                     "       stq_c %0,%1\n"
                     "       beq %0,1b\n"
                     "2:\n"
                     : "=&r" (temp), "+m" (*addr), "=&r" (was_equal)
                     : "r" (new_val), "Ir" (old)
                     :"memory");
  return (int)was_equal;
}
#define AO_HAVE_compare_and_swap


