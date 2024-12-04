

#include "../all_atomic_load_store.h"





#include "../ordered.h"




struct AO_pa_clearable_loc {
  int data[4];
};

#undef AO_TS_INITIALIZER
#define AO_TS_t struct AO_pa_clearable_loc
#define AO_TS_INITIALIZER { { 1, 1, 1, 1 } }


typedef enum {AO_PA_TS_set = 0, AO_PA_TS_clear = 1} AO_PA_TS_val;
#define AO_TS_VAL_t AO_PA_TS_val
#define AO_TS_CLEAR AO_PA_TS_clear
#define AO_TS_SET AO_PA_TS_set





#define AO_ldcw(a, ret) \
  __asm__ __volatile__("ldcw 0(%2), %0" \
                       : "=r" (ret), "=m" (*(a)) : "r" (a))








#define AO_PA_LDCW_ALIGNMENT 16
#define AO_ldcw_align(addr) \
            ((volatile unsigned *)(((unsigned long)(addr) \
                                        + (AO_PA_LDCW_ALIGNMENT - 1)) \
                                   & ~(AO_PA_LDCW_ALIGNMENT - 1)))


AO_INLINE AO_TS_VAL_t
AO_test_and_set_full(volatile AO_TS_t * addr)
{
  volatile unsigned int ret;
  volatile unsigned *a = AO_ldcw_align(addr);

  AO_ldcw(a, ret);
  return (AO_TS_VAL_t)ret;
}
#define AO_HAVE_test_and_set_full

AO_INLINE void
AO_pa_clear(volatile AO_TS_t * addr)
{
  volatile unsigned *a = AO_ldcw_align(addr);

  AO_compiler_barrier();
  *a = 1;
}
#define AO_CLEAR(addr) AO_pa_clear(addr)
#define AO_HAVE_CLEAR

#undef AO_PA_LDCW_ALIGNMENT
#undef AO_ldcw
#undef AO_ldcw_align
