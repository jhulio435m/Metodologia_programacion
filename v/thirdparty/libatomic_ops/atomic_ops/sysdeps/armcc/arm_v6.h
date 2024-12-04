#include "../test_and_set_t_is_ao_t.h"

#if __TARGET_ARCH_ARM < 6
# if !defined(CPPCHECK)
#   error Do not use with ARM instruction sets lower than v6
# endif
#else

#define AO_ACCESS_CHECK_ALIGNED
#define AO_ACCESS_short_CHECK_ALIGNED
#define AO_ACCESS_int_CHECK_ALIGNED
#include "../all_atomic_only_load.h"

#include "../standard_ao_double_t.h"



AO_INLINE void
AO_nop_full(void)
{
# ifndef AO_UNIPROCESSOR
    unsigned int dest=0;
   
   
    __asm {
            mcr p15,0,dest,c7,c10,5
            };
# else
    AO_compiler_barrier();
# endif
}
#define AO_HAVE_nop_full

AO_INLINE void AO_store(volatile AO_t *addr, AO_t value)
{
        unsigned long tmp;

retry:
__asm {
        ldrex   tmp, [addr]
        strex   tmp, value, [addr]
        teq     tmp, #0
        bne     retry
        };
}
#define AO_HAVE_store


#ifndef AO_PREFER_GENERALIZED
AO_INLINE AO_TS_VAL_t
AO_test_and_set(volatile AO_TS_t *addr) {
        AO_TS_VAL_t oldval;
        unsigned long tmp;
        unsigned long one = 1;
retry:
__asm {
        ldrex   oldval, [addr]
        strex   tmp, one, [addr]
        teq     tmp, #0
        bne     retry
        }

        return oldval;
}
#define AO_HAVE_test_and_set

AO_INLINE AO_t
AO_fetch_and_add(volatile AO_t *p, AO_t incr)
{
        unsigned long tmp,tmp2;
        AO_t result;

retry:
__asm {
        ldrex   result, [p]
        add     tmp, incr, result
        strex   tmp2, tmp, [p]
        teq     tmp2, #0
        bne     retry
        }

        return result;
}
#define AO_HAVE_fetch_and_add

AO_INLINE AO_t
AO_fetch_and_add1(volatile AO_t *p)
{
        unsigned long tmp,tmp2;
        AO_t result;

retry:
__asm {
        ldrex   result, [p]
        add     tmp, result, #1
        strex   tmp2, tmp, [p]
        teq     tmp2, #0
        bne     retry
        }

        return result;
}
#define AO_HAVE_fetch_and_add1

AO_INLINE AO_t
AO_fetch_and_sub1(volatile AO_t *p)
{
        unsigned long tmp,tmp2;
        AO_t result;

retry:
__asm {
        ldrex   result, [p]
        sub     tmp, result, #1
        strex   tmp2, tmp, [p]
        teq     tmp2, #0
        bne     retry
        }

        return result;
}
#define AO_HAVE_fetch_and_sub1
#endif

#ifndef AO_GENERALIZE_ASM_BOOL_CAS
 
  AO_INLINE int
  AO_compare_and_swap(volatile AO_t *addr, AO_t old_val, AO_t new_val)
  {
    AO_t result, tmp;

  retry:
    __asm__ {
      mov     result, #2
      ldrex   tmp, [addr]
      teq     tmp, old_val
#     ifdef __thumb__
        it      eq
#     endif
      strexeq result, new_val, [addr]
      teq     result, #1
      beq     retry
    }
    return !(result&2);
  }
# define AO_HAVE_compare_and_swap
#endif

AO_INLINE AO_t
AO_fetch_compare_and_swap(volatile AO_t *addr, AO_t old_val, AO_t new_val)
{
         AO_t fetched_val, tmp;

retry:
__asm__ {
        mov     tmp, #2
        ldrex   fetched_val, [addr]
        teq     fetched_val, old_val
#     ifdef __thumb__
        it      eq
#     endif
        strexeq tmp, new_val, [addr]
        teq     tmp, #1
        beq     retry
        }
        return fetched_val;
}
#define AO_HAVE_fetch_compare_and_swap


__asm inline double_ptr_storage AO_load_ex(const volatile AO_double_t *addr) {
        LDREXD r0,r1,[r0]
}

__asm inline int AO_store_ex(AO_t val1, AO_t val2, volatile AO_double_t *addr) {
        STREXD r3,r0,r1,[r2]
        MOV    r0,r3
}

AO_INLINE AO_double_t
AO_double_load(const volatile AO_double_t *addr)
{
  AO_double_t result;

  result.AO_whole = AO_load_ex(addr);
  return result;
}
#define AO_HAVE_double_load

AO_INLINE int
AO_compare_double_and_swap_double(volatile AO_double_t *addr,
                                  AO_t old_val1, AO_t old_val2,
                                  AO_t new_val1, AO_t new_val2)
{
        double_ptr_storage old_val =
                        ((double_ptr_storage)old_val2 << 32) | old_val1;
        double_ptr_storage tmp;
        int result;

        while(1) {
                tmp = AO_load_ex(addr);
                if(tmp != old_val)      return 0;
                result = AO_store_ex(new_val1, new_val2, addr);
                if(!result)     return 1;
        }
}
#define AO_HAVE_compare_double_and_swap_double

#endif

#define AO_T_IS_INT
