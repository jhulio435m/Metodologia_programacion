

#if AO_CLANG_PREREQ(3, 9) && !defined(AO_DISABLE_GCC_ATOMICS)
 

 
# define AO_GCC_FORCE_HAVE_CAS

# define AO_GCC_HAVE_double_SYNC_CAS
# include "../standard_ao_double_t.h"

# include "generic.h"

#else

#include "../all_aligned_atomic_load_store.h"

#include "../test_and_set_t_is_ao_t.h"





AO_INLINE void
AO_nop_full(void)
{
  __asm__ __volatile__("syncht" : : : "memory");
}
#define AO_HAVE_nop_full




#ifndef AO_PREFER_GENERALIZED
AO_INLINE AO_t
AO_fetch_and_add(volatile AO_t *addr, AO_t incr)
{
  AO_t oldval;
  AO_t newval;
  __asm__ __volatile__(
     "1:\n"
     "  %0 = memw_locked(%3);\n"       
     "  %1 = add (%0,%4);\n"           
     "  memw_locked(%3,p1) = %1;\n"    
     "  if (!p1) jump 1b;\n"           
     : "=&r"(oldval), "=&r"(newval), "+m"(*addr)
     : "r"(addr), "r"(incr)
     : "memory", "p1");
  return oldval;
}
#define AO_HAVE_fetch_and_add

AO_INLINE AO_TS_VAL_t
AO_test_and_set(volatile AO_TS_t *addr)
{
  int oldval;
  int locked_value = 1;

  __asm__ __volatile__(
     "1:\n"
     "  %0 = memw_locked(%2);\n"       
     "  {\n"
     "    p2 = cmp.eq(%0,#0);\n"       
     "    if (!p2.new) jump:nt 2f;\n"  
     "  }\n"
     "  memw_locked(%2,p1) = %3;\n"    
     "  if (!p1) jump 1b;\n"           
     "2:\n"                            
     : "=&r"(oldval), "+m"(*addr)
     : "r"(addr), "r"(locked_value)
     : "memory", "p1", "p2");
  return (AO_TS_VAL_t)oldval;
}
#define AO_HAVE_test_and_set
#endif

#ifndef AO_GENERALIZE_ASM_BOOL_CAS
  AO_INLINE int
  AO_compare_and_swap(volatile AO_t *addr, AO_t old, AO_t new_val)
  {
    AO_t __oldval;
    int result = 0;
    __asm__ __volatile__(
      "1:\n"
      "  %0 = memw_locked(%3);\n"      
      "  {\n"
      "    p2 = cmp.eq(%0,%4);\n"      
      "    if (!p2.new) jump:nt 2f;\n" 
      "  }\n"
      "  memw_locked(%3,p1) = %5;\n"   
      "  if (!p1) jump 1b;\n"          
      "  %1 = #1\n"                    
      "2:\n"
      : "=&r" (__oldval), "+r" (result), "+m"(*addr)
      : "r" (addr), "r" (old), "r" (new_val)
      : "p1", "p2", "memory"
    );
    return result;
  }
# define AO_HAVE_compare_and_swap
#endif

AO_INLINE AO_t
AO_fetch_compare_and_swap(volatile AO_t *addr, AO_t old_val, AO_t new_val)
{
  AO_t __oldval;

  __asm__ __volatile__(
     "1:\n"
     "  %0 = memw_locked(%2);\n"       
     "  {\n"
     "    p2 = cmp.eq(%0,%3);\n"       
     "    if (!p2.new) jump:nt 2f;\n"  
     "  }\n"
     "  memw_locked(%2,p1) = %4;\n"    
     "  if (!p1) jump 1b;\n"           
     "2:\n"
     : "=&r" (__oldval), "+m"(*addr)
     : "r" (addr), "r" (old_val), "r" (new_val)
     : "p1", "p2", "memory"
  );
  return __oldval;
}
#define AO_HAVE_fetch_compare_and_swap

#define AO_T_IS_INT

#endif

#undef AO_GCC_FORCE_HAVE_CAS
#undef AO_GCC_HAVE_double_SYNC_CAS
