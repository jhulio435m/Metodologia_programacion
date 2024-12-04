

#if (AO_GNUC_PREREQ(4, 8) || AO_CLANG_PREREQ(3, 5)) \
    && !defined(AO_DISABLE_GCC_ATOMICS)
 
# define AO_GCC_ATOMIC_TEST_AND_SET
#endif

#ifdef __native_client__
 
# define AO_MASK_PTR(reg) "       bical " reg ", " reg ", #0xc0000000\n"
# define AO_BR_ALIGN "       .align 4\n"
#else
# define AO_MASK_PTR(reg)
# define AO_BR_ALIGN
#endif

#if defined(__thumb__) && !defined(__thumb2__)
 
 
 
# define AO_THUMB_GO_ARM \
           "       adr     r3, 4f\n" \
           "       bx      r3\n" \
           "      .align\n" \
           "      .arm\n" \
           AO_BR_ALIGN \
           "4:\n"
# define AO_THUMB_RESTORE_MODE \
           "       adr     r3, 5f + 1\n" \
           "       bx      r3\n" \
           "       .thumb\n" \
           AO_BR_ALIGN \
           "5:\n"
# define AO_THUMB_SWITCH_CLOBBERS "r3",
#else
# define AO_THUMB_GO_ARM
# define AO_THUMB_RESTORE_MODE
# define AO_THUMB_SWITCH_CLOBBERS
#endif



#if !defined(__ARM_ARCH_2__) && !defined(__ARM_ARCH_3__) \
    && !defined(__ARM_ARCH_3M__) && !defined(__ARM_ARCH_4__) \
    && !defined(__ARM_ARCH_4T__) \
    && ((!defined(__ARM_ARCH_5__) && !defined(__ARM_ARCH_5E__) \
         && !defined(__ARM_ARCH_5T__) && !defined(__ARM_ARCH_5TE__) \
         && !defined(__ARM_ARCH_5TEJ__) && !defined(__ARM_ARCH_6M__)) \
        || defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) \
        || defined(__ARM_ARCH_8A__))
# define AO_ARM_HAVE_LDREX
# if !defined(__ARM_ARCH_6__) && !defined(__ARM_ARCH_6J__) \
     && !defined(__ARM_ARCH_6T2__)
   
#   define AO_ARM_HAVE_LDREXBH
# endif
# if !defined(__ARM_ARCH_6__) && !defined(__ARM_ARCH_6J__) \
     && !defined(__ARM_ARCH_6T2__) && !defined(__ARM_ARCH_6Z__) \
     && !defined(__ARM_ARCH_6ZT2__)
#   if !defined(__ARM_ARCH_6K__) && !defined(__ARM_ARCH_6KZ__) \
       && !defined(__ARM_ARCH_6ZK__)
     
#     define AO_ARM_HAVE_DMB
#   endif
#   if (!defined(__thumb__) \
        || (defined(__thumb2__) && !defined(__ARM_ARCH_7__) \
            && !defined(__ARM_ARCH_7M__) && !defined(__ARM_ARCH_7EM__))) \
       && (!defined(__clang__) || AO_CLANG_PREREQ(3, 3))
     
     
     
     
     
#     define AO_ARM_HAVE_LDREXD
#   endif
# endif
#endif

#if !defined(__ARM_ARCH_2__) && !defined(__ARM_ARCH_6M__) \
    && !defined(__ARM_ARCH_8A__) && !defined(__thumb2__)
# define AO_ARM_HAVE_SWP
               
               
#endif

#if !defined(AO_UNIPROCESSOR) && defined(AO_ARM_HAVE_DMB) \
    && !defined(AO_PREFER_BUILTIN_ATOMICS)
  AO_INLINE void
  AO_nop_write(void)
  {
   
   
   
   
   
   
   
   
   
   
   
    __asm__ __volatile__("dmb ishst" : : : "memory");
  }
# define AO_HAVE_nop_write
#endif

#ifndef AO_GCC_ATOMIC_TEST_AND_SET

#ifdef AO_UNIPROCESSOR
 
 
  AO_INLINE void
  AO_nop_full(void)
  {
    AO_compiler_barrier();
  }
# define AO_HAVE_nop_full

#elif defined(AO_ARM_HAVE_DMB)
 
 
 
 
  AO_INLINE void
  AO_nop_full(void)
  {
   
    __asm__ __volatile__("dmb" : : : "memory");
  }
# define AO_HAVE_nop_full

#elif defined(AO_ARM_HAVE_LDREX)
 
 
  AO_INLINE void
  AO_nop_full(void)
  {
    unsigned dest = 0;

   
   
    __asm__ __volatile__("@AO_nop_full\n"
      AO_THUMB_GO_ARM
      "       mcr p15,0,%0,c7,c10,5\n"
      AO_THUMB_RESTORE_MODE
      : "=&r"(dest)
      :
      : AO_THUMB_SWITCH_CLOBBERS "memory");
  }
# define AO_HAVE_nop_full

#else
 
#endif

#endif

#ifdef AO_ARM_HAVE_LDREX

 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
# ifdef AO_BROKEN_TASKSWITCH_CLREX

#   define AO_SKIPATOMIC_store
#   define AO_SKIPATOMIC_store_release
#   define AO_SKIPATOMIC_char_store
#   define AO_SKIPATOMIC_char_store_release
#   define AO_SKIPATOMIC_short_store
#   define AO_SKIPATOMIC_short_store_release
#   define AO_SKIPATOMIC_int_store
#   define AO_SKIPATOMIC_int_store_release

#   ifndef AO_PREFER_BUILTIN_ATOMICS

    AO_INLINE void AO_store(volatile AO_t *addr, AO_t value)
    {
      int flag;

      __asm__ __volatile__("@AO_store\n"
        AO_THUMB_GO_ARM
        AO_BR_ALIGN
        "1: " AO_MASK_PTR("%2")
        "       ldrex %0, [%2]\n"
        AO_MASK_PTR("%2")
        "       strex %0, %3, [%2]\n"
        "       teq %0, #0\n"
        "       bne 1b\n"
        AO_THUMB_RESTORE_MODE
        : "=&r" (flag), "+m" (*addr)
        : "r" (addr), "r" (value)
        : AO_THUMB_SWITCH_CLOBBERS "cc");
    }
#   define AO_HAVE_store

#   ifdef AO_ARM_HAVE_LDREXBH
      AO_INLINE void AO_char_store(volatile unsigned char *addr,
                                   unsigned char value)
      {
        int flag;

        __asm__ __volatile__("@AO_char_store\n"
          AO_THUMB_GO_ARM
          AO_BR_ALIGN
          "1: " AO_MASK_PTR("%2")
          "       ldrexb %0, [%2]\n"
          AO_MASK_PTR("%2")
          "       strexb %0, %3, [%2]\n"
          "       teq    %0, #0\n"
          "       bne 1b\n"
          AO_THUMB_RESTORE_MODE
          : "=&r" (flag), "+m" (*addr)
          : "r" (addr), "r" (value)
          : AO_THUMB_SWITCH_CLOBBERS "cc");
      }
#     define AO_HAVE_char_store

      AO_INLINE void AO_short_store(volatile unsigned short *addr,
                                    unsigned short value)
      {
        int flag;

        __asm__ __volatile__("@AO_short_store\n"
          AO_THUMB_GO_ARM
          AO_BR_ALIGN
          "1: " AO_MASK_PTR("%2")
          "       ldrexh %0, [%2]\n"
          AO_MASK_PTR("%2")
          "       strexh %0, %3, [%2]\n"
          "       teq    %0, #0\n"
          "       bne 1b\n"
          AO_THUMB_RESTORE_MODE
          : "=&r" (flag), "+m" (*addr)
          : "r" (addr), "r" (value)
          : AO_THUMB_SWITCH_CLOBBERS "cc");
      }
#     define AO_HAVE_short_store
#   endif

#   endif

# elif !defined(AO_GCC_ATOMIC_TEST_AND_SET)
#   include "../loadstore/atomic_store.h"
   
# endif

#endif

#ifndef AO_GCC_ATOMIC_TEST_AND_SET

# include "../test_and_set_t_is_ao_t.h"

#ifdef AO_ARM_HAVE_LDREX

 
 
# define AO_ACCESS_CHECK_ALIGNED
# define AO_ACCESS_short_CHECK_ALIGNED
# define AO_ACCESS_int_CHECK_ALIGNED
# include "../all_atomic_only_load.h"

# ifndef AO_HAVE_char_store
#   include "../loadstore/char_atomic_store.h"
#   include "../loadstore/short_atomic_store.h"
# endif


#ifndef AO_PREFER_GENERALIZED
#if !defined(AO_FORCE_USE_SWP) || !defined(AO_ARM_HAVE_SWP)
 
 
 
 
 
 
  AO_INLINE AO_TS_VAL_t
  AO_test_and_set(volatile AO_TS_t *addr)
  {
    AO_TS_VAL_t oldval;
    int flag;

    __asm__ __volatile__("@AO_test_and_set\n"
      AO_THUMB_GO_ARM
      AO_BR_ALIGN
      "1: " AO_MASK_PTR("%3")
      "       ldrex   %0, [%3]\n"
      AO_MASK_PTR("%3")
      "       strex   %1, %4, [%3]\n"
      "       teq     %1, #0\n"
      "       bne     1b\n"
      AO_THUMB_RESTORE_MODE
      : "=&r"(oldval), "=&r"(flag), "+m"(*addr)
      : "r"(addr), "r"(1)
      : AO_THUMB_SWITCH_CLOBBERS "cc");
    return oldval;
  }
# define AO_HAVE_test_and_set
#endif

AO_INLINE AO_t
AO_fetch_and_add(volatile AO_t *p, AO_t incr)
{
  AO_t result, tmp;
  int flag;

  __asm__ __volatile__("@AO_fetch_and_add\n"
    AO_THUMB_GO_ARM
    AO_BR_ALIGN
    "1: " AO_MASK_PTR("%5")
    "       ldrex   %0, [%5]\n"        
    "       add     %2, %0, %4\n"      
    AO_MASK_PTR("%5")
    "       strex   %1, %2, [%5]\n"    
    "       teq     %1, #0\n"
    "       bne     1b\n"
    AO_THUMB_RESTORE_MODE
    : "=&r"(result), "=&r"(flag), "=&r"(tmp), "+m"(*p)
    : "r"(incr), "r"(p)                               
    : AO_THUMB_SWITCH_CLOBBERS "cc");
  return result;
}
#define AO_HAVE_fetch_and_add

AO_INLINE AO_t
AO_fetch_and_add1(volatile AO_t *p)
{
  AO_t result, tmp;
  int flag;

  __asm__ __volatile__("@AO_fetch_and_add1\n"
    AO_THUMB_GO_ARM
    AO_BR_ALIGN
    "1: " AO_MASK_PTR("%4")
    "       ldrex   %0, [%4]\n"        
    "       add     %1, %0, #1\n"      
    AO_MASK_PTR("%4")
    "       strex   %2, %1, [%4]\n"    
    "       teq     %2, #0\n"
    "       bne     1b\n"
    AO_THUMB_RESTORE_MODE
    : "=&r"(result), "=&r"(tmp), "=&r"(flag), "+m"(*p)
    : "r"(p)
    : AO_THUMB_SWITCH_CLOBBERS "cc");
  return result;
}
#define AO_HAVE_fetch_and_add1

AO_INLINE AO_t
AO_fetch_and_sub1(volatile AO_t *p)
{
  AO_t result, tmp;
  int flag;

  __asm__ __volatile__("@AO_fetch_and_sub1\n"
    AO_THUMB_GO_ARM
    AO_BR_ALIGN
    "1: " AO_MASK_PTR("%4")
    "       ldrex   %0, [%4]\n"        
    "       sub     %1, %0, #1\n"      
    AO_MASK_PTR("%4")
    "       strex   %2, %1, [%4]\n"    
    "       teq     %2, #0\n"
    "       bne     1b\n"
    AO_THUMB_RESTORE_MODE
    : "=&r"(result), "=&r"(tmp), "=&r"(flag), "+m"(*p)
    : "r"(p)
    : AO_THUMB_SWITCH_CLOBBERS "cc");
  return result;
}
#define AO_HAVE_fetch_and_sub1

AO_INLINE void
AO_and(volatile AO_t *p, AO_t value)
{
  AO_t tmp, result;

  __asm__ __volatile__("@AO_and\n"
    AO_THUMB_GO_ARM
    AO_BR_ALIGN
    "1: " AO_MASK_PTR("%4")
    "       ldrex   %0, [%4]\n"
    "       and     %1, %0, %3\n"
    AO_MASK_PTR("%4")
    "       strex   %0, %1, [%4]\n"
    "       teq     %0, #0\n"
    "       bne     1b\n"
    AO_THUMB_RESTORE_MODE
    : "=&r" (tmp), "=&r" (result), "+m" (*p)
    : "r" (value), "r" (p)
    : AO_THUMB_SWITCH_CLOBBERS "cc");
}
#define AO_HAVE_and

AO_INLINE void
AO_or(volatile AO_t *p, AO_t value)
{
  AO_t tmp, result;

  __asm__ __volatile__("@AO_or\n"
    AO_THUMB_GO_ARM
    AO_BR_ALIGN
    "1: " AO_MASK_PTR("%4")
    "       ldrex   %0, [%4]\n"
    "       orr     %1, %0, %3\n"
    AO_MASK_PTR("%4")
    "       strex   %0, %1, [%4]\n"
    "       teq     %0, #0\n"
    "       bne     1b\n"
    AO_THUMB_RESTORE_MODE
    : "=&r" (tmp), "=&r" (result), "+m" (*p)
    : "r" (value), "r" (p)
    : AO_THUMB_SWITCH_CLOBBERS "cc");
}
#define AO_HAVE_or

AO_INLINE void
AO_xor(volatile AO_t *p, AO_t value)
{
  AO_t tmp, result;

  __asm__ __volatile__("@AO_xor\n"
    AO_THUMB_GO_ARM
    AO_BR_ALIGN
    "1: " AO_MASK_PTR("%4")
    "       ldrex   %0, [%4]\n"
    "       eor     %1, %0, %3\n"
    AO_MASK_PTR("%4")
    "       strex   %0, %1, [%4]\n"
    "       teq     %0, #0\n"
    "       bne     1b\n"
    AO_THUMB_RESTORE_MODE
    : "=&r" (tmp), "=&r" (result), "+m" (*p)
    : "r" (value), "r" (p)
    : AO_THUMB_SWITCH_CLOBBERS "cc");
}
#define AO_HAVE_xor
#endif

#ifdef AO_ARM_HAVE_LDREXBH
  AO_INLINE unsigned char
  AO_char_fetch_and_add(volatile unsigned char *p, unsigned char incr)
  {
    unsigned result, tmp;
    int flag;

    __asm__ __volatile__("@AO_char_fetch_and_add\n"
      AO_THUMB_GO_ARM
      AO_BR_ALIGN
      "1: " AO_MASK_PTR("%5")
      "       ldrexb  %0, [%5]\n"
      "       add     %2, %0, %4\n"
      AO_MASK_PTR("%5")
      "       strexb  %1, %2, [%5]\n"
      "       teq     %1, #0\n"
      "       bne     1b\n"
      AO_THUMB_RESTORE_MODE
      : "=&r" (result), "=&r" (flag), "=&r" (tmp), "+m" (*p)
      : "r" ((unsigned)incr), "r" (p)
      : AO_THUMB_SWITCH_CLOBBERS "cc");
    return (unsigned char)result;
  }
# define AO_HAVE_char_fetch_and_add

  AO_INLINE unsigned short
  AO_short_fetch_and_add(volatile unsigned short *p, unsigned short incr)
  {
    unsigned result, tmp;
    int flag;

    __asm__ __volatile__("@AO_short_fetch_and_add\n"
      AO_THUMB_GO_ARM
      AO_BR_ALIGN
      "1: " AO_MASK_PTR("%5")
      "       ldrexh  %0, [%5]\n"
      "       add     %2, %0, %4\n"
      AO_MASK_PTR("%5")
      "       strexh  %1, %2, [%5]\n"
      "       teq     %1, #0\n"
      "       bne     1b\n"
      AO_THUMB_RESTORE_MODE
      : "=&r" (result), "=&r" (flag), "=&r" (tmp), "+m" (*p)
      : "r" ((unsigned)incr), "r" (p)
      : AO_THUMB_SWITCH_CLOBBERS "cc");
    return (unsigned short)result;
  }
# define AO_HAVE_short_fetch_and_add
#endif

#ifndef AO_GENERALIZE_ASM_BOOL_CAS
 
  AO_INLINE int
  AO_compare_and_swap(volatile AO_t *addr, AO_t old_val, AO_t new_val)
  {
    AO_t result, tmp;

    __asm__ __volatile__("@AO_compare_and_swap\n"
      AO_THUMB_GO_ARM
      AO_BR_ALIGN
      "1:     mov     %0, #2\n"        
      AO_MASK_PTR("%3")
      "       ldrex   %1, [%3]\n"      
      "       teq     %1, %4\n"        
      AO_MASK_PTR("%3")
#     ifdef __thumb2__
       
       
        "       it      eq\n"
#     endif
      "       strexeq %0, %5, [%3]\n"  
      "       teq     %0, #1\n"
      "       beq     1b\n"            
      AO_THUMB_RESTORE_MODE
      : "=&r"(result), "=&r"(tmp), "+m"(*addr)
      : "r"(addr), "r"(old_val), "r"(new_val)
      : AO_THUMB_SWITCH_CLOBBERS "cc");
    return !(result&2);
  }
# define AO_HAVE_compare_and_swap
#endif

AO_INLINE AO_t
AO_fetch_compare_and_swap(volatile AO_t *addr, AO_t old_val, AO_t new_val)
{
  AO_t fetched_val;
  int flag;

  __asm__ __volatile__("@AO_fetch_compare_and_swap\n"
    AO_THUMB_GO_ARM
    AO_BR_ALIGN
    "1:     mov     %0, #2\n"          
    AO_MASK_PTR("%3")
    "       ldrex   %1, [%3]\n"        
    "       teq     %1, %4\n"          
    AO_MASK_PTR("%3")
#   ifdef __thumb2__
      "       it      eq\n"
#   endif
    "       strexeq %0, %5, [%3]\n"    
    "       teq     %0, #1\n"
    "       beq     1b\n"              
    AO_THUMB_RESTORE_MODE
    : "=&r"(flag), "=&r"(fetched_val), "+m"(*addr)
    : "r"(addr), "r"(old_val), "r"(new_val)
    : AO_THUMB_SWITCH_CLOBBERS "cc");
  return fetched_val;
}
#define AO_HAVE_fetch_compare_and_swap

#ifdef AO_ARM_HAVE_LDREXD
# include "../standard_ao_double_t.h"

 
 
 
 
 
 
  AO_INLINE AO_double_t
  AO_double_load(const volatile AO_double_t *addr)
  {
    AO_double_t result;

   
    __asm__ __volatile__("@AO_double_load\n"
      AO_MASK_PTR("%1")
      "       ldrexd  %0, %H0, [%1]"
      : "=&r" (result.AO_whole)
      : "r" (addr)
     );
    return result;
  }
# define AO_HAVE_double_load

  AO_INLINE void
  AO_double_store(volatile AO_double_t *addr, AO_double_t new_val)
  {
    AO_double_t old_val;
    int status;

    do {
     
      __asm__ __volatile__("@AO_double_store\n"
        AO_MASK_PTR("%3")
        "       ldrexd  %0, %H0, [%3]\n"
        AO_MASK_PTR("%3")
        "       strexd  %1, %4, %H4, [%3]"
        : "=&r" (old_val.AO_whole), "=&r" (status), "+m" (*addr)
        : "r" (addr), "r" (new_val.AO_whole)
        : "cc");
    } while (AO_EXPECT_FALSE(status));
  }
# define AO_HAVE_double_store

  AO_INLINE int
  AO_double_compare_and_swap(volatile AO_double_t *addr,
                             AO_double_t old_val, AO_double_t new_val)
  {
    double_ptr_storage tmp;
    int result = 1;

    do {
     
      __asm__ __volatile__("@AO_double_compare_and_swap\n"
        AO_MASK_PTR("%1")
        "       ldrexd  %0, %H0, [%1]\n"
        : "=&r"(tmp)
        : "r"(addr)
       );
      if (tmp != old_val.AO_whole)
        break;
      __asm__ __volatile__(
        AO_MASK_PTR("%2")
        "       strexd  %0, %3, %H3, [%2]\n"
        : "=&r"(result), "+m"(*addr)
        : "r" (addr), "r" (new_val.AO_whole)
        : "cc");
    } while (AO_EXPECT_FALSE(result));
    return !result;  
  }
# define AO_HAVE_double_compare_and_swap
#endif

#else






#include "../all_aligned_atomic_load_store.h"



#endif

#if !defined(AO_HAVE_test_and_set_full) && !defined(AO_HAVE_test_and_set) \
    && defined (AO_ARM_HAVE_SWP) && (!defined(AO_PREFER_GENERALIZED) \
                                || !defined(AO_HAVE_fetch_compare_and_swap))
  AO_INLINE AO_TS_VAL_t
  AO_test_and_set_full(volatile AO_TS_t *addr)
  {
    AO_TS_VAL_t oldval;
   
   
   
   
   
   
   

    __asm__ __volatile__("@AO_test_and_set_full\n"
      AO_THUMB_GO_ARM
      AO_MASK_PTR("%3")
      "       swp %0, %2, [%3]\n"
               
               
      AO_THUMB_RESTORE_MODE
      : "=&r"(oldval), "=&r"(addr)
      : "r"(1), "1"(addr)
      : AO_THUMB_SWITCH_CLOBBERS "memory");
    return oldval;
  }
# define AO_HAVE_test_and_set_full
#endif

#define AO_T_IS_INT

#else

# if defined(__clang__) && !defined(AO_ARM_HAVE_LDREX)
   
   
#   define AO_SKIPATOMIC_ANY_and_ANY
#   define AO_SKIPATOMIC_ANY_or_ANY
#   define AO_SKIPATOMIC_ANY_xor_ANY
# endif

# ifdef AO_ARM_HAVE_LDREXD
#   include "../standard_ao_double_t.h"
# endif
# include "generic.h"

#endif

#undef AO_ARM_HAVE_DMB
#undef AO_ARM_HAVE_LDREX
#undef AO_ARM_HAVE_LDREXBH
#undef AO_ARM_HAVE_LDREXD
#undef AO_ARM_HAVE_SWP
#undef AO_BR_ALIGN
#undef AO_MASK_PTR
#undef AO_SKIPATOMIC_ANY_and_ANY
#undef AO_SKIPATOMIC_ANY_or_ANY
#undef AO_SKIPATOMIC_ANY_xor_ANY
#undef AO_SKIPATOMIC_char_store
#undef AO_SKIPATOMIC_char_store_release
#undef AO_SKIPATOMIC_int_store
#undef AO_SKIPATOMIC_int_store_release
#undef AO_SKIPATOMIC_short_store
#undef AO_SKIPATOMIC_short_store_release
#undef AO_SKIPATOMIC_store
#undef AO_SKIPATOMIC_store_release
#undef AO_THUMB_GO_ARM
#undef AO_THUMB_RESTORE_MODE
#undef AO_THUMB_SWITCH_CLOBBERS
