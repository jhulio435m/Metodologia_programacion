




#if !defined(AO_PREFER_BUILTIN_ATOMICS) && !defined(AO_THREAD_SANITIZER) \
    && !defined(AO_UNIPROCESSOR)
  AO_INLINE void
  AO_nop_write(void)
  {
    __asm__ __volatile__("dmb ishst" : : : "memory");
  }
# define AO_HAVE_nop_write
#endif




#if !defined(__clang__) || AO_CLANG_PREREQ(3, 9)

# include "../standard_ao_double_t.h"





#if (!defined(__ILP32__) && !defined(__clang__)) \
    || defined(AO_AARCH64_ASM_LOAD_STORE_CAS)

# ifndef AO_PREFER_GENERALIZED
    AO_INLINE AO_double_t
    AO_double_load(const volatile AO_double_t *addr)
    {
      AO_double_t result;
      int status;

     
     
      do {
        __asm__ __volatile__("
#       ifdef __ILP32__
          "       ldxp  %w0, %w1, %3\n"
          "       stxp %w2, %w0, %w1, %3"
#       else
          "       ldxp  %0, %1, %3\n"
          "       stxp %w2, %0, %1, %3"
#       endif
        : "=&r" (result.AO_val1), "=&r" (result.AO_val2), "=&r" (status)
        : "Q" (*addr));
      } while (AO_EXPECT_FALSE(status));
      return result;
    }
#   define AO_HAVE_double_load

    AO_INLINE AO_double_t
    AO_double_load_acquire(const volatile AO_double_t *addr)
    {
      AO_double_t result;
      int status;

      do {
        __asm__ __volatile__("
#       ifdef __ILP32__
          "       ldaxp  %w0, %w1, %3\n"
          "       stxp %w2, %w0, %w1, %3"
#       else
          "       ldaxp  %0, %1, %3\n"
          "       stxp %w2, %0, %1, %3"
#       endif
        : "=&r" (result.AO_val1), "=&r" (result.AO_val2), "=&r" (status)
        : "Q" (*addr));
      } while (AO_EXPECT_FALSE(status));
      return result;
    }
#   define AO_HAVE_double_load_acquire

    AO_INLINE void
    AO_double_store(volatile AO_double_t *addr, AO_double_t value)
    {
      AO_double_t old_val;
      int status;

      do {
        __asm__ __volatile__("
#       ifdef __ILP32__
          "       ldxp  %w0, %w1, %3\n"
          "       stxp %w2, %w4, %w5, %3"
#       else
          "       ldxp  %0, %1, %3\n"
          "       stxp %w2, %4, %5, %3"
#       endif
        : "=&r" (old_val.AO_val1), "=&r" (old_val.AO_val2), "=&r" (status),
          "=Q" (*addr)
        : "r" (value.AO_val1), "r" (value.AO_val2));
       
       
       
      } while (AO_EXPECT_FALSE(status));
    }
#   define AO_HAVE_double_store

    AO_INLINE void
    AO_double_store_release(volatile AO_double_t *addr, AO_double_t value)
    {
      AO_double_t old_val;
      int status;

      do {
        __asm__ __volatile__("
#       ifdef __ILP32__
          "       ldxp  %w0, %w1, %3\n"
          "       stlxp %w2, %w4, %w5, %3"
#       else
          "       ldxp  %0, %1, %3\n"
          "       stlxp %w2, %4, %5, %3"
#       endif
        : "=&r" (old_val.AO_val1), "=&r" (old_val.AO_val2), "=&r" (status),
          "=Q" (*addr)
        : "r" (value.AO_val1), "r" (value.AO_val2));
      } while (AO_EXPECT_FALSE(status));
    }
#   define AO_HAVE_double_store_release
# endif

  AO_INLINE int
  AO_double_compare_and_swap(volatile AO_double_t *addr,
                             AO_double_t old_val, AO_double_t new_val)
  {
    AO_double_t tmp;
    int result = 1;

    do {
      __asm__ __volatile__("
#       ifdef __ILP32__
          "       ldxp  %w0, %w1, %2\n"
#       else
          "       ldxp  %0, %1, %2\n"
#       endif
        : "=&r" (tmp.AO_val1), "=&r" (tmp.AO_val2)
        : "Q" (*addr));
      if (tmp.AO_val1 != old_val.AO_val1 || tmp.AO_val2 != old_val.AO_val2)
        break;
      __asm__ __volatile__(
#       ifdef __ILP32__
          "       stxp %w0, %w2, %w3, %1\n"
#       else
          "       stxp %w0, %2, %3, %1\n"
#       endif
        : "=&r" (result), "=Q" (*addr)
        : "r" (new_val.AO_val1), "r" (new_val.AO_val2));
    } while (AO_EXPECT_FALSE(result));
    return !result;
  }
# define AO_HAVE_double_compare_and_swap

  AO_INLINE int
  AO_double_compare_and_swap_acquire(volatile AO_double_t *addr,
                                     AO_double_t old_val, AO_double_t new_val)
  {
    AO_double_t tmp;
    int result = 1;

    do {
      __asm__ __volatile__("
#       ifdef __ILP32__
          "       ldaxp  %w0, %w1, %2\n"
#       else
          "       ldaxp  %0, %1, %2\n"
#       endif
        : "=&r" (tmp.AO_val1), "=&r" (tmp.AO_val2)
        : "Q" (*addr));
      if (tmp.AO_val1 != old_val.AO_val1 || tmp.AO_val2 != old_val.AO_val2)
        break;
      __asm__ __volatile__(
#       ifdef __ILP32__
          "       stxp %w0, %w2, %w3, %1\n"
#       else
          "       stxp %w0, %2, %3, %1\n"
#       endif
        : "=&r" (result), "=Q" (*addr)
        : "r" (new_val.AO_val1), "r" (new_val.AO_val2));
    } while (AO_EXPECT_FALSE(result));
    return !result;
  }
# define AO_HAVE_double_compare_and_swap_acquire

  AO_INLINE int
  AO_double_compare_and_swap_release(volatile AO_double_t *addr,
                                     AO_double_t old_val, AO_double_t new_val)
  {
    AO_double_t tmp;
    int result = 1;

    do {
      __asm__ __volatile__("
#       ifdef __ILP32__
          "       ldxp  %w0, %w1, %2\n"
#       else
          "       ldxp  %0, %1, %2\n"
#       endif
        : "=&r" (tmp.AO_val1), "=&r" (tmp.AO_val2)
        : "Q" (*addr));
      if (tmp.AO_val1 != old_val.AO_val1 || tmp.AO_val2 != old_val.AO_val2)
        break;
      __asm__ __volatile__(
#       ifdef __ILP32__
          "       stlxp %w0, %w2, %w3, %1\n"
#       else
          "       stlxp %w0, %2, %3, %1\n"
#       endif
        : "=&r" (result), "=Q" (*addr)
        : "r" (new_val.AO_val1), "r" (new_val.AO_val2));
    } while (AO_EXPECT_FALSE(result));
    return !result;
  }
# define AO_HAVE_double_compare_and_swap_release

  AO_INLINE int
  AO_double_compare_and_swap_full(volatile AO_double_t *addr,
                                  AO_double_t old_val, AO_double_t new_val)
  {
    AO_double_t tmp;
    int result = 1;

    do {
      __asm__ __volatile__("
#       ifdef __ILP32__
          "       ldaxp  %w0, %w1, %2\n"
#       else
          "       ldaxp  %0, %1, %2\n"
#       endif
        : "=&r" (tmp.AO_val1), "=&r" (tmp.AO_val2)
        : "Q" (*addr));
      if (tmp.AO_val1 != old_val.AO_val1 || tmp.AO_val2 != old_val.AO_val2)
        break;
      __asm__ __volatile__(
#       ifdef __ILP32__
          "       stlxp %w0, %w2, %w3, %1\n"
#       else
          "       stlxp %w0, %2, %3, %1\n"
#       endif
        : "=&r" (result), "=Q" (*addr)
        : "r" (new_val.AO_val1), "r" (new_val.AO_val2));
    } while (AO_EXPECT_FALSE(result));
    return !result;
  }
# define AO_HAVE_double_compare_and_swap_full

#endif



# ifndef __ILP32__
#   define AO_GCC_HAVE_double_SYNC_CAS
# endif

#endif

#if (defined(__clang__) && !AO_CLANG_PREREQ(3, 8)) || defined(__APPLE_CC__)
 
# define AO_GCC_FORCE_HAVE_CAS
#endif

#include "generic.h"

#undef AO_GCC_FORCE_HAVE_CAS
#undef AO_GCC_HAVE_double_SYNC_CAS
