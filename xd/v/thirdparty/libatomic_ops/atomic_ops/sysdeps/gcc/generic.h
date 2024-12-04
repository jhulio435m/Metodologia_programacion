





#define AO_GCC_ATOMIC_TEST_AND_SET
#include "../test_and_set_t_is_char.h"

#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1) \
    || defined(AO_GCC_FORCE_HAVE_CAS)
# define AO_GCC_HAVE_char_SYNC_CAS
#endif

#if (__SIZEOF_SHORT__ == 2 && defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2)) \
    || defined(AO_GCC_FORCE_HAVE_CAS)
# define AO_GCC_HAVE_short_SYNC_CAS
#endif

#if (__SIZEOF_INT__ == 4 && defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4)) \
    || (__SIZEOF_INT__ == 8 && defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)) \
    || defined(AO_GCC_FORCE_HAVE_CAS)
# define AO_GCC_HAVE_int_SYNC_CAS
#endif

#if (__SIZEOF_SIZE_T__ == 4 && defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4)) \
    || (__SIZEOF_SIZE_T__ == 8 \
        && defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)) \
    || defined(AO_GCC_FORCE_HAVE_CAS)
# define AO_GCC_HAVE_SYNC_CAS
#endif

#undef AO_compiler_barrier
#define AO_compiler_barrier() __atomic_signal_fence(__ATOMIC_SEQ_CST)

#ifdef AO_UNIPROCESSOR
 
 
  AO_INLINE void
  AO_nop_full(void)
  {
    AO_compiler_barrier();
  }
# define AO_HAVE_nop_full

#elif defined(AO_THREAD_SANITIZER) && !defined(AO_USE_ATOMIC_THREAD_FENCE)
 
 

#else
  AO_INLINE void
  AO_nop_read(void)
  {
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
  }
# define AO_HAVE_nop_read

# ifndef AO_HAVE_nop_write
    AO_INLINE void
    AO_nop_write(void)
    {
      __atomic_thread_fence(__ATOMIC_RELEASE);
    }
#   define AO_HAVE_nop_write
# endif

  AO_INLINE void
  AO_nop_full(void)
  {
   
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
  }
# define AO_HAVE_nop_full
#endif

#include "generic-small.h"

#ifndef AO_PREFER_GENERALIZED
# include "generic-arithm.h"

# define AO_CLEAR(addr) __atomic_clear(addr, __ATOMIC_RELEASE)
# define AO_HAVE_CLEAR

  AO_INLINE AO_TS_VAL_t
  AO_test_and_set(volatile AO_TS_t *addr)
  {
    return (AO_TS_VAL_t)(__atomic_test_and_set(addr, __ATOMIC_RELAXED)
                         ? AO_TS_SET : AO_TS_CLEAR);
  }
# define AO_HAVE_test_and_set

  AO_INLINE AO_TS_VAL_t
  AO_test_and_set_acquire(volatile AO_TS_t *addr)
  {
    return (AO_TS_VAL_t)(__atomic_test_and_set(addr, __ATOMIC_ACQUIRE)
                         ? AO_TS_SET : AO_TS_CLEAR);
  }
# define AO_HAVE_test_and_set_acquire

  AO_INLINE AO_TS_VAL_t
  AO_test_and_set_release(volatile AO_TS_t *addr)
  {
    return (AO_TS_VAL_t)(__atomic_test_and_set(addr, __ATOMIC_RELEASE)
                         ? AO_TS_SET : AO_TS_CLEAR);
  }
# define AO_HAVE_test_and_set_release

  AO_INLINE AO_TS_VAL_t
  AO_test_and_set_full(volatile AO_TS_t *addr)
  {
    return (AO_TS_VAL_t)(__atomic_test_and_set(addr, __ATOMIC_SEQ_CST)
                         ? AO_TS_SET : AO_TS_CLEAR);
  }
# define AO_HAVE_test_and_set_full
#endif

#ifdef AO_HAVE_DOUBLE_PTR_STORAGE

# if ((__SIZEOF_SIZE_T__ == 4 \
       && defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8)) \
      || (__SIZEOF_SIZE_T__ == 8 \
          && defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_16))) \
     && !defined(AO_SKIPATOMIC_double_compare_and_swap_ANY)
#   define AO_GCC_HAVE_double_SYNC_CAS
# endif

# if !defined(AO_GCC_HAVE_double_SYNC_CAS) || !defined(AO_PREFER_GENERALIZED)

# if !defined(AO_HAVE_double_load) && !defined(AO_SKIPATOMIC_double_load)
    AO_INLINE AO_double_t
    AO_double_load(const volatile AO_double_t *addr)
    {
      AO_double_t result;

      result.AO_whole = __atomic_load_n(&addr->AO_whole, __ATOMIC_RELAXED);
      return result;
    }
#   define AO_HAVE_double_load
# endif

# if !defined(AO_HAVE_double_load_acquire) \
     && !defined(AO_SKIPATOMIC_double_load_acquire)
    AO_INLINE AO_double_t
    AO_double_load_acquire(const volatile AO_double_t *addr)
    {
      AO_double_t result;

      result.AO_whole = __atomic_load_n(&addr->AO_whole, __ATOMIC_ACQUIRE);
      return result;
    }
#   define AO_HAVE_double_load_acquire
# endif

# if !defined(AO_HAVE_double_store) && !defined(AO_SKIPATOMIC_double_store)
    AO_INLINE void
    AO_double_store(volatile AO_double_t *addr, AO_double_t value)
    {
      __atomic_store_n(&addr->AO_whole, value.AO_whole, __ATOMIC_RELAXED);
    }
#   define AO_HAVE_double_store
# endif

# if !defined(AO_HAVE_double_store_release) \
     && !defined(AO_SKIPATOMIC_double_store_release)
    AO_INLINE void
    AO_double_store_release(volatile AO_double_t *addr, AO_double_t value)
    {
      __atomic_store_n(&addr->AO_whole, value.AO_whole, __ATOMIC_RELEASE);
    }
#   define AO_HAVE_double_store_release
# endif

#endif

#endif

#ifdef AO_GCC_HAVE_double_SYNC_CAS
# ifndef AO_HAVE_double_compare_and_swap
    AO_INLINE int
    AO_double_compare_and_swap(volatile AO_double_t *addr,
                               AO_double_t old_val, AO_double_t new_val)
    {
      return (int)__atomic_compare_exchange_n(&addr->AO_whole,
                                &old_val.AO_whole,
                                new_val.AO_whole,
                                0,
                                __ATOMIC_RELAXED,
                                __ATOMIC_RELAXED);
    }
#   define AO_HAVE_double_compare_and_swap
# endif

# ifndef AO_HAVE_double_compare_and_swap_acquire
    AO_INLINE int
    AO_double_compare_and_swap_acquire(volatile AO_double_t *addr,
                                       AO_double_t old_val,
                                       AO_double_t new_val)
    {
      return (int)__atomic_compare_exchange_n(&addr->AO_whole,
                                &old_val.AO_whole, new_val.AO_whole, 0,
                                __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_double_compare_and_swap_acquire
# endif

# ifndef AO_HAVE_double_compare_and_swap_release
    AO_INLINE int
    AO_double_compare_and_swap_release(volatile AO_double_t *addr,
                                       AO_double_t old_val,
                                       AO_double_t new_val)
    {
      return (int)__atomic_compare_exchange_n(&addr->AO_whole,
                                &old_val.AO_whole, new_val.AO_whole, 0,
                                __ATOMIC_RELEASE,
                                __ATOMIC_RELAXED);
    }
#   define AO_HAVE_double_compare_and_swap_release
# endif

# ifndef AO_HAVE_double_compare_and_swap_full
    AO_INLINE int
    AO_double_compare_and_swap_full(volatile AO_double_t *addr,
                                    AO_double_t old_val, AO_double_t new_val)
    {
      return (int)__atomic_compare_exchange_n(&addr->AO_whole,
                                &old_val.AO_whole, new_val.AO_whole, 0,
                                __ATOMIC_ACQ_REL,
                                __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_double_compare_and_swap_full
# endif
#endif
