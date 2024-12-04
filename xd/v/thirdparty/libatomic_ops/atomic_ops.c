#if defined(HAVE_CONFIG_H)
# include "config.h"
#endif

#if (defined(__hexagon__) || defined(__native_client__)) \
    && !defined(AO_USE_NO_SIGNALS) && !defined(AO_USE_NANOSLEEP)
 
 
 
# define AO_USE_NO_SIGNALS
# define AO_USE_NANOSLEEP
#endif

#if defined(AO_USE_WIN32_PTHREADS) && !defined(AO_USE_NO_SIGNALS)
# define AO_USE_NO_SIGNALS
#endif

#if (defined(__CYGWIN__) || defined(__GLIBC__) || defined(__GNU__) \
     || defined(__linux__)) \
    && !defined(AO_USE_NO_SIGNALS) && !defined(_GNU_SOURCE)
# define _GNU_SOURCE 1
#endif

#ifndef AO_BUILD
# define AO_BUILD
#endif

#undef AO_REQUIRE_CAS
#include "atomic_ops.h"

#ifdef __cplusplus
  extern "C" {
#endif

AO_API void AO_pause(int);

#ifdef __cplusplus
  }
#endif

#if !defined(_MSC_VER) && !defined(__MINGW32__) && !defined(__BORLANDC__) \
    || defined(AO_USE_NO_SIGNALS)

#ifndef AO_NO_PTHREADS
# include <pthread.h>
#endif

#ifndef AO_USE_NO_SIGNALS
# include <signal.h>
#endif

#ifdef AO_USE_NANOSLEEP
 
# include <sys/time.h>
# include <time.h>
#elif defined(AO_USE_WIN32_PTHREADS)
# include <windows.h>
#elif defined(_HPUX_SOURCE)
# include <sys/time.h>
#else
# include <sys/select.h>
#endif

#ifndef AO_HAVE_double_t
# include "atomic_ops/sysdeps/standard_ao_double_t.h"
#endif

#ifdef __cplusplus
  extern "C" {
#endif

AO_API AO_t AO_fetch_compare_and_swap_emulation(volatile AO_t *addr,
                                                AO_t old_val, AO_t new_val);

AO_API int
AO_compare_double_and_swap_double_emulation(volatile AO_double_t *addr,
                                            AO_t old_val1, AO_t old_val2,
                                            AO_t new_val1, AO_t new_val2);

AO_API void AO_store_full_emulation(volatile AO_t *addr, AO_t val);


#ifndef AO_NO_PTHREADS
  AO_API pthread_mutex_t AO_pt_lock;
#endif

#ifdef __cplusplus
  }
#endif

#ifndef AO_NO_PTHREADS
  pthread_mutex_t AO_pt_lock = PTHREAD_MUTEX_INITIALIZER;
#endif


#define AO_HASH_SIZE 16

#define AO_HASH(x) ((unsigned)((AO_uintptr_t)(x) >> 12) & (AO_HASH_SIZE-1))

static AO_TS_t AO_locks[AO_HASH_SIZE] = {
  AO_TS_INITIALIZER, AO_TS_INITIALIZER, AO_TS_INITIALIZER, AO_TS_INITIALIZER,
  AO_TS_INITIALIZER, AO_TS_INITIALIZER, AO_TS_INITIALIZER, AO_TS_INITIALIZER,
  AO_TS_INITIALIZER, AO_TS_INITIALIZER, AO_TS_INITIALIZER, AO_TS_INITIALIZER,
  AO_TS_INITIALIZER, AO_TS_INITIALIZER, AO_TS_INITIALIZER, AO_TS_INITIALIZER,
};

static void lock_ool(volatile AO_TS_t *l)
{
  int i = 0;

  while (AO_test_and_set_acquire(l) == AO_TS_SET)
    AO_pause(++i);
}

AO_INLINE void lock(volatile AO_TS_t *l)
{
  if (AO_EXPECT_FALSE(AO_test_and_set_acquire(l) == AO_TS_SET))
    lock_ool(l);
}

AO_INLINE void unlock(volatile AO_TS_t *l)
{
  AO_CLEAR(l);
}

#ifndef AO_USE_NO_SIGNALS
  static sigset_t all_sigs;
  static volatile AO_t initialized = 0;
  static volatile AO_TS_t init_lock = AO_TS_INITIALIZER;

  AO_INLINE void block_all_signals(sigset_t *old_sigs_ptr)
  {
    if (AO_EXPECT_FALSE(!AO_load_acquire(&initialized)))
    {
      lock(&init_lock);
      if (!initialized)
        sigfillset(&all_sigs);
      unlock(&init_lock);
      AO_store_release(&initialized, 1);
    }
    sigprocmask(SIG_BLOCK, &all_sigs, old_sigs_ptr);
       
       
       
       
       
       
       
  }
#endif

AO_API AO_t AO_fetch_compare_and_swap_emulation(volatile AO_t *addr,
                                                AO_t old_val, AO_t new_val)
{
  AO_TS_t *my_lock = AO_locks + AO_HASH(addr);
  AO_t fetched_val;

# ifndef AO_USE_NO_SIGNALS
    sigset_t old_sigs;
    block_all_signals(&old_sigs);
# endif
  lock(my_lock);
  fetched_val = *addr;
  if (fetched_val == old_val)
    *addr = new_val;
  unlock(my_lock);
# ifndef AO_USE_NO_SIGNALS
    sigprocmask(SIG_SETMASK, &old_sigs, NULL);
# endif
  return fetched_val;
}

AO_API int
AO_compare_double_and_swap_double_emulation(volatile AO_double_t *addr,
                                            AO_t old_val1, AO_t old_val2,
                                            AO_t new_val1, AO_t new_val2)
{
  AO_TS_t *my_lock = AO_locks + AO_HASH(addr);
  int result;

# ifndef AO_USE_NO_SIGNALS
    sigset_t old_sigs;
    block_all_signals(&old_sigs);
# endif
  lock(my_lock);
  if (addr -> AO_val1 == old_val1 && addr -> AO_val2 == old_val2)
    {
      addr -> AO_val1 = new_val1;
      addr -> AO_val2 = new_val2;
      result = 1;
    }
  else
    result = 0;
  unlock(my_lock);
# ifndef AO_USE_NO_SIGNALS
    sigprocmask(SIG_SETMASK, &old_sigs, NULL);
# endif
  return result;
}

AO_API void AO_store_full_emulation(volatile AO_t *addr, AO_t val)
{
  AO_TS_t *my_lock = AO_locks + AO_HASH(addr);
  lock(my_lock);
  *addr = val;
  unlock(my_lock);
}

#else

# include <windows.h>

# define AO_USE_WIN32_PTHREADS
               

  extern int AO_non_posix_implementation_is_entirely_in_headers;

#endif

static volatile AO_t spin_dummy = 0;


static void AO_spin(int n)
{
  AO_t j = AO_load(&spin_dummy);
  int i = 2 << n;

  while (i-- > 0)
    j += j << 2;
 
  AO_store(&spin_dummy, j);
}

AO_API void AO_pause(int n)
{
  if (n < 12) {
    AO_spin(n);
  } else {
#   ifdef AO_USE_NANOSLEEP
      struct timespec ts;
      ts.tv_sec = 0;
      ts.tv_nsec = n > 28 ? 100000L * 1000 : 1L << (n - 2);
      nanosleep(&ts, 0);
#   elif defined(AO_USE_WIN32_PTHREADS)
      Sleep(n > 28 ? 100
                   : n < 22 ? 1 : (DWORD)1 << (n - 22));
#   else
      struct timeval tv;
     
      int usec = n > 28 ? 100000 : 1 << (n - 12);
               
               

      tv.tv_sec = 0;
      tv.tv_usec = usec;
      (void)select(0, 0, 0, 0, &tv);
#   endif
  }
}
