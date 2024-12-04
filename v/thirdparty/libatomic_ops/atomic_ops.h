#ifndef AO_ATOMIC_OPS_H
#define AO_ATOMIC_OPS_H

#include "atomic_ops/ao_version.h"
                       
                       

#include <assert.h>
#include <stddef.h>

#define AO_t size_t

#if defined(__SIZEOF_POINTER__) \
    && (__SIZEOF_POINTER__ == 2 * __SIZEOF_SIZE_T__)
 
# define AO_FAT_POINTER
#endif

#ifndef AO_FAT_POINTER
# define AO_uintptr_t AO_t
#elif defined(__e2k__)
 
  typedef unsigned __int128 AO_uintptr_t;
#else
# include <inttypes.h>
# define AO_uintptr_t uintptr_t
#endif


struct AO_uintptr_t_size_static_assert {
  char dummy[sizeof(AO_uintptr_t) == sizeof(void *) ? 1 : -1];
};




#define AO_TS_INITIALIZER ((AO_TS_t)AO_TS_CLEAR)


#if defined(__GNUC__) && defined(__GNUC_MINOR__)
# define AO_GNUC_PREREQ(major, minor) \
            ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((major) << 16) + (minor))
#else
# define AO_GNUC_PREREQ(major, minor) 0
#endif


#if defined(__clang__) && defined(__clang_major__)
# define AO_CLANG_PREREQ(major, minor) \
    ((__clang_major__ << 16) + __clang_minor__ >= ((major) << 16) + (minor))
#else
# define AO_CLANG_PREREQ(major, minor) 0
#endif


#if (defined(__GNUC__) || defined(_MSC_VER) || defined(__INTEL_COMPILER) \
        || defined(__DMC__) || defined(__WATCOMC__)) && !defined(AO_NO_INLINE)
# define AO_INLINE static __inline
#elif defined(__sun) && !defined(AO_NO_INLINE)
# define AO_INLINE static inline
#else
# define AO_INLINE static
#endif

#if AO_GNUC_PREREQ(3, 0) && !defined(LINT2)
# define AO_EXPECT_FALSE(expr) __builtin_expect(expr, 0)
 
#else
# define AO_EXPECT_FALSE(expr) (expr)
#endif

#if defined(__has_feature)
 
# if __has_feature(address_sanitizer)
#   define AO_ADDRESS_SANITIZER
# endif
# if __has_feature(memory_sanitizer)
#   define AO_MEMORY_SANITIZER
# endif
# if __has_feature(thread_sanitizer)
#   define AO_THREAD_SANITIZER
# endif
#else
# ifdef __SANITIZE_ADDRESS__
   
#   define AO_ADDRESS_SANITIZER
# endif
#endif

#ifndef AO_ATTR_NO_SANITIZE_MEMORY
# ifndef AO_MEMORY_SANITIZER
#   define AO_ATTR_NO_SANITIZE_MEMORY
# elif AO_CLANG_PREREQ(3, 8)
#   define AO_ATTR_NO_SANITIZE_MEMORY __attribute__((no_sanitize("memory")))
# else
#   define AO_ATTR_NO_SANITIZE_MEMORY __attribute__((no_sanitize_memory))
# endif
#endif

#ifndef AO_ATTR_NO_SANITIZE_THREAD
# ifndef AO_THREAD_SANITIZER
#   define AO_ATTR_NO_SANITIZE_THREAD
# elif AO_CLANG_PREREQ(3, 8)
#   define AO_ATTR_NO_SANITIZE_THREAD __attribute__((no_sanitize("thread")))
# else
#   define AO_ATTR_NO_SANITIZE_THREAD __attribute__((no_sanitize_thread))
# endif
#endif

#if (AO_GNUC_PREREQ(7, 5) || __STDC_VERSION__ >= 201112L) && !defined(LINT2)
# define AO_ALIGNOF_SUPPORTED 1
#endif

#if defined(AO_DLL) && !defined(AO_API)
# ifdef AO_BUILD
#   if defined(__CEGCC__) || (defined(__MINGW32__) && !defined(__cplusplus))
#     define AO_API __declspec(dllexport)
#   elif defined(_MSC_VER) || defined(__BORLANDC__) || defined(__CYGWIN__) \
         || defined(__DMC__) || defined(__MINGW32__) || defined(__WATCOMC__)
#     define AO_API extern __declspec(dllexport)
#   endif
# else
#   if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__CEGCC__) \
       || defined(__CYGWIN__) || defined(__DMC__)
#     define AO_API __declspec(dllimport)
#   elif defined(__MINGW32_DELAY_LOAD__)
#     define AO_API __declspec(dllexport)
#   elif defined(__MINGW32__) || defined(__WATCOMC__)
#     define AO_API extern __declspec(dllimport)
#   endif
# endif
#endif

#ifndef AO_API
# define AO_API extern
#endif

#ifdef AO_ALIGNOF_SUPPORTED
# define AO_ASSERT_ADDR_ALIGNED(addr) \
    assert(((AO_uintptr_t)(addr) & (__alignof__(*(addr)) - 1)) == 0)
#else
# define AO_ASSERT_ADDR_ALIGNED(addr) \
    assert(((AO_uintptr_t)(addr) & (sizeof(*(addr)) - 1)) == 0)
#endif

#if defined(__GNUC__) && !defined(__INTEL_COMPILER)
# define AO_compiler_barrier() __asm__ __volatile__("" : : : "memory")
#elif defined(_MSC_VER) || defined(__DMC__) || defined(__BORLANDC__) \
        || defined(__WATCOMC__)
# if defined(_AMD64_) || defined(_M_X64) || _MSC_VER >= 1400
#   if defined(_WIN32_WCE)

#   elif defined(_MSC_VER)
#     include <intrin.h>
#   endif
#   pragma intrinsic(_ReadWriteBarrier)
#   define AO_compiler_barrier() _ReadWriteBarrier()
       
       
# else
#   define AO_compiler_barrier() __asm { }
       
       
# endif
#elif defined(__INTEL_COMPILER)
# define AO_compiler_barrier() __memory_barrier()
                                       
#elif defined(_HPUX_SOURCE)
# if defined(__ia64)
#   include <machine/sys/inline.h>
#   define AO_compiler_barrier() _Asm_sched_fence()
# else
   
   
    static volatile int AO_barrier_dummy;
#   define AO_compiler_barrier() (void)(AO_barrier_dummy = AO_barrier_dummy)
# endif
#else
 
 
# define AO_compiler_barrier() asm("")
#endif

#if defined(AO_USE_PTHREAD_DEFS)
# include "atomic_ops/sysdeps/generic_pthread.h"
#endif

#if (defined(__CC_ARM) || defined(__ARMCC__)) && !defined(__GNUC__) \
    && !defined(AO_USE_PTHREAD_DEFS)
# include "atomic_ops/sysdeps/armcc/arm_v6.h"
# define AO_GENERALIZE_TWICE
#endif

#if defined(__GNUC__) && !defined(AO_USE_PTHREAD_DEFS) \
    && !defined(__INTEL_COMPILER)
# if defined(__i386__)
   
   
   
#   include "atomic_ops/sysdeps/gcc/x86.h"
# elif defined(__x86_64__)
#   if AO_GNUC_PREREQ(4, 2) && !defined(AO_USE_SYNC_CAS_BUILTIN)
     
#     define AO_USE_SYNC_CAS_BUILTIN
#   endif
#   include "atomic_ops/sysdeps/gcc/x86.h"
# elif defined(__ia64__)
#   include "atomic_ops/sysdeps/gcc/ia64.h"
#   define AO_GENERALIZE_TWICE
# elif defined(__hppa__)
#   include "atomic_ops/sysdeps/gcc/hppa.h"
#   define AO_CAN_EMUL_CAS
# elif defined(__alpha__)
#   include "atomic_ops/sysdeps/gcc/alpha.h"
#   define AO_GENERALIZE_TWICE
# elif defined(__s390__)
#   include "atomic_ops/sysdeps/gcc/s390.h"
# elif defined(__sparc__)
#   include "atomic_ops/sysdeps/gcc/sparc.h"
#   define AO_CAN_EMUL_CAS
# elif defined(__m68k__)
#   include "atomic_ops/sysdeps/gcc/m68k.h"
# elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__) \
       || defined(__powerpc64__) || defined(__ppc64__) || defined(_ARCH_PPC)
#   include "atomic_ops/sysdeps/gcc/powerpc.h"
# elif defined(__aarch64__)
#   include "atomic_ops/sysdeps/gcc/aarch64.h"
#   define AO_CAN_EMUL_CAS
# elif defined(__arm__)
#   include "atomic_ops/sysdeps/gcc/arm.h"
#   define AO_CAN_EMUL_CAS
# elif defined(__cris__) || defined(CRIS)
#   include "atomic_ops/sysdeps/gcc/cris.h"
#   define AO_CAN_EMUL_CAS
#   define AO_GENERALIZE_TWICE
# elif defined(__mips__)
#   include "atomic_ops/sysdeps/gcc/mips.h"
# elif defined(__sh__) || defined(SH4)
#   include "atomic_ops/sysdeps/gcc/sh.h"
#   define AO_CAN_EMUL_CAS
# elif defined(__avr32__)
#   include "atomic_ops/sysdeps/gcc/avr32.h"
# elif defined(__e2k__)
#   include "atomic_ops/sysdeps/gcc/e2k.h"
# elif defined(__hexagon__)
#   include "atomic_ops/sysdeps/gcc/hexagon.h"
# elif defined(__nios2__)
#   include "atomic_ops/sysdeps/gcc/generic.h"
#   define AO_CAN_EMUL_CAS
# elif defined(__riscv)
#   include "atomic_ops/sysdeps/gcc/riscv.h"
# elif defined(__tile__)
#   include "atomic_ops/sysdeps/gcc/tile.h"
# else
#   include "atomic_ops/sysdeps/gcc/generic.h"
# endif
#endif

#if (defined(__IBMC__) || defined(__IBMCPP__)) && !defined(__GNUC__) \
    && !defined(AO_USE_PTHREAD_DEFS)
# if defined(__powerpc__) || defined(__powerpc) || defined(__ppc__) \
     || defined(__PPC__) || defined(_M_PPC) || defined(_ARCH_PPC) \
     || defined(_ARCH_PWR)
#   include "atomic_ops/sysdeps/ibmc/powerpc.h"
#   define AO_GENERALIZE_TWICE
# endif
#endif

#if defined(__INTEL_COMPILER) && !defined(AO_USE_PTHREAD_DEFS)
# if defined(__ia64__)
#   include "atomic_ops/sysdeps/icc/ia64.h"
#   define AO_GENERALIZE_TWICE
# endif
# if defined(__GNUC__)
   
#   if defined(__i386__)
#     include "atomic_ops/sysdeps/gcc/x86.h"
#   endif
#   if defined(__x86_64__)
#     if (__INTEL_COMPILER > 1110) && !defined(AO_USE_SYNC_CAS_BUILTIN)
#       define AO_USE_SYNC_CAS_BUILTIN
#     endif
#     include "atomic_ops/sysdeps/gcc/x86.h"
#   endif
# endif
#endif

#if defined(_HPUX_SOURCE) && !defined(__GNUC__) && !defined(AO_USE_PTHREAD_DEFS)
# if defined(__ia64)
#   include "atomic_ops/sysdeps/hpc/ia64.h"
#   define AO_GENERALIZE_TWICE
# else
#   include "atomic_ops/sysdeps/hpc/hppa.h"
#   define AO_CAN_EMUL_CAS
# endif
#endif

#if defined(_MSC_VER) || defined(__DMC__) || defined(__BORLANDC__) \
        || (defined(__WATCOMC__) && defined(__NT__))
# if defined(_AMD64_) || defined(_M_X64)
#   include "atomic_ops/sysdeps/msftc/x86_64.h"
# elif defined(_M_ARM64)
#   include "atomic_ops/sysdeps/msftc/arm64.h"
# elif defined(_M_IX86) || defined(x86)
#   include "atomic_ops/sysdeps/msftc/x86.h"
# elif defined(_M_ARM) || defined(ARM) || defined(_ARM_)
#   include "atomic_ops/sysdeps/msftc/arm.h"
#   define AO_GENERALIZE_TWICE
# endif
#endif

#if defined(__sun) && !defined(__GNUC__) && !defined(AO_USE_PTHREAD_DEFS)
 
# if defined(__i386) || defined(__x86_64) || defined(__amd64)
#   include "atomic_ops/sysdeps/sunc/x86.h"
# endif
#endif

#if !defined(__GNUC__) && (defined(sparc) || defined(__sparc)) \
    && !defined(AO_USE_PTHREAD_DEFS)
# include "atomic_ops/sysdeps/sunc/sparc.h"
# define AO_CAN_EMUL_CAS
#endif

#if (defined(AO_REQUIRE_CAS) && !defined(AO_HAVE_compare_and_swap) \
    && !defined(AO_HAVE_fetch_compare_and_swap) \
    && !defined(AO_HAVE_compare_and_swap_full) \
    && !defined(AO_HAVE_fetch_compare_and_swap_full) \
    && !defined(AO_HAVE_compare_and_swap_acquire) \
    && !defined(AO_HAVE_fetch_compare_and_swap_acquire)) || defined(CPPCHECK)
# if defined(AO_CAN_EMUL_CAS)
#   include "atomic_ops/sysdeps/emul_cas.h"
# elif !defined(CPPCHECK)
#   error Cannot implement AO_compare_and_swap_full on this architecture.
# endif
#endif



#if defined(AO_AO_TS_T) && !defined(AO_HAVE_CLEAR)
# define AO_CLEAR(addr) AO_store_release((AO_TS_t *)(addr), AO_TS_CLEAR)
# define AO_HAVE_CLEAR
#endif
#if defined(AO_CHAR_TS_T) && !defined(AO_HAVE_CLEAR)
# define AO_CLEAR(addr) AO_char_store_release((AO_TS_t *)(addr), AO_TS_CLEAR)
# define AO_HAVE_CLEAR
#endif


#if !defined(AO_GENERALIZE_TWICE) && defined(AO_CAN_EMUL_CAS) \
    && !defined(AO_HAVE_compare_and_swap_full) \
    && !defined(AO_HAVE_fetch_compare_and_swap_full)
# define AO_GENERALIZE_TWICE
#endif




#include "atomic_ops/generalize.h"

#if !defined(AO_GENERALIZE_TWICE) \
    && defined(AO_HAVE_compare_double_and_swap_double) \
    && (!defined(AO_HAVE_double_load) || !defined(AO_HAVE_double_store))
# define AO_GENERALIZE_TWICE
#endif

#ifdef AO_T_IS_INT
 
# include "atomic_ops/sysdeps/ao_t_is_int.h"
# ifndef AO_GENERALIZE_TWICE
   
#   define AO_GENERALIZE_TWICE
# endif
#endif

#ifdef AO_GENERALIZE_TWICE
# include "atomic_ops/generalize.h"
#endif


#define AO_TS_T AO_TS_t
#define AO_T AO_t
#define AO_TS_VAL AO_TS_VAL_t

#endif
