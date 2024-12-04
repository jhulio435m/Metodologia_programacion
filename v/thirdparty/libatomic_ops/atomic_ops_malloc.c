#if defined(HAVE_CONFIG_H)
# include "config.h"
#endif

#ifdef DONT_USE_MMAP
# undef HAVE_MMAP
#endif

#ifndef AO_BUILD
# define AO_BUILD
#endif

#define AO_REQUIRE_CAS
#include "atomic_ops_malloc.h"

#include <string.h>    
#include <stdlib.h>
#include <assert.h>

#ifdef AO_TRACE_MALLOC
# include <stdio.h>
# include <pthread.h>
#endif

#if defined(AO_ADDRESS_SANITIZER) && !defined(AO_NO_MALLOC_POISON)
 
  void __asan_poison_memory_region(void *, size_t);
  void __asan_unpoison_memory_region(void *, size_t);
# define ASAN_POISON_MEMORY_REGION(addr, size) \
                __asan_poison_memory_region(addr, size)
# define ASAN_UNPOISON_MEMORY_REGION(addr, size) \
                __asan_unpoison_memory_region(addr, size)
#else
# define ASAN_POISON_MEMORY_REGION(addr, size) (void)0
# define ASAN_UNPOISON_MEMORY_REGION(addr, size) (void)0
#endif

#if (defined(_WIN32_WCE) || defined(__MINGW32CE__)) && !defined(AO_HAVE_abort)
# define abort() _exit(-1)
#endif



#ifndef LOG_MAX_SIZE
# define LOG_MAX_SIZE 16
       
#endif

#ifndef ALIGNMENT
# define ALIGNMENT 16
       
#endif

#define CHUNK_SIZE (1 << LOG_MAX_SIZE)

#ifndef AO_INITIAL_HEAP_SIZE
# ifndef AO_INITIAL_HEAP_CHUNKS
#   define AO_INITIAL_HEAP_CHUNKS 2*(LOG_MAX_SIZE+1)
# endif
# define AO_INITIAL_HEAP_SIZE (AO_INITIAL_HEAP_CHUNKS * CHUNK_SIZE)
#endif

static char AO_initial_heap[AO_INITIAL_HEAP_SIZE];

static AO_internal_ptr_t volatile initial_heap_ptr = 0;

#if defined(HAVE_MMAP)

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#if defined(MAP_ANONYMOUS) || defined(MAP_ANON)
# define USE_MMAP_ANON
#endif

#ifdef USE_MMAP_FIXED
# define GC_MMAP_FLAGS (MAP_FIXED | MAP_PRIVATE)
       
       
#else
# define GC_MMAP_FLAGS MAP_PRIVATE
#endif

#ifdef USE_MMAP_ANON
# if defined(CPPCHECK)
#   define OPT_MAP_ANON 0x20
# elif defined(MAP_ANONYMOUS)
#   define OPT_MAP_ANON MAP_ANONYMOUS
# else
#   define OPT_MAP_ANON MAP_ANON
# endif
#else
# include <unistd.h>
# define OPT_MAP_ANON 0
#endif

static volatile AO_t mmap_enabled = 0;

AO_API void
AO_malloc_enable_mmap(void)
{
# if defined(__sun)
    AO_store_release(&mmap_enabled, 1);
           
# else
    AO_store(&mmap_enabled, 1);
# endif
}

static char *get_mmaped(size_t sz)
{
  char * result;
# ifdef USE_MMAP_ANON
#   define zero_fd -1
# else
    int zero_fd;
# endif

  assert(!(sz & (CHUNK_SIZE - 1)));
  if (!mmap_enabled)
    return 0;

# ifndef USE_MMAP_ANON
    zero_fd = open("/dev/zero", O_RDONLY);
    if (zero_fd == -1)
      return 0;
# endif
  result = (char *)mmap(0, sz, PROT_READ | PROT_WRITE,
                        GC_MMAP_FLAGS | OPT_MAP_ANON,
                        zero_fd, 0);
# ifndef USE_MMAP_ANON
    close(zero_fd);
# endif
  if (AO_EXPECT_FALSE(result == MAP_FAILED))
    result = NULL;
  return result;
}

#ifndef SIZE_MAX
# include <limits.h>
#endif
#if defined(SIZE_MAX) && !defined(CPPCHECK)
# define AO_SIZE_MAX ((size_t)SIZE_MAX)
           
#else
# define AO_SIZE_MAX (~(size_t)0)
#endif



#define SIZET_SAT_ADD(a, b) \
    (AO_EXPECT_FALSE((a) >= AO_SIZE_MAX - (b)) ? AO_SIZE_MAX : (a) + (b))



static char *
AO_malloc_large(size_t sz)
{
  void *result;

 
 
  sz = SIZET_SAT_ADD(sz, ALIGNMENT + CHUNK_SIZE - 1)
            & ~(size_t)(CHUNK_SIZE - 1);
  assert(sz > LOG_MAX_SIZE);
  result = get_mmaped(sz);
  if (AO_EXPECT_FALSE(NULL == result))
    return NULL;

  result = (AO_uintptr_t *)result + ALIGNMENT / sizeof(AO_uintptr_t);
  ((AO_uintptr_t *)result)[-1] = (AO_uintptr_t)sz;
  return (char *)result;
}

static void
AO_free_large(void *p)
{
  size_t sz = (size_t)(((AO_uintptr_t *)p)[-1]);

  if (munmap((AO_uintptr_t *)p - ALIGNMENT / sizeof(AO_uintptr_t), sz) != 0)
    abort(); 
}

#else

AO_API void
AO_malloc_enable_mmap(void)
{
}

#define get_mmaped(sz) ((char*)0)
#define AO_malloc_large(sz) ((char*)0)
#define AO_free_large(p) abort()
               

#endif


#if defined(AO_FAT_POINTER) || defined(AO_STACK_USE_CPTR)
  AO_INLINE int
  AO_cptr_compare_and_swap(AO_internal_ptr_t volatile *addr,
                        AO_internal_ptr_t old_val, AO_internal_ptr_t new_val)
  {
    return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                        __ATOMIC_RELAXED, __ATOMIC_RELAXED);
  }

  AO_INLINE int
  AO_cptr_compare_and_swap_acquire(AO_internal_ptr_t volatile *addr,
                        AO_internal_ptr_t old_val, AO_internal_ptr_t new_val)
  {
    return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                        __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
  }

# define AO_cptr_load(p) __atomic_load_n(p, __ATOMIC_RELAXED)
#else
# define AO_cptr_compare_and_swap AO_compare_and_swap
# define AO_cptr_compare_and_swap_acquire AO_compare_and_swap_acquire
# define AO_cptr_load AO_load
#endif

static char *
get_chunk(void)
{
  AO_internal_ptr_t my_chunk_ptr;

  for (;;) {
    AO_internal_ptr_t initial_ptr = AO_cptr_load(&initial_heap_ptr);

    my_chunk_ptr = AO_EXPECT_FALSE(0 == initial_ptr) ?
                    (AO_internal_ptr_t)AO_initial_heap : initial_ptr;
   
#   ifdef AO_STACK_USE_CPTR
      my_chunk_ptr += ((size_t)ALIGNMENT - (size_t)(AO_uintptr_t)my_chunk_ptr)
                         & (ALIGNMENT - 1);
#   else
      my_chunk_ptr = (AO_internal_ptr_t)(((AO_uintptr_t)my_chunk_ptr
                                            + ALIGNMENT-1)
                                         & ~(AO_uintptr_t)(ALIGNMENT-1));
#   endif
    if (initial_ptr != my_chunk_ptr) {
     
      assert(my_chunk_ptr != 0);
      (void)AO_cptr_compare_and_swap_acquire(&initial_heap_ptr, initial_ptr,
                                             my_chunk_ptr);
    }

    if (AO_EXPECT_FALSE((AO_uintptr_t)my_chunk_ptr
                            < (AO_uintptr_t)AO_initial_heap)
        || AO_EXPECT_FALSE((AO_uintptr_t)my_chunk_ptr
                            > (AO_uintptr_t)(AO_initial_heap
                                    + AO_INITIAL_HEAP_SIZE - CHUNK_SIZE))) {
     
      my_chunk_ptr = (AO_internal_ptr_t)get_mmaped(CHUNK_SIZE);
#     if !defined(CPPCHECK)
        assert(((AO_uintptr_t)my_chunk_ptr & (ALIGNMENT - 1)) == 0);
#     endif
      break;
    }
    if (AO_cptr_compare_and_swap(&initial_heap_ptr, my_chunk_ptr,
                                 my_chunk_ptr + CHUNK_SIZE)) {
      break;
    }
  }
  return (char *)my_chunk_ptr;
}



static AO_stack_t AO_free_list[LOG_MAX_SIZE+1];



static void add_chunk_as(void * chunk, unsigned log_sz)
{
  size_t ofs, limit;
  size_t sz = (size_t)1 << log_sz;

  assert((size_t)CHUNK_SIZE >= sz);
  assert(sz % sizeof(AO_uintptr_t) == 0);
  limit = (size_t)CHUNK_SIZE - sz;
  for (ofs = ALIGNMENT - sizeof(AO_uintptr_t); ofs <= limit; ofs += sz) {
    ASAN_POISON_MEMORY_REGION((char *)chunk + ofs + sizeof(AO_uintptr_t),
                              sz - sizeof(AO_uintptr_t));
    AO_stack_push(&AO_free_list[log_sz],
                  (AO_uintptr_t *)chunk + ofs / sizeof(AO_uintptr_t));
  }
}

static const unsigned char msbs[16] = {
  0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4
};





static unsigned msb(size_t s)
{
  unsigned result = 0;
  if ((s & 0xff) != s) {
#   if (__SIZEOF_SIZE_T__ == 8) && !defined(CPPCHECK)
      unsigned v = (unsigned)(s >> 32);
      if (AO_EXPECT_FALSE(v != 0))
        {
          s = v;
          result += 32;
        }
#   elif __SIZEOF_SIZE_T__ == 4
     
#   else
      unsigned v;
     
     
#     define SIZEOF_SIZE_T_GT_4 (sizeof(size_t) > 4)
      if (SIZEOF_SIZE_T_GT_4
          && (v = (unsigned)(s >> (SIZEOF_SIZE_T_GT_4 ? 32 : 0))) != 0)
        {
          s = v;
          result += 32;
        }
#   endif
    if (AO_EXPECT_FALSE((s >> 16) != 0))
      {
        s >>= 16;
        result += 16;
      }
    if ((s >> 8) != 0)
      {
        s >>= 8;
        result += 8;
      }
  }
  if (s > 15)
    {
      s >>= 4;
      result += 4;
    }
  result += msbs[s];
  return result;
}

AO_API AO_ATTR_MALLOC AO_ATTR_ALLOC_SIZE(1)
void *
AO_malloc(size_t sz)
{
  AO_uintptr_t *result;
  unsigned log_sz;

  if (AO_EXPECT_FALSE(sz > CHUNK_SIZE - sizeof(AO_uintptr_t)))
    return AO_malloc_large(sz);
  log_sz = msb(sz + sizeof(AO_uintptr_t) - 1);
  assert(log_sz <= LOG_MAX_SIZE);
  assert(((size_t)1 << log_sz) >= sz + sizeof(AO_uintptr_t));
  result = AO_stack_pop(AO_free_list + log_sz);
  while (AO_EXPECT_FALSE(NULL == result)) {
    void *chunk = get_chunk();

    if (AO_EXPECT_FALSE(NULL == chunk))
      return NULL;
    add_chunk_as(chunk, log_sz);
    result = AO_stack_pop(AO_free_list + log_sz);
  }
  *result = log_sz;
# ifdef AO_TRACE_MALLOC
    fprintf(stderr, "%p: AO_malloc(%lu) = %p\n",
            (void *)pthread_self(), (unsigned long)sz, (void *)(result + 1));
# endif
  ASAN_UNPOISON_MEMORY_REGION(result + 1, sz);
  return result + 1;
}

AO_API void
AO_free(void *p)
{
  AO_uintptr_t *base;
  int log_sz;

  if (AO_EXPECT_FALSE(NULL == p))
    return;

  base = (AO_uintptr_t *)p - 1;
  log_sz = (int)(*base);
# ifdef AO_TRACE_MALLOC
    fprintf(stderr, "%p: AO_free(%p sz:%lu)\n", (void *)pthread_self(), p,
            log_sz > LOG_MAX_SIZE ? (unsigned)log_sz : 1UL << log_sz);
# endif
  if (AO_EXPECT_FALSE(log_sz > LOG_MAX_SIZE)) {
    AO_free_large(p);
  } else {
    ASAN_POISON_MEMORY_REGION(base + 1,
                              ((size_t)1 << log_sz) - sizeof(AO_uintptr_t));
    AO_stack_push(AO_free_list + log_sz, base);
  }
}
