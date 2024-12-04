

#ifndef GC_INLINE_H
#define GC_INLINE_H















#include "gc.h"
#include "gc_tiny_fl.h"

#if GC_GNUC_PREREQ(3, 0) || defined(__clang__)
# define GC_EXPECT(expr, outcome) __builtin_expect(expr, outcome)
 
#else
# define GC_EXPECT(expr, outcome) (expr)
#endif

#ifndef GC_ASSERT
# ifdef NDEBUG
#   define GC_ASSERT(expr)
# else
#   include <assert.h>
#   define GC_ASSERT(expr) assert(expr)
# endif
#endif

#ifndef GC_PREFETCH_FOR_WRITE
# if (GC_GNUC_PREREQ(3, 0) || defined(__clang__)) \
     && !defined(GC_NO_PREFETCH_FOR_WRITE)
#   define GC_PREFETCH_FOR_WRITE(x) __builtin_prefetch((x), 1)
# elif defined(_MSC_VER) && !defined(GC_NO_PREFETCH_FOR_WRITE) \
       && (defined(_M_IX86) || defined(_M_X64)) && !defined(_CHPE_ONLY_) \
       && (_MSC_VER >= 1900)
#   include <intrin.h>
#   define GC_PREFETCH_FOR_WRITE(x) _m_prefetchw(x)
   
# else
#   define GC_PREFETCH_FOR_WRITE(x) (void)0
# endif
#endif

#ifdef __cplusplus
  extern "C" {
#endif


#define GC_I_PTRFREE 0
#define GC_I_NORMAL  1




GC_API int GC_CALL GC_get_dont_add_byte_at_end(void);



















GC_API void GC_CALL GC_generic_malloc_many(size_t,
                                           int, void **);




GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
        GC_malloc_kind(size_t, int);

#ifdef GC_THREADS
 
  GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
        GC_malloc_kind_global(size_t, int);
#else
# define GC_malloc_kind_global GC_malloc_kind
#endif



#if !defined(GC_THREADS) || !defined(AO_HAVE_store)
# define GC_FAST_M_AO_STORE(my_fl, next) (void)(*(my_fl) = (next))
#elif defined(__SIZEOF_POINTER__) && (__SIZEOF_POINTER__ > __SIZEOF_SIZE_T__)
 
 
# define GC_FAST_M_AO_STORE(my_fl, next) \
                        __atomic_store_n(my_fl, next, __ATOMIC_RELAXED)
#else
# define GC_FAST_M_AO_STORE(my_fl, next) \
                        AO_store((volatile AO_t *)(my_fl), (size_t)(next))
#endif


















#define GC_FAST_MALLOC_GRANS(result, lg, tiny_fl, num_direct, k, \
                             default_expr, init) \
  do { \
    if (GC_EXPECT((lg) >= GC_TINY_FREELISTS, 0)) { \
        result = (default_expr); \
    } else { \
        void **my_fl = (tiny_fl) + (lg); \
        void *my_entry = *my_fl; \
        void *next; \
        \
        for (;;) { \
            if (GC_EXPECT((GC_word)my_entry \
                          > (num_direct) + GC_TINY_FREELISTS + 1, 1)) { \
                next = *(void **)(my_entry); \
                result = my_entry; \
                GC_FAST_M_AO_STORE(my_fl, next); \
                init; \
                GC_PREFETCH_FOR_WRITE(next); \
                if ((k) != GC_I_PTRFREE) { \
                    GC_end_stubborn_change(my_fl); \
                    GC_reachable_here(next); \
                } \
                GC_ASSERT(GC_size(result) >= (lg) * GC_GRANULE_BYTES); \
                GC_ASSERT((k) == GC_I_PTRFREE \
                          || 0 == ((void **)result)[1]); \
                break; \
            } \
            \
            if ((GC_signed_word)my_entry - (GC_signed_word)(num_direct) <= 0 \
                    \
                    && my_entry != 0) { \
                \
                GC_FAST_M_AO_STORE(my_fl, (char *)my_entry + (lg) + 1); \
                result = (default_expr); \
                break; \
            } else { \
                \
                GC_generic_malloc_many(0 == (lg) ? GC_GRANULE_BYTES \
                                            : GC_RAW_BYTES_FROM_INDEX(lg), \
                                       k, my_fl); \
                my_entry = *my_fl; \
                if (my_entry == 0) { \
                    result = (*GC_get_oom_fn())((lg) * GC_GRANULE_BYTES); \
                    break; \
                } \
            } \
        } \
    } \
  } while (0)








#define GC_MALLOC_WORDS_KIND(result, n, tiny_fl, k, init) \
    do { \
      size_t lg = GC_PTRS_TO_WHOLE_GRANULES(n); \
      \
      GC_FAST_MALLOC_GRANS(result, lg, tiny_fl, 0, k, \
                           GC_malloc_kind(lg * GC_GRANULE_BYTES, k), init); \
    } while (0)

#define GC_MALLOC_WORDS(result, n, tiny_fl) \
        GC_MALLOC_WORDS_KIND(result, n, tiny_fl, GC_I_NORMAL, \
                             (void)(*(void **)(result) = 0))

#define GC_MALLOC_ATOMIC_WORDS(result, n, tiny_fl) \
        GC_MALLOC_WORDS_KIND(result, n, tiny_fl, GC_I_PTRFREE, (void)0)


#define GC_CONS(result, first, second, tiny_fl) \
    do { \
      void *l = (void *)(first); \
      void *r = (void *)(second); \
      GC_MALLOC_WORDS_KIND(result, 2, tiny_fl, GC_I_NORMAL, (void)0); \
      if ((result) != 0) { \
        *(void **)(result) = l; \
        GC_ptr_store_and_dirty((void **)(result) + 1, r); \
        GC_reachable_here(l); \
      } \
    } while (0)





GC_API void GC_CALL GC_print_free_list(int, size_t);

#ifdef __cplusplus
  }
#endif

#endif
