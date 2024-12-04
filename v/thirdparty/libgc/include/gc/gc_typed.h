



#ifndef GC_TYPED_H
#define GC_TYPED_H

#ifndef GC_H
# include "gc.h"
#endif

#ifdef __cplusplus
  extern "C" {
#endif


#define GC_WORDSZ (8 * sizeof(GC_word))


#define GC_WORD_LEN(t) (sizeof(t) / sizeof(GC_word))


#define GC_WORD_OFFSET(t, f) (offsetof(t, f) / sizeof(GC_word))



typedef GC_word * GC_bitmap;




#define GC_BITMAP_SIZE(t) ((GC_WORD_LEN(t) + GC_WORDSZ - 1) / GC_WORDSZ)




#define GC_set_bit(bm, index) \
            ((bm)[(index) / GC_WORDSZ] |= (GC_word)1 << ((index) % GC_WORDSZ))
#define GC_get_bit(bm, index) \
            (((bm)[(index) / GC_WORDSZ] >> ((index) % GC_WORDSZ)) & 1)

typedef GC_word GC_descr;

GC_API GC_descr GC_CALL GC_make_descriptor(const GC_word *,
                                size_t);
               
               
               
               
               
               
               
               
               
               
               
               
               
               
               











GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
        GC_malloc_explicitly_typed(size_t,
                                   GC_descr);
               
               
               
               
               

GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
        GC_malloc_explicitly_typed_ignore_off_page(size_t,
                                                   GC_descr);

GC_API GC_ATTR_MALLOC GC_ATTR_CALLOC_SIZE(1, 2) void * GC_CALL
        GC_calloc_explicitly_typed(size_t,
                                   size_t,
                                   GC_descr);
       
       
       
       
       
       
       
       
       

#define GC_CALLOC_TYPED_DESCR_PTRS 1
#define GC_CALLOC_TYPED_DESCR_WORDS 8

#ifdef GC_BUILD
  struct GC_calloc_typed_descr_s;
#else
  struct GC_calloc_typed_descr_s {
    GC_uintptr_t opaque_p[GC_CALLOC_TYPED_DESCR_PTRS];
    GC_word opaque[GC_CALLOC_TYPED_DESCR_WORDS - GC_CALLOC_TYPED_DESCR_PTRS];
  };
#endif

GC_API int GC_CALL GC_calloc_prepare_explicitly_typed(
                        struct GC_calloc_typed_descr_s *,
                        size_t, size_t,
                        size_t, GC_descr);
       
       
       
       
       
       
       
       
       
       
       

GC_API GC_ATTR_MALLOC void * GC_CALL GC_calloc_do_explicitly_typed(
                        const struct GC_calloc_typed_descr_s *,
                        size_t);
       

#ifdef GC_DEBUG
# define GC_MALLOC_EXPLICITLY_TYPED(bytes, d) ((void)(d), GC_MALLOC(bytes))
# define GC_MALLOC_EXPLICITLY_TYPED_IGNORE_OFF_PAGE(bytes, d) \
                        GC_MALLOC_EXPLICITLY_TYPED(bytes, d)
# define GC_CALLOC_EXPLICITLY_TYPED(n, bytes, d) \
                        ((void)(d), GC_MALLOC((n) * (bytes)))
#else
# define GC_MALLOC_EXPLICITLY_TYPED(bytes, d) \
                        GC_malloc_explicitly_typed(bytes, d)
# define GC_MALLOC_EXPLICITLY_TYPED_IGNORE_OFF_PAGE(bytes, d) \
                        GC_malloc_explicitly_typed_ignore_off_page(bytes, d)
# define GC_CALLOC_EXPLICITLY_TYPED(n, bytes, d) \
                        GC_calloc_explicitly_typed(n, bytes, d)
#endif

#ifdef __cplusplus
  }
#endif

#endif
