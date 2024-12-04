





#ifndef GC_GCJ_H
#define GC_GCJ_H

       
       
       
       
       
       
       
       

#ifndef GC_H
# include "gc.h"
#endif

#ifdef __cplusplus
  extern "C" {
#endif






















GC_API GC_ATTR_DEPRECATED void GC_CALL GC_init_gcj_malloc(int,
                                                          void *);





GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
        GC_gcj_malloc(size_t, const void *);



GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
        GC_debug_gcj_malloc(size_t, const void *,
                            GC_EXTRA_PARAMS);




GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
        GC_gcj_malloc_ignore_off_page(size_t,
                                      const void *);



GC_API int GC_gcj_kind;

GC_API int GC_gcj_debug_kind;

#ifdef GC_DEBUG
# define GC_GCJ_MALLOC(s,d) GC_debug_gcj_malloc(s,d,GC_EXTRAS)
# define GC_GCJ_MALLOC_IGNORE_OFF_PAGE(s,d) GC_GCJ_MALLOC(s,d)
#else
# define GC_GCJ_MALLOC(s,d) GC_gcj_malloc(s,d)
# define GC_GCJ_MALLOC_IGNORE_OFF_PAGE(s,d) GC_gcj_malloc_ignore_off_page(s,d)
#endif

#ifdef __cplusplus
  }
#endif

#endif
