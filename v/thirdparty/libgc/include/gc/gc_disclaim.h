

#ifndef GC_DISCLAIM_H
#define GC_DISCLAIM_H

#include "gc.h"

#ifdef __cplusplus
  extern "C" {
#endif







GC_API void GC_CALL GC_init_finalized_malloc(void);


typedef int (GC_CALLBACK * GC_disclaim_proc)(void *);











GC_API void GC_CALL GC_register_disclaim_proc(int,
                                              GC_disclaim_proc,
                                              int);


struct GC_finalizer_closure {
    GC_finalization_proc proc;
    void *cd;
};














GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
        GC_finalized_malloc(size_t,
            const struct GC_finalizer_closure *) GC_ATTR_NONNULL(2);

#ifdef __cplusplus
  }
#endif

#endif
