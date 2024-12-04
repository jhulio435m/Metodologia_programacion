
















#ifndef GC_BACKPTR_H
#define GC_BACKPTR_H

#ifndef GC_H
# include "gc.h"
#endif

#ifdef __cplusplus
  extern "C" {
#endif

typedef enum {
    GC_UNREFERENCED,   
    GC_NO_SPACE,       
    GC_REFD_FROM_ROOT, 
    GC_REFD_FROM_REG,  
                       
    GC_REFD_FROM_HEAP, 
    GC_FINALIZER_REFD  
} GC_ref_kind;












GC_API GC_ref_kind GC_CALL GC_get_back_ptr_info(void *,
                                void **, size_t *)
                                GC_ATTR_NONNULL(1);




GC_API void * GC_CALL GC_generate_random_heap_address(void);



GC_API void * GC_CALL GC_generate_random_valid_address(void);





GC_API void GC_CALL GC_generate_random_backtrace(void);




GC_API void GC_CALL GC_print_backtrace(void *) GC_ATTR_NONNULL(1);

#ifdef __cplusplus
  }
#endif

#endif
