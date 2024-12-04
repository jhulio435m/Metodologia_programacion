

#ifndef GC_JAVAXFC_H
#define GC_JAVAXFC_H

#ifndef GC_H
# include "gc.h"
#endif

#ifdef __cplusplus
  extern "C" {
#endif


GC_API void GC_CALL GC_finalize_all(void);

#ifdef GC_THREADS
 
 
 
 
 
# ifndef GC_SUSPEND_THREAD_ID
#   define GC_SUSPEND_THREAD_ID void*
# endif
  GC_API void GC_CALL GC_suspend_thread(GC_SUSPEND_THREAD_ID);
  GC_API void GC_CALL GC_resume_thread(GC_SUSPEND_THREAD_ID);

 
 
 
 
  GC_API int GC_CALL GC_is_thread_suspended(GC_SUSPEND_THREAD_ID);
#endif

#ifdef __cplusplus
  }
#endif

#endif
