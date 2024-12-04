




#ifndef GC_PTHREAD_REDIRECTS_H
#define GC_PTHREAD_REDIRECTS_H


#if defined(GC_H) && defined(GC_PTHREADS)










#ifndef GC_PTHREAD_REDIRECTS_ONLY

# include <pthread.h>
# ifndef GC_NO_DLOPEN
#   include <dlfcn.h>
# endif
# ifndef GC_NO_PTHREAD_SIGMASK
#   include <signal.h> 
# endif

# ifdef __cplusplus
    extern "C" {
# endif

# ifndef GC_SUSPEND_THREAD_ID
#   define GC_SUSPEND_THREAD_ID pthread_t
# endif

# ifndef GC_NO_DLOPEN
    GC_API void *GC_dlopen(const char *, int);
# endif

# ifndef GC_NO_PTHREAD_SIGMASK
#   if defined(GC_PTHREAD_SIGMASK_NEEDED) \
        || defined(GC_HAVE_PTHREAD_SIGMASK) || defined(_BSD_SOURCE) \
        || defined(_GNU_SOURCE) || defined(_NETBSD_SOURCE) \
        || (_POSIX_C_SOURCE >= 199506L) || (_XOPEN_SOURCE >= 500) \
        || (__POSIX_VISIBLE >= 199506)
      GC_API int GC_pthread_sigmask(int, const sigset_t *,
                                    sigset_t *);
#   else
#     define GC_NO_PTHREAD_SIGMASK
#   endif
# endif

# ifndef GC_PTHREAD_CREATE_CONST
   
#   define GC_PTHREAD_CREATE_CONST const
# endif

  GC_API int GC_pthread_create(pthread_t *,
                               GC_PTHREAD_CREATE_CONST pthread_attr_t *,
                               void *(*)(void *), void *);
  GC_API int GC_pthread_join(pthread_t, void **);
  GC_API int GC_pthread_detach(pthread_t);

# ifndef GC_NO_PTHREAD_CANCEL
    GC_API int GC_pthread_cancel(pthread_t);
# endif

# if defined(GC_HAVE_PTHREAD_EXIT) && !defined(GC_PTHREAD_EXIT_DECLARED)
#   define GC_PTHREAD_EXIT_DECLARED
    GC_API void GC_pthread_exit(void *) GC_PTHREAD_EXIT_ATTRIBUTE;
# endif

# ifdef __cplusplus
    }
# endif

#endif

#if !defined(GC_NO_THREAD_REDIRECTS) && !defined(GC_USE_LD_WRAP)
 
 
 
# undef pthread_create
# undef pthread_join
# undef pthread_detach
# define pthread_create GC_pthread_create
# define pthread_join GC_pthread_join
# define pthread_detach GC_pthread_detach

# ifndef GC_NO_PTHREAD_SIGMASK
#   undef pthread_sigmask
#   define pthread_sigmask GC_pthread_sigmask
# endif
# ifndef GC_NO_DLOPEN
#   undef dlopen
#   define dlopen GC_dlopen
# endif
# ifndef GC_NO_PTHREAD_CANCEL
#   undef pthread_cancel
#   define pthread_cancel GC_pthread_cancel
# endif
# ifdef GC_HAVE_PTHREAD_EXIT
#   undef pthread_exit
#   define pthread_exit GC_pthread_exit
# endif
#endif

#endif

#endif
