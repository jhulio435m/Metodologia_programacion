


#if defined(GC_H)











#define GC_TMP_VERSION_MAJOR 8
#define GC_TMP_VERSION_MINOR 3
#define GC_TMP_VERSION_MICRO 0

#ifdef GC_VERSION_MAJOR
# if GC_TMP_VERSION_MAJOR != GC_VERSION_MAJOR \
     || GC_TMP_VERSION_MINOR != GC_VERSION_MINOR \
     || GC_TMP_VERSION_MICRO != GC_VERSION_MICRO
#   error Inconsistent version info.  Check README.md, include/gc_version.h and configure.ac.
# endif
#else
# define GC_VERSION_MAJOR GC_TMP_VERSION_MAJOR
# define GC_VERSION_MINOR GC_TMP_VERSION_MINOR
# define GC_VERSION_MICRO GC_TMP_VERSION_MICRO
#endif

#endif
