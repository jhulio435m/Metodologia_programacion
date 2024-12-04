

#ifndef GC_TINY_FL_H
#define GC_TINY_FL_H





























#if defined(CPPCHECK) && GC_GRANULE_BYTES == 1
# undef GC_GRANULE_BYTES
#endif
#ifdef GC_GRANULE_BYTES
# define GC_GRANULE_PTRS (GC_GRANULE_BYTES / GC_SIZEOF_PTR)
#else
# define GC_GRANULE_PTRS 2
# define GC_GRANULE_BYTES (GC_GRANULE_PTRS * GC_SIZEOF_PTR)
#endif


#define GC_PTRS_TO_GRANULES(n) ((n) / GC_GRANULE_PTRS)



#define GC_PTRS_TO_WHOLE_GRANULES(n) \
                GC_PTRS_TO_GRANULES((n) + GC_GRANULE_PTRS - 1)





#ifndef GC_TINY_FREELISTS
# if GC_GRANULE_BYTES >= 16
#   define GC_TINY_FREELISTS 25
# else
#   define GC_TINY_FREELISTS 33
# endif
#endif










#define GC_RAW_BYTES_FROM_INDEX(i) ((i) * GC_GRANULE_BYTES)


#undef GC_GRANULE_WORDS
#define GC_GRANULE_WORDS GC_GRANULE_PTRS


#define GC_WORDS_TO_GRANULES(n) GC_PTRS_TO_GRANULES(n)


#define GC_WORDS_TO_WHOLE_GRANULES(n) GC_PTRS_TO_WHOLE_GRANULES(n)

#endif
