



#ifndef CORD_H
#define CORD_H

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
  extern "C" {
#endif

#if defined(GC_DLL) && !defined(CORD_NOT_DLL) && !defined(CORD_API)
 
# ifdef CORD_BUILD
#   if defined(__MINGW32__) && !defined(__cplusplus) || defined(__CEGCC__)
#     define CORD_API __declspec(dllexport)
#   elif defined(_MSC_VER) || defined(__DMC__) || defined(__BORLANDC__) \
         || defined(__CYGWIN__) || defined(__MINGW32__) \
         || defined(__WATCOMC__)
#     define CORD_API extern __declspec(dllexport)
#   elif defined(__GNUC__) && !defined(GC_NO_VISIBILITY) \
         && (__GNUC__ >= 4 || defined(GC_VISIBILITY_HIDDEN_SET))
   
#     define CORD_API extern __attribute__((__visibility__("default")))
#   endif
# else
#   if defined(__BORLANDC__) || defined(__CEGCC__) || defined(__CYGWIN__) \
       || defined(__DMC__) || defined(_MSC_VER)
#     define CORD_API __declspec(dllimport)
#   elif defined(__MINGW32__) || defined(__WATCOMC__)
#     define CORD_API extern __declspec(dllimport)
#   endif
# endif
#endif

#ifndef CORD_API
# define CORD_API extern
#endif







typedef const char * CORD;


#define CORD_EMPTY 0


#define CORD_IS_STRING(s) (*(s) != '\0')



CORD_API CORD CORD_cat(CORD, CORD);





CORD_API CORD CORD_cat_char_star(CORD,
                                 const char *, size_t);


CORD_API size_t CORD_len(CORD);


typedef char (*CORD_fn)(size_t, void *);


CORD_API CORD CORD_from_fn(CORD_fn, void *,
                           size_t);



CORD_API CORD CORD_substr(CORD, size_t, size_t);









CORD_API CORD CORD_balance(CORD);








typedef int (*CORD_iter_fn)(char, void *);



typedef int (*CORD_batched_iter_fn)(const char *, void *);

#define CORD_NO_FN ((CORD_batched_iter_fn)0)









CORD_API int CORD_iter5(CORD, size_t, CORD_iter_fn,
                        CORD_batched_iter_fn,
                        void *);


CORD_API int CORD_iter(CORD, CORD_iter_fn, void *);
#define CORD_iter(x, f1, cd) CORD_iter5(x, 0, f1, CORD_NO_FN, cd)



CORD_API int CORD_riter4(CORD, size_t, CORD_iter_fn,
                         void *);


CORD_API int CORD_riter(CORD, CORD_iter_fn, void *);

#ifdef __cplusplus
  }
#endif











#include "cord_pos.h"



#ifdef __cplusplus
  extern "C" {
#endif

#define CORD_FOR(pos, cord) \
    for (CORD_set_pos(pos, cord, 0); CORD_pos_valid(pos); CORD_next(pos))



#ifndef CORD_DONT_DECLARE_OOM_FN
  CORD_API void (*CORD_oom_fn)(void);
#endif
#ifdef CORD_BUILD
  void CORD__call_oom_fn(void);
#endif



CORD_API void CORD_dump(CORD);





CORD_API CORD CORD_cat_char(CORD, char);


CORD_API CORD CORD_catn(int, ...);


CORD_API char CORD_fetch(CORD, size_t);


CORD_API int CORD_cmp(CORD, CORD);



CORD_API int CORD_ncmp(CORD, size_t,
                       CORD, size_t, size_t);




CORD_API size_t CORD_str(CORD, size_t, CORD);




CORD_API CORD CORD_chars(char, size_t);

#define CORD_nul(i) CORD_chars('\0', (i))

















CORD_API CORD CORD_from_file(FILE *);




CORD_API CORD CORD_from_file_eager(FILE *);



CORD_API CORD CORD_from_file_lazy(FILE *);



CORD_API char * CORD_to_char_star(CORD);



CORD_API CORD CORD_from_char_star(const char *);



CORD_API const char * CORD_to_const_char_star(CORD);




CORD_API int CORD_put(CORD, FILE *);


#define CORD_NOT_FOUND ((size_t)(-1))




CORD_API size_t CORD_chr(CORD, size_t, int);




CORD_API size_t CORD_rchr(CORD, size_t, int);

#ifdef __cplusplus
  }
#endif

























#ifndef CORD_NO_IO

#include <stdarg.h>

# ifdef __cplusplus
    extern "C" {
# endif

  CORD_API int CORD_sprintf(CORD *, CORD, ...);
  CORD_API int CORD_vsprintf(CORD *, CORD, va_list);
  CORD_API int CORD_fprintf(FILE *, CORD, ...);
  CORD_API int CORD_vfprintf(FILE *, CORD, va_list);
  CORD_API int CORD_printf(CORD, ...);
  CORD_API int CORD_vprintf(CORD, va_list);

# ifdef __cplusplus
    }
# endif

#endif

#endif
