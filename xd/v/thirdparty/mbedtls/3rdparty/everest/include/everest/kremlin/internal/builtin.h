

#ifndef __KREMLIN_BUILTIN_H
#define __KREMLIN_BUILTIN_H


#if (defined(_WIN32) || defined(_WIN64))
#  include <malloc.h>
#endif


void kremlinit_globals(void);

#endif
