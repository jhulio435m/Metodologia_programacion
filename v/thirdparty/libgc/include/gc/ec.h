

#ifndef EC_H
#define EC_H

#ifndef CORD_H
# include "cord.h"
#endif

#ifdef __cplusplus
  extern "C" {
#endif






#ifndef CORD_BUFSZ
#   define CORD_BUFSZ 128
#endif



typedef struct CORD_ec_struct {
    CORD ec_cord;
    char * ec_bufptr;
    char ec_buf[CORD_BUFSZ+1];
} CORD_ec[1];


CORD_API void CORD_ec_flush_buf(CORD_ec);


#define CORD_ec_to_cord(x) (CORD_ec_flush_buf(x), (x)[0].ec_cord)


#define CORD_ec_init(x) \
                ((x)[0].ec_cord = 0, (void)((x)[0].ec_bufptr = (x)[0].ec_buf))


#define CORD_ec_append(x, c) \
                ((void)((x)[0].ec_bufptr == (x)[0].ec_buf + CORD_BUFSZ \
                        ? (CORD_ec_flush_buf(x), 0) : 0), \
                 (void)(*(x)[0].ec_bufptr++ = (c)))



CORD_API void CORD_ec_append_cord(CORD_ec, CORD);

#ifdef __cplusplus
  }
#endif

#endif
