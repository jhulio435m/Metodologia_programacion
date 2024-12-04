


#if !defined(CORD_POSITION_H) && defined(CORD_H)
#define CORD_POSITION_H

#ifdef __cplusplus
  extern "C" {
#endif






#define CORD_MAX_DEPTH 48
       
       

struct CORD_pe {
    CORD pe_cord;
    size_t pe_start_pos;
};



typedef struct CORD_Pos {
    size_t cur_pos;

    int path_len;
#       define CORD_POS_INVALID 0x55555555
               

    const char *cur_leaf;      
                               
                               
                               
                               
                               
                               
    size_t cur_start;  
    size_t cur_end;    
                       
    struct CORD_pe path[CORD_MAX_DEPTH + 1];
       
       
#   define CORD_FUNCTION_BUF_SZ 8
    char function_buf[CORD_FUNCTION_BUF_SZ];
                                       
                                       
} CORD_pos[1];


CORD_API CORD CORD_pos_to_cord(CORD_pos);


CORD_API size_t CORD_pos_to_index(CORD_pos);


CORD_API char CORD_pos_fetch(CORD_pos);



CORD_API void CORD_set_pos(CORD_pos, CORD, size_t);




CORD_API void CORD_next(CORD_pos);




CORD_API void CORD_prev(CORD_pos);


CORD_API int CORD_pos_valid(CORD_pos);

CORD_API char CORD__pos_fetch(CORD_pos);
CORD_API void CORD__next(CORD_pos);
CORD_API void CORD__prev(CORD_pos);

#define CORD_pos_fetch(p) \
    ((p)[0].cur_end != 0 ? \
        (p)[0].cur_leaf[(p)[0].cur_pos - (p)[0].cur_start] \
        : CORD__pos_fetch(p))

#define CORD_next(p) \
    ((p)[0].cur_pos + 1 < (p)[0].cur_end ? \
        (p)[0].cur_pos++ \
        : (CORD__next(p), 0U))

#define CORD_prev(p) \
    ((p)[0].cur_end != 0 && (p)[0].cur_pos > (p)[0].cur_start ? \
        (p)[0].cur_pos-- \
        : (CORD__prev(p), 0U))

#define CORD_pos_to_index(p) ((p)[0].cur_pos)

#define CORD_pos_to_cord(p) ((p)[0].path[0].pe_cord)

#define CORD_pos_valid(p) ((p)[0].path_len != CORD_POS_INVALID)



#define CORD_pos_chars_left(p) ((long)(p)[0].cur_end - (long)(p)[0].cur_pos)
       

#define CORD_pos_advance(p,n) ((p)[0].cur_pos += (n) - 1, CORD_next(p))
       
       

#define CORD_pos_cur_char_addr(p) \
    ((p)[0].cur_leaf + ((p)[0].cur_pos - (p)[0].cur_start))
       

#ifdef __cplusplus
  }
#endif

#endif
