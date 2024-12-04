


#ifndef GC_MARK_H
#define GC_MARK_H

#ifndef GC_H
# include "gc.h"
#endif

#ifdef __cplusplus
  extern "C" {
#endif

#define GC_PROC_BYTES 100

#if defined(GC_BUILD) || defined(NOT_GCBUILD)
  struct GC_ms_entry;
  struct GC_hblk_s;
#else
  struct GC_ms_entry { void *opaque; };
  struct GC_hblk_s { void *opaque; };
#endif




























typedef struct GC_ms_entry * (GC_CALLBACK * GC_mark_proc)(GC_word *,
                                struct GC_ms_entry *,
                                struct GC_ms_entry *,
                                GC_word);

#define GC_LOG_MAX_MARK_PROCS 6
#define GC_MAX_MARK_PROCS (1 << GC_LOG_MAX_MARK_PROCS)




#define GC_RESERVED_MARK_PROCS 8
#define GC_GCJ_RESERVED_MARK_PROC_INDEX 0




#define GC_DS_TAG_BITS 2
#define GC_DS_TAGS   ((1U << GC_DS_TAG_BITS) - 1)
#define GC_DS_LENGTH 0 
                       
#define GC_DS_BITMAP 1 
                       
                       
                       
                       
                       
                       
                       
#define GC_DS_PROC   2
                       
                       
                       
                       
#define GC_MAKE_PROC(proc_index, env) \
            ((((((GC_word)(env)) << GC_LOG_MAX_MARK_PROCS) \
               | (unsigned)(proc_index)) << GC_DS_TAG_BITS) \
             | (GC_word)GC_DS_PROC)
#define GC_DS_PER_OBJECT 3
                       
                       
                       
                       
                       
                       
                       
                       
                       
                       
                       
                       
                       
                       
                       
#define GC_INDIR_PER_OBJ_BIAS 0x10

GC_API void * GC_least_plausible_heap_addr;
GC_API void * GC_greatest_plausible_heap_addr;
                       
                       
                       
                       
                       
                       
                       







GC_API void GC_CALL GC_set_pointer_mask(GC_word);
GC_API GC_word GC_CALL GC_get_pointer_mask(void);




GC_API void GC_CALL GC_set_pointer_shift(unsigned);
GC_API unsigned GC_CALL GC_get_pointer_shift(void);




















GC_API struct GC_ms_entry * GC_CALL GC_mark_and_push(void *,
                                struct GC_ms_entry *,
                                struct GC_ms_entry *,
                                void **);

#define GC_MARK_AND_PUSH(obj, msp, lim, src) \
    (GC_ADDR_LT((char *)GC_least_plausible_heap_addr, (char *)(obj)) \
     && GC_ADDR_LT((char *)(obj), (char *)GC_greatest_plausible_heap_addr) \
        ? GC_mark_and_push(obj, msp, lim, src) : (msp))

GC_API void GC_CALL GC_push_proc(GC_word, void *);

GC_API struct GC_ms_entry * GC_CALL GC_custom_push_proc(GC_word,
                                void *,
                                struct GC_ms_entry *,
                                struct GC_ms_entry *);

GC_API struct GC_ms_entry * GC_CALL GC_custom_push_range(void *,
                                void *,
                                struct GC_ms_entry *,
                                struct GC_ms_entry *);





GC_API GC_ATTR_CONST size_t GC_CALL GC_get_debug_header_size(void);
#define GC_USR_PTR_FROM_BASE(p) \
                ((void *)((char *)(p) + GC_get_debug_header_size()))





GC_API GC_ATTR_DEPRECATED
# ifdef GC_BUILD
    const
# endif
  size_t GC_debug_header_size;



GC_API GC_ATTR_CONST size_t GC_CALL GC_get_hblk_size(void);

typedef void (GC_CALLBACK * GC_walk_hblk_fn)(struct GC_hblk_s *,
                                             void *);




GC_API void GC_CALL GC_apply_to_all_blocks(GC_walk_hblk_fn,
                                void *) GC_ATTR_NONNULL(1);


typedef void (GC_CALLBACK * GC_walk_free_blk_fn)(struct GC_hblk_s *,
                                                 int,
                                                 void *);





GC_API void GC_CALL GC_iterate_free_hblks(GC_walk_free_blk_fn,
                                void *) GC_ATTR_NONNULL(1);






GC_API struct GC_hblk_s *GC_CALL GC_is_black_listed(struct GC_hblk_s *,
                                                    size_t);




GC_API unsigned GC_CALL GC_count_set_marks_in_hblk(const void *);






GC_API void ** GC_CALL GC_new_free_list(void);
GC_API void ** GC_CALL GC_new_free_list_inner(void);


GC_API unsigned GC_CALL GC_new_kind(void **,
                            GC_word,
                            int,
                            int) GC_ATTR_NONNULL(1);
               
GC_API unsigned GC_CALL GC_new_kind_inner(void **,
                            GC_word,
                            int,
                            int) GC_ATTR_NONNULL(1);



GC_API unsigned GC_CALL GC_new_proc(GC_mark_proc);
GC_API unsigned GC_CALL GC_new_proc_inner(GC_mark_proc);




GC_API void GC_CALL GC_init_gcj_malloc_mp(unsigned,
                                          GC_mark_proc);











GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL GC_generic_malloc(
                                                            size_t,
                                                            int);

GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
                                        GC_generic_malloc_ignore_off_page(
                                            size_t, int);
                               
                               
                               


GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
                                        GC_generic_malloc_uncollectable(
                                            size_t, int);




GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
                                        GC_generic_or_special_malloc(
                                            size_t, int);
GC_API GC_ATTR_MALLOC GC_ATTR_ALLOC_SIZE(1) void * GC_CALL
                                        GC_debug_generic_or_special_malloc(
                                            size_t, int,
                                            GC_EXTRA_PARAMS);

#ifdef GC_DEBUG
# define GC_GENERIC_OR_SPECIAL_MALLOC(sz, knd) \
                GC_debug_generic_or_special_malloc(sz, knd, GC_EXTRAS)
#else
# define GC_GENERIC_OR_SPECIAL_MALLOC(sz, knd) \
                GC_generic_or_special_malloc(sz, knd)
#endif



GC_API int GC_CALL GC_get_kind_and_size(const void *, size_t *)
                                                        GC_ATTR_NONNULL(1);

typedef void (GC_CALLBACK * GC_describe_type_fn)(void *,
                                                 char *);
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
                               
#define GC_TYPE_DESCR_LEN 40

GC_API void GC_CALL GC_register_describe_type_fn(int,
                                                 GC_describe_type_fn);
                               
                               
                               




GC_API void * GC_CALL GC_clear_stack(void *);










typedef void (GC_CALLBACK * GC_start_callback_proc)(void);
GC_API void GC_CALL GC_set_start_callback(GC_start_callback_proc);
GC_API GC_start_callback_proc GC_CALL GC_get_start_callback(void);






GC_API int GC_CALL GC_is_marked(const void *) GC_ATTR_NONNULL(1);
GC_API void GC_CALL GC_clear_mark_bit(const void *) GC_ATTR_NONNULL(1);
GC_API void GC_CALL GC_set_mark_bit(const void *) GC_ATTR_NONNULL(1);





GC_API void GC_CALL GC_push_all(void *, void *);
GC_API void GC_CALL GC_push_all_eager(void *, void *);
GC_API void GC_CALL GC_push_conditional(void *, void *,
                                        int);
GC_API void GC_CALL GC_push_finalizer_structures(void);





typedef void (GC_CALLBACK * GC_push_other_roots_proc)(void);
GC_API void GC_CALL GC_set_push_other_roots(GC_push_other_roots_proc);
GC_API GC_push_other_roots_proc GC_CALL GC_get_push_other_roots(void);






typedef void (GC_CALLBACK * GC_reachable_object_proc)(void *,
                                                size_t,
                                                void *);
GC_API void GC_CALL GC_enumerate_reachable_objects_inner(
                                GC_reachable_object_proc,
                                void *) GC_ATTR_NONNULL(1);



GC_API int GC_CALL GC_is_tmp_root(void *);

GC_API void GC_CALL GC_print_trace(GC_word);
GC_API void GC_CALL GC_print_trace_inner(GC_word);






typedef struct GC_ms_entry * (GC_CALLBACK * GC_on_mark_stack_empty_proc)(
                                struct GC_ms_entry *,
                                struct GC_ms_entry *);
GC_API void GC_CALL GC_set_on_mark_stack_empty(GC_on_mark_stack_empty_proc);
GC_API GC_on_mark_stack_empty_proc GC_CALL GC_get_on_mark_stack_empty(void);

#ifdef __cplusplus
  }
#endif

#endif
