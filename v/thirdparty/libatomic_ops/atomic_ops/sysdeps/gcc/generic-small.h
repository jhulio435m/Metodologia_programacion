

#if !defined(AO_GCC_HAVE_char_SYNC_CAS) || !defined(AO_PREFER_GENERALIZED)

AO_INLINE unsigned/**/char
AO_char_load(const volatile unsigned/**/char *addr)
{
  return __atomic_load_n(addr, __ATOMIC_RELAXED);
}
#define AO_HAVE_char_load

AO_INLINE unsigned/**/char
AO_char_load_acquire(const volatile unsigned/**/char *addr)
{
  return __atomic_load_n(addr, __ATOMIC_ACQUIRE);
}
#define AO_HAVE_char_load_acquire
















#ifndef AO_SKIPATOMIC_char_store
  AO_INLINE void
  AO_char_store(volatile unsigned/**/char *addr, unsigned/**/char value)
  {
    __atomic_store_n(addr, value, __ATOMIC_RELAXED);
  }
# define AO_HAVE_char_store
#endif

#ifndef AO_SKIPATOMIC_char_store_release
  AO_INLINE void
  AO_char_store_release(volatile unsigned/**/char *addr, unsigned/**/char value)
  {
    __atomic_store_n(addr, value, __ATOMIC_RELEASE);
  }
# define AO_HAVE_char_store_release
#endif

#endif

#ifdef AO_GCC_HAVE_char_SYNC_CAS

  AO_INLINE unsigned/**/char
  AO_char_fetch_compare_and_swap(volatile unsigned/**/char *addr,
                                  unsigned/**/char old_val, unsigned/**/char new_val)
  {
    (void)__atomic_compare_exchange_n(addr,
                                      &old_val,
                                      new_val,
                                      0,
                                      __ATOMIC_RELAXED,
                                      __ATOMIC_RELAXED);
    return old_val;
  }
# define AO_HAVE_char_fetch_compare_and_swap

  AO_INLINE unsigned/**/char
  AO_char_fetch_compare_and_swap_acquire(volatile unsigned/**/char *addr,
                                          unsigned/**/char old_val, unsigned/**/char new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    return old_val;
  }
# define AO_HAVE_char_fetch_compare_and_swap_acquire

  AO_INLINE unsigned/**/char
  AO_char_fetch_compare_and_swap_release(volatile unsigned/**/char *addr,
                                          unsigned/**/char old_val, unsigned/**/char new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_RELEASE,
                                      __ATOMIC_RELAXED);
    return old_val;
  }
# define AO_HAVE_char_fetch_compare_and_swap_release

  AO_INLINE unsigned/**/char
  AO_char_fetch_compare_and_swap_full(volatile unsigned/**/char *addr,
                                       unsigned/**/char old_val, unsigned/**/char new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_ACQ_REL,
                                      __ATOMIC_ACQUIRE);
    return old_val;
  }
# define AO_HAVE_char_fetch_compare_and_swap_full

# ifndef AO_GENERALIZE_ASM_BOOL_CAS
    AO_INLINE int
    AO_char_compare_and_swap(volatile unsigned/**/char *addr,
                              unsigned/**/char old_val, unsigned/**/char new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
#   define AO_HAVE_char_compare_and_swap

    AO_INLINE int
    AO_char_compare_and_swap_acquire(volatile unsigned/**/char *addr,
                                      unsigned/**/char old_val, unsigned/**/char new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_char_compare_and_swap_acquire

    AO_INLINE int
    AO_char_compare_and_swap_release(volatile unsigned/**/char *addr,
                                      unsigned/**/char old_val, unsigned/**/char new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                              __ATOMIC_RELEASE,
                                              __ATOMIC_RELAXED);
    }
#   define AO_HAVE_char_compare_and_swap_release

    AO_INLINE int
    AO_char_compare_and_swap_full(volatile unsigned/**/char *addr,
                                   unsigned/**/char old_val, unsigned/**/char new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                              __ATOMIC_ACQ_REL,
                                              __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_char_compare_and_swap_full

# endif

#endif


#if !defined(AO_GCC_HAVE_short_SYNC_CAS) || !defined(AO_PREFER_GENERALIZED)

AO_INLINE unsigned/**/short
AO_short_load(const volatile unsigned/**/short *addr)
{
  return __atomic_load_n(addr, __ATOMIC_RELAXED);
}
#define AO_HAVE_short_load

AO_INLINE unsigned/**/short
AO_short_load_acquire(const volatile unsigned/**/short *addr)
{
  return __atomic_load_n(addr, __ATOMIC_ACQUIRE);
}
#define AO_HAVE_short_load_acquire
















#ifndef AO_SKIPATOMIC_short_store
  AO_INLINE void
  AO_short_store(volatile unsigned/**/short *addr, unsigned/**/short value)
  {
    __atomic_store_n(addr, value, __ATOMIC_RELAXED);
  }
# define AO_HAVE_short_store
#endif

#ifndef AO_SKIPATOMIC_short_store_release
  AO_INLINE void
  AO_short_store_release(volatile unsigned/**/short *addr, unsigned/**/short value)
  {
    __atomic_store_n(addr, value, __ATOMIC_RELEASE);
  }
# define AO_HAVE_short_store_release
#endif

#endif

#ifdef AO_GCC_HAVE_short_SYNC_CAS

  AO_INLINE unsigned/**/short
  AO_short_fetch_compare_and_swap(volatile unsigned/**/short *addr,
                                  unsigned/**/short old_val, unsigned/**/short new_val)
  {
    (void)__atomic_compare_exchange_n(addr,
                                      &old_val,
                                      new_val,
                                      0,
                                      __ATOMIC_RELAXED,
                                      __ATOMIC_RELAXED);
    return old_val;
  }
# define AO_HAVE_short_fetch_compare_and_swap

  AO_INLINE unsigned/**/short
  AO_short_fetch_compare_and_swap_acquire(volatile unsigned/**/short *addr,
                                          unsigned/**/short old_val, unsigned/**/short new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    return old_val;
  }
# define AO_HAVE_short_fetch_compare_and_swap_acquire

  AO_INLINE unsigned/**/short
  AO_short_fetch_compare_and_swap_release(volatile unsigned/**/short *addr,
                                          unsigned/**/short old_val, unsigned/**/short new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_RELEASE,
                                      __ATOMIC_RELAXED);
    return old_val;
  }
# define AO_HAVE_short_fetch_compare_and_swap_release

  AO_INLINE unsigned/**/short
  AO_short_fetch_compare_and_swap_full(volatile unsigned/**/short *addr,
                                       unsigned/**/short old_val, unsigned/**/short new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_ACQ_REL,
                                      __ATOMIC_ACQUIRE);
    return old_val;
  }
# define AO_HAVE_short_fetch_compare_and_swap_full

# ifndef AO_GENERALIZE_ASM_BOOL_CAS
    AO_INLINE int
    AO_short_compare_and_swap(volatile unsigned/**/short *addr,
                              unsigned/**/short old_val, unsigned/**/short new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
#   define AO_HAVE_short_compare_and_swap

    AO_INLINE int
    AO_short_compare_and_swap_acquire(volatile unsigned/**/short *addr,
                                      unsigned/**/short old_val, unsigned/**/short new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_short_compare_and_swap_acquire

    AO_INLINE int
    AO_short_compare_and_swap_release(volatile unsigned/**/short *addr,
                                      unsigned/**/short old_val, unsigned/**/short new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                              __ATOMIC_RELEASE,
                                              __ATOMIC_RELAXED);
    }
#   define AO_HAVE_short_compare_and_swap_release

    AO_INLINE int
    AO_short_compare_and_swap_full(volatile unsigned/**/short *addr,
                                   unsigned/**/short old_val, unsigned/**/short new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                              __ATOMIC_ACQ_REL,
                                              __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_short_compare_and_swap_full

# endif

#endif


#if !defined(AO_GCC_HAVE_int_SYNC_CAS) || !defined(AO_PREFER_GENERALIZED)

AO_INLINE unsigned
AO_int_load(const volatile unsigned *addr)
{
  return __atomic_load_n(addr, __ATOMIC_RELAXED);
}
#define AO_HAVE_int_load

AO_INLINE unsigned
AO_int_load_acquire(const volatile unsigned *addr)
{
  return __atomic_load_n(addr, __ATOMIC_ACQUIRE);
}
#define AO_HAVE_int_load_acquire
















#ifndef AO_SKIPATOMIC_int_store
  AO_INLINE void
  AO_int_store(volatile unsigned *addr, unsigned value)
  {
    __atomic_store_n(addr, value, __ATOMIC_RELAXED);
  }
# define AO_HAVE_int_store
#endif

#ifndef AO_SKIPATOMIC_int_store_release
  AO_INLINE void
  AO_int_store_release(volatile unsigned *addr, unsigned value)
  {
    __atomic_store_n(addr, value, __ATOMIC_RELEASE);
  }
# define AO_HAVE_int_store_release
#endif

#endif

#ifdef AO_GCC_HAVE_int_SYNC_CAS

  AO_INLINE unsigned
  AO_int_fetch_compare_and_swap(volatile unsigned *addr,
                                  unsigned old_val, unsigned new_val)
  {
    (void)__atomic_compare_exchange_n(addr,
                                      &old_val,
                                      new_val,
                                      0,
                                      __ATOMIC_RELAXED,
                                      __ATOMIC_RELAXED);
    return old_val;
  }
# define AO_HAVE_int_fetch_compare_and_swap

  AO_INLINE unsigned
  AO_int_fetch_compare_and_swap_acquire(volatile unsigned *addr,
                                          unsigned old_val, unsigned new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    return old_val;
  }
# define AO_HAVE_int_fetch_compare_and_swap_acquire

  AO_INLINE unsigned
  AO_int_fetch_compare_and_swap_release(volatile unsigned *addr,
                                          unsigned old_val, unsigned new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_RELEASE,
                                      __ATOMIC_RELAXED);
    return old_val;
  }
# define AO_HAVE_int_fetch_compare_and_swap_release

  AO_INLINE unsigned
  AO_int_fetch_compare_and_swap_full(volatile unsigned *addr,
                                       unsigned old_val, unsigned new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_ACQ_REL,
                                      __ATOMIC_ACQUIRE);
    return old_val;
  }
# define AO_HAVE_int_fetch_compare_and_swap_full

# ifndef AO_GENERALIZE_ASM_BOOL_CAS
    AO_INLINE int
    AO_int_compare_and_swap(volatile unsigned *addr,
                              unsigned old_val, unsigned new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
#   define AO_HAVE_int_compare_and_swap

    AO_INLINE int
    AO_int_compare_and_swap_acquire(volatile unsigned *addr,
                                      unsigned old_val, unsigned new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_int_compare_and_swap_acquire

    AO_INLINE int
    AO_int_compare_and_swap_release(volatile unsigned *addr,
                                      unsigned old_val, unsigned new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                              __ATOMIC_RELEASE,
                                              __ATOMIC_RELAXED);
    }
#   define AO_HAVE_int_compare_and_swap_release

    AO_INLINE int
    AO_int_compare_and_swap_full(volatile unsigned *addr,
                                   unsigned old_val, unsigned new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                              __ATOMIC_ACQ_REL,
                                              __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_int_compare_and_swap_full

# endif

#endif


#if !defined(AO_GCC_HAVE_SYNC_CAS) || !defined(AO_PREFER_GENERALIZED)

AO_INLINE AO_t
AO_load(const volatile AO_t *addr)
{
  return __atomic_load_n(addr, __ATOMIC_RELAXED);
}
#define AO_HAVE_load

AO_INLINE AO_t
AO_load_acquire(const volatile AO_t *addr)
{
  return __atomic_load_n(addr, __ATOMIC_ACQUIRE);
}
#define AO_HAVE_load_acquire
















#ifndef AO_SKIPATOMIC_store
  AO_INLINE void
  AO_store(volatile AO_t *addr, AO_t value)
  {
    __atomic_store_n(addr, value, __ATOMIC_RELAXED);
  }
# define AO_HAVE_store
#endif

#ifndef AO_SKIPATOMIC_store_release
  AO_INLINE void
  AO_store_release(volatile AO_t *addr, AO_t value)
  {
    __atomic_store_n(addr, value, __ATOMIC_RELEASE);
  }
# define AO_HAVE_store_release
#endif

#endif

#ifdef AO_GCC_HAVE_SYNC_CAS

  AO_INLINE AO_t
  AO_fetch_compare_and_swap(volatile AO_t *addr,
                                  AO_t old_val, AO_t new_val)
  {
    (void)__atomic_compare_exchange_n(addr,
                                      &old_val,
                                      new_val,
                                      0,
                                      __ATOMIC_RELAXED,
                                      __ATOMIC_RELAXED);
    return old_val;
  }
# define AO_HAVE_fetch_compare_and_swap

  AO_INLINE AO_t
  AO_fetch_compare_and_swap_acquire(volatile AO_t *addr,
                                          AO_t old_val, AO_t new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    return old_val;
  }
# define AO_HAVE_fetch_compare_and_swap_acquire

  AO_INLINE AO_t
  AO_fetch_compare_and_swap_release(volatile AO_t *addr,
                                          AO_t old_val, AO_t new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_RELEASE,
                                      __ATOMIC_RELAXED);
    return old_val;
  }
# define AO_HAVE_fetch_compare_and_swap_release

  AO_INLINE AO_t
  AO_fetch_compare_and_swap_full(volatile AO_t *addr,
                                       AO_t old_val, AO_t new_val)
  {
    (void)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                      __ATOMIC_ACQ_REL,
                                      __ATOMIC_ACQUIRE);
    return old_val;
  }
# define AO_HAVE_fetch_compare_and_swap_full

# ifndef AO_GENERALIZE_ASM_BOOL_CAS
    AO_INLINE int
    AO_compare_and_swap(volatile AO_t *addr,
                              AO_t old_val, AO_t new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                        __ATOMIC_RELAXED, __ATOMIC_RELAXED);
    }
#   define AO_HAVE_compare_and_swap

    AO_INLINE int
    AO_compare_and_swap_acquire(volatile AO_t *addr,
                                      AO_t old_val, AO_t new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_compare_and_swap_acquire

    AO_INLINE int
    AO_compare_and_swap_release(volatile AO_t *addr,
                                      AO_t old_val, AO_t new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                              __ATOMIC_RELEASE,
                                              __ATOMIC_RELAXED);
    }
#   define AO_HAVE_compare_and_swap_release

    AO_INLINE int
    AO_compare_and_swap_full(volatile AO_t *addr,
                                   AO_t old_val, AO_t new_val)
    {
      return (int)__atomic_compare_exchange_n(addr, &old_val, new_val, 0,
                                              __ATOMIC_ACQ_REL,
                                              __ATOMIC_ACQUIRE);
    }
#   define AO_HAVE_compare_and_swap_full

# endif

#endif
