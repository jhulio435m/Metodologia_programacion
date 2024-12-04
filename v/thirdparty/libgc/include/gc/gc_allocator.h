



#ifndef GC_ALLOCATOR_H
#define GC_ALLOCATOR_H

#include "gc.h"

#include <new> 

#ifdef GC_NAMESPACE_ALLOCATOR
namespace boehmgc
{
#endif

#if !defined(GC_NO_MEMBER_TEMPLATES) && defined(_MSC_VER) && _MSC_VER <= 1200
  
# define GC_NO_MEMBER_TEMPLATES
#endif

#if defined(GC_NEW_ABORTS_ON_OOM) || defined(_LIBCPP_NO_EXCEPTIONS)
# define GC_ALLOCATOR_THROW_OR_ABORT() GC_abort_on_oom()
#else
# define GC_ALLOCATOR_THROW_OR_ABORT() throw std::bad_alloc()
#endif

#if __cplusplus >= 201103L
# define GC_ALCTR_PTRDIFF_T std::ptrdiff_t
# define GC_ALCTR_SIZE_T std::size_t
#else
# define GC_ALCTR_PTRDIFF_T ptrdiff_t
# define GC_ALCTR_SIZE_T size_t
#endif





struct GC_true_type {};
struct GC_false_type {};

template <class GC_tp>
struct GC_type_traits {
  GC_false_type GC_is_ptr_free;
};

#define GC_DECLARE_PTRFREE(T) \
    template<> struct GC_type_traits<T> { GC_true_type GC_is_ptr_free; }

GC_DECLARE_PTRFREE(char);
GC_DECLARE_PTRFREE(signed char);
GC_DECLARE_PTRFREE(unsigned char);
GC_DECLARE_PTRFREE(signed short);
GC_DECLARE_PTRFREE(unsigned short);
GC_DECLARE_PTRFREE(signed int);
GC_DECLARE_PTRFREE(unsigned int);
GC_DECLARE_PTRFREE(signed long);
GC_DECLARE_PTRFREE(unsigned long);
GC_DECLARE_PTRFREE(float);
GC_DECLARE_PTRFREE(double);
GC_DECLARE_PTRFREE(long double);




template <class GC_Tp>
inline void * GC_selective_alloc(GC_ALCTR_SIZE_T n, GC_Tp,
                                 bool ignore_off_page) {
    void *obj = ignore_off_page ? GC_MALLOC_IGNORE_OFF_PAGE(n) : GC_MALLOC(n);
    if (0 == obj)
      GC_ALLOCATOR_THROW_OR_ABORT();
    return obj;
}

#if !defined(__WATCOMC__)
  
  template <>
  inline void * GC_selective_alloc<GC_true_type>(GC_ALCTR_SIZE_T n,
                                                 GC_true_type,
                                                 bool ignore_off_page) {
    void *obj = ignore_off_page ? GC_MALLOC_ATOMIC_IGNORE_OFF_PAGE(n)
                                 : GC_MALLOC_ATOMIC(n);
    if (0 == obj)
      GC_ALLOCATOR_THROW_OR_ABORT();
    return obj;
  }
#endif


template <class GC_Tp>
class gc_allocator {
public:
  typedef GC_ALCTR_SIZE_T    size_type;
  typedef GC_ALCTR_PTRDIFF_T difference_type;
  typedef GC_Tp*       pointer;
  typedef const GC_Tp* const_pointer;
  typedef GC_Tp&       reference;
  typedef const GC_Tp& const_reference;
  typedef GC_Tp        value_type;

  template <class GC_Tp1> struct rebind {
    typedef gc_allocator<GC_Tp1> other;
  };

  GC_CONSTEXPR gc_allocator() GC_NOEXCEPT {}
  GC_CONSTEXPR gc_allocator(const gc_allocator&) GC_NOEXCEPT {}
# ifndef GC_NO_MEMBER_TEMPLATES
    template <class GC_Tp1> GC_ATTR_EXPLICIT
    GC_CONSTEXPR gc_allocator(const gc_allocator<GC_Tp1>&) GC_NOEXCEPT {}
# endif
  GC_CONSTEXPR ~gc_allocator() GC_NOEXCEPT {}

  GC_CONSTEXPR pointer address(reference GC_x) const { return &GC_x; }
  GC_CONSTEXPR const_pointer address(const_reference GC_x) const {
    return &GC_x;
  }

  
  
  GC_CONSTEXPR GC_Tp* allocate(size_type GC_n, const void* = 0) {
    GC_type_traits<GC_Tp> traits;
    return static_cast<GC_Tp *>(GC_selective_alloc(GC_n * sizeof(GC_Tp),
                                        traits.GC_is_ptr_free, false));
  }

  GC_CONSTEXPR void deallocate(pointer __p, size_type) GC_NOEXCEPT {
    GC_FREE(__p);
  }

  GC_CONSTEXPR size_type max_size() const GC_NOEXCEPT {
    return static_cast<GC_ALCTR_SIZE_T>(-1) / sizeof(GC_Tp);
  }

  GC_CONSTEXPR void construct(pointer __p, const GC_Tp& __val) {
    new(__p) GC_Tp(__val);
  }

  GC_CONSTEXPR void destroy(pointer __p) { __p->~GC_Tp(); }
};

template<>
class gc_allocator<void> {
public:
  typedef GC_ALCTR_SIZE_T    size_type;
  typedef GC_ALCTR_PTRDIFF_T difference_type;
  typedef void*       pointer;
  typedef const void* const_pointer;
  typedef void        value_type;

  template <class GC_Tp1> struct rebind {
    typedef gc_allocator<GC_Tp1> other;
  };
};

template <class GC_T1, class GC_T2>
GC_CONSTEXPR inline bool operator==(const gc_allocator<GC_T1>&,
                                    const gc_allocator<GC_T2>&) GC_NOEXCEPT {
  return true;
}

template <class GC_T1, class GC_T2>
GC_CONSTEXPR inline bool operator!=(const gc_allocator<GC_T1>&,
                                    const gc_allocator<GC_T2>&) GC_NOEXCEPT {
  return false;
}


template <class GC_Tp>
class gc_allocator_ignore_off_page {
public:
  typedef GC_ALCTR_SIZE_T    size_type;
  typedef GC_ALCTR_PTRDIFF_T difference_type;
  typedef GC_Tp*       pointer;
  typedef const GC_Tp* const_pointer;
  typedef GC_Tp&       reference;
  typedef const GC_Tp& const_reference;
  typedef GC_Tp        value_type;

  template <class GC_Tp1> struct rebind {
    typedef gc_allocator_ignore_off_page<GC_Tp1> other;
  };

  GC_CONSTEXPR gc_allocator_ignore_off_page() GC_NOEXCEPT {}
  GC_CONSTEXPR gc_allocator_ignore_off_page(
                const gc_allocator_ignore_off_page&) GC_NOEXCEPT {}
# ifndef GC_NO_MEMBER_TEMPLATES
    template <class GC_Tp1> GC_ATTR_EXPLICIT
    GC_CONSTEXPR gc_allocator_ignore_off_page(
                const gc_allocator_ignore_off_page<GC_Tp1>&) GC_NOEXCEPT {}
# endif
  GC_CONSTEXPR ~gc_allocator_ignore_off_page() GC_NOEXCEPT {}

  GC_CONSTEXPR pointer address(reference GC_x) const { return &GC_x; }
  GC_CONSTEXPR const_pointer address(const_reference GC_x) const {
    return &GC_x;
  }

  
  
  GC_CONSTEXPR GC_Tp* allocate(size_type GC_n, const void* = 0) {
    GC_type_traits<GC_Tp> traits;
    return static_cast<GC_Tp *>(GC_selective_alloc(GC_n * sizeof(GC_Tp),
                                        traits.GC_is_ptr_free, true));
  }

  GC_CONSTEXPR void deallocate(pointer __p, size_type) GC_NOEXCEPT {
    GC_FREE(__p);
  }

  GC_CONSTEXPR size_type max_size() const GC_NOEXCEPT {
    return static_cast<GC_ALCTR_SIZE_T>(-1) / sizeof(GC_Tp);
  }

  GC_CONSTEXPR void construct(pointer __p, const GC_Tp& __val) {
    new(__p) GC_Tp(__val);
  }

  GC_CONSTEXPR void destroy(pointer __p) { __p->~GC_Tp(); }
};

template<>
class gc_allocator_ignore_off_page<void> {
public:
  typedef GC_ALCTR_SIZE_T    size_type;
  typedef GC_ALCTR_PTRDIFF_T difference_type;
  typedef void*       pointer;
  typedef const void* const_pointer;
  typedef void        value_type;

  template <class GC_Tp1> struct rebind {
    typedef gc_allocator_ignore_off_page<GC_Tp1> other;
  };
};

template <class GC_T1, class GC_T2>
GC_CONSTEXPR inline bool operator==(const gc_allocator_ignore_off_page<GC_T1>&,
                const gc_allocator_ignore_off_page<GC_T2>&) GC_NOEXCEPT {
  return true;
}

template <class GC_T1, class GC_T2>
GC_CONSTEXPR inline bool operator!=(const gc_allocator_ignore_off_page<GC_T1>&,
                const gc_allocator_ignore_off_page<GC_T2>&) GC_NOEXCEPT {
  return false;
}







template <class GC_Tp>
class traceable_allocator {
public:
  typedef GC_ALCTR_SIZE_T    size_type;
  typedef GC_ALCTR_PTRDIFF_T difference_type;
  typedef GC_Tp*       pointer;
  typedef const GC_Tp* const_pointer;
  typedef GC_Tp&       reference;
  typedef const GC_Tp& const_reference;
  typedef GC_Tp        value_type;

  template <class GC_Tp1> struct rebind {
    typedef traceable_allocator<GC_Tp1> other;
  };

  GC_CONSTEXPR traceable_allocator() GC_NOEXCEPT {}
  GC_CONSTEXPR traceable_allocator(const traceable_allocator&) GC_NOEXCEPT {}
# ifndef GC_NO_MEMBER_TEMPLATES
    template <class GC_Tp1> GC_ATTR_EXPLICIT
    GC_CONSTEXPR traceable_allocator(
                const traceable_allocator<GC_Tp1>&) GC_NOEXCEPT {}
# endif
  GC_CONSTEXPR ~traceable_allocator() GC_NOEXCEPT {}

  GC_CONSTEXPR pointer address(reference GC_x) const { return &GC_x; }
  GC_CONSTEXPR const_pointer address(const_reference GC_x) const {
    return &GC_x;
  }

  
  
  GC_CONSTEXPR GC_Tp* allocate(size_type GC_n, const void* = 0) {
    void * obj = GC_MALLOC_UNCOLLECTABLE(GC_n * sizeof(GC_Tp));
    if (0 == obj)
      GC_ALLOCATOR_THROW_OR_ABORT();
    return static_cast<GC_Tp*>(obj);
  }

  GC_CONSTEXPR void deallocate(pointer __p, size_type) GC_NOEXCEPT {
    GC_FREE(__p);
  }

  GC_CONSTEXPR size_type max_size() const GC_NOEXCEPT {
    return static_cast<GC_ALCTR_SIZE_T>(-1) / sizeof(GC_Tp);
  }

  GC_CONSTEXPR void construct(pointer __p, const GC_Tp& __val) {
    new(__p) GC_Tp(__val);
  }

  GC_CONSTEXPR void destroy(pointer __p) { __p->~GC_Tp(); }
};

template<>
class traceable_allocator<void> {
public:
  typedef GC_ALCTR_SIZE_T    size_type;
  typedef GC_ALCTR_PTRDIFF_T difference_type;
  typedef void*       pointer;
  typedef const void* const_pointer;
  typedef void        value_type;

  template <class GC_Tp1> struct rebind {
    typedef traceable_allocator<GC_Tp1> other;
  };
};

template <class GC_T1, class GC_T2>
GC_CONSTEXPR inline bool operator==(const traceable_allocator<GC_T1>&,
                const traceable_allocator<GC_T2>&) GC_NOEXCEPT {
  return true;
}

template <class GC_T1, class GC_T2>
GC_CONSTEXPR inline bool operator!=(const traceable_allocator<GC_T1>&,
                const traceable_allocator<GC_T2>&) GC_NOEXCEPT {
  return false;
}

#undef GC_ALCTR_PTRDIFF_T
#undef GC_ALCTR_SIZE_T

#ifdef GC_NAMESPACE_ALLOCATOR
}
#endif

#endif