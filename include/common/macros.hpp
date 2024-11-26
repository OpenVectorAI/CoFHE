#ifndef CoFHE_MACROS_HPP_INCLUDED
#define CoFHE_MACROS_HPP_INCLUDED

#define CoFHE_FUNC_MACRO_CONCATENATE_IMPL(s1, s2) s1##s2
#define CoFHE_FUNC_MACRO_CONCATENATE(s1, s2) CoFHE_FUNC_MACRO_CONCATENATE_IMPL(s1, s2)

#define CoFHE_FUNC_MACRO_UNIQUE_NAME(base) CoFHE_FUNC_MACRO_CONCATENATE(base, __COUNTER__)

#define CoFHE_UNUSED_VAR(x) (void)(x)

#define CoFHE_FUNC __attribute__((nothrow))
#define CoFHE_FUNC_NO_INLINE CoFHE_FUNC __attribute__((noinline))
#define CoFHE_FUNC_ALWAYS_INLINE CoFHE_FUNC __attribute__((always_inline))

#define CoFHE_FUNC_DEPRECATED(msg) CoFHE_FUNC __attribute__((deprecated(msg)))

#ifdef __linux__
#define CoFHE_LINUX 1
#elif defined(_WIN32) || defined(_WIN64)
#define CoFHE_WINDOWS 1
#elif defined(__APPLE__)
#define CoFHE_APPLE 1
#else
#error "Unsupported platform"
#endif
#if defined(__CUDACC__)
#define CoFHE_DEVICE_AGNOSTIC_FUNC CoFHE_FUNC __host__ __device__
#else
#define CoFHE_DEVICE_AGNOSTIC_FUNC CoFHE_FUNC
#endif

#endif