#ifndef CoFHE_ATOMICS_HPP_INCLUDED
#define CoFHE_ATOMICS_HPP_INCLUDED

#include "./common/macros.hpp"

#ifndef CoFHE_CUDA
#include <atomic>
#else
#include <cuda/std/atomic>
#endif

namespace CoFHE
{
#ifndef CoFHE_CUDA
    template <typename T>
    using Atomic = std::atomic<T>;
#else
    template <typename T>
    using Atomic = cuda::std::atomic<T>;
#endif
} // namespace CoFHE

#endif // CoFHE_ATOMICS_HPP_INCLUDED