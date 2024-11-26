#ifndef CoFHE_MEMORY_HPP_INCLUDED
#define CoFHE_MEMORY_HPP_INCLUDED

#include "./common/macros.hpp"

#ifndef CoFHE_CUDA
#include <cstdlib>
#else
#include <cuda_runtime.h>
#endif

namespace CoFHE{
    // Allocator class, similiar to std::polymorphic byte allocator
    // Always returns byte
}

#endif // CoFHE_MEMORY_HPP_INCLUDED