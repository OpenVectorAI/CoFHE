#ifndef CoFHE_VARIANT_HPP_INCLUDED
#define CoFHE_VARIANT_HPP_INCLUDED


#include "./common/macros.hpp"

#ifndef CoFHE_CUDA
#include <variant>
#else
#include <cuda/std/variant>
#endif

namespace CoFHE
{
    #ifndef CoFHE_CUDA
    template <typename... Ts>
    using Variant = std::variant<Ts...>;
    #else
    template <typename... Ts>
    using Variant = cuda::std::variant<Ts...>;
    #endif
} // namespace CoFHE

#endif