#ifndef CoFHE_VECTOR_HPP_INCLUDED
#define CoFHE_VECTOR_HPP_INCLUDED

#include <vector>
namespace CoFHE
{
    // Only use size(), reserve(), push_back(), insert(), emplace_back(), remove(),
    // clear(), iterators and operator[] from Vector, may not be std::Vector Assume
    // to be thread safe for non-related indexes
    template <typename T>
    using Vector = std::vector<T>;
}

#endif