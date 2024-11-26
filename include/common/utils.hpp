#ifndef CoFHE_UTILS_HPP_INCLUDED
#define CoFHE_UTILS_HPP_INCLUDED

#include <iostream>

#include "common/vector.hpp"

namespace CoFHE
{
    void print_vector(const Vector<size_t> &vec, std::ostream &out = std::cout)

    {
        for (auto i : vec)
        {
            out << i << " ";
        }
        out << std::endl;
    }
}

#endif