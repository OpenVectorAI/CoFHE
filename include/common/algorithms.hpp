#ifndef CoFHE_ALGORITHMS_HPP_INCLUDED
#define CoFHE_ALGORITHMS_HPP_INCLUDED

#include "common/macros.hpp"
#include "common/type_traits.hpp"

namespace CoFHE
{
    template <typename T>
        requires std::is_nothrow_copy_assignable_v<T>
    void copy(T *first, T *last, T *result)
    {
        while (first != last)
        {
            *result = *first;
            ++result;
            ++first;
        }
    }

    template <typename T>
        requires std::is_nothrow_copy_assignable_v<T>
    void copy_backward(T *first, T *last, T *result)
    {
        while (first != last)
        {
            --last;
            --result;
            *result = *last;
        }
    }

    // add req concepts
    template <typename T>
    T min(T a, T b)
    {
        return a < b ? a : b;
    }
    
    // add req concepts
    template <typename T>
    T max(T a, T b)
    {
        return a > b ? a : b;
    }


int nCr(int n, int r)
{
    // return 1 / ((n + 1) * std::beta(n - k + 1, k + 1));
    double res = 1;
    for (int i = 1; i <= r; i++)
    {
        res = res * (n - r + i) / i;
    }
    return res;
}
    

} // namespace CoFHE

#endif