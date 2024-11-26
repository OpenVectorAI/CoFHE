#ifndef CoFHE_ITERATORS_HPP
#define CoFHE_ITERATORS_HPP

#include "common/type_traits.hpp"

namespace CoFHE
{
    
template <typename T, bool is_const = false>
    class Iterator
    {
    public:
        using value_type = T;
        using reference = T &;
        using pointer = T *;
        using const_reference = const T &;
        using const_pointer = const T *;

        Iterator(pointer start, pointer end) noexcept : start(start), end(end), ptr(start) {}
        Iterator &operator++() noexcept
        {
            if (ptr == end)
            {
                reached_end = true;
            }
            ++ptr;
            return *this;
        }
        Iterator operator++(int) noexcept
        {
            Iterator temp = *this;
            if (ptr == end)
            {
                reached_end = true;
            }
            ++ptr;
            return temp;
        }
        Iterator &operator--() noexcept
        {
            if (ptr == start)
            {
                reached_start = true;
            }
            --ptr;
            return *this;
        }
        Iterator operator--(int) noexcept
        {
            Iterator temp = *this;
            if (ptr == start)
            {
                reached_start = true;
            }
            --ptr;
            return temp;
        }
        Iterator &operator+=(size_t n) noexcept
        {
            if (end-ptr <= n)
            {
                reached_end = true;
            }
            ptr += n;
            return *this;
        }
        Iterator &operator+(size_t n) const noexcept
        {
            Iterator temp = *this;
            temp += n;
            return temp;
        }
        Iterator &operator-=(size_t n) noexcept
        {
            if (ptr-start <= n)
            {
                reached_start = true;
            }
            ptr -= n;
            return *this;
        }
        Iterator &operator-(size_t n) const noexcept
        {
            Iterator temp = *this;
            temp -= n;
            return temp;
        }
        const_reference operator*() const noexcept
            requires IsNoThrowDereferenceable<T>
        {
            return *ptr;
        }
        reference operator*() noexcept
            requires (!is_const && IsNoThrowDereferenceable<T>)
        {
            return *ptr;
        }
        const_pointer operator->() const noexcept
        {
            return ptr;
        }
        pointer operator->() noexcept
            requires (!is_const)
        {
            return ptr;
        }
        bool operator==(const Iterator &other) const noexcept
        {
            return ((reached_end && other.reached_end) || (reached_start && other.reached_start)) || (ptr == other.ptr);
        }
        bool operator!=(const Iterator &other) const noexcept
        {
            return !(*this == other);
        }
        bool operator<(const Iterator &other) const noexcept
        {
            if (reached_start)
            {
                if (other.reached_start)
                {
                    return false;
                }
                return true;
            }
            if (other.reached_start)
            {
                return false;
            }
            if (!reached_end)
            {
                if (other.reached_end)
                {
                    return false;
                }
                return true;
            }
            if (other.reached_end)
            {
                return false;
            }
            return ptr < other.ptr;
        }
        bool operator>(const Iterator &other) const noexcept
        {
            return other < *this;
        }
        bool operator<=(const Iterator &other) const noexcept
        {
            return !(*this > other);
        }
        bool operator>=(const Iterator &other) const noexcept
        {
            return !(*this < other);
        }

    private:
        pointer start;
        pointer end;
        pointer ptr;
        bool reached_start = false;
        bool reached_end = false;
    };

    template <typename T, bool is_const = false>
    class ReverseIterator
    {
    public:
        using value_type = T;
        using pointer = T *;
        using const_pointer = const T *;
        using reference = T &;
        using const_reference = const T &;

        ReverseIterator(pointer start, pointer end) noexcept : start(start), end(end), ptr(end) {}
        ReverseIterator &operator++() noexcept
        {
            if (ptr == start)
            {
                reached_start = true;
            }
            --ptr;
            return *this;
        }

        ReverseIterator operator++(int) noexcept
        {
            ReverseIterator temp = *this;
            if (ptr == start)
            {
                reached_start = true;
            }
            --ptr;
            return temp;
        }

        ReverseIterator &operator--() noexcept
        {
            if (ptr == end)
            {
                reached_end = true;
            }
            ++ptr;
            return *this;
        }

        ReverseIterator operator--(int) noexcept
        {
            ReverseIterator temp = *this;
            if (ptr == end)
            {
                reached_end = true;
            }
            ++ptr;
            return temp;
        }

        ReverseIterator &operator+=(size_t n) noexcept
        {
            if (ptr - n <= start)
            {
                reached_start = true;
            }
            ptr -= n;
            return *this;
        }

        ReverseIterator &operator+(size_t n) const noexcept
        {
            ReverseIterator temp = *this;
            temp += n;
            return temp;
        }

        ReverseIterator &operator-=(size_t n) noexcept
        {
            if (ptr + n >= end)
            {
                reached_end = true;
            }
            ptr += n;
            return *this;
        }

        ReverseIterator &operator-(size_t n) const noexcept
        {
            ReverseIterator temp = *this;
            temp -= n;
            return temp;
        }

        const_reference operator*() const noexcept
        {
            return *ptr;
        }

        reference operator*() noexcept
            requires (!is_const && IsNoThrowDereferenceable<T>)
        {
            return *ptr;
        }

        const_pointer operator->() const noexcept
        {
            return ptr;
        }

        pointer operator->() noexcept
            requires (!is_const)
        {
            return ptr;
        }

        bool operator==(const ReverseIterator &other) const noexcept
        {
            return ((reached_end && other.reached_end) || (reached_start && other.reached_start)) || (ptr == other.ptr);
        }

        bool operator!=(const ReverseIterator &other) const noexcept
        {
            return !(*this == other);
        }

        bool operator<(const ReverseIterator &other) const noexcept
        {
            if (other.reached_start)
            {
                if (reached_start)
                {
                    return false;
                }
                return true;
            }
            if (reached_start)
            {
                return false;
            }
            if (!other.reached_end)
            {
                if (reached_end)
                {
                    return false;
                }
                return true;
            }
            if (reached_end)
            {
                return false;
            }
            return ptr > other.ptr;
        }

        bool operator>(const ReverseIterator &other) const noexcept
        {
            return other < *this;
        }

        bool operator<=(const ReverseIterator &other) const noexcept
        {
            return !(*this > other);
        }

        bool operator>=(const ReverseIterator &other) const noexcept
        {
            return !(*this < other);
        }

    private:
        pointer start;
        pointer end;
        pointer ptr;
        bool reached_start = false;
        bool reached_end = false;
    };
} // namespace CoFHE
    
#endif // CoFHE_ITERATORS_HPP