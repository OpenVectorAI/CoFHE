#ifndef CoFHE_OPTIONAL_HPP_INCLUDED
#define CoFHE_OPTIONAL_HPP_INCLUDED

#include "common/macros.hpp"
#include "common/type_traits.hpp"

namespace CoFHE
{
    template <typename T>
        requires std::is_nothrow_destructible_v<T>
    class Optional
    {
    public:
        using value_type = T;
        using pointer = value_type *;
        using const_pointer = const pointer;
        using reference = value_type &;
        using const_reference = const value_type &;
        using rvalue_reference = value_type &&;
        using const_rvalue_reference = const value_type &&;

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Optional() noexcept : has_value_m(false) {}
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Optional(const value_type &t) noexcept
            requires std::is_nothrow_copy_constructible_v<T>
            : has_value_m(true)
        {
            new (t) value_type(t);
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Optional(value_type &&t) noexcept
            requires std::is_nothrow_move_constructible_v<T>
            : has_value_m(true)
        {
            new (t) value_type(std::move(t));
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Optional(const Optional &other) noexcept
            requires std::is_nothrow_copy_constructible_v<T>
            : has_value_m(other.has_value_m)
        {
            if (has_value_m)
            {
                new (t) value_type(other.t);
            }
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Optional(Optional &&other) noexcept
            requires std::is_nothrow_move_constructible_v<T>
            : has_value_m(other.has_value_m)
        {
            if (has_value_m)
            {
                new (t) value_type(std::move(other.t));
            }
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Optional &operator=(const Optional &other) noexcept
            requires std::is_nothrow_copy_constructible_v<T> && std::is_nothrow_copy_assignable_v<T>
        {
            if (has_value_m)
            {
                t.~value_type();
            }
            has_value_m = other.has_value_m;
            if (has_value_m)
            {
                new (t) value_type(other.t);
            }
            return *this;
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Optional &operator=(Optional &&other) noexcept
            requires std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_assignable_v<T>
        {
            if (has_value_m)
            {
                t.~value_type();
            }
            has_value_m = other.has_value_m;
            if (has_value_m)
            {
                new (t) value_type(std::move(other.t));
            }
            return *this;
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ~Optional() noexcept
        {
            if (has_value_m)
            {
                t.~value_type();
            }
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool has_value() const noexcept { return has_value_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr operator bool() const noexcept { return has_value_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr reference value() & noexcept
        {
            return reinterpret_cast<reference>(t);
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_reference value() const & noexcept
        {
            return reinterpret_cast<const_reference>(t);
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr rvalue_reference value() && noexcept
        {
            return reinterpret_cast<rvalue_reference>(t);
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_rvalue_reference value() const && noexcept
        {
            return reinterpret_cast<const_rvalue_reference>(t);
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr void reset() noexcept
        {
            if (has_value_m)
            {
                t.~value_type();
            }
            has_value_m = false;
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr reference operator*() & noexcept { return value(); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_reference operator*() const & noexcept { return value(); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr rvalue_reference operator*() && noexcept { return std::move(value()); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_rvalue_reference operator*() const && noexcept { return std::move(value()); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr pointer operator->() noexcept { return reinterpret_cast<pointer>(&t); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_pointer operator->() const noexcept { return reinterpret_cast<const_pointer>(&t); }

        template <typename... Args>
            requires std::is_nothrow_constructible_v<T, Args...>
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr void emplace(Args &&...args) noexcept
        {
            if (has_value_m)
            {
                t.~value_type();
            }
            new (t) value_type(std::forward<Args>(args)...);
            has_value_m = true;
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC friend void swap(Optional &lhs, Optional &rhs) noexcept
            requires std::is_nothrow_swappable_v<T>
        {
            using std::swap;
            swap(lhs.has_value_m, rhs.has_value_m);
            if (lhs.has_value_m && rhs.has_value_m)
            {
                swap(reinterpret_cast<reference>(lhs.t), reinterpret_cast<reference>(rhs.t));
            }
        }

    private:
        bool has_value_m;
        char t alignas(T)[sizeof(T)];
    };
} // namespace CoFHE

#endif // CoFHE_OPTIONAL_HPP_INCLUDED