
#ifndef CoFHE_EXPECTED_HPP_INCLUDED
#define CoFHE_EXPECTED_HPP_INCLUDED

#include "./common/macros.hpp"
#include "./common/type_traits.hpp"

namespace CoFHE
{
    template <typename E>
        requires std::is_nothrow_destructible_v<E> && std::negation_v<std::is_void<E>>
    class Unexpected final
    {
    public:
        using value_type = E;
        using reference = value_type &;
        using const_reference = const value_type &;
        using rvalue_reference = value_type &&;
        using const_rvalue_reference = const value_type &&;

        template <typename... Args>
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Unexpected(Args &&...args) noexcept
            requires std::is_nothrow_constructible_v<value_type, Args...>
            : e(std::forward<Args>(args)...)
        {
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Unexpected(const Unexpected &u) noexcept
            requires std::is_nothrow_copy_constructible_v<value_type>
            : e(u.e)
        {
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Unexpected(Unexpected &&u) noexcept
            requires std::is_nothrow_move_constructible_v<value_type>
            : e(std::move(u.e))
        {
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Unexpected &operator=(const Unexpected &u) noexcept
            requires std::is_nothrow_copy_assignable_v<value_type>
        {
            e = u.e;
            return *this;
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Unexpected &operator=(Unexpected &&u) noexcept
            requires std::is_nothrow_move_assignable_v<value_type>
        {
            e = std::move(u.e);
            return *this;
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ~Unexpected() noexcept = default;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr reference error() & noexcept { return e; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_reference error() const & noexcept { return e; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr rvalue_reference error() && noexcept { return std::move(e); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_rvalue_reference error() const && noexcept { return std::move(e); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr friend void swap(Unexpected &lhs, Unexpected &rhs) noexcept
            requires std::is_nothrow_swappable_v<value_type>
        {
            using std::swap;
            swap(lhs.e, rhs.e);
        }

    private:
        value_type e;
    };

    template <typename T, typename E>
        requires std::is_nothrow_destructible_v<T> && std::is_nothrow_destructible_v<E> && std::negation_v<std::is_void<T>> && std::negation_v<std::is_void<E>>
    class Expected
    {
    public:
        using value_type = T;
        using error_type = E;
        using unexpected_type = Unexpected<E>;
        using value_pointer = value_type *;
        using const_value_pointer = const value_type *;
        using value_reference = value_type &;
        using const_value_reference = const value_type &;
        using value_rvalue_reference = value_type &&;
        using const_value_rvalue_reference = const value_type &&;
        using unexpected_reference = unexpected_type &;
        using const_unexpected_reference = const unexpected_type &;
        using unexpected_rvalue_reference = unexpected_type &&;
        using const_unexpected_rvalue_reference = const unexpected_type &&;

        template <typename... Args>
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Expected(Args &&...args) noexcept
            requires std::is_nothrow_constructible_v<T, Args...>
            : t(std::forward<Args>(args)...), has_value_m(true)
        {
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Expected(const Unexpected<E> &e) noexcept
            requires std::is_nothrow_copy_constructible_v<E>
            : t(e), has_value_m(false)
        {
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr Expected(Unexpected<E> &&e) noexcept
            requires std::is_nothrow_move_constructible_v<E>
            : t(std::move(e)), has_value_m(false)
        {
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ~Expected() noexcept
        {
            if (has_error())
            {
                t.e.~Unexpected<E>();
            }
            else
            {
                t.t.~T();
            }
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool has_value() const noexcept { return has_value_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool has_error() const noexcept { return !has_value_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr value_reference value() & noexcept { return t.t; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_value_reference value() const& noexcept { return t.t; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr value_rvalue_reference value() && noexcept { return std::move(t.t); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_value_rvalue_reference value() const&& noexcept { return std::move(t.t); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr unexpected_reference error() & noexcept { return t.e; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_unexpected_reference error() const& noexcept { return t.e; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr unexpected_rvalue_reference error() && noexcept { return std::move(t.e); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_unexpected_rvalue_reference error() const&& noexcept { return std::move(t.e); }
        
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr friend void swap(Expected &lhs, Expected &rhs) noexcept
            requires std::is_nothrow_swappable_v<T> && std::is_nothrow_swappable_v<E>
        {
            using std::swap;
            swap(lhs.t, rhs.t);
            swap(lhs.has_value_m, rhs.has_value_m);
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr value_pointer operator->() noexcept
            requires IsNoThrowAddressable<value_type>
        {
            return &t.t;
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_value_pointer operator->() const noexcept
            requires IsNoThrowAddressable<value_type>
        {
            return &t.t;
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr value_reference operator*() { return t.t; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const_value_reference operator*() const noexcept { return t.t; }

    private:
        union union_expected_t
        {
            T t;
            Unexpected<E> e;
            template <typename... Args>
            CoFHE_DEVICE_AGNOSTIC_FUNC constexpr union_expected_t(Args &&...args) noexcept
                requires std::is_nothrow_constructible_v<T, Args...>
                : t(std::forward<Args>(args)...)
            {
            }
            CoFHE_DEVICE_AGNOSTIC_FUNC constexpr union_expected_t(Unexpected<E> &&e) noexcept
                requires std::is_nothrow_move_constructible_v<E>
                : e(std::move(e))
            {
            }
            CoFHE_DEVICE_AGNOSTIC_FUNC constexpr union_expected_t(const Unexpected<E> &e) noexcept
                requires std::is_nothrow_copy_constructible_v<E>
                : e(e)
            {
            }
            ~union_expected_t() noexcept {}
        };
        union_expected_t t;
        bool has_value_m;
    };
    
} // namespace CoFHE
#endif