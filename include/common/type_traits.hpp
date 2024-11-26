#ifndef CoFHE_TYPE_TRAITS_HPP_INCLUDED
#define CoFHE_TYPE_TRAITS_HPP_INCLUDED

#include <type_traits>
#include <utility>

namespace CoFHE
{
    template <typename T>
    concept IsNoThrowAddressable = requires(T t) {
        { &t } noexcept;
    };

    template <typename T, typename R, typename... Args>
    concept IsNoThrowCallable = requires(T t) {
        { t(std::declval<Args>()...) } noexcept -> std::convertible_to<R>;
    };

    template <typename T>
    concept IsNoThrowDereferenceable = requires(T* t) {
        { *t } noexcept;
    };

    template <typename T, bool require_noexcept = true>
    concept IsLessThanComparable = requires(T lhs, T rhs) {
        { lhs < rhs } -> std::convertible_to<bool>;
        requires !require_noexcept || noexcept(lhs < rhs);
    };

    template <typename T, bool require_noexcept = true>
    concept IsGreaterThanComparable = requires(T lhs, T rhs) {
        { lhs > rhs } -> std::convertible_to<bool>;
        requires !require_noexcept || noexcept(lhs > rhs);
    };

    template <typename T, bool require_noexcept = true>
    concept IsLessEqualComparable = requires(T lhs, T rhs) {
        { lhs <= rhs } -> std::convertible_to<bool>;
        requires !require_noexcept || noexcept(lhs <= rhs);
    };

    template <typename T, bool require_noexcept = true>
    concept IsGreaterEqualComparable = requires(T lhs, T rhs) {
        { lhs >= rhs } -> std::convertible_to<bool>;
        requires !require_noexcept || noexcept(lhs >= rhs);
    };

    template <typename T, bool require_noexcept = true>
    concept IsEqualityComparable = requires(T lhs, T rhs) {
        { lhs == rhs } -> std::convertible_to<bool>;
        requires !require_noexcept || noexcept(lhs == rhs);
    };

    template <typename T, bool require_noexcept = true>
    concept IsInequalityComparable = requires(T lhs, T rhs) {
        { lhs != rhs } -> std::convertible_to<bool>;
        requires !require_noexcept || noexcept(lhs != rhs);
    };
}

#endif
