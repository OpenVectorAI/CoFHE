#ifndef PIMPL_HPP_INCLUDED
#define PIMPL_HPP_INCLUDED

#include "common/pointers.hpp"
#include "./common/type_traits.hpp"
namespace CoFHE
{
  template <typename T, typename Deleter = DefaultDeleter>
    // requires std::is_nothrow_destructible_v<T> && std::is_nothrow_destructible_v<Deleter> && IsNoThrowCallable<Deleter, void, T *>
  class PImpl
  {
  public:
    using value_type = T;
    using pointer = value_type *;
    using reference = value_type &;
    using const_pointer = const value_type *;
    using const_reference = const value_type &;
    using rvalue_reference = value_type &&;
    using const_rvalue_reference = const value_type &&;
    using deleter_type = Deleter;
    using deleter_reference = Deleter &;
    using deleter_const_reference = const Deleter &;

    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // explicit PImpl(OwningPtr<T> t) noexcept
    //   requires std::is_nothrow_default_constructible_v<Deleter>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // explicit PImpl(OwningPtr<T> t, const Deleter &d) noexcept
    //   requires std::is_nothrow_copy_constructible_v<Deleter>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // explicit PImpl(OwningPtr<T> t, Deleter &&d) noexcept
    //   requires std::is_nothrow_move_constructible_v<Deleter>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // explicit PImpl(UniquePtr<T, Deleter> t) noexcept;
    // template <typename... Args>
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // explicit PImpl(Args &&...args) noexcept
    //   requires std::is_nothrow_constructible_v<T, Args...> && std::is_nothrow_default_constructible_v<Deleter>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // ~PImpl() noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // PImpl(const PImpl &other) noexcept = delete;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // PImpl &operator=(const PImpl &other) noexcept = delete;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // PImpl(PImpl &&other) noexcept
    //   requires std::is_nothrow_move_constructible_v<Deleter> || std::is_nothrow_copy_constructible_v<Deleter>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // PImpl &operator=(PImpl &&other) noexcept
    //   requires std::is_nothrow_move_assignable_v<Deleter> || std::is_nothrow_copy_assignable_v<Deleter>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // pointer operator->() noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // const_pointer operator->() const noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // reference operator*() & noexcept requires IsNoThrowDereferenceable<T>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // const_reference operator*() const & noexcept requires IsNoThrowDereferenceable<T>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // rvalue_reference operator*() && noexcept requires IsNoThrowDereferenceable<T>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // const_rvalue_reference operator*() const && noexcept requires IsNoThrowDereferenceable<T>;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // pointer get() noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // const_pointer get() const noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // deleter_reference get_deleter() noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // deleter_const_reference get_deleter() const noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // explicit operator bool() const noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // bool operator==(const PImpl &other) const noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // bool operator!=(const PImpl &other) const noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // bool operator==(std::nullptr_t) const noexcept;
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // bool operator!=(std::nullptr_t) const noexcept;
    // template <typename T1, typename D1>
    // CoFHE_DEVICE_AGNOSTIC_FUNC
    // friend void swap(PImpl<T1, D1> &lhs, PImpl<T1, D1> &rhs) noexcept
    //   requires std::is_nothrow_swappable_v<D1>;

    CoFHE_DEVICE_AGNOSTIC_FUNC
    explicit PImpl(OwningPtr<T> t) noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    explicit PImpl(OwningPtr<T> t, const Deleter &d) noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    explicit PImpl(OwningPtr<T> t, Deleter &&d) noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    explicit PImpl(UniquePtr<T, Deleter> t) noexcept;
    template <typename... Args>
    CoFHE_DEVICE_AGNOSTIC_FUNC explicit PImpl(Args &&...args) noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    ~PImpl() noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    PImpl(const PImpl &other) noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    PImpl &operator=(const PImpl &other) noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    PImpl(PImpl &&other) noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    PImpl &operator=(PImpl &&other) noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    pointer operator->() noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    const_pointer operator->() const noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    reference operator*() & noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    const_reference operator*() const & noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    rvalue_reference operator*() && noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    const_rvalue_reference operator*() const && noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    pointer get() noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    const_pointer get() const noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    deleter_reference get_deleter() noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    deleter_const_reference get_deleter() const noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    explicit operator bool() const noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    bool operator==(const PImpl &other) const noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    bool operator!=(const PImpl &other) const noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    bool operator==(std::nullptr_t) const noexcept;
    CoFHE_DEVICE_AGNOSTIC_FUNC
    bool operator!=(std::nullptr_t) const noexcept;
    template <typename T1, typename D1>
    CoFHE_DEVICE_AGNOSTIC_FUNC friend void swap(PImpl<T1, D1> &lhs, PImpl<T1, D1> &rhs) noexcept;

  private:
    OwningPtr<T> m;
    Deleter d;
  };
} // namespace CoFHE

#endif