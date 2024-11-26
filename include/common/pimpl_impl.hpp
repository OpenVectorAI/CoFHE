#ifndef PIMPL_IMPL_H
#define PIMPL_IMPL_H

#include "common/pimpl.hpp"
#include "common/type_traits.hpp"

#include "../cofhe_p.hpp"

using namespace CoFHE;
// template <typename T, typename Deleter>
// PImpl<T, Deleter>::PImpl(OwningPtr<T> t) noexcept
//     requires std::is_nothrow_default_constructible_v<Deleter>
//     : m{t}
// {
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::PImpl(OwningPtr<T> t, const Deleter &d) noexcept
//     requires std::is_nothrow_copy_constructible_v<Deleter>
//     : m{t, d}
// {
// }
// template <typename T, typename Deleter>
// PImpl<T, Deleter>::PImpl(OwningPtr<T> t, Deleter &&d) noexcept
//     requires std::is_nothrow_move_constructible_v<Deleter>
//     : m{t, std::move(d)}
// {
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::PImpl(UniquePtr<T, Deleter> t) noexcept : m{std::move(t)}
// {
// }

// template <typename T, typename Deleter>
// template <typename... Args>
// PImpl<T, Deleter>::PImpl(Args &&...args) noexcept
//     requires std::is_nothrow_constructible_v<T, Args...> && std::is_nothrow_default_constructible_v<Deleter>
//     : m{make_shared_bare<T>(std::forward<Args>(args)...)}
// {
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::~PImpl() noexcept
// {
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::PImpl(PImpl &&other) noexcept
//     requires std::is_nothrow_move_constructible_v<Deleter> || std::is_nothrow_copy_constructible_v<Deleter>
//     : m{std::move(other.m)}
// {
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter> &PImpl<T, Deleter>::operator=(PImpl &&other) noexcept
//     requires std::is_nothrow_move_assignable_v<Deleter> || std::is_nothrow_copy_assignable_v<Deleter>
// {
//     m = std::move(other.m);
//     return *this;
// }

template <typename T, typename Deleter>
PImpl<T, Deleter>::PImpl
    (OwningPtr<T> t) noexcept
    : m{t}
{
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::PImpl
    (OwningPtr<T> t, const Deleter &d) noexcept
    : m{t}, d{d}
{
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::PImpl
    (OwningPtr<T> t, Deleter &&d) noexcept
    : m{t}, d{std::move(d)}
{
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::PImpl(UniquePtr<T, Deleter> t) noexcept : m{t.release()}, d{t.get_deleter()}
{
}

template <typename T, typename Deleter>
template <typename... Args>
PImpl<T, Deleter>::PImpl(Args &&...args) noexcept: m{T(std::forward<Args>(args)...)}
{
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::~PImpl() noexcept
{
    d(m);
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::PImpl(const PImpl &other) noexcept: m{nullptr}, d{other.d}
{
    m = new T(*other.m);
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::PImpl(PImpl &&other) noexcept: m{other.n}, d{std::move(other.d)}
{
    other.m = nullptr;
}

template <typename T, typename Deleter>
PImpl<T, Deleter> &PImpl<T, Deleter>::operator=(const PImpl &other) noexcept
{
    if (this != &other)
    {
        T *tmp = new T(*other.m);
        d(m);
        m = tmp;
        d = other.d;
    }
    return *this;
}

template <typename T, typename Deleter>
PImpl<T, Deleter> &PImpl<T, Deleter>::operator=(PImpl &&other) noexcept
{
    if (this != &other)
    {
        d(m);
        m = other.m;
        d = std::move(other.d);
        other.m = nullptr;
    }
    return *this;
}


// template <typename T, typename Deleter>
// PImpl<T, Deleter>::pointer PImpl<T, Deleter>::operator->() noexcept
// {
//     return m.get();
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::const_pointer PImpl<T, Deleter>::operator->() const noexcept
// {
//     return m.get();
// }



// template <typename T, typename Deleter>
// PImpl<T, Deleter>::reference PImpl<T, Deleter>::operator*() & noexcept
//     requires IsNoThrowDereferenceable<T>
// {
//     return *m;
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::const_reference PImpl<T, Deleter>::operator*() const & noexcept
//     requires IsNoThrowDereferenceable<T>
// {
//     return *m;
// }

// ypename T, typename Deleter>
// PImpl<T, Deleter>::rvalue_reference PImpl<T, Deleter>::operator*() && noexcept
//     requires IsNoThrowDereferenceable<T>
// {
//     return std::move(*m);
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::const_rvalue_reference PImpl<T, Deleter>::operator*() const && noexcept
//     requires IsNoThrowDereferenceable<T>
// {
//     return std::move(*m);
// }
// template <typename T, typename Deleter>
// PImpl<T, Deleter>::pointer PImpl<T, Deleter>::get() noexcept
// {
//     return m.get();
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::const_pointer PImpl<T, Deleter>::get() const noexcept
// {
//     return m.get();
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::deleter_reference PImpl<T, Deleter>::get_deleter() noexcept
// {
//     return m.get_deleter();
// }

// template <typename T, typename Deleter>
// PImpl<T, Deleter>::deleter_const_reference PImpl<T, Deleter>::get_deleter() const noexcept
// {
//     return m.get_deleter();
// }

template<typename T, typename Deleter>
PImpl<T, Deleter>::pointer PImpl<T, Deleter>::operator->() noexcept
{
    return m;
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::const_pointer PImpl<T, Deleter>::operator->() const noexcept
{
    return m;
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::reference PImpl<T, Deleter>::operator*() & noexcept{
    return *m;
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::const_reference PImpl<T, Deleter>::operator*() const & noexcept{
    return *m;
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::rvalue_reference PImpl<T, Deleter>::operator*() && noexcept{
    return std::move(*m);
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::const_rvalue_reference PImpl<T, Deleter>::operator*() const && noexcept{
    return std::move(*m);
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::pointer PImpl<T, Deleter>::get() noexcept
{
    return m;
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::const_pointer PImpl<T, Deleter>::get() const noexcept
{
    return m;
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::deleter_reference PImpl<T, Deleter>::get_deleter() noexcept
{
    return d;
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::deleter_const_reference PImpl<T, Deleter>::get_deleter() const noexcept
{
    return d;
}

template <typename T, typename Deleter>
PImpl<T, Deleter>::operator bool() const noexcept
{
    return m != nullptr;
}

template <typename T, typename Deleter>
bool PImpl<T, Deleter>::operator==(const PImpl &other) const noexcept
{
    return m == other.m;
}

template <typename T, typename Deleter>
bool PImpl<T, Deleter>::operator!=(const PImpl &other) const noexcept
{
    return m != other.m;
}

template <typename T, typename Deleter>
bool PImpl<T, Deleter>::operator==(std::nullptr_t) const noexcept
{
    return m == nullptr;
}

template <typename T, typename Deleter>
bool PImpl<T, Deleter>::operator!=(std::nullptr_t) const noexcept
{
    return m != nullptr;
}

template <typename T, typename Deleter>
void swap(PImpl<T, Deleter> &lhs, PImpl<T, Deleter> &rhs) noexcept{
    using std::swap;
    swap(lhs.m, rhs.m);
}

#endif