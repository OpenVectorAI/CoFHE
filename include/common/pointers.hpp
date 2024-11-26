#ifndef CoFHE_UNIQUE_PTR_HPP_INCLUDED
#define CoFHE_UNIQUE_PTR_HPP_INCLUDED

#include <memory>

#include "./common/synchronization.hpp"
#include "./common/macros.hpp"
#include "./common/expected.hpp"
#include "./common/system_error.hpp"
#include "./common/type_traits.hpp"

namespace CoFHE
{
    template <typename T>
    using OwningPtr = T *;

    template <typename T>
    class ReferenceWrapper
    {
    public:
        using value_type = T;
        using reference = T &;

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ReferenceWrapper(reference ref) noexcept : ref(ref) {}
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr reference get() const noexcept
        {
            return ref;
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr operator value_type &() const noexcept
        {
            return ref;
        }

    private:
        reference ref;
    };

    template <typename T>
    CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ReferenceWrapper<T>
    ref(T &ref) noexcept
    {
        return ReferenceWrapper<T>(ref);
    }

    template <typename T>
    CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ReferenceWrapper<const T>
    cref(const T &ref) noexcept
    {
        return ReferenceWrapper<const T>(ref);
    }

    struct DefaultDeleter
    {
        template <typename T>
        constexpr void operator()(T *ptr) const noexcept
        {
            delete ptr;
        }
    };

    template <typename T, typename Deleter = DefaultDeleter>
        requires std::is_nothrow_destructible_v<Deleter> && IsNoThrowCallable<Deleter, void, T *>
    class UniquePtr
    {
    public:
        using value_type = T;
        using pointer = T *;
        using reference = T &;
        using deleter_type = Deleter;
        using const_deleter_ref_type = const Deleter &;

        CoFHE_DEVICE_AGNOSTIC_FUNC explicit constexpr UniquePtr(pointer ptr = nullptr) noexcept
            requires std::is_nothrow_default_constructible_v<Deleter>
            : ptr(ptr), deleter(Deleter())
        {
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC explicit constexpr UniquePtr(pointer ptr, const deleter_type &deleter) noexcept
            requires std::is_nothrow_copy_constructible_v<Deleter>
            : ptr(ptr), deleter(deleter)
        {
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC explicit constexpr UniquePtr(pointer ptr, deleter_type &&deleter) noexcept
            requires std::is_nothrow_move_constructible_v<Deleter>
            : ptr(ptr), deleter(std::move(deleter))
        {
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr UniquePtr(const UniquePtr &) = delete;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr UniquePtr &operator=(const UniquePtr &) = delete;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr UniquePtr(UniquePtr &&other) noexcept
            requires std::is_nothrow_move_constructible_v<Deleter> || std::is_nothrow_copy_constructible_v<Deleter>
            : ptr(other.ptr), deleter(std::is_nothrow_move_constructible_v<Deleter> ? std::move(other.deleter) : other.deleter)
        {
            other.ptr = nullptr;
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr UniquePtr &operator=(UniquePtr &&other) noexcept
            requires std::is_nothrow_move_assignable_v<Deleter> || std::is_nothrow_copy_assignable_v<Deleter>
        {
            if (this != &other)
            {
                reset(other.ptr);
                if constexpr (std::is_nothrow_move_assignable_v<Deleter>)
                {
                    deleter = std::move(other.deleter);
                }
                else
                {
                    deleter = other.deleter;
                }
                other.ptr = nullptr;
            }
            return *this;
        }

        ~UniquePtr() noexcept
        {
            reset();
        }

        void reset(pointer p = nullptr) noexcept
        {
            if (ptr)
            {
                deleter(ptr);
            }
            ptr = p;
        }

        pointer release() noexcept
        {
            pointer p = ptr;
            ptr = nullptr;
            return p;
        }

        pointer get() const noexcept
        {
            return ptr;
        }

        deleter_type &get_deleter() noexcept
        {
            return deleter;
        }

        const_deleter_ref_type &get_deleter() const noexcept
        {
            return deleter;
        }

        pointer operator->() const noexcept
        {
            return ptr;
        }

        reference operator*() const noexcept
            requires IsNoThrowDereferenceable<T>
        {
            return *ptr;
        }

        explicit operator bool() const noexcept
        {
            return ptr != nullptr;
        }

        bool operator==(const UniquePtr &other) const noexcept
        {
            return ptr == other.ptr;
        }

        bool operator!=(const UniquePtr &other) const noexcept
        {
            return ptr != other.ptr;
        }

        bool operator==(std::nullptr_t) const noexcept
        {
            return ptr == nullptr;
        }

        bool operator!=(std::nullptr_t) const noexcept
        {
            return ptr != nullptr;
        }

        friend void swap(UniquePtr &lhs, UniquePtr &rhs) noexcept
            requires std::is_nothrow_swappable_v<Deleter>
        {
            using std::swap;
            swap(lhs.ptr, rhs.ptr);
            swap(lhs.deleter, rhs.deleter);
        }

    private:
        pointer ptr;
        deleter_type deleter;
    };

    template <typename T, typename... Args>
    UniquePtr<T> make_unique_bare(Args &&...args) noexcept
    {
        return UniquePtr<T>(new (std::nothrow) T(std::forward<Args>(args)...));
    }

    template <typename T, typename... Args>
    Expected<UniquePtr<T>, SystemErrorCategory::ErrorCodeType> make_unique(Args &&...args)
    {
        if (auto ptr = new (std::nothrow) T(std::forward<Args>(args)...))
        {
            return UniquePtr<T>(ptr);
        }
        return SystemError::out_of_memory();
    }

    class SharedPtrControlBlockBase
    {
    public:
        SharedPtrControlBlockBase(size_t count = 1, size_t weak_count = 0) noexcept : count_m(count), weak_count_m(weak_count) {}
        SharedPtrControlBlockBase(const SharedPtrControlBlockBase &) noexcept = delete;
        SharedPtrControlBlockBase &operator=(const SharedPtrControlBlockBase &) noexcept = delete;
        SharedPtrControlBlockBase(SharedPtrControlBlockBase &&) noexcept = delete;
        SharedPtrControlBlockBase &operator=(SharedPtrControlBlockBase &&) noexcept = delete;
        void increment() noexcept
        {
            LockGuard lock(mutex);
            ++count_m;
        }

        void decrement() noexcept
        {
            LockGuard lock(mutex);
            --count_m;
        }

        void increment_weak() noexcept
        {
            LockGuard lock(mutex);
            ++weak_count_m;
        }

        void decrement_weak() noexcept
        {
            LockGuard lock(mutex);
            --weak_count_m;
        }

        bool dead() const noexcept
        {
            LockGuard lock(mutex);
            return count_m + weak_count_m == 0;
        }

        size_t use_count() const noexcept
        {
            return count_m;
        }

        size_t weak_count() const noexcept
        {
            return weak_count_m;
        }

        size_t total_count() const noexcept
        {
            LockGuard lock(mutex);
            return weak_count_m + count_m;
        }

        void call_deleter(void *ptr) noexcept
        {
            LockGuard lock(mutex);
            call_deleter_impl(ptr);
        }

    protected:
        size_t count_m;
        size_t weak_count_m;
        mutable Mutex mutex;
        virtual void call_deleter_impl(void *ptr) noexcept = 0;
    };

    template <typename T, typename Deleter = DefaultDeleter>
        requires IsNoThrowCallable<Deleter, void, T *>
    class SharedPtrControlBlock : public SharedPtrControlBlockBase
    {
    public:
        SharedPtrControlBlock(size_t count = 1, size_t weak_count = 0) noexcept
            requires std::is_nothrow_default_constructible_v<Deleter>
            : SharedPtrControlBlockBase(count, weak_count), deleter()
        {
        }
        SharedPtrControlBlock(size_t count, size_t weak_count, const Deleter &deleter) noexcept
            requires std::is_nothrow_copy_constructible_v<Deleter>
            : SharedPtrControlBlockBase(count, weak_count), deleter(deleter)
        {
        }
        SharedPtrControlBlock(size_t count, size_t weak_count, Deleter &&deleter) noexcept
            requires std::is_nothrow_move_constructible_v<Deleter>
            : SharedPtrControlBlockBase(count, weak_count), deleter(std::move(deleter))
        {
        }
        SharedPtrControlBlock(const SharedPtrControlBlock &) noexcept = delete;
        SharedPtrControlBlock &operator=(const SharedPtrControlBlock &) noexcept = delete;
        SharedPtrControlBlock(SharedPtrControlBlock &&) noexcept = delete;
        SharedPtrControlBlock &operator=(SharedPtrControlBlock &&) noexcept = delete;

        void call_deleter_impl(void *ptr) noexcept override
        {
            if (count_m == 0)
            {
                deleter(reinterpret_cast<T *>(ptr));
            }
            if (weak_count_m == 0 && count_m == 0)
            {
                delete this;
            }
        }

    private:
        Deleter deleter;
    };

    template <typename T>
    class SharedPtrControlBlockCombined : public SharedPtrControlBlockBase
    {
    public:
        SharedPtrControlBlockCombined(size_t count = 1, size_t weak_count = 0) noexcept : SharedPtrControlBlockBase(count, weak_count)
        {
        }
        SharedPtrControlBlockCombined(const SharedPtrControlBlockCombined &) noexcept = delete;
        SharedPtrControlBlockCombined &operator=(const SharedPtrControlBlockCombined &) noexcept = delete;
        SharedPtrControlBlockCombined(SharedPtrControlBlockCombined &&) noexcept = delete;
        SharedPtrControlBlockCombined &operator=(SharedPtrControlBlockCombined &&) noexcept = delete;

        void call_deleter_impl(void *ptr) noexcept override
        {
            if (count_m == 0)
            {
                reinterpret_cast<T *>(ptr)->~T();
            }
            if (weak_count_m == 0 && count_m == 0)
            {
                delete this;
            }
        }

        T *get_data_member() noexcept
        {
            return reinterpret_cast<T *>(data_member);
        }

    private:
        char data_member alignas(alignof(T))[sizeof(T)];
    };

    template <typename T>
    class WeakPtr;

    // template <typename T>
    // using SharedPtr = std::shared_ptr<T>;

    template <typename T>
    class SharedPtr
    {
        template <typename U, typename... Args>
        friend SharedPtr<U> make_shared_bare(Args &&...args) noexcept
            requires std::is_nothrow_constructible_v<U, Args...>;
        template <typename U, typename... Args>
        friend Expected<SharedPtr<U>, SystemErrorCategory::ErrorCodeType> make_shared(Args &&...args) noexcept
            requires std::is_nothrow_constructible_v<U, Args...>;
        friend WeakPtr<T>;

    public:
        using value_type = T;
        using pointer = T *;
        using reference = T &;

        template <typename U>
        SharedPtr(nullptr_t) noexcept
            : ptr(nullptr), control_block(nullptr)
        {
        }

        template <typename Deleter = DefaultDeleter>
        SharedPtr(pointer ptr) noexcept
            requires std::is_nothrow_default_constructible_v<Deleter>
            : ptr(ptr), control_block(new SharedPtrControlBlock<T,Deleter>())
        {
        }

        template <typename Deleter = DefaultDeleter>
        SharedPtr(pointer ptr, const Deleter &deleter) noexcept
            requires std::is_nothrow_copy_constructible_v<Deleter>
            : ptr(ptr), control_block(new SharedPtrControlBlock<T,Deleter>(1, 0, deleter))
        {
        }

        template <typename Deleter = DefaultDeleter>
        SharedPtr(pointer ptr, Deleter &&deleter) noexcept
            requires std::is_nothrow_move_constructible_v<Deleter>
            : ptr(ptr), control_block(new SharedPtrControlBlock<T,Deleter>(1, 0, std::move(deleter)))
        {
        }

        SharedPtr(const SharedPtr &other) noexcept
            : ptr(other.ptr), control_block(other.control_block)
        {
            if (control_block)
            {
                control_block->increment();
            }
        }

        SharedPtr(SharedPtr &&other) noexcept
            : ptr(other.ptr), control_block(other.control_block)
        {
            other.ptr = nullptr;
            other.control_block = nullptr;
        }

        template <typename Deleter = DefaultDeleter>
        SharedPtr(const UniquePtr<T, Deleter> &&unique_ptr) noexcept
            requires std::is_nothrow_move_constructible_v<Deleter>
            : ptr(unique_ptr.get()), control_block(new SharedPtrControlBlock<T,Deleter>(1, 0, std::move(unique_ptr.get_deleter())))
        {
        }

        SharedPtr &operator=(const SharedPtr &other) noexcept
        {
            if (this != &other)
            {
                reset();
                ptr = other.ptr;
                control_block = other.control_block;
                if (control_block)
                {
                    control_block->increment();
                }
            }
            return *this;
        }

        SharedPtr &operator=(SharedPtr &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                ptr = other.ptr;
                control_block = other.control_block;
                other.ptr = nullptr;
                other.control_block = nullptr;
            }
            return *this;
        }

        template <typename Deleter = DefaultDeleter>
        SharedPtr &operator=(const UniquePtr<T, Deleter> &&unique_ptr) noexcept
            requires std::is_nothrow_move_constructible_v<Deleter>
        {
            reset();
            ptr = unique_ptr.release();
            control_block = new SharedPtrControlBlock<T,Deleter>(1, 0, std::move(unique_ptr.get_deleter()));
            return *this;
        }

        ~SharedPtr() noexcept
        {
            reset();
        }

        template <typename Deleter = DefaultDeleter>
        void reset(pointer p = nullptr) noexcept
            requires std::is_nothrow_default_constructible_v<Deleter>
        {
            if (control_block)
            {
                control_block->decrement();
                control_block->call_deleter(ptr);
                ptr = p;
            }
            if (ptr)
            {
                control_block = new SharedPtrControlBlock<T,Deleter>();
            }
        }

        template <typename Deleter = DefaultDeleter>
        void reset(pointer p, const Deleter &deleter) noexcept
            requires std::is_nothrow_copy_constructible_v<Deleter>
        {
            if (control_block)
            {
                control_block->decrement();
                control_block->call_deleter(ptr);
                ptr = p;
                if (ptr)
                {
                    control_block = new SharedPtrControlBlock<T,Deleter>(1, 0, deleter);
                }
            }
            else
            {
                ptr = p;
                if (ptr)
                {
                    control_block = new SharedPtrControlBlock<T,Deleter>(1, 0, deleter);
                }
            }
        }

        template <typename Deleter = DefaultDeleter>
        void reset(pointer p, Deleter &&deleter) noexcept
            requires std::is_nothrow_move_constructible_v<Deleter>
        {
            if (control_block)
            {
                control_block->decrement();
                control_block->call_deleter(ptr);
                ptr = p;
                if (ptr)
                {
                    control_block = new SharedPtrControlBlock<T,Deleter>(1, 0, std::move(deleter));
                }
            }
            else
            {
                ptr = p;
                if (ptr)
                {
                    control_block = new SharedPtrControlBlock<T,Deleter>(1, 0, std::move(deleter));
                }
            }
        }

        pointer get() const noexcept
        {
            return ptr;
        }

        reference operator*() const noexcept
            requires IsNoThrowDereferenceable<T>
        {
            return *ptr;
        }

        pointer operator->() const noexcept
        {
            return ptr;
        }

        explicit operator bool() const noexcept
        {
            return ptr != nullptr;
        }

        bool operator==(const SharedPtr &other) const noexcept
        {
            return ptr == other.ptr;
        }

        bool operator!=(const SharedPtr &other) const noexcept
        {
            return ptr != other.ptr;
        }

        bool operator==(std::nullptr_t) const noexcept
        {
            return ptr == nullptr;
        }

        bool operator!=(std::nullptr_t) const noexcept
        {
            return ptr != nullptr;
        }

        size_t use_count() const noexcept
        {
            if (!control_block)
            {
                return 0;
            }
            return control_block->use_count();
        }

        size_t weak_count() const noexcept
        {
            if (!control_block)
            {
                return 0;
            }
            return control_block->weak_count();
        }

        size_t total_count() const noexcept
        {
            if (!control_block)
            {
                return 0;
            }
            return control_block->total_count();
        }

    private:
        pointer ptr;
        SharedPtrControlBlockBase *control_block;

        SharedPtr(SharedPtrControlBlockCombined<T> *control_block) noexcept
            : ptr(reinterpret_cast<T *>(control_block->get_data_member())), control_block(control_block)
        {
        }
    };

    template <typename T, typename... Args>
    SharedPtr<T> make_shared_bare(Args &&...args) noexcept
        requires std::is_nothrow_constructible_v<T, Args...>
    {
        SharedPtrControlBlockCombined<T> *control_block = new (std::nothrow) SharedPtrControlBlockCombined<T>(1, 0);
        if (!control_block)
        {
            return SharedPtr<T>(nullptr);
        }
        new (control_block->get_data_member()) T(std::forward<Args>(args)...);
        return SharedPtr<T>(control_block);
    }

    template <typename T, typename... Args>
    Expected<SharedPtr<T>, SystemErrorCategory::ErrorCodeType> make_shared(Args &&...args) noexcept
        requires std::is_nothrow_constructible_v<T, Args...>
    {
        SharedPtrControlBlockCombined<T> *control_block = new (std::nothrow) SharedPtrControlBlockCombined<T>(1, 0);
        if (!control_block)
        {
            return Unexpected<SystemErrorCategory::ErrorCodeType>(SystemError::out_of_memory());
        }
        new (control_block->get_data_member()) T(std::forward<Args>(args)...);
        return SharedPtr<T>(control_block);
    }

    template <typename T>
    class WeakPtr
    {
    public:
        using value_type = T;
        using pointer = T *;
        using reference = T &;

        WeakPtr(nullptr_t) noexcept
            : ptr(nullptr), control_block(nullptr)
        {
        }

        WeakPtr(const SharedPtr<T> &shared_ptr) noexcept
            : ptr(shared_ptr.ptr), control_block(shared_ptr.control_block)
        {
            if (control_block)
            {
                control_block->increment_weak();
            }
        }

        WeakPtr(const WeakPtr &other) noexcept
            : ptr(other.ptr), control_block(other.control_block)
        {
            if (control_block)
            {
                control_block->increment_weak();
            }
        }

        WeakPtr(WeakPtr &&other) noexcept
            : ptr(other.ptr), control_block(other.control_block)
        {
            other.ptr = nullptr;
            other.control_block = nullptr;
        }

        WeakPtr &operator=(const WeakPtr &other) noexcept
        {
            if (this != &other)
            {
                reset();
                ptr = other.ptr;
                control_block = other.control_block;
                if (control_block)
                {
                    control_block->increment_weak();
                }
            }
            return *this;
        }

        WeakPtr &operator=(SharedPtr<T> &&other) noexcept
        {
            reset();
            ptr = other.ptr;
            control_block = other.control_block;
            if (control_block)
            {
                control_block->increment_weak();
            }
            return *this;
        }

        WeakPtr &operator=(WeakPtr &&other) noexcept
        {
            if (this != &other)
            {
                reset();
                ptr = other.ptr;
                control_block = other.control_block;
                other.ptr = nullptr;
                other.control_block = nullptr;
            }
            return *this;
        }

        ~WeakPtr() noexcept
        {
            reset();
        }

        SharedPtr<T> lock() const noexcept
        {
            if (!control_block || expired())
            {
                return SharedPtr<T>(nullptr);
            }
            return SharedPtr<T>(ptr, control_block);
        }

        void reset() noexcept
        {
            if (control_block)
            {
                control_block->decrement_weak();
                control_block->call_deleter(ptr);
            }
            ptr = nullptr;
            control_block = nullptr;
        }

        bool expired() const noexcept
        {
            return !control_block || control_block->use_count() == 0;
        }

        size_t use_count() const noexcept
        {
            if (!control_block)
            {
                return 0;
            }
            return control_block->use_count();
        }

    private:
        pointer ptr;
        SharedPtrControlBlockBase *control_block;
    };

} // namespace CoFHE
#endif