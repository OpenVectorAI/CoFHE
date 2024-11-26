#ifndef CoFHE_SYNCHRONIZATION_HPP_INCLUDED
#define CoFHE_SYNCHRONIZATION_HPP_INCLUDED

#include "./common/macros.hpp"

#ifndef CoFHE_CUDA
#include <mutex>
#else
#include <cuda/std/mutex>
#endif
namespace CoFHE
{
#ifndef CoFHE_CUDA
    using Mutex = std::mutex;
#else
    using Mutex = cuda::std::mutex;
#endif

class LockGuard
{
public:
    CoFHE_DEVICE_AGNOSTIC_FUNC
    explicit LockGuard(Mutex &mutex) noexcept : mutex(mutex)
    {
        mutex.lock();
    }

    CoFHE_DEVICE_AGNOSTIC_FUNC
    ~LockGuard() noexcept
    {
        mutex.unlock();
    }

private:
    Mutex &mutex;   
};

} // namespace CoFHE

#endif // CoFHE_SYNCHRONIZATION_HPP_INCLUDED