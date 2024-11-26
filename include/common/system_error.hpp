#ifndef CoFHE_SYSTEM_ERROR_HPP_INCLUDED
#define CoFHE_SYSTEM_ERROR_HPP_INCLUDED
#include "./common/macros.hpp"
#include "./common/error.hpp"
#ifdef CoFHE_LINUX
#include <errno.h>

namespace CoFHE
{
    enum class SystemErrorEnum
    {
        success = 0,
        out_of_memory = ENOMEM,
        resource_temporarily_unavailable = EAGAIN,
        operation_not_permitted = EPERM,
        permission_denied = EACCES,
        io_error = EIO,
        file_exists = EEXIST,
        not_a_directory = ENOTDIR,
        is_a_directory = EISDIR,
        invalid_argument = EINVAL,
        bad_address = EFAULT,
        interrupted_system_call = EINTR,
    };

    CoFHE_DEVICE_AGNOSTIC_FUNC
    constexpr String strerror(int error) noexcept
    {
        switch (error)
        {
        case 0:
            return "Success";
        case ENOMEM:
            return "Out of memory";
        case EAGAIN:
            return "Resource temporarily unavailable";
        case EPERM:
            return "Operation not permitted";
        case EACCES:
            return "Permission denied";
        case EIO:
            return "I/O error";
        case EEXIST:
            return "File exists";
        case ENOTDIR:
            return "Not a directory";
        case EISDIR:
            return "Is a directory";
        case EINVAL:
            return "Invalid argument";
        case EFAULT:
            return "Bad address";
        case EINTR:
            return "Interrupted system call";
        default:
            return "Unknown error";
        }
    }

    class SystemErrorCategory
    {
    public:
        using ErrorCodeType = ErrorCode<SystemErrorCategory>;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ~SystemErrorCategory() noexcept = default;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr SystemErrorCategory(const SystemErrorCategory &) noexcept = delete;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr SystemErrorCategory &operator=(const SystemErrorCategory &) noexcept = delete;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr SystemErrorCategory(SystemErrorCategory &&) noexcept = delete;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr SystemErrorCategory &operator=(SystemErrorCategory &&) noexcept = delete;
        
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr String name() const noexcept { return "system"; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr String message(const ErrorCodeType &error) const noexcept { return strerror(error.value()); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool operator==(const SystemErrorCategory &rhs) const noexcept { return this == &rhs; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool operator!=(const SystemErrorCategory &rhs) const noexcept { return this != &rhs; }

        CoFHE_DEVICE_AGNOSTIC_FUNC
        static const SystemErrorCategory &instance() noexcept
        {
            static SystemErrorCategory instance;
            return instance;
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC
        static ErrorCodeType make_error_code(int error) noexcept
        {
            return ErrorCodeType(error, instance());
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC
        static ErrorCodeType make_error_code(SystemErrorEnum error) noexcept
        {
            return ErrorCodeType(static_cast<int>(error), instance());
        }

    private:
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr SystemErrorCategory() noexcept = default;
    };

    CoFHE_DEVICE_AGNOSTIC_FUNC
    inline ErrorCode<SystemErrorCategory> make_error_code(SystemErrorEnum error) noexcept
    {
        return SystemErrorCategory::make_error_code(static_cast<int>(error));
    }

    class SystemError
    {
    public:
        using ErrorCodeType = SystemErrorCategory::ErrorCodeType;
        static  ErrorCodeType success()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::success);
        }
        static  ErrorCodeType out_of_memory()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::out_of_memory);
        }
        static  ErrorCodeType resource_temporarily_unavailable()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::resource_temporarily_unavailable);
        }
        static  ErrorCodeType operation_not_permitted()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::operation_not_permitted);
        }
        static  ErrorCodeType permission_denied()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::permission_denied);
        }
        static  ErrorCodeType io_error()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::io_error);
        }
        static  ErrorCodeType file_exists()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::file_exists);
        }
        static  ErrorCodeType not_a_directory()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::not_a_directory);
        }
        static  ErrorCodeType is_a_directory()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::is_a_directory);
        }
        static  ErrorCodeType invalid_argument()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::invalid_argument);
        }
        static  ErrorCodeType bad_address()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::bad_address);
        }
        static  ErrorCodeType interrupted_system_call()
        {
            return SystemErrorCategory::make_error_code(SystemErrorEnum::interrupted_system_call);
        }
    };

} // namespace CoFHE
#elif defined(CoFHE_WINDOWS)
#error "Windows not supported"
#endif
#endif