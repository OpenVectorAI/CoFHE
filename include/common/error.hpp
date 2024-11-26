#ifndef CoFHE_ERROR_HPP_INCLUDED
#define CoFHE_ERROR_HPP_INCLUDED
#include <errno.h>
#include <error.h>
#include <string.h>
#include "common/macros.hpp"
#include "./common/type_traits.hpp"

#include <iostream>

namespace CoFHE
{
    using String = std::string;
    template <typename T>
    concept StringConvertible = std::is_same_v<T, String>;
    template <typename ErrorCategoryImpl>
    concept ErrorCategoryImplConcept = requires(ErrorCategoryImpl category) {
        typename ErrorCategoryImpl::ErrorCodeType;
        { std::as_const(category).name() } noexcept -> StringConvertible;
        { std::as_const(category).message(1) } noexcept -> StringConvertible;
        { std::as_const(category) == std::as_const(category) } noexcept -> std::same_as<bool>;
        { std::as_const(category) != std::as_const(category) } noexcept -> std::same_as<bool>;
        { ErrorCategoryImpl::instance() } noexcept -> std::same_as<const ErrorCategoryImpl &>;
        // no public constructors or assignment operators
        // cant really check for some random constructor
        requires std::negation_v<std::is_default_constructible<ErrorCategoryImpl>>;
        requires std::negation_v<std::is_copy_constructible<ErrorCategoryImpl>>;
        requires std::negation_v<std::is_move_constructible<ErrorCategoryImpl>>;
        requires std::negation_v<std::is_copy_assignable<ErrorCategoryImpl>>;
        requires std::negation_v<std::is_move_assignable<ErrorCategoryImpl>>;

        requires std::is_nothrow_destructible_v<ErrorCategoryImpl>;
    };

    template <typename ErrorCategoryType> // requires ErrorCategoryImplConcept<ErrorCategoryType>
    class ErrorCode
    {
    public:
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ErrorCode() noexcept : value_m(0), category_m(ErrorCategoryType::instance()) {}
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr explicit ErrorCode(int value, const ErrorCategoryType &category) noexcept : value_m(value), category_m(category) {}
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ~ErrorCode() noexcept = default;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr int value() const noexcept { return value_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr const ErrorCategoryType &category() const noexcept { return category_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr String message() const noexcept { return category_m.message(value_m); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr explicit operator bool() const noexcept { return value_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr explicit operator int() const noexcept { return value_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool operator==(ErrorCode other) const noexcept { return value_m == other.value_m && &category_m == &other.category_m; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool operator!=(ErrorCode other) const noexcept { return value_m != other.value_m || &category_m != &other.category_m; }

    private:
        int value_m;
        const ErrorCategoryType &category_m;
    };

    template <typename ErrorHandlerImpl, typename HandlerReturn, typename ErrorCodeType>
    concept ErrorHandlerImplConcept = requires(ErrorHandlerImpl handler, ErrorCodeType error) {
        { handler.handle_error(error) } noexcept -> std::same_as<HandlerReturn>;
        requires std::is_nothrow_destructible_v<ErrorHandlerImpl>;
    };

    class DefaultErrorHandler
    {
        public:
        template <typename ErrorCodeType>
        CoFHE_DEVICE_AGNOSTIC_FUNC void handle_error(ErrorCodeType error) noexcept
        {
            std::cerr << error.category().name() << ": " << error.message() << std::endl;
            abort();
        }
    };
        

    enum class GenericErrorEnum
    {
        success = 0,
        failure = 1,
        out_of_range = 2,
        invalid_argument = 3,
        not_implemented = 4,
        memory_error = 5,
        memory_allocation_failure = 6,
    };

    constexpr String generic_error_message(GenericErrorEnum error)
    {
        switch (error)
        {
        case GenericErrorEnum::success:
            return "Success";
        case GenericErrorEnum::failure:
            return "Failure";
        case GenericErrorEnum::out_of_range:
            return "Out of range";
        case GenericErrorEnum::invalid_argument:
            return "Invalid argument";
        case GenericErrorEnum::not_implemented:
            return "Not implemented";
        case GenericErrorEnum::memory_error:
            return "Memory error";
        case GenericErrorEnum::memory_allocation_failure:
            return "Memory allocation failure";
        default:
            return "Unknown error";
        }
    }

    class GenericErrorCategory
    {
    public:
        using ErrorCodeType = ErrorCode<GenericErrorCategory>;

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr ~GenericErrorCategory() noexcept = default;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr GenericErrorCategory(const GenericErrorCategory &) noexcept = delete;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr GenericErrorCategory &operator=(const GenericErrorCategory &) noexcept = delete;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr GenericErrorCategory(GenericErrorCategory &&) noexcept = delete;
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr GenericErrorCategory &operator=(GenericErrorCategory &&) noexcept = delete;

        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr String name() const noexcept { return "generic"; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr String message(int value) const noexcept { return generic_error_message(static_cast<GenericErrorEnum>(value)); }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool operator==(const GenericErrorCategory &rhs) const noexcept { return this == &rhs; }
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr bool operator!=(const GenericErrorCategory &rhs) const noexcept { return this != &rhs; }

        CoFHE_DEVICE_AGNOSTIC_FUNC
        static const GenericErrorCategory &instance() noexcept
        {
            static GenericErrorCategory instance;
            return instance;
        }

        CoFHE_DEVICE_AGNOSTIC_FUNC
        static ErrorCodeType make_error_code(int error) noexcept
        {
            return ErrorCodeType(static_cast<int>(error), instance());
        }
        CoFHE_DEVICE_AGNOSTIC_FUNC
        static ErrorCodeType make_error_code(GenericErrorEnum error) noexcept
        {
            return ErrorCodeType(static_cast<int>(error), instance());
        }

    private:
        CoFHE_DEVICE_AGNOSTIC_FUNC constexpr GenericErrorCategory() noexcept
        {
            static_assert(ErrorCategoryImplConcept<GenericErrorCategory>, "ErrorCategoryImplConcept<GenericErrorCategory> is not satisfied");
        };
    };

    CoFHE_DEVICE_AGNOSTIC_FUNC
    inline ErrorCode<GenericErrorCategory> make_error_code(GenericErrorEnum error) noexcept
    {
        return GenericErrorCategory::make_error_code(error);
    }

    class GenericError
    {
    public:
        static GenericErrorCategory::ErrorCodeType success()
        {
            return GenericErrorCategory::make_error_code(GenericErrorEnum::success);
        }
        static GenericErrorCategory::ErrorCodeType failure()
        {
            return GenericErrorCategory::make_error_code(GenericErrorEnum::failure);
        }
        static GenericErrorCategory::ErrorCodeType out_of_range()
        {
            return GenericErrorCategory::make_error_code(GenericErrorEnum::out_of_range);
        }
        static GenericErrorCategory::ErrorCodeType invalid_argument()
        {
            return GenericErrorCategory::make_error_code(GenericErrorEnum::invalid_argument);
        }
        static GenericErrorCategory::ErrorCodeType not_implemented()
        {
            return GenericErrorCategory::make_error_code(GenericErrorEnum::not_implemented);
        }
        static GenericErrorCategory::ErrorCodeType memory_error()
        {
            return GenericErrorCategory::make_error_code(GenericErrorEnum::memory_error);
        }
        static GenericErrorCategory::ErrorCodeType memory_allocation_failure()
        {
            return GenericErrorCategory::make_error_code(GenericErrorEnum::memory_allocation_failure);
        }
    };

    class GenericErrorHandler
    {
    public:
        using ErrorCodeType = GenericErrorCategory::ErrorCodeType;
        void handle_error(ErrorCodeType error) noexcept
        {
            if (error == GenericError::success())
            {
                return;
            }
            std::cerr << error.category().name() << ": " << error.message() << std::endl;
            abort();
        }
    };

} // namespace CoFHE

#endif