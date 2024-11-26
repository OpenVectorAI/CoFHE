#ifndef TENSOR_HPP_INCLUDED
#define TENSOR_HPP_INCLUDED

#include <ostream>

#include "common/algorithms.hpp"
#include "common/macros.hpp"
#include "common/vector.hpp"
#include "common/variant.hpp"
#include "common/pointers.hpp"
#include "common/expected.hpp"
#include "common/iterators.hpp"
#include "common/optional.hpp"

namespace CoFHE
{

    template <typename T>
    class Storage
    {
    public:
        using iterator = typename Vector<T>::iterator;
        using const_iterator = typename Vector<T>::const_iterator;
        using reverse_iterator = typename Vector<T>::reverse_iterator;
        using const_reverse_iterator = typename Vector<T>::const_reverse_iterator;
        using value_type = T;
        using reference = value_type &;
        using const_reference = const reference;
        using pointer = value_type *;
        using const_pointer = const pointer;

        Storage() noexcept = default;
        Storage(size_t n, value_type value = value_type()) : shape(1, n), data(n, std::move(value)) {}
        Storage(size_t n, size_t m, value_type value = value_type()) : shape(2, n), data(n * m, std::move(value))
        {
            shape[1] = m;
        }
        Storage(Vector<size_t> shape, value_type value = value_type()) : shape(std::move(shape)), data(1, std::move(value))
        {
            int n = 1;
            for (size_t i = 0; i < this->shape.size(); i++)
            {
                n *= this->shape[i];
            }
            data.resize(n, value);
        }
        Storage(Vector<size_t> shape, Vector<value_type> data) noexcept : shape(std::move(shape)), data(std::move(data))
        {
            size_t num_elements = 1;
            for (size_t i = 0; i < this->shape.size(); i++)
            {
                num_elements *= this->shape[i];
            }
            if (num_elements != this->data.size() && num_elements != this->data.capacity())
            {
                throw std::invalid_argument("Data size must be equal to product of shape");
            }
        }

        reference operator[](size_t i) { return data[i]; }
        const_reference operator[](size_t i) const { return data[i]; }

        reference at(size_t i) { return data.at(i); }
        const_reference at(size_t i) const { return data.at(i); }

        iterator begin() { return data.begin(); }
        const_iterator begin() const { return data.begin(); }
        const_iterator cbegin() const { return data.cbegin(); }
        iterator end() { return data.end(); }
        const_iterator end() const { return data.end(); }
        const_iterator cend() const { return data.cend(); }
        reverse_iterator rbegin() { return data.rbegin(); }
        const_reverse_iterator rbegin() const { return data.rbegin(); }
        const_reverse_iterator crbegin() const { return data.crbegin(); }
        reverse_iterator rend() { return data.rend(); }
        const_reverse_iterator rend() const { return data.rend(); }
        const_reverse_iterator crend() const { return data.crend(); }

        size_t size() const { return data.size(); }

        Vector<size_t> get_shape() { return shape; }
        const Vector<size_t> &get_shape() const { return shape; }

        void push_back(value_type value) { return data.push_back(std::move(value)); }

        template <class... Args>
        void emplace_back(Args &&...args) { data.emplace_back(args...); }

        iterator insert(size_t pos, const value_type &value) { data.insert(data.begin() + pos, value); }
        iterator insert(size_t pos, value_type &&value) { data.insert(data.begin() + pos, std::move(value)); }
        iterator insert(size_t pos, const Vector<value_type> &values) { data.insert(data.begin() + pos, values.begin(), values.end()); }
        iterator insert(size_t pos, Vector<value_type> &&values) { data.insert(data.begin() + pos, std::make_move_iterator(values.begin()), std::make_move_iterator(values.end())); }
        iterator remove(size_t pos) { data.erase(data.begin() + pos); }
        iterator remove(size_t start, size_t end) { data.erase(data.begin() + start, data.begin() + end); }
        iterator remove(value_type *pos) { data.erase(pos); }
        iterator remove(value_type *start, value_type *end) { data.erase(start, end); }
        void clear() { data.clear(); }

        // pointer get_data() { return data.data(); }
        // const_pointer get_data() const { return data.data(); }
        // Vector<T> get_storage() { return data; }
        // const Vector<T> &get_storage() const { return data; }

        void reserve(size_t n) { return data.reserve(n); }
        void resize(size_t n, value_type value = value_type()) { return data.resize(n, std::move(value)); }

    private:
        Vector<size_t> shape;
        Vector<value_type> data;
    };

    inline void normalize_index(Vector<size_t> &index, const Vector<size_t> &shape, const Vector<size_t> &broadcast_degree)
    {
        for (size_t i = 0; i < index.size(); i++)
        {
            index[i] = index[i] % (shape[i] / broadcast_degree[i]);
        }
    }

    // check the stride(return value) after the function call to see if it is 0 or not
    // to confirm if the stride was completed or not
    size_t make_forward_stride(size_t stride, const Vector<size_t> &start, const Vector<size_t> &end, size_t &current_section, size_t &consumed_part_of_current_section)
    {
#ifdef DEBUG
        if (start.size() != end.size())
        {
            throw std::invalid_argument("Start and end size must be equal");
        }
#endif
        while (stride > 0 && current_section < start.size())
        {
            if (stride > end[current_section] - start[current_section] - consumed_part_of_current_section)
            {
                stride -= end[current_section] - start[current_section] - consumed_part_of_current_section;
                consumed_part_of_current_section = 0;
                current_section++;
            }
            else
            {
                consumed_part_of_current_section += stride;
                stride = 0;
                break;
            }
        }
        return stride;
    }

    size_t make_backward_stride(size_t stride, const Vector<size_t> &start, const Vector<size_t> &end, size_t &current_section, size_t &consumed_part_of_current_section)
    {
#ifdef DEBUG
        if (start.size() != end.size())
        {
            throw std::invalid_argument("Start and end size must be equal");
        }
        for (size_t i = 0; i < start.size(); i++)
        {
            if (start[i] >= end[i])
            {
                throw std::invalid_argument("Start must be less than end");
            }
        }
        if (current_section >= start.size())
        {
            throw std::invalid_argument("Current section must be less than start size");
        }
        if (consumed_part_of_current_section > end[current_section] - start[current_section])
        {
            throw std::invalid_argument("Consumed part of current section must be less than or equal capacity of current section");
        }
#endif
        if (consumed_part_of_current_section)
        {
            consumed_part_of_current_section -= min(consumed_part_of_current_section, stride);
            current_section--;
            stride -= consumed_part_of_current_section;
        }
        while (stride > 0 && current_section < start.size())
        {
            if (stride > consumed_part_of_current_section)
            {
                stride -= consumed_part_of_current_section;
                consumed_part_of_current_section = 0;
                current_section--;
            }
            else
            {
                consumed_part_of_current_section -= stride;
                stride = 0;
                break;
            }
        }
        return stride;
    }

    template <typename T, bool is_const>
    class Accessor;

    template <typename T, bool is_const>
    class AccessorIterator
    {
    public:
        using base_value_type = T;
        using base_value_reference = base_value_type &;
        using base_value_pointer = base_value_type *;
        using const_base_value_type = const base_value_type;
        using const_base_value_reference = const_base_value_type &;
        using value_type = Accessor<base_value_type, false>;
        using const_value_type = Accessor<base_value_type, true>;
        using reference = value_type &;
        using const_reference = const value_type &;
        using iterator_category = std::random_access_iterator_tag;

        AccessorIterator(SharedPtr<Storage<base_value_type>> storage, const Vector<size_t> &shape, const Vector<size_t> &broadcast_degree, const Vector<size_t> &start, const Vector<size_t> &end, size_t stride) noexcept : storage_m(std::move(storage)), shape_m(shape), broadcast_degree_m(broadcast_degree), start_m(start), end_m(end), stride_m(stride), current_section(0), consumed_part_of_current_section(0)
        {
            remaining_elements = shape_m[0];
        }

        const_value_type operator*() const noexcept
        {
            size_t current_section_local = current_section;
            size_t consumed_part_of_current_section_local = consumed_part_of_current_section;
            auto res = make_forward_stride(stride_m, start_m, end_m, current_section_local, consumed_part_of_current_section_local);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            Vector<size_t> shape_local(shape_m.begin() + 1, shape_m.end());
            Vector<size_t> start_local(start_m.begin() + current_section, start_m.end());
            Vector<size_t> end_local(end_m.begin() + current_section, end_m.end());
            Vector<size_t> broadcast_degree_local(broadcast_degree_m.begin() + 1, broadcast_degree_m.end());
            start_local[0] = start_m[current_section] + consumed_part_of_current_section;
            end_local[current_section_local] = start_m[current_section_local] + consumed_part_of_current_section_local;
            return const_value_type(storage_m, shape_local, broadcast_degree_local, start_local, end_local);
        }

        value_type operator*() noexcept
            requires(!is_const)
        {
            size_t current_section_local = current_section;
            size_t consumed_part_of_current_section_local = consumed_part_of_current_section;
            auto res = make_forward_stride(stride_m, start_m, end_m, current_section_local, consumed_part_of_current_section_local);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            Vector<size_t> shape_local(shape_m.begin() + 1, shape_m.end());
            Vector<size_t> start_local(start_m.begin() + current_section, start_m.end());
            Vector<size_t> end_local(end_m.begin() + current_section, end_m.end());
            Vector<size_t> broadcast_degree_local(broadcast_degree_m.begin() + 1, broadcast_degree_m.end());
            start_local[0] = start_m[current_section] + consumed_part_of_current_section;
            end_local[current_section_local] = start_m[current_section_local] + consumed_part_of_current_section_local;
            return value_type(storage_m, shape_local, broadcast_degree_local, start_local, end_local);
        }

        bool is_iterator_of_1d_accessor() const noexcept
        {
            return shape_m.size() == 1;
        }

        const_base_value_reference at(size_t n) const noexcept
        {
            n %= (shape_m[0] / broadcast_degree_m[0]);
            size_t local_section = 0;
            size_t local_consumed_part_of_current_section = 0;
            auto stride = make_forward_stride(n * stride_m, start_m, end_m, local_section, local_consumed_part_of_current_section);
            if (stride)
            {
                throw std::runtime_error("Stride not completed");
            }
            return storage_m->at(start_m[local_section] + local_consumed_part_of_current_section);
        }

        base_value_reference at(size_t n) noexcept
            requires(!is_const)
        {
            n %= (shape_m[0] / broadcast_degree_m[0]);
            size_t local_section = 0;
            size_t local_consumed_part_of_current_section = 0;
            auto stride = make_forward_stride(n * stride_m, start_m, end_m, local_section, local_consumed_part_of_current_section);
            if (stride)
            {
                throw std::runtime_error("Stride not completed");
            }
            return storage_m->at(start_m[local_section] + local_consumed_part_of_current_section);
        }

        AccessorIterator &operator++() noexcept
        {
            --remaining_elements;
            if (remaining_elements == -1)
            {
                return *this;
            }
            if (shape_m[0] - remaining_elements >= shape_m[0] / broadcast_degree_m[0])
            {
                current_section = 0;
                consumed_part_of_current_section = 0;
            }
            else
            {
                size_t res = make_forward_stride(stride_m, start_m, end_m, current_section, consumed_part_of_current_section);
                if (res)
                {
                    throw std::runtime_error("Stride not completed");
                }
            }
            return *this;
        }

        AccessorIterator operator++(int) noexcept
        {
            AccessorIterator temp = *this;
            --remaining_elements;
            if (remaining_elements == -1)
            {
                return temp;
            }
            if (shape_m[0] - remaining_elements >= shape_m[0] / broadcast_degree_m[0])
            {
                current_section = 0;
                consumed_part_of_current_section = 0;
            }
            else
            {
                size_t res = make_forward_stride(stride_m, start_m, end_m, current_section, consumed_part_of_current_section);
                if (res)
                {
                    throw std::runtime_error("Stride not completed");
                }
            }
            return temp;
        }

        AccessorIterator &operator--() noexcept
        {
            ++remaining_elements;
            if (remaining_elements == shape_m[0])
            {
                return *this;
            }
            size_t res = make_backward_stride(stride_m, start_m, end_m, current_section, consumed_part_of_current_section);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            return *this;
        }

        AccessorIterator operator--(int) noexcept
        {
            AccessorIterator temp = *this;
            ++remaining_elements;
            if (remaining_elements == shape_m[0])
            {
                return temp;
            }
            size_t res = make_backward_stride(stride_m, start_m, end_m, current_section, consumed_part_of_current_section);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            return temp;
        }

        AccessorIterator &operator+=(size_t n) noexcept
        {
            remaining_elements -= n;
            if (remaining_elements < 0)
            {
                return *this;
            }
            if (shape_m[0] - remaining_elements >= shape_m[0] / broadcast_degree_m[0])
            {
                current_section = 0;
                consumed_part_of_current_section = 0;
                n %= (shape_m[0] / broadcast_degree_m[0]);
            }
            size_t res = make_forward_stride(n * stride_m, start_m, end_m, current_section, consumed_part_of_current_section);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            return *this;
        }

        AccessorIterator operator+(size_t n) const noexcept
        {
            AccessorIterator temp = *this;
            temp += n;
            return temp;
        }

        AccessorIterator &operator-=(size_t n) noexcept
        {
            remaining_elements += n;
            if (remaining_elements >= shape_m[0])
            {
                return *this;
            }
            if (n >= shape_m[0] / broadcast_degree_m[0])
            {
                current_section = 0;
                consumed_part_of_current_section = 0;
                n %= (shape_m[0] / broadcast_degree_m[0]);
            }
            size_t res = make_backward_stride(n * stride_m, start_m, end_m, current_section, consumed_part_of_current_section);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            return *this;
        }

        AccessorIterator operator-(size_t n) const noexcept
        {
            AccessorIterator temp = *this;
            temp -= n;
            return temp;
        }

        bool operator==(const AccessorIterator &other) const noexcept
        {
            return remaining_elements == other.remaining_elements;
        }

        bool operator!=(const AccessorIterator &other) const noexcept
        {
            return !(*this == other);
        }

        bool operator<(const AccessorIterator &other) const noexcept
        {
            return remaining_elements < other.remaining_elements;
        }

        bool operator>(const AccessorIterator &other) const noexcept
        {
            return remaining_elements > other.remaining_elements;
        }

        bool operator<=(const AccessorIterator &other) const noexcept
        {
            return !(*this > other);
        }

        bool operator>=(const AccessorIterator &other) const noexcept
        {
            return !(*this < other);
        }

    private:
        SharedPtr<Storage<base_value_type>> storage_m;
        const Vector<size_t> shape_m;
        const Vector<size_t> broadcast_degree_m;
        const Vector<size_t> start_m;
        const Vector<size_t> end_m;
        size_t stride_m;
        size_t current_section;
        size_t consumed_part_of_current_section;
        int32_t remaining_elements;
    };

    template <typename T, bool is_const = false>
    class Accessor
    {
    public:
        using base_value_type = T;
        using base_value_reference = base_value_type &;
        using base_value_pointer = base_value_type *;
        using const_base_value_type = const base_value_type;
        using const_base_value_reference = const_base_value_type &;
        using const_base_value_pointer = const_base_value_type *;
        using value_type = Accessor<base_value_type, false>;
        using const_value_type = Accessor<base_value_type, true>;
        using reference = value_type &;
        using const_reference = const_value_type &;
        using iterator = AccessorIterator<base_value_type, false>;
        using const_iterator = AccessorIterator<base_value_type, true>;
        // using reverse_iterator = AccessorReverseIterator<iterator>;
        // using const_reverse_iterator = AccessorReverseIterator<const_iterator>;

        explicit Accessor() = default;
        explicit Accessor(const Storage<base_value_type> &storage_m) : shape_m(storage_m.get_shape()), start_m(1, 0), end_m(1, storage_m.size()), storage_m(new Storage<base_value_type>(storage_m))
        {
            one_init_broadcast_degree();
            calculate_stride();
        }
        explicit Accessor(const SharedPtr<Storage<base_value_type>> &storage_m) : shape_m(storage_m->get_shape()), start_m(1, 0), end_m(1, storage_m->size()), storage_m(storage_m)
        {
            one_init_broadcast_degree();
            calculate_stride();
        }
        Accessor(const SharedPtr<Storage<base_value_type>> &storage_m, const Vector<size_t> &shape_m, const Vector<size_t> &start_m, const Vector<size_t> &end_m) : shape_m(shape_m), start_m(start_m), end_m(end_m), storage_m(storage_m)
        {
            one_init_broadcast_degree();
            calculate_stride();
        }
        Accessor(SharedPtr<Storage<base_value_type>> &&storage_m, Vector<size_t> &&shape_m, Vector<size_t> &&start_m, Vector<size_t> &&end_m) : shape_m(std::move(shape_m)), start_m(std::move(start_m)), end_m(std::move(end_m)), storage_m(std::move(storage_m))
        {
            one_init_broadcast_degree();
            calculate_stride();
        }
        Accessor(const Accessor<base_value_type> &other, Vector<size_t> &&shape_m, Vector<size_t> &&start_m, Vector<size_t> &&end_m) : shape_m(std::move(shape_m)), start_m(std::move(start_m)), end_m(std::move(end_m)), storage_m(other.storage_m)
        {
            one_init_broadcast_degree();
            calculate_stride();
        }
        Accessor(const SharedPtr<Storage<base_value_type>> &storage_m, const Vector<size_t> &shape_m, const Vector<size_t> &broadcast_defgree, const Vector<size_t> &start_m, const Vector<size_t> &end_m) : shape_m(shape_m),
                                                                                                                                                                                                             broadcast_degree_m(broadcast_defgree), start_m(start_m), end_m(std::move(end_m)), storage_m(storage_m)
        {
            calculate_stride();
        }

        Accessor<base_value_type, is_const> copy() const noexcept
        {
            Vector<base_value_type> new_storage_vec;
            new_storage_vec.reserve(num_elements());
            copy(new_storage_vec);
            SharedPtr<Storage<base_value_type>> new_storage(new Storage<base_value_type>(shape_m, new_storage_vec));
            return Accessor<base_value_type,is_const>(new_storage, shape_m, {0}, {new_storage->size()});
        }

        void copy(Vector<base_value_type> &new_storage) const noexcept
        {
            if (this->is_column_vector())

            {
                for (size_t i = 0; i < shape_m[0]; i++)
                {
                    new_storage.push_back(at(i));
                }
            }
            else
            {
                for (auto i : *this)
                {
                    i.copy(new_storage);
                }
            }
        }

        template <typename U>
            requires std::is_nothrow_copy_constructible_v<U>  && IsNoThrowCallable<U, void, base_value_reference>
                                                            void walk(U fn) noexcept
                         requires(!is_const)
        {
            if (is_broadcasted())
                *this = copy();
            if (this->is_column_vector())
            {
                for (size_t i = 0; i < shape_m[0]; i++)
                {
                    fn(at(i));
                }
            }
            else
            {
                for (auto i : *this)
                {
                    i.walk(fn);
                }
            }
        }

        template <typename U>
            requires std::is_nothrow_copy_constructible_v<U>  && IsNoThrowCallable<U, void, base_value_reference, const Vector<size_t>&>
                                                            void walk(U fn) noexcept
                         requires(!is_const)
        {
            if (is_broadcasted())
                *this = copy();
            std::vector<size_t> index;
            index.reserve(shape_m.size());
            walk_helper(fn, index);
        }

        template <typename U>
            requires std::is_nothrow_copy_constructible_v<U>  && IsNoThrowCallable<U, void, const_base_value_reference,const Vector<size_t>&>
                                                            void walk(U fn) const noexcept
        {
            if (is_broadcasted())
                *(const_cast<Accessor<base_value_type, is_const> *>(this)) = copy();
            std::vector<size_t> index;
            index.reserve(shape_m.size());
            walk_helper(fn, index);
        }
        template <typename U>
            requires std::is_nothrow_copy_constructible_v<U>  && IsNoThrowCallable<U, void, const_base_value_reference>
        void walk(U fn) const noexcept
        {
            if (is_broadcasted())
                *(const_cast<Accessor<base_value_type, is_const> *>(this)) = copy();
            if (this->is_column_vector())

            {
                for (size_t i = 0; i < shape_m[0]; i++)
                {
                    fn(at(i));
                }
            }
            else
            {
                for (auto i : *this)
                {
                    i.walk(fn);
                }
            }
        }

        // to be broadcastable either the shape of the tensor should be same or divisible by current shape
        Accessor<T, is_const> broadcast(const Vector<size_t> &new_shape) noexcept
        {
            if (new_shape.size() == 0)
            {
                throw std::runtime_error("New shape cannot be empty");
            }
            Vector<size_t> new_broadcast_degree(new_shape.size(), 1);
            size_t size_diff = new_shape.size() - shape_m.size();
            for (size_t i = 0; i < shape_m.size(); i++)
            {
                if (new_shape[i + size_diff] % shape_m[i])
                {
                    throw std::runtime_error("Shape mismatch");
                }
                else
                {
                    new_broadcast_degree[i + size_diff] = new_shape[i + size_diff] / shape_m[i] * broadcast_degree_m[i];
                }
            }
            for (size_t i = 0; i < size_diff; i++)
            {
                new_broadcast_degree[i] = new_shape[i];
            }
            return Accessor<T, is_const>(storage_m, new_shape, new_broadcast_degree, start_m, end_m);
        }

        void reshape(const Vector<size_t> &new_shape)
        {
            size_t total_elements = 1;
            for (auto i : new_shape)
            {
                total_elements *= i;
            }
            if (total_elements != num_elements())
            {
                throw std::runtime_error("Total elements mismatch");
            }
            // we can reshape without copying if the new shape have same last dimensions ??
            if (is_broadcasted())
            {
                *this = copy();
            }
            shape_m = new_shape;
            one_init_broadcast_degree();
            calculate_stride();
        }

        const_base_value_reference at(size_t index) const noexcept
        {
            if (!is_column_vector())
            {
                throw std::runtime_error("Accessor is not a column vector");
            }
            index %= (shape_m[0] / broadcast_degree_m[0]);
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            auto stride = make_forward_stride(index, start_m, end_m, current_section, consumed_part_of_current_section);
            if (stride)
            {
                throw std::runtime_error("Stride not completed");
            }
            return storage_m->at(start_m[current_section] + consumed_part_of_current_section);
        }

        const_base_value_reference at(size_t row_index, size_t column_index) const noexcept
        {
            if (!is_2d_matrix())
            {
                throw std::runtime_error("Accessor is not a 2D matrix");
            }
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            auto stride = make_forward_stride(row_index * strides_m[0] + column_index, start_m, end_m, current_section, consumed_part_of_current_section);
            if (stride)
            {
                throw std::runtime_error("Stride not completed");
            }
            return storage_m->at(start_m[current_section] + consumed_part_of_current_section);
        }

        base_value_reference at(size_t index) noexcept
            requires(!is_const)
        {
            if (!is_column_vector())
            {
                throw std::runtime_error("Accessor is not a column vector");
            }
            index %= (shape_m[0] / broadcast_degree_m[0]);
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            auto stride = make_forward_stride(index, start_m, end_m, current_section, consumed_part_of_current_section);
            if (stride)
            {
                throw std::runtime_error("Stride not completed");
            }
            return storage_m->at(start_m[current_section] + consumed_part_of_current_section);
        }

        base_value_reference at(size_t row_index, size_t column_index) noexcept
            requires(!is_const)
        {
            if (!is_2d_matrix())
            {
                throw std::runtime_error("Accessor is not a 2D matrix");
            }
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            auto stride = make_forward_stride(row_index * strides_m[0] + column_index, start_m, end_m, current_section, consumed_part_of_current_section);
            if (stride)
            {
                throw std::runtime_error("Stride not completed");
            }
            return storage_m->at(start_m[current_section] + consumed_part_of_current_section);
        }

        const_base_value_reference at(const Vector<size_t> &index) const noexcept
        {
            if (index.size() != shape_m.size())
            {
                throw std::out_of_range("Shape mismatch");
            }
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            size_t stride = 0;
            for (size_t i = 0; i < index.size(); i++)
            {
                stride += index[i] * strides_m[i];
            }
            auto res = make_forward_stride(stride, start_m, end_m, current_section, consumed_part_of_current_section);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            return storage_m->at(start_m[current_section] + consumed_part_of_current_section);
        }

        base_value_reference at(const Vector<size_t> &index) noexcept
            requires(!is_const)
        {
            if (index.size() != shape_m.size())
            {
                throw std::out_of_range("Shape mismatch");
            }
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            size_t stride = 0;
            for (size_t i = 0; i < index.size(); i++)
            {
                stride += index[i] * strides_m[i];
            }
            auto res = make_forward_stride(stride, start_m, end_m, current_section, consumed_part_of_current_section);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            return storage_m->at(start_m[current_section] + consumed_part_of_current_section);
        }

        void set(const Vector<size_t> &start_dims, const Vector<base_value_type> &values) noexcept
            requires(!is_const)
        {
            size_t skip_ele = 0;
            for (size_t i = 0; i < start_dims.size(); ++i)
            {
                skip_ele += start_dims[i] * strides_m[i];
            }
            if (skip_ele >= num_elements())
            {
                throw std::runtime_error("Index out of range");
            }

            size_t current_section = 0, already_used_part = 0;
            for (; current_section < start_m.size(); ++current_section)
            {
                if (end_m[current_section] - start_m[current_section] > skip_ele)
                {
                    already_used_part = skip_ele;
                    break;
                }
                skip_ele -= end_m[current_section] - start_m[current_section];
            }
            for (size_t i = 0; i < values.size(); ++i)
            {
                if (current_section >= start_m.size())
                {
                    throw std::runtime_error("Index out of range");
                }
                if (already_used_part == end_m[current_section] - start_m[current_section])
                {
                    already_used_part = 0;
                    ++current_section;
                }
                *(storage_m->get_data() + start_m[current_section] + already_used_part) = values[i];
                ++already_used_part;
            }
        }

        void set(size_t i, const base_value_type &value) noexcept
            requires(!is_const)
        {
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            auto res = make_forward_stride(i, start_m, end_m, current_section, consumed_part_of_current_section);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            storage_m->at(start_m[current_section] + consumed_part_of_current_section) = value;
        }

        void set(const Vector<size_t> &dim, const base_value_type &value)
            requires(!is_const)
        {
            if (dim.size() != shape_m.size())
            {
                throw std::out_of_range("Shape mismatch");
            }
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            size_t res_start_section = 0;
            size_t res_start_position = 0;
            size_t stride = 1;
            for (size_t i = 0; i < dim.size(); i++)
            {
                stride *= dim[i] * strides_m[i];
            }
            auto res = make_forward_stride(stride, start_m, end_m, current_section, consumed_part_of_current_section);
            if (res)
            {
                throw std::runtime_error("Stride not completed");
            }
            storage_m->at(start_m[current_section] + consumed_part_of_current_section) = value;
        }

        void set(size_t offset, const Vector<base_value_type> &values)
            requires(!is_const)
        {
            size_t current_section = 0;
            size_t consumed_part_of_current_section = 0;
            size_t res_start_section = 0;
            size_t res_start_position = 0;
            auto stride_local = make_forward_stride(offset, start_m, end_m, current_section, consumed_part_of_current_section);
            if (stride_local)
            {
                throw std::runtime_error("Stride not completed");
            }
            for (size_t i = 0; i < values.size(); i++)
            {
                if (current_section >= start_m.size())
                {
                    throw std::runtime_error("Index out of range");
                }
                if (consumed_part_of_current_section == end_m[current_section] - start_m[current_section])
                {
                    consumed_part_of_current_section = 0;
                    ++current_section;
                }
                storage_m->at(start_m[current_section] + consumed_part_of_current_section) = values[i];
                ++consumed_part_of_current_section;
            }
        }

        iterator begin()
            requires(!is_const)
        {
            return iterator(storage_m, shape_m, broadcast_degree_m, start_m, end_m, strides_m[0]);
        }
        const_iterator begin() const
        {
            return const_iterator(storage_m, shape_m, broadcast_degree_m, start_m, end_m, strides_m[0]);
        }

        const_iterator cbegin() const
        {
            return const_iterator(storage_m, shape_m, broadcast_degree_m, start_m, end_m, strides_m[0]);
        }

        iterator end()
            requires(!is_const)
        {
            auto itr = begin();
            itr += shape_m[0];
            return itr;
        }

        const_iterator end() const
        {
            auto itr = begin();
            itr += shape_m[0];
            return itr;
        }

        const_iterator cend() const
        {
            auto itr = cbegin();
            itr += shape_m[0];
            return itr;
        }

        size_t size() const { return shape_m[0]; }
        size_t num_elements() const
        {
            size_t nums = 1;
            for (auto i : shape_m)
            {
                nums *= i;
            }
            return nums;
        }
        size_t rows() const
        {
            if (shape_m.size() == 2)
            {
                return shape_m[0];
            }
            throw std::runtime_error("Accessor is not 2D");
        }

        size_t cols() const
        {
            if (shape_m.size() == 2)
            {
                return shape_m[1];
            }
            throw std::runtime_error("Accessor is not 2D");
        }

        bool is_column_vector() const
        {
            return shape_m.size() == 1;
        }

        bool is_2d_matrix() const
        {
            return shape_m.size() == 2;
        }

        bool is_contiguous() const
        {

            return start_m.size() == 1;
        }

        bool is_broadcastable(const Accessor<base_value_type> &other) const
        {
            if (shape_m.size() <= other.shape_m.size())
            {
                size_t size_diff = other.shape_m.size() - shape_m.size();
                for (size_t i = 0; i < shape_m.size(); i++)
                {
                    if (other.shape_m[i + size_diff] % shape_m[i])
                    {
                        return false;
                    }
                }
                return true;
            }
            else
            {
                return false;
            }
        }

        bool is_broadcasted() const
        {
            for (size_t i = 0; i < broadcast_degree_m.size(); i++)
            {
                if (broadcast_degree_m[i] != 1)
                {
                    return true;
                }
            }
            return false;
        }

        void make_contiguous()
        {
            if (is_contiguous())
                return;
            *this = copy();
        }

        Vector<size_t> shape() { return shape_m; }
        const Vector<size_t> &shape() const { return shape_m; }

        void print(std::ostream &cout)
        {
            if (is_2d_matrix())
            {
                for (size_t i = 0; i < shape_m[0]; i++)
                {
                    for (size_t j = 0; j < shape_m[1]; j++)
                    {
                        cout << at(i, j) << " ";
                    }
                    cout << std::endl;
                }
            }
            else
            {
                auto print = [&](const T &val) noexcept
                { cout << val << " "; };
                walk(print);
                cout << std::endl;
            }
        }

    private:
        Vector<size_t> shape_m;
        Vector<size_t> broadcast_degree_m;
        Vector<size_t> start_m;
        Vector<size_t> end_m;
        Vector<size_t> strides_m;
        SharedPtr<Storage<base_value_type>> storage_m;

        void calculate_stride()
        {
            strides_m.resize(shape_m.size());
            strides_m[shape_m.size() - 1] = 1;
            for (int32_t i = strides_m.size() - 2; i >= 0; --i)
            {
                strides_m[i] = strides_m[i + 1] * (shape_m[i + 1] / broadcast_degree_m[i + 1]);
            }
        }

        void one_init_broadcast_degree()
        {
            broadcast_degree_m.resize(shape_m.size());
            for (size_t i = 0; i < shape_m.size(); i++)
            {
                broadcast_degree_m[i] = 1;
            }
        }

        template <typename U>
            void walk_helper(U fn, std::vector<size_t> &index) noexcept
        {
            if (this->is_column_vector())
            {
                for (size_t i = 0; i < shape_m[0]; i++)
                {
                    index.push_back(i);
                    fn(at(i), index);
                    index.pop_back();
                }
            }
            else
            {
                size_t curr_ind = 0;
                for (auto i : *this)
                {   
                    index.push_back(curr_ind);
                    i.walk_helper(fn, index);
                    index.pop_back();
                    curr_ind++;
                }
            }
        }

        template <typename U>
            void walk_helper(U fn, std::vector<size_t> &index) const noexcept
        {
            if (this->is_column_vector())
            {
                for (size_t i = 0; i < shape_m[0]; i++)
                {
                    index.push_back(i);
                    fn(at(i), index);
                    index.pop_back();
                }
            }
            else
            {
                size_t curr_ind = 0;
                for (auto i : *this)
                {
                    index.push_back(curr_ind);
                    i.walk_helper(fn, index);
                    index.pop_back();
                    curr_ind++;
                }
            }
        }
    };

    template <typename T>
    class Tensor
    {
    public:
        using base_value_type = typename Accessor<T>::base_value_type;
        using value_type = typename Accessor<T>::value_type; // we need it to be T for 0 degree also
        using iterator = typename Accessor<T>::iterator;
        using const_iterator = typename Accessor<T>::const_iterator;
        using reference = typename Accessor<T>::reference;
        using const_reference = typename Accessor<T>::const_reference;
        using base_value_reference = typename Accessor<T>::base_value_reference;
        using const_base_value_reference = typename Accessor<T>::const_base_value_reference;

        explicit Tensor(const_base_value_reference value) : accessor(SharedPtr<Storage<base_value_type>>(new Storage<base_value_type>(1,value))) , is_zero_degree_m(true) {}
        Tensor(Vector<size_t> shape, base_value_type value = base_value_type()) : accessor(SharedPtr<Storage<base_value_type>>(new Storage<base_value_type>(shape, value))) {}
        explicit Tensor(size_t n, base_value_type value = base_value_type()) : accessor(SharedPtr<Storage<base_value_type>>(new Storage<base_value_type>(n, value))) {}
        Tensor(size_t n, size_t m, base_value_type value = base_value_type()) : accessor(SharedPtr<Storage<base_value_type>>(new Storage<base_value_type>(n, m, value))) {}
        Tensor(const Vector<size_t> &shape, const Vector<base_value_type> &values) : accessor(SharedPtr<Storage<base_value_type>>(new Storage<base_value_type>(shape, values))) {}
        Tensor(Vector<size_t> &&shape, Vector<base_value_type> &&values) : accessor(SharedPtr<Storage<base_value_type>>(new Storage<base_value_type>(std::move(shape), std::move(values)))) {}

        void set(Vector<size_t> start_dims, Vector<base_value_type> values) { accessor.set(start_dims, values); }
        void set(size_t i, base_value_type value) { accessor.set(i, value); }
        void set(Vector<size_t> dim, base_value_type value) { accessor.set(dim, value); }
        void set(size_t offset, Vector<base_value_type> values) { accessor.set(offset, values); }
        void walk(auto fn) { accessor.walk(fn); }
        void walk(auto fn) const { accessor.walk(fn); }

        Tensor<base_value_type> broadcast(Vector<size_t> new_shape)
        {
            if (is_zero_degree_m)
                throw std::runtime_error("Cannot broadcast a zero degree tensor");
            return Tensor<T>(accessor.broadcast(new_shape));
        }

        base_value_reference at(size_t index) { return accessor.at(index); }
        const_base_value_reference at(size_t index) const { return accessor.at(index); }
        base_value_reference at(const Vector<size_t> &index) { return accessor.at(index); }
        const_base_value_reference at(const Vector<size_t> &index) const { return accessor.at(index); }
        base_value_reference operator[](size_t index) { return accessor.at(index); }
        const_base_value_reference operator[](size_t index) const { return accessor.at(index); }
        base_value_reference at(size_t row_index, size_t column_index) { return accessor.at(row_index, column_index); }
        const_base_value_reference at(size_t row_index, size_t column_index) const { return accessor.at(row_index, column_index); }

        iterator begin() { return accessor.begin(); }
        iterator end() { return accessor.end(); }
        const_iterator begin() const { return accessor.begin(); }
        const_iterator end() const { return accessor.end(); }
        const_iterator cbegin() const { return accessor.cbegin(); }
        const_iterator cend() const { return accessor.cend(); }

        size_t size() const { return accessor.size(); }
        size_t num_elements() const { return accessor.num_elements(); }
        Vector<size_t> shape()
        {
            if (is_zero_degree_m)
                return {0};
            return accessor.shape();
        }
        const Vector<size_t> &shape() const
        {
            if (is_zero_degree_m)
                throw std::runtime_error("A zero degree tensor has no shape");
            return accessor.shape();
        }

        size_t ndim() const { return accessor.shape().size(); }
        size_t rows() const { return accessor.rows(); }
        size_t cols() const { return accessor.cols(); }
        bool is_zero_degree() const { return is_zero_degree_m; }
        base_value_type get_value() const
        {
            if (!is_zero_degree_m)
                throw std::runtime_error("Not a zero degree tensor");
            return accessor.at(0);
        }
        bool is_column_vector() const { return accessor.is_column_vector(); }
        Vector<T> get_column_vector() const
        {
            if (!is_column_vector())
                throw std::runtime_error("Not a column vector");
            Vector<T> data;
            for (size_t i = 0; i < size(); i++)
            {
                data.push_back(accessor.at(i));
            }
            return data;
        }

        Vector<T> get_row_vector() const
        {
            if (!is_2d_matrix())
                throw std::runtime_error("Not a 2D matrix");
            Vector<T> data;
            for (size_t i = 0; i < rows(); i++)
            {
                for (size_t j = 0; j < cols(); j++)
                {
                    data.push_back(accessor.at(i, j));
                }
            }
            return data;
        }

        Tensor<T> get_row(size_t index) const
        {
            if (!is_2d_matrix())
                throw std::runtime_error("Not a 2D matrix");
            return Tensor<T>(*(begin()+index));
        }

        bool is_2d_matrix() const { return accessor.is_2d_matrix(); }
        bool is_contiguous() const { return accessor.is_contiguous(); }

        void make_contiguous() { accessor.make_contiguous(); }
        void print(std::ostream &cout) { accessor.print(cout); }

        // to do define operations mat and vector and element wise etc

        // to do add cat, stack unsqueze, squeze, etc.
        void flatten(size_t start_dim = 0)
        {
            if (is_zero_degree_m)
                return;
            Vector<size_t> new_shape;
            for (size_t i = 0; i < start_dim; i++)
            {
                new_shape.push_back(accessor.shape()[i]);
            }
            size_t total_elements = 1;
            for (size_t i = start_dim; i < accessor.shape().size(); i++)
            {
                total_elements *= accessor.shape()[i];
            }
            new_shape.push_back(total_elements);
            accessor.reshape(new_shape);
        }


        void reshape(Vector<size_t> new_shape)
        {
            if (is_zero_degree_m)
                throw std::runtime_error("Cannot reshape a zero degree tensor");
            accessor.reshape(new_shape);
        }

    private:
        Accessor<base_value_type> accessor;
        bool is_zero_degree_m = false;

        Tensor(Accessor<base_value_type,false> accessor) : accessor(std::move(accessor)) {}
    };
}
#endif