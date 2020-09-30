#pragma once

using s8  = signed char;
using s16 = signed short;
using s32 = signed int;
using s64 = signed long;

using u8  = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long;

#define INT8_C(n)  n
#define INT16_C(n) n
#define INT32_C(n) n
#define INT64_C(n) n##l

#define UINT8_C(n)  n
#define UINT16_C(n) n
#define UINT32_C(n) n##u
#define UINT64_C(n) n##ul

using size_t    = u64;
using ptrdiff_t = u64;
using uintptr_t = u64;

using Result = u32;
using Handle = u32;

using TimeSpan = s64;

/// Thread information structure.
struct Thread {
    Handle handle;         ///< Thread handle.
    bool   owns_stack_mem; ///< Whether the stack memory is automatically allocated.
    void*  stack_mem;      ///< Pointer to stack memory.
    void*  stack_mirror;   ///< Pointer to stack memory mirror.
    size_t stack_sz;       ///< Stack size.
    void** tls_array;
    struct Thread* next;
    struct Thread** prev_next;
};

#define NX_INLINE
#define ALWAYS_INLINE
#define NON_COPYABLE(c)
#define NON_MOVEABLE(c)
#define R_ABORT_UNLESS(...)
#define AMS_ASSERT(...)
#define AMS_ABORT_UNLESS(...)
#define static_assert(...)

#define INVALID_HANDLE ((Handle) 0)
#define BITSIZEOF(x) (sizeof(x) * 8)

namespace std {

template <typename T>
T *addressof(T &t) {
    return &t;
}

template <size_t Size, size_t Align>
struct aligned_storage {
    struct type {
        alignas(Align) u8 _data[Size];
    };
};

} // namespace std

namespace nn::util {

template<typename T, size_t Size, size_t Align>
struct TypedStorage {
    typename std::aligned_storage<Size, Align>::type _storage;
};

#define TYPED_STORAGE(...) ::nn::util::TypedStorage<__VA_ARGS__, sizeof(__VA_ARGS__), alignof(__VA_ARGS__)>

} // namespace nn::util

#include <vapours/literals.hpp>
#include <vapours/svc/svc_common.hpp>
#include <vapours/util/util_bitpack.hpp>
#include <vapours/util/util_intrusive_list.hpp>
