#pragma once

#include <cstdint>

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

struct DynarmicCP15 {
    u32 uprw = 0;
    u32 uro = 0;
};
