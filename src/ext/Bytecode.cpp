#include "ext/Bytecode.h"

#include "Luau/Compiler.h"
#include "Luau/BytecodeBuilder.h"
#include "Luau/BytecodeUtils.h"

#include <zstd.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace vt::ext {
namespace {

class Enc : public Luau::BytecodeEncoder {
    void encode(uint32_t* data, size_t count) override {
        for (size_t i = 0; i < count;) {
            auto& op = *reinterpret_cast<uint8_t*>(data + i);
            i += Luau::getOpLength(LuauOpcode(op));
            op = (uint8_t)(op * 227u);
        }
    }
};

uint32_t xxh32(const void* data, size_t len, uint32_t seed) {
    static const uint32_t p1 = 2654435761u, p2 = 2246822519u, p3 = 3266489917u, p4 = 668265263u, p5 = 374761393u;
    auto rotl = [](uint32_t x, int r) { return (x << r) | (x >> (32 - r)); };
    const uint8_t* p = (const uint8_t*)data;
    const uint8_t* b = p + len;
    uint32_t h;
    if (len >= 16) {
        uint32_t v1 = seed + p1 + p2, v2 = seed + p2, v3 = seed, v4 = seed - p1;
        for (; p + 16 <= b; p += 16) {
            uint32_t a, c, d, e;
            memcpy(&a, p, 4); memcpy(&c, p + 4, 4); memcpy(&d, p + 8, 4); memcpy(&e, p + 12, 4);
            v1 = rotl(v1 + a * p2, 13) * p1;
            v2 = rotl(v2 + c * p2, 13) * p1;
            v3 = rotl(v3 + d * p2, 13) * p1;
            v4 = rotl(v4 + e * p2, 13) * p1;
        }
        h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
    } else
        h = seed + p5;
    h += (uint32_t)len;
    for (; p + 4 <= b; p += 4) {
        uint32_t k;
        memcpy(&k, p, 4);
        h = rotl(h + k * p3, 17) * p4;
    }
    for (; p < b; ++p)
        h = rotl(h + *p * p5, 11) * p1;
    h ^= h >> 15; h *= p2; h ^= h >> 13; h *= p3; h ^= h >> 15;
    return h;
}

std::string compress_rsb1(const std::string& bc) {
    const size_t maxs = ZSTD_compressBound(bc.size());
    std::vector<char> buf(maxs + 8);
    buf[0] = 'R'; buf[1] = 'S'; buf[2] = 'B'; buf[3] = '1';
    const uint32_t sz = (uint32_t)bc.size();
    memcpy(&buf[4], &sz, 4);
    const size_t cs = ZSTD_compress(buf.data() + 8, maxs, bc.data(), bc.size(), 22);
    if (ZSTD_isError(cs))
        return {};
    const size_t n = cs + 8;
    buf.resize(n);
    const uint32_t hash = xxh32(buf.data(), n, 42u);
    const uint8_t* hb = (const uint8_t*)&hash;
    for (size_t i = 0; i < n; ++i)
        buf[i] = (char)((uint8_t)buf[i] ^ (uint8_t)((hb[i % 4] + (int)i * 41) & 0xFF));
    return std::string(buf.data(), n);
}

} // namespace

std::pair<bool, std::string> compile_rbx_bytecode(const std::string& source) {
    Enc enc{};
    Luau::CompileOptions opt{};
    opt.optimizationLevel = 1;
    opt.debugLevel = 1;
    std::string bc = Luau::compile(source, opt, {}, &enc);
    if (bc.empty() || bc[0] == '\0') {
        if (!bc.empty())
            bc.erase(std::remove(bc.begin(), bc.end(), '\0'), bc.end());
        return {false, bc.empty() ? "compile failed" : bc};
    }
    std::string packed = compress_rsb1(bc);
    if (packed.empty())
        return {false, "zstd compress failed"};
    return {true, packed};
}

std::pair<bool, std::string> compile_raw_luau_bytecode(const std::string& source) {
    Enc enc{};
    Luau::CompileOptions opt{};
    opt.optimizationLevel = 1;
    opt.debugLevel = 1;
    std::string bc = Luau::compile(source, opt, {}, &enc);
    if (bc.empty() || bc[0] == '\0') {
        if (!bc.empty())
            bc.erase(std::remove(bc.begin(), bc.end(), '\0'), bc.end());
        return {false, bc.empty() ? "compile failed" : bc};
    }
    return {true, std::move(bc)};
}

} // namespace vt::ext
