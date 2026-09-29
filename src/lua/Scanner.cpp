#include "lua/Scanner.h"

#include <Windows.h>
#include <cctype>
#include <cstring>

namespace vt {

namespace {
uintptr_t match_region(const uint8_t* start, size_t span, const uint8_t* pat, const uint8_t* msk, size_t n) {
    uintptr_t hit = 0;
    __try {
        for (size_t i = 0; i <= span; ++i) {
            bool ok = true;
            for (size_t j = 0; j < n; ++j) {
                if (msk[j] && start[i + j] != pat[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                hit = (uintptr_t)(start + i);
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        hit = 0;
    }
    return hit;
}
}

bool PatternScanner::parse(const std::string& ida, std::vector<uint8_t>& bytes, std::vector<bool>& mask) {
    bytes.clear();
    mask.clear();
    for (size_t i = 0; i < ida.size();) {
        while (i < ida.size() && std::isspace((unsigned char)ida[i]))
            ++i;
        if (i >= ida.size())
            break;
        if (ida[i] == '?') {
            bytes.push_back(0);
            mask.push_back(false);
            ++i;
            if (i < ida.size() && ida[i] == '?')
                ++i;
            continue;
        }
        if (i + 1 >= ida.size())
            return false;
        char tmp[3] = {ida[i], ida[i + 1], 0};
        bytes.push_back((uint8_t)std::strtoul(tmp, nullptr, 16));
        mask.push_back(true);
        i += 2;
    }
    return !bytes.empty();
}

uintptr_t PatternScanner::find(uintptr_t base, size_t size, const std::string& ida) {
    if (!base || !size || ida.empty())
        return 0;
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;
    if (!parse(ida, bytes, mask))
        return 0;

    const size_t n = bytes.size();
    if (n > size)
        return 0;
    std::vector<uint8_t> msk(n);
    for (size_t j = 0; j < n; ++j)
        msk[j] = mask[j] ? 1 : 0;

    MEMORY_BASIC_INFORMATION mbi{};
    for (uintptr_t addr = base; addr < base + size; ) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi)))
            break;
        const DWORD prot = mbi.Protect & 0xFF;
        const bool exec = mbi.State == MEM_COMMIT &&
            !(mbi.Protect & PAGE_GUARD) &&
            (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
             prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
        const uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        const uintptr_t from = addr;
        const uintptr_t to = region_end < base + size ? region_end : base + size;
        if (exec && to > from + n) {
            if (auto hit = match_region((const uint8_t*)from, (size_t)(to - from - n),
                                        bytes.data(), msk.data(), n))
                return hit;
        }
        addr = to;
        if (addr <= from)
            break;
    }
    return 0;
}

uintptr_t PatternScanner::find_rip32(uintptr_t base, size_t size, const std::string& ida, int rip_offset) {
    const uintptr_t hit = find(base, size, ida);
    if (!hit)
        return 0;
    const int32_t rel = *(int32_t*)(hit + rip_offset);
    return hit + rip_offset + 4 + rel;
}

} // namespace vt
