#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vt {

// IDA-style pattern: "48 8B 05 ?? ?? ?? ?? 48 85 C0"
// ?? / ? = wildcard.
class PatternScanner {
public:
    static uintptr_t find(uintptr_t base, size_t size, const std::string& ida);
    static uintptr_t find_rip32(uintptr_t base, size_t size, const std::string& ida, int rip_offset = 3);

private:
    static bool parse(const std::string& ida, std::vector<uint8_t>& bytes, std::vector<bool>& mask);
};

} // namespace vt
