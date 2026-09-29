#pragma once

#include <string>
#include <utility>

namespace vt::ext {

// Roblox corescript format used by Xeno/kseno: Luau compile (opcode*227),
// RSB1 + size + zstd, then XXH32 stream XOR.
std::pair<bool, std::string> compile_rbx_bytecode(const std::string& source);

// Raw Luau bytecode (opcode*227) for direct luau_load calls — no RSB1 layer.
std::pair<bool, std::string> compile_raw_luau_bytecode(const std::string& source);

} // namespace vt::ext
