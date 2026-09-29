#pragma once

#include <filesystem>
#include <vector>
#include <cstdint>

namespace vt {

// Module is compiled into the exe as RCDATA. Nothing else to ship.
class Payload {
public:
    static std::vector<uint8_t> module_bytes();
    static void seed(); // hidden data folder + default scripts/config (no visible DLL)
    static std::filesystem::path unpack_hidden_module(); // LoadLibrary only
};

} // namespace vt
