#pragma once

#include <Windows.h>
#include <filesystem>
#include <cstdint>
#include <string>

namespace vt {

// Maps a PE image into a remote process without LoadLibrary.
// Resolves imports from the target's already-loaded modules, applies relocs,
// fires TLS callbacks, then DllMain(DLL_PROCESS_ATTACH).
//
// Quiet usermode map: no LoadLibrary name, no RWX, headers wiped after
// entry, thread start spoofed through ntdll. Still a private image. Not magic.
class ManualMapper {
public:
    struct Result {
        bool        ok = false;
        uintptr_t   base = 0;
        uintptr_t   iat_slot = 0;
        uintptr_t   iat_stub = 0;
        uintptr_t   iat_orig = 0;
        bool        wait_hooked = false;
        std::wstring error;
    };

    static Result map(HANDLE process, const std::filesystem::path& dll);
    static Result map_buffer(HANDLE process, const uint8_t* pe, size_t pe_size);
};

} // namespace vt
