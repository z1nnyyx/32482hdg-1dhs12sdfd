#pragma once

#include <Windows.h>
#include <string>
#include <filesystem>

namespace vt {

enum class InjectMethod {
    LoadLibrary, // CreateRemoteThread + LoadLibraryW. Easiest. Hyperion flags this.
    ManualMap,   // Map PE yourself. Harder to fingerprint, still not "undetected".
};

struct InjectResult {
    bool        ok = false;
    std::wstring error;
    uintptr_t   module_base = 0;
    uintptr_t   iat_slot = 0;
    uintptr_t   iat_stub = 0;
    uintptr_t   iat_orig = 0;
    bool        wait_hooked = false;
};

class Injector {
public:
    static InjectResult inject(HANDLE process,
                               const std::filesystem::path& dll,
                               InjectMethod method = InjectMethod::LoadLibrary);

    // Uses the module packed inside the exe (no extra DLL file required).
    static InjectResult inject_embedded(HANDLE process, InjectMethod method);

    static bool already_present(DWORD pid, const wchar_t* module_name = L"VoidTrace.dll");

private:
    static InjectResult load_library(HANDLE process, const std::filesystem::path& dll);
};

} // namespace vt
