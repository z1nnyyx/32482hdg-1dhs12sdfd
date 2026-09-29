#include "shared/PipeKey.h"
#include "shared/Obfuscate.h"
#include "shared/Log.h"

#include <Windows.h>
#include <bcrypt.h>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace vt {
namespace {
std::wstring g_cached;
}

// Section name: obfuscated at runtime, never a plaintext literal.
// Looks like a mundane Win32 compatibility object to any observer.
std::wstring PipeKey::section_name() {
    return WOBF(L"Local\\AppCompatDataStore_7f2e");
}

// Generate a random pipe path: \\.\pipe\DevSKU_<8 random hex chars>
// "DevSKU" mimics internal Windows developer/SKU service pipes.
std::wstring PipeKey::generate_name() {
    uint32_t rnd = 0;
    if (BCryptGenRandom(nullptr, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        // Fallback: mix of timing and PID
        rnd = (uint32_t)(GetTickCount() ^ (GetCurrentProcessId() * 0x9E3779B9u));
    }

    // Pipe prefix — obfuscated, never plaintext "DevSKU"
    std::wstring prefix = WOBF(L"\\\\.\\pipe\\DevSKU_");
    wchar_t hex[9]{};
    swprintf_s(hex, L"%08X", rnd);
    return prefix + hex;
}

std::wstring PipeKey::create() {
    const auto name = generate_name();
    const auto sec  = section_name();

    const size_t bytes = kBufLen * sizeof(wchar_t);
    HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                                  PAGE_READWRITE, 0, (DWORD)bytes, sec.c_str());
    if (!h || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (h) CloseHandle(h);
        VT_WARN(L"PipeKey::create — section already exists, reusing");
        // Read whatever is already there so EXE and DLL stay in sync.
        h = OpenFileMappingW(FILE_MAP_READ, FALSE, sec.c_str());
        if (!h) return name; // can't share; fall back to the generated name
        auto* view = (const wchar_t*)MapViewOfFile(h, FILE_MAP_READ, 0, 0, bytes);
        std::wstring existing;
        if (view) {
            existing = view;
            UnmapViewOfFile(view);
        }
        CloseHandle(h);
        g_cached = existing.empty() ? name : existing;
        return g_cached;
    }

    auto* view = (wchar_t*)MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, bytes);
    if (!view) {
        CloseHandle(h);
        VT_ERR(L"PipeKey::create — MapViewOfFile failed");
        return name;
    }

    std::memset(view, 0, bytes);
    wcsncpy_s(view, kBufLen, name.c_str(), kBufLen - 1);
    FlushViewOfFile(view, bytes);
    UnmapViewOfFile(view);
    // Keep the handle open for the lifetime of the EXE so the section persists.
    // Intentionally leaked — the kernel cleans it up on process exit.
    g_cached = name;
    VT_LOG(L"PipeKey::create — " + name);
    return name;
}

std::wstring PipeKey::cached() {
    return g_cached;
}

std::wstring PipeKey::open(int timeout_ms) {
    const auto sec   = section_name();
    const size_t bytes = kBufLen * sizeof(wchar_t);
    const DWORD  start = GetTickCount();

    while (true) {
        HANDLE h = OpenFileMappingW(FILE_MAP_READ, FALSE, sec.c_str());
        if (h) {
            auto* view = (const wchar_t*)MapViewOfFile(h, FILE_MAP_READ, 0, 0, bytes);
            std::wstring result;
            if (view && view[0] != L'\0') {
                result = view;
                UnmapViewOfFile(view);
                CloseHandle(h);
                VT_LOG(L"PipeKey::open — " + result);
                return result;
            }
            if (view) UnmapViewOfFile(view);
            CloseHandle(h);
        }

        if ((int)(GetTickCount() - start) >= timeout_ms)
            break;
        Sleep(50);
    }

    VT_ERR(L"PipeKey::open — timed out waiting for pipe key section");
    return {};
}

} // namespace vt
