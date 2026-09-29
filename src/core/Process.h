#pragma once

#include <Windows.h>
#include <string>
#include <optional>
#include <cstdint>

namespace vt {

struct RobloxProcess {
    DWORD     pid   = 0;
    HWND      hwnd  = nullptr;
    uintptr_t base  = 0;
    size_t    size  = 0;
    std::wstring path;
};

class ProcessFinder {
public:
    static std::optional<RobloxProcess> find(const std::wstring& exe_name = L"RobloxPlayerBeta.exe");
    static HANDLE open(DWORD pid, DWORD access = PROCESS_ALL_ACCESS);
    static bool still_alive(DWORD pid);
    static std::wstring window_title(HWND hwnd);
};

} // namespace vt
