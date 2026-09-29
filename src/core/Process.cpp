#include "core/Process.h"
#include "shared/Utils.h"

#include <TlHelp32.h>
#include <Psapi.h>

namespace vt {
namespace {

struct EnumCtx {
    DWORD pid = 0;
    HWND  hwnd = nullptr;
    long  area = 0;
};

BOOL CALLBACK enum_windows_cb(HWND hwnd, LPARAM lp) {
    auto* ctx = reinterpret_cast<EnumCtx*>(lp);
    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != ctx->pid)
        return TRUE;
    if (!IsWindowVisible(hwnd) || !IsWindowEnabled(hwnd))
        return TRUE;
    if (GetWindow(hwnd, GW_OWNER))
        return TRUE;
    RECT rc{};
    if (!GetClientRect(hwnd, &rc))
        return TRUE;
    const long area = (long)(rc.right - rc.left) * (long)(rc.bottom - rc.top);
    if (area < 200 * 150)
        return TRUE;
    if (area > ctx->area) {
        ctx->area = area;
        ctx->hwnd = hwnd;
    }
    return TRUE;
}

} // namespace

std::optional<RobloxProcess> ProcessFinder::find(const std::wstring& exe_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return std::nullopt;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::optional<RobloxProcess> found;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe_name.c_str()) != 0)
                continue;
            if (_wcsicmp(pe.szExeFile, L"RobloxStudioBeta.exe") == 0)
                continue;
            RobloxProcess rp;
            rp.pid = pe.th32ProcessID;
            if (auto mod = find_module(rp.pid, exe_name.c_str())) {
                rp.base = mod->base;
                rp.size = mod->size;
                rp.path = mod->path;
                if (rp.path.find(L"RobloxStudio") != std::wstring::npos)
                    continue;
            }
            EnumCtx ctx{rp.pid, nullptr, 0};
            EnumWindows(enum_windows_cb, (LPARAM)&ctx);
            rp.hwnd = ctx.hwnd;
            if (!found || (rp.hwnd && !found->hwnd) || ctx.area > 0)
                found = rp;
            if (rp.hwnd)
                break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

HANDLE ProcessFinder::open(DWORD pid, DWORD access) {
    return OpenProcess(access, FALSE, pid);
}

bool ProcessFinder::still_alive(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return false;
    DWORD code = 0;
    const bool ok = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return ok;
}

std::wstring ProcessFinder::window_title(HWND hwnd) {
    if (!hwnd)
        return {};
    wchar_t title[256]{};
    GetWindowTextW(hwnd, title, 256);
    return title;
}

} // namespace vt
