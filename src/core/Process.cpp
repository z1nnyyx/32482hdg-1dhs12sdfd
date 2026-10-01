#include "core/Process.h"
#include "shared/Config.h"
#include "shared/Utils.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <cwctype>

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

namespace {
// Lower-case ASCII copy of a wide string, for substring matching on paths.
std::wstring to_lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](wchar_t c) { return (wchar_t)std::towlower(c); });
    return s;
}

// A UWP (Microsoft Store) Roblox install lives under
// %LOCALAPPDATA%\Packages\ROBLOXCORPORATION.ROBLOX_<publisher-id>\...
// The legacy install lives under %LOCALAPPDATA%\Roblox\Versions\... .
// Both run binaries named RobloxPlayerBeta.exe, so the only reliable way to
// tell them apart is the full image path.
bool is_uwp_path(const std::wstring& path_lower) {
    return path_lower.find(L"\\packages\\roblox") != std::wstring::npos ||
           path_lower.find(L"windowsapps") != std::wstring::npos;
}
} // namespace

std::optional<RobloxProcess> ProcessFinder::find(const std::wstring& exe_name) {
    const auto& cfg = Config::instance().get();
    const bool want_studio = cfg.studio_mode;
    const bool want_uwp    = cfg.uwp_mode && !want_studio;
    // In Studio mode, override exe lookup to RobloxStudioBeta.exe.
    const std::wstring target = want_studio ? L"RobloxStudioBeta.exe" : exe_name;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return std::nullopt;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::optional<RobloxProcess> found;      // best legacy candidate
    std::optional<RobloxProcess> found_uwp;  // best UWP candidate
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, target.c_str()) != 0)
                continue;
            RobloxProcess rp;
            rp.pid = pe.th32ProcessID;
            bool uwp = false;
            if (auto mod = find_module(rp.pid, target.c_str())) {
                rp.base = mod->base;
                rp.size = mod->size;
                rp.path = mod->path;
                const auto lp = to_lower(rp.path);
                // In Player modes, reject any process whose image path says
                // Studio (defensive — Studio's exe name differs, but belt+braces).
                if (!want_studio && lp.find(L"robloxstudio") != std::wstring::npos)
                    continue;
                uwp = is_uwp_path(lp);
            }
            EnumCtx ctx{rp.pid, nullptr, 0};
            EnumWindows(enum_windows_cb, (LPARAM)&ctx);
            rp.hwnd = ctx.hwnd;
            auto& slot = uwp ? found_uwp : found;
            if (!slot || (rp.hwnd && !slot->hwnd) || ctx.area > 0)
                slot = rp;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (want_studio)
        return found;                                   // only legacy-path bucket is populated for Studio
    if (want_uwp)
        return found_uwp ? found_uwp : found;           // prefer Store, fall back to legacy
    return found ? found : found_uwp;                   // prefer legacy, fall back to Store
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
