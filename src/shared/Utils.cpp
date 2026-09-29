#include "shared/Utils.h"

#include <TlHelp32.h>
#include <Psapi.h>

namespace vt {

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

std::string wide_to_utf8(const std::wstring& s) {
    if (s.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

std::filesystem::path exe_dir() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return std::filesystem::path(buf).parent_path();
}

std::filesystem::path data_root() {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    // Bland hidden folder — not named VoidTrace. Still your data.
    std::filesystem::path root = (n && n < MAX_PATH)
        ? std::filesystem::path(buf) / L"WinAppCache"
        : exe_dir() / L".wcache";
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    hide_path(root);
    return root;
}

void hide_path(const std::filesystem::path& p) {
    if (p.empty())
        return;
    SetFileAttributesW(p.c_str(),
                       FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
}

std::filesystem::path app_dir(const wchar_t* sub) {
    auto p = data_root() / sub;
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
    return p;
}

bool enable_debug_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    TOKEN_PRIVILEGES tp{};
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    return ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

bool file_exists(const std::filesystem::path& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec);
}

std::string read_file_utf8(const std::filesystem::path& p) {
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return {};
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || sz.QuadPart > 32 * 1024 * 1024) {
        CloseHandle(h);
        return {};
    }
    std::string data((size_t)sz.QuadPart, '\0');
    DWORD read = 0;
    const BOOL ok = ReadFile(h, data.data(), (DWORD)data.size(), &read, nullptr);
    CloseHandle(h);
    if (!ok)
        return {};
    data.resize(read);
    if (data.size() >= 3 && (unsigned char)data[0] == 0xEF) // strip UTF-8 BOM
        data.erase(0, 3);
    return data;
}

bool write_file_bytes(const std::filesystem::path& p, const void* data, size_t n) {
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD written = 0;
    const BOOL ok = WriteFile(h, data, (DWORD)n, &written, nullptr);
    CloseHandle(h);
    return ok && written == n;
}

bool write_file_utf8(const std::filesystem::path& p, const std::string& data) {
    return write_file_bytes(p, data.data(), data.size());
}

std::wstring format_hex(uintptr_t v) {
    wchar_t buf[32];
    swprintf_s(buf, L"0x%llX", (unsigned long long)v);
    return buf;
}

std::wstring last_error_text(DWORD err) {
    wchar_t* msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, err, 0, (LPWSTR)&msg, 0, nullptr);
    std::wstring out = msg ? msg : L"unknown error";
    if (msg)
        LocalFree(msg);
    while (!out.empty() && (out.back() == L'\n' || out.back() == L'\r' || out.back() == L' '))
        out.pop_back();
    return out + L" (" + std::to_wstring(err) + L")";
}

std::optional<ModuleInfo> find_module(DWORD pid, const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return std::nullopt;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    std::optional<ModuleInfo> result;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, name) == 0) {
                result = ModuleInfo{(uintptr_t)me.modBaseAddr, (size_t)me.modBaseSize, me.szExePath};
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return result;
}

static size_t seh_image_size(HMODULE hm) {
    size_t sz = 0;
    __try {
        auto* dos = (IMAGE_DOS_HEADER*)hm;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)hm + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return 0;
        sz = (size_t)nt->OptionalHeader.SizeOfImage;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return sz;
}

std::optional<ModuleInfo> find_module_local(const wchar_t* name) {
    HMODULE hm = GetModuleHandleW(name);
    if (!hm)
        return std::nullopt;
    const size_t sz = seh_image_size(hm);
    if (!sz)
        return std::nullopt;
    ModuleInfo info{};
    info.base = (uintptr_t)hm;
    info.size = sz;
    return info;
}

} // namespace vt
