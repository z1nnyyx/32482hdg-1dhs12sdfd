#include "core/DriverDrop.h"
#include "shared/Log.h"

#include <Windows.h>
#include <bcrypt.h>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")

namespace vt {
namespace {

// UNICODE_STRING initialiser (no CRT wide-string helpers in kernel-style code).
void init_us(UNICODE_STRING* us, const wchar_t* s) {
    const auto len = (USHORT)(wcslen(s) * sizeof(wchar_t));
    us->Length        = len;
    us->MaximumLength = len;
    us->Buffer        = const_cast<wchar_t*>(s);
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────

void DriverDrop::init_unicode(UNICODE_STRING* us, const wchar_t* buf) { init_us(us, buf); }

DriverDrop::NtLoadDriver_t DriverDrop::get_NtLoadDriver() {
    auto* ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? (NtLoadDriver_t)GetProcAddress(ntdll, "NtLoadDriver") : nullptr;
}

DriverDrop::NtUnloadDriver_t DriverDrop::get_NtUnloadDriver() {
    auto* ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? (NtUnloadDriver_t)GetProcAddress(ntdll, "NtUnloadDriver") : nullptr;
}

bool DriverDrop::enable_load_driver_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid{};
    const bool ok = LookupPrivilegeValueW(nullptr, SE_LOAD_DRIVER_NAME, &luid);
    if (ok) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid       = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
    CloseHandle(token);
    return ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

std::wstring DriverDrop::extract_resource(WORD id, const wchar_t* tmp_dir) {
    HRSRC   hrsrc = FindResourceW(nullptr, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!hrsrc)                         return {};
    HGLOBAL hg    = LoadResource(nullptr, hrsrc);
    if (!hg)                            return {};
    const void* data = LockResource(hg);
    const DWORD size = SizeofResource(nullptr, hrsrc);
    if (!data || !size)                 return {};

    // Generate random file name.
    ULONGLONG rnd = 0;
    BCryptGenRandom(nullptr, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wchar_t path[MAX_PATH]{};
    swprintf_s(path, L"%s%016llX.sys", tmp_dir, rnd);

    HANDLE hf = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return {};
    DWORD written = 0;
    WriteFile(hf, data, size, &written, nullptr);
    CloseHandle(hf);
    if (written != size) { DeleteFileW(path); return {}; }
    return path;
}

bool DriverDrop::create_registry_key(const wchar_t* reg_key, const wchar_t* image_path) {
    // reg_key example: L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MySvc"
    // Convert kernel-style to Win32 style for RegCreateKey.
    // Kernel path starts with \Registry\Machine — Win32 path starts with HKLM.
    const wchar_t* prefix = L"\\Registry\\Machine\\";
    const size_t   plen   = wcslen(prefix);
    if (wcsncmp(reg_key, prefix, plen) != 0) return false;

    const wchar_t* subkey = reg_key + plen;
    HKEY  hk  = nullptr;
    DWORD disp = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, nullptr, 0,
                        KEY_ALL_ACCESS, nullptr, &hk, &disp) != ERROR_SUCCESS)
        return false;

    // ImagePath = NT path (with \??\ prefix for absolute paths).
    wchar_t nt_path[MAX_PATH]{};
    swprintf_s(nt_path, L"\\??\\%s", image_path);
    RegSetValueExW(hk, L"ImagePath", 0, REG_EXPAND_SZ,
                   (const BYTE*)nt_path, (DWORD)((wcslen(nt_path)+1)*sizeof(wchar_t)));

    DWORD svc_type = 1; // SERVICE_KERNEL_DRIVER
    DWORD err_ctrl = 0;
    DWORD svc_start = 3;
    RegSetValueExW(hk, L"Type",         0, REG_DWORD, (const BYTE*)&svc_type,  sizeof(svc_type));
    RegSetValueExW(hk, L"ErrorControl", 0, REG_DWORD, (const BYTE*)&err_ctrl,  sizeof(err_ctrl));
    RegSetValueExW(hk, L"Start",        0, REG_DWORD, (const BYTE*)&svc_start, sizeof(svc_start));
    RegCloseKey(hk);
    return true;
}

void DriverDrop::delete_registry_key(const wchar_t* reg_key) {
    const wchar_t* prefix = L"\\Registry\\Machine\\";
    const size_t   plen   = wcslen(prefix);
    if (wcsncmp(reg_key, prefix, plen) != 0) return;
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, reg_key + plen);
}

bool DriverDrop::load(WORD resource_id, const wchar_t* svc_name, const wchar_t* reg_key) {
    if (!enable_load_driver_privilege()) {
        VT_WARN(L"DriverDrop: SE_LOAD_DRIVER_PRIVILEGE not available");
        return false;
    }

    wchar_t tmp_dir[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp_dir);

    m_path = extract_resource(resource_id, tmp_dir);
    if (m_path.empty()) {
        VT_WARN(L"DriverDrop: resource extraction failed");
        return false;
    }

    if (!create_registry_key(reg_key, m_path.c_str())) {
        VT_WARN(L"DriverDrop: registry key creation failed");
        DeleteFileW(m_path.c_str()); m_path.clear();
        return false;
    }
    m_reg_key = reg_key;

    auto fn_load = get_NtLoadDriver();
    if (!fn_load) {
        VT_WARN(L"DriverDrop: NtLoadDriver not found");
        cleanup(); return false;
    }

    UNICODE_STRING us{};
    init_us(&us, reg_key);
    LONG status = fn_load(&us);
    if (status != 0) {
        wchar_t buf[64];
        swprintf_s(buf, L"DriverDrop: NtLoadDriver failed 0x%08X", (ULONG)status);
        VT_WARN(buf);
        cleanup(); return false;
    }

    VT_LOG(L"DriverDrop: driver loaded from " + m_path);
    m_loaded = true;
    return true;
}

void DriverDrop::cleanup() {
    if (m_loaded) {
        auto fn_unload = get_NtUnloadDriver();
        if (fn_unload && !m_reg_key.empty()) {
            UNICODE_STRING us{};
            init_us(&us, m_reg_key.c_str());
            fn_unload(&us);
        }
        m_loaded = false;
    }
    if (!m_reg_key.empty()) {
        delete_registry_key(m_reg_key.c_str());
        m_reg_key.clear();
    }
    if (!m_path.empty()) {
        // Small delay to ensure the driver is fully unloaded before deletion.
        Sleep(100);
        DeleteFileW(m_path.c_str());
        m_path.clear();
    }
}

} // namespace vt
