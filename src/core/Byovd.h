#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

// BYOVD (Bring Your Own Vulnerable Driver) — universal kernel R/W layer.
//
// Probes a chain of drivers that are commonly pre-installed on gaming PCs.
// Falls back to a resource-dropped driver if none are found.
//
// Backend probe order (each non-fatal if absent):
//   1. RTCore64    — MSI Afterburner / MSI Dragon Center (CVE-2019-16098)
//   2. MsIo64      — MSI Dragon Center / MSI App Player (same IOCTL family)
//   3. gdrv        — GIGABYTE App / Aorus Engine (CVE-2018-19320)
//   4. Dropped     — resource-embedded driver extracted + loaded at runtime
//
// When any backend opens, hide_allocation() walks the target process VAD tree
// and zeroes the StartingVpn/EndingVpn fields on the matched MMVAD_SHORT node,
// making the allocation invisible to Hyperion's kernel VAD scan.
//
// Usage:
//   Byovd::get().init();
//   if (Byovd::get().ready())
//       Byovd::get().hide_allocation(proc, base, size);

namespace vt {

enum class KernelBackend { None, RtCore64, MsIo64, Gdrv, Dropped };

class Byovd {
public:
    static Byovd& get();

    // Probe all backends.  Returns true if any succeed.  Non-fatal — the
    // injection pipeline continues even without kernel access.
    bool init();

    bool ready()                   const { return m_backend != KernelBackend::None; }
    KernelBackend backend()        const { return m_backend; }
    const wchar_t* backend_name()  const;

    // Raw kernel virtual-address read/write (1, 2, 4, or 8 bytes).
    bool kread (uintptr_t addr, void* out,       DWORD size);
    bool kwrite(uintptr_t addr, const void* in,  DWORD size);

    // Typed convenience wrappers.
    uint8_t  read8 (uintptr_t a) { uint8_t  v=0; kread(a,&v,1); return v; }
    uint32_t read32(uintptr_t a) { uint32_t v=0; kread(a,&v,4); return v; }
    uint64_t read64(uintptr_t a) { uint64_t v=0; kread(a,&v,8); return v; }
    void write8 (uintptr_t a, uint8_t  v) { kwrite(a,&v,1); }
    void write32(uintptr_t a, uint32_t v) { kwrite(a,&v,4); }
    void write64(uintptr_t a, uint64_t v) { kwrite(a,&v,8); }

    // Locate EPROCESS for the given process handle via the system handle table.
    uintptr_t eprocess_of(HANDLE process);

    // Walk target EPROCESS VAD tree, find the node covering
    // [alloc_base, alloc_base+alloc_size) and zero its VPN fields.
    bool hide_allocation(HANDLE process, uintptr_t alloc_base, size_t alloc_size);

    void shutdown();

private:
    Byovd() = default;
    ~Byovd() { shutdown(); }

    KernelBackend m_backend = KernelBackend::None;
    HANDLE        m_device  = INVALID_HANDLE_VALUE;

    // ── RTCore64 / MsIo64 backend ─────────────────────────────────────────
    // Both drivers expose the same kernel-VA direct R/W IOCTLs.
    static constexpr DWORD kRt_Read  = 0x80002048;
    static constexpr DWORD kRt_Write = 0x8000204C;

    bool rtcore_try();   // tries RTCore64 then MsIo64 device names
    bool rtcore_read (uintptr_t addr, void* out, DWORD size);
    bool rtcore_write(uintptr_t addr, const void* in, DWORD size);

    // ── gdrv backend (GIGABYTE, CVE-2018-19320) ───────────────────────────
    // Exposes physical memory R/W via MmGetPhysicalAddress + MmMapIoSpace.
    // We translate kernel VAs → physical → map into our process → read/write.
    static constexpr DWORD kGdrv_GetPhys   = 0xC3502804; // MmGetPhysicalAddress wrapper
    static constexpr DWORD kGdrv_MapPhys   = 0xC3502808; // MmMapIoSpace wrapper
    static constexpr DWORD kGdrv_UnmapPhys = 0xC350A808; // MmUnmapIoSpace wrapper

    bool gdrv_try();
    bool gdrv_read (uintptr_t addr, void* out, DWORD size);
    bool gdrv_write(uintptr_t addr, const void* in, DWORD size);
    // Helpers:
    uintptr_t gdrv_get_phys(uintptr_t kernel_va);
    uintptr_t gdrv_map_phys(uintptr_t phys, DWORD size);
    bool      gdrv_unmap_phys(uintptr_t user_va, DWORD size);

    // ── Dropped-driver backend ────────────────────────────────────────────
    // If BYOVD_DRIVER_RESOURCE is defined in the project, the EXE embeds a
    // vulnerable driver as a RCDATA resource.  init() drops it to %TEMP%,
    // loads via NtLoadDriver, then opens its device.  cleanup() in shutdown().
    bool dropped_try();
    std::wstring m_dropped_path;
    std::wstring m_dropped_svc;

    // ── EPROCESS / MMVAD_SHORT offsets ───────────────────────────────────
    // Auto-detected in init() by probing the running Windows build.
    // Fallback values cover 20H2 (19042) through 24H2 (26100).
    DWORD m_off_UniqueProcessId   = 0x440;
    DWORD m_off_VadRoot           = 0x7D8;
    static constexpr DWORD kOff_VadLeft           = 0x000;
    static constexpr DWORD kOff_VadRight          = 0x008;
    static constexpr DWORD kOff_StartingVpn       = 0x020;
    static constexpr DWORD kOff_EndingVpn         = 0x024;
    static constexpr DWORD kOff_StartingVpnHigh   = 0x028;
    static constexpr DWORD kOff_EndingVpnHigh     = 0x029;

    // Detect correct EPROCESS offsets by build number.
    void detect_offsets();
};

} // namespace vt
