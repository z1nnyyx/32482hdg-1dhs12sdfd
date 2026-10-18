#pragma once

#include <Windows.h>
#include <cstdint>

namespace vt {

// CFG-valid `jmp [rax/rcx+disp]` found in system CF tables (ntdll, combase,
// ole32, …) or the target's own CF table (scanned from the host via RPM).
// Host scans; the mapped module uses the VA as-is.
struct CfgGadget {
    uintptr_t va = 0;
    int       disp = 0;
    bool      via_rax = true;
    bool      reload_rcx = false; // mov rax,[rcx] then jmp [rax+disp]
    bool ok() const { return va && disp >= 0; }
};

CfgGadget scan_cfg_gadget();
CfgGadget scan_cfg_gadget_remote(HANDLE process, DWORD pid);

} // namespace vt
