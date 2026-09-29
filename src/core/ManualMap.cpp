#include "core/ManualMap.h"
#include "shared/CfgProxy.h"
#include "core/Syscall.h"
#include "core/ThreadHijack.h"
#include "core/Byovd.h"
#include "shared/Utils.h"
#include "shared/Obfuscate.h"
#include "shared/Log.h"
#include "shared/PipeKey.h"
#include "shared/Config.h"
#include "shared/OffBlob.h"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <algorithm>
#include <vector>
#include <fstream>
#include <cstring>

namespace vt {
namespace {

using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
using NtFlushInstructionCache_t = NTSTATUS(NTAPI*)(HANDLE, PVOID, SIZE_T);

// Ghost-section injection: NtCreateSection (pagefile-backed) + NtMapViewOfSection.
// SEC_COMMIT | SEC_RESERVE with no file object → backed by pagefile.
// The resulting VAD entry appears as a mapped section (not a private VadNone),
// which is less suspicious to Hyperion's heuristic scanner.
using NtCreateSection_t = NTSTATUS(NTAPI*)(
    PHANDLE,         // SectionHandle
    ACCESS_MASK,     // DesiredAccess
    PVOID,           // ObjectAttributes (null for pagefile)
    PLARGE_INTEGER,  // MaximumSize
    ULONG,           // SectionPageProtection (PAGE_*)
    ULONG,           // AllocationAttributes (SEC_COMMIT)
    HANDLE           // FileHandle (null for pagefile)
);
using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(
    HANDLE,          // SectionHandle
    HANDLE,          // ProcessHandle
    PVOID*,          // BaseAddress (in/out)
    ULONG_PTR,       // ZeroBits
    SIZE_T,          // CommitSize
    PLARGE_INTEGER,  // SectionOffset (null = start)
    PSIZE_T,         // ViewSize (in/out)
    ULONG,           // InheritDisposition  1=ViewShare 2=ViewUnmap
    ULONG,           // AllocationType
    ULONG            // Win32Protect (PAGE_*)
);
using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);

constexpr ULONG kHideFromDebugger = 0x4;

// Resolved once and cached so repeated maps don't repeat plaintext lookups.
static HMODULE s_ntdll = nullptr;
static NtCreateThreadEx_t    s_NtCreateThreadEx = nullptr;
static NtFlushInstructionCache_t s_NtFlush      = nullptr;
static NtCreateSection_t     s_NtCreateSection  = nullptr;
static NtMapViewOfSection_t  s_NtMapView        = nullptr;
static NtUnmapViewOfSection_t s_NtUnmapView     = nullptr;

static void resolve_ntdll() {
    if (s_ntdll)
        return;
    s_ntdll = GetModuleHandleW(WOBF(L"ntdll.dll").c_str());
    if (!s_ntdll)
        return;
    s_NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(s_ntdll, OBF("NtCreateThreadEx").c_str());
    s_NtFlush          = (NtFlushInstructionCache_t)GetProcAddress(s_ntdll, OBF("NtFlushInstructionCache").c_str());
    // Ghost-section functions: direct ntdll calls (no CallSpoof).
    // The CallSpoof double-ret scheme advances RSP by +8 per call; three calls
    // here would leave RSP off by +24 inside map_buffer, corrupting the frame.
    // NtCreateSection/NtMapViewOfSection are low-risk ops that don't need
    // call-stack spoofing — the VAD appearance alone provides the stealth benefit.
    s_NtCreateSection  = (NtCreateSection_t)GetProcAddress(s_ntdll, OBF("NtCreateSection").c_str());
    s_NtMapView        = (NtMapViewOfSection_t)GetProcAddress(s_ntdll, OBF("NtMapViewOfSection").c_str());
    s_NtUnmapView      = (NtUnmapViewOfSection_t)GetProcAddress(s_ntdll, OBF("NtUnmapViewOfSection").c_str());
}

bool read_all(const std::filesystem::path& p, std::vector<uint8_t>& out) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return false;
    f.seekg(0, std::ios::end);
    const auto n = (size_t)f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize(n);
    return (bool)f.read((char*)out.data(), n);
}

PIMAGE_NT_HEADERS64 nt_hdr(uint8_t* base) {
    auto* dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    auto* nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;
    return nt;
}

uintptr_t rva_to_file(uint8_t* raw, PIMAGE_NT_HEADERS64 nt, DWORD rva) {
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (rva >= sec->VirtualAddress && rva < sec->VirtualAddress + sec->Misc.VirtualSize)
            return (uintptr_t)(raw + sec->PointerToRawData + (rva - sec->VirtualAddress));
    }
    return 0;
}

DWORD export_rva(uint8_t* raw, PIMAGE_NT_HEADERS64 nt, const char* name) {
    const auto& exp = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp.VirtualAddress || !exp.Size)
        return 0;
    auto* dir = (PIMAGE_EXPORT_DIRECTORY)rva_to_file(raw, nt, exp.VirtualAddress);
    if (!dir)
        return 0;
    auto* names = (DWORD*)rva_to_file(raw, nt, dir->AddressOfNames);
    auto* ords  = (WORD*)rva_to_file(raw, nt, dir->AddressOfNameOrdinals);
    auto* funcs = (DWORD*)rva_to_file(raw, nt, dir->AddressOfFunctions);
    if (!names || !ords || !funcs)
        return 0;
    for (DWORD i = 0; i < dir->NumberOfNames; ++i) {
        const char* n = (const char*)rva_to_file(raw, nt, names[i]);
        if (n && strcmp(n, name) == 0)
            return funcs[ords[i]];
    }
    return 0;
}

void cfg_mark(HANDLE process, void* page) {
#ifndef CFG_CALL_TARGET_VALID_XFG
#define CFG_CALL_TARGET_VALID_XFG 0x00000008ull
#endif
    auto& sc = Syscalls::get();
    if (sc.SetInformationVirtualMemory) {
        struct Range { void* va; SIZE_T n; } range{ page, 0x1000 };
        const ULONG_PTR flags[] = {
            CFG_CALL_TARGET_VALID,
            CFG_CALL_TARGET_VALID | CFG_CALL_TARGET_VALID_XFG,
        };
        for (ULONG_PTR fl : flags) {
            CFG_CALL_TARGET_INFO tgt{};
            tgt.Offset = 0;
            tgt.Flags = fl;
            ULONG processed = 0;
            struct Info {
                ULONG  n;
                ULONG  reserved;
                ULONG* processed;
                CFG_CALL_TARGET_INFO* targets;
                void*  section;
                ULONGLONG file_off;
            } inf{ 1, 0, &processed, &tgt, nullptr, 0 };
            const NTSTATUS st = sc.SetInformationVirtualMemory(
                process, 2 /*VmCfgCallTargetInformation*/, 1, &range, &inf, sizeof(inf));
            if (st >= 0) {
                VT_LOG(L"IAT: CFG marked via NtSIVM flags=" +
                       std::to_wstring((unsigned long long)fl));
                return;
            }
            VT_WARN(L"IAT: NtSIVM ns=" + std::to_wstring((unsigned)st));
        }
    }
    using SPVCT_t = BOOL(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);
    static SPVCT_t pfn = nullptr;
    if (!pfn) {
        auto kb = GetModuleHandleW(L"KernelBase.dll");
        if (kb)
            pfn = (SPVCT_t)GetProcAddress(kb, "SetProcessValidCallTargets");
    }
    if (!pfn)
        return;
    CFG_CALL_TARGET_INFO info{};
    info.Offset = 0;
    info.Flags  = CFG_CALL_TARGET_VALID;
    if (pfn(process, page, 0x1000, 1, &info))
        VT_LOG(L"IAT: CFG marked hook page (kernelbase)");
    else
        VT_WARN(L"IAT: SetProcessValidCallTargets err=" + std::to_wstring(GetLastError()));
}

bool remote_write(HANDLE p, uintptr_t dest, const void* src, size_t n) {
    SIZE_T written = 0;
    return SC_WriteProcessMemory(p, (void*)dest, src, n, &written) && written == n;
}

uintptr_t ntdll_jmp_rcx() {
    resolve_ntdll();
    HMODULE ntdll = s_ntdll;
    if (!ntdll)
        return 0;
    auto* base = (uint8_t*)ntdll;
    auto* dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    auto* nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        const size_t n = sec->Misc.VirtualSize;
        const uint8_t* p = base + sec->VirtualAddress;
        for (size_t j = 0; j + 1 < n; ++j) {
            if (p[j] == 0xFF && p[j + 1] == 0xE1)
                return (uintptr_t)(p + j);
        }
    }
    return 0;
}

// IAT hook injection: overwrite a frequently-called import pointer so an
// EXISTING Roblox thread executes our stub.  No new thread is created, so
// Hyperion's PsSetCreateThreadNotifyRoutine never fires.
// The stub one-shots DllMain, then on every later PeekMessage calls VT_TICK
// and tail-jumps the real import.  Do not restore the IAT and do not point
// the slot at VT_TICK (wrong prototype — that froze the message pump).
static bool try_iat_hook(HANDLE process, uintptr_t image_base, uintptr_t entry,
                          uintptr_t tick, const std::vector<uintptr_t>& tls_cbs,
                          uintptr_t* out_slot, uintptr_t* out_stub, uintptr_t* out_orig) {
    const DWORD pid = GetProcessId(process);

    // Enumerate ALL modules loaded in Roblox — the EXE usually imports only from
    // RobloxPlayerBeta.dll; system IAT slots (ntdll, kernel32, etc.) live inside
    // RobloxPlayerBeta.dll's import table, not the EXE's.
    struct ModInfo { uintptr_t base; wchar_t name[64]; };
    std::vector<ModInfo> mods;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{sizeof(me)};
            if (Module32FirstW(snap, &me)) {
                do {
                    ModInfo mi{};
                    mi.base = (uintptr_t)me.modBaseAddr;
                    wcsncpy_s(mi.name, me.szModule, 63);
                    mods.push_back(mi);
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }
    }
    if (mods.empty()) { VT_WARN(L"IAT: cannot enumerate Roblox modules"); return false; }

    const uintptr_t rbx_base = mods[0].base;
    VT_LOG(L"IAT: Roblox base=0x" + [&]{wchar_t b[20];swprintf_s(b,L"%llX",(ULONGLONG)rbx_base);return std::wstring(b);}() +
           L" (" + std::to_wstring(mods.size()) + L" modules)");
    for (int i = 0; i < (int)mods.size() && i < 8; ++i)
        VT_LOG(L"IAT mod[" + std::to_wstring(i) + L"]: " + mods[i].name);

    // Target functions, ordered by call frequency.
    // KERNELBASE.dll imports ntdll with Nt-prefixed names — those entries are the
    // real IAT slots that fire on every WaitForSingleObject / QueryPerformanceCounter
    // call.  KERNEL32.DLL's WaitForSingleObject is just a forwarder to kernelbase
    // and never calls through kernel32's own IAT, so hooking kernel32's IAT slot
    // for NtWaitForSingleObject yields zero hits.
    // Ordered by priority: lowest index = picked first by the priority-aware scan.
    // Rules: non-inlinable before inlinable; heap/sync before wait; wait before misc.
    // GetCurrentThreadId and GetLastError are typically compiled inline by MSVC
    // (TEB reads) — they appear last so they're only used if nothing better is found.
    static const char* const targets[] = {
        // TIER 0 — Message / input loop. Fires every frame even if CRT heap is unused.
        "NtUserPeekMessage", "NtUserGetMessage", "NtUserDispatchMessage",
        "NtUserWaitMessage", "PeekMessageW", "GetMessageW", "DispatchMessageW",
        "GetCursorPos", "NtUserGetCursorPos", "NtUserGetAsyncKeyState", "GetAsyncKeyState",
        // TIER 1 — Heap allocators: called on every malloc/free, never inlined.
        "HeapAlloc", "HeapFree", "HeapReAlloc",
        "RtlAllocateHeap", "RtlFreeHeap", "RtlReAllocateHeap",
        // TIER 2 — Critical section ops: non-inlinable, called by any MT code.
        "EnterCriticalSection", "LeaveCriticalSection", "TryEnterCriticalSection",
        "RtlEnterCriticalSection", "RtlLeaveCriticalSection", "RtlTryEnterCriticalSection",
        // TIER 3 — Performance counter: called every frame via KERNELBASE's IAT.
        "NtQueryPerformanceCounter", "RtlQueryPerformanceCounter",
        "QueryPerformanceCounter", "QueryPerformanceFrequency",
        // TIER 4 — Wait/sleep: called by engine scheduling.
        "NtDelayExecution", "NtWaitForSingleObject", "NtWaitForMultipleObjects",
        "NtWaitForAlertByThreadId", "NtSignalAndWaitForSingleObject",
        "Sleep", "SleepEx",
        "WaitForSingleObject", "WaitForSingleObjectEx",
        "WaitForMultipleObjects", "WaitForMultipleObjectsEx",
        // TIER 5 — Event/handle/memory.
        "CloseHandle", "SetEvent", "ResetEvent",
        "VirtualAlloc", "VirtualFree", "VirtualProtect",
        // TIER 6 — Timing (misc).
        "GetTickCount64", "GetSystemTimeAsFileTime", "NtQuerySystemTime",
        // TIER 7 — Often inlined; last resort.
        "GetCurrentThreadId", "GetCurrentProcessId",
        "GetLastError", "RtlGetVersion",
        // TIER 8 — Exception unwinding.
        "RtlInitializeCriticalSection",
        "RtlPcToFileHeader", "RtlLookupFunctionEntry", "RtlUnwindEx",
        nullptr
    };

    // Build local address table once — used by the address-based fallback scan.
    std::vector<std::pair<uintptr_t, const char*>> local_addrs;
    {
        static const wchar_t* const src_dlls[] = {
            L"ntdll.dll", L"kernel32.dll", L"KernelBase.dll",
            L"user32.dll", L"win32u.dll", L"dxgi.dll", L"d3d11.dll",
            L"kernelbase.dll", L"NTDLL.DLL",
            nullptr
        };
        for (int d = 0; src_dlls[d]; ++d) {
            HMODULE hm = GetModuleHandleW(src_dlls[d]);
            if (!hm) continue;
            for (int t = 0; targets[t]; ++t) {
                void* p = GetProcAddress(hm, targets[t]);
                if (p) local_addrs.push_back({(uintptr_t)p, targets[t]});
            }
        }
    }

    // Scan one module's import table.
    // Collects ALL matching IAT slots, then returns the one with the LOWEST
    // index in targets[] (highest priority) so we never accidentally pick an
    // inlinable function (GetLastError, GetCurrentThreadId) when a real heap
    // or sync import is available in the same module.
    auto scan_module = [&](const ModInfo& mi) -> std::pair<uintptr_t, uintptr_t> {
        const uintptr_t mbase = mi.base;

        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        ReadProcessMemory(process, (void*)mbase, &dos, sizeof(dos), nullptr);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) return {0, 0};
        ReadProcessMemory(process, (void*)(mbase + dos.e_lfanew), &nt, sizeof(nt), nullptr);
        if (nt.Signature != IMAGE_NT_SIGNATURE) return {0, 0};

        const auto& imp = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!imp.VirtualAddress || !imp.Size) return {0, 0};

        struct Cand { int prio; uintptr_t slot, orig; };
        std::vector<Cand> cands;

        // ── Name-based scan (requires OriginalFirstThunk / INT present) ──────
        for (size_t off = 0; off < imp.Size; off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IMAGE_IMPORT_DESCRIPTOR desc{};
            if (!ReadProcessMemory(process, (void*)(mbase + imp.VirtualAddress + off),
                                   &desc, sizeof(desc), nullptr)) break;
            if (!desc.Name) break;
            if (!desc.OriginalFirstThunk) continue;

            const uintptr_t iat_base = mbase + desc.FirstThunk;
            const uintptr_t int_base = mbase + desc.OriginalFirstThunk;

            for (int i = 0; i < 16384; ++i) {
                ULONGLONG ord = 0;
                if (!ReadProcessMemory(process, (void*)(int_base + i*8), &ord, 8, nullptr) || !ord) break;
                if (IMAGE_SNAP_BY_ORDINAL64(ord)) continue;

                char fn[128]{};
                ReadProcessMemory(process, (void*)(mbase + (ord & ~IMAGE_ORDINAL_FLAG64) + 2), fn, 127, nullptr);
                fn[127] = '\0';

                for (int t = 0; targets[t]; ++t) {
                    if (strcmp(fn, targets[t]) != 0) continue;
                    ULONGLONG cur = 0;
                    if (!ReadProcessMemory(process, (void*)(iat_base + i*8), &cur, 8, nullptr) || !cur) break;
                    cands.push_back({t, iat_base + (uintptr_t)i*8, (uintptr_t)cur});
                    break;
                }
            }
        }

        // ── Address-based scan (fallback when INT absent or zeroed) ──────────
        if (cands.empty()) {
            for (size_t off = 0; off < imp.Size; off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
                IMAGE_IMPORT_DESCRIPTOR desc{};
                if (!ReadProcessMemory(process, (void*)(mbase + imp.VirtualAddress + off),
                                       &desc, sizeof(desc), nullptr)) break;
                if (!desc.FirstThunk) break;

                const uintptr_t iat_base = mbase + desc.FirstThunk;
                for (int i = 0; i < 32768; ++i) {
                    ULONGLONG cur = 0;
                    if (!ReadProcessMemory(process, (void*)(iat_base + i*8), &cur, 8, nullptr) || !cur) break;
                    for (auto& [addr, name] : local_addrs) {
                        if (cur != addr) continue;
                        // Find priority index for this name
                        int prio = 9999;
                        for (int t = 0; targets[t]; ++t)
                            if (strcmp(targets[t], name) == 0) { prio = t; break; }
                        cands.push_back({prio, iat_base + (uintptr_t)i*8, (uintptr_t)cur});
                        break;
                    }
                }
            }
        }

        if (cands.empty()) return {0, 0};

        // Pick the candidate with the lowest priority index (best tier).
        Cand best = cands[0];
        for (auto& c : cands)
            if (c.prio < best.prio) best = c;

        VT_LOG(L"IAT[prio=" + std::to_wstring(best.prio) +
               L" '" + std::wstring(targets[best.prio < 9999 ? best.prio : 0],
                                    targets[best.prio < 9999 ? best.prio : 0] +
                                    strlen(targets[best.prio < 9999 ? best.prio : 0])) +
               L"']: in " + mi.name +
               L" slot=0x" + [&]{wchar_t b[20];swprintf_s(b,L"%llX",(ULONGLONG)best.slot);return std::wstring(b);}() +
               L" orig=0x" + [&]{wchar_t b[20];swprintf_s(b,L"%llX",(ULONGLONG)best.orig);return std::wstring(b);}());

        return {best.slot, best.orig};
    };

    uintptr_t iat_slot = 0, original_fn = 0;

    auto name_is = [](const wchar_t* a, const wchar_t* b) {
        return _wcsicmp(a, b) == 0;
    };
    auto is_shim_dll = [&](const wchar_t* name) -> bool {
        // Compatibility shims (apphelp, Ac*) sit in the module list but their
        // heap IAT is never called — last run hooked apphelp!RtlAllocateHeap
        // and DllMain never ran.
        static const wchar_t* const skip[] = {
            L"apphelp.dll", L"AcLayers.dll", L"AcGenral.dll", L"AcSpecfc.dll",
            L"AcWinRT.dll", L"sxs.dll", L"mscoree.dll", L"mscoreei.dll",
            L"clr.dll", L"clrjit.dll", L"mscoreei.dll", L"version.dll",
            L"kernel.appcore.dll", L"sechost.dll", L"bcrypt.dll",
            L"bcryptprimitives.dll", L"cryptbase.dll", L"cryptsp.dll",
            L"sspicli.dll", L"msasn1.dll", nullptr
        };
        for (int i = 0; skip[i]; ++i)
            if (name_is(name, skip[i])) return true;
        if (wcsstr(name, L"api-ms-") || wcsstr(name, L"API-MS-"))
            return true;
        return false;
    };
    auto is_hyperion_locked = [&](const wchar_t* n) -> bool {
        static const wchar_t* const k[] = {
            L"RobloxPlayerBeta.exe", L"RobloxPlayerBeta.dll",
            L"KERNELBASE.dll", L"kernelbase.dll", nullptr
        };
        for (int i = 0; k[i]; ++i)
            if (name_is(n, k[i])) return true;
        return false;
    };
    auto try_mod = [&](const ModInfo& mi) -> bool {
        if (mi.base == rbx_base || is_shim_dll(mi.name) || is_hyperion_locked(mi.name))
            return false;
        auto [s, o] = scan_module(mi);
        if (!s || !o)
            return false;
        DWORD pp = 0;
        if (!VirtualProtectEx(process, (void*)s, 8, PAGE_READWRITE, &pp))
            return false;
        VirtualProtectEx(process, (void*)s, 8, pp, &pp);
        iat_slot = s;
        original_fn = o;
        VT_LOG(L"IAT: writable slot in " + std::wstring(mi.name));
        return true;
    };
    auto find_named = [&](const wchar_t* want) -> const ModInfo* {
        for (auto& mi : mods)
            if (name_is(mi.name, want))
                return &mi;
        return nullptr;
    };

    // USER32 PeekMessage / GetCursorPos is the path that actually fires.
    // Game-DLL IAT is Hyperion-locked (err=87). Shims look writable and never run.
    static const wchar_t* const prefer[] = {
        L"USER32.dll", L"user32.dll",
        L"win32u.dll", L"WIN32U.dll",
        L"dxgi.dll", L"DXGI.dll",
        L"d3d11.dll", L"D3D11.dll",
        L"ucrtbase.dll", L"UCRTBASE.DLL",
        L"msvcrt.dll", L"MSVCRT.DLL",
        L"imm32.dll", L"IMM32.dll",
        L"gdi32.dll", L"GDI32.dll",
        nullptr
    };
    for (int i = 0; prefer[i] && !iat_slot; ++i) {
        if (auto* mi = find_named(prefer[i])) {
            VT_LOG(L"IAT: scanning " + std::wstring(mi->name));
            try_mod(*mi);
        }
    }
    if (!iat_slot) {
        if (auto* mi = find_named(L"RobloxPlayerBeta.dll")) {
            VT_LOG(L"IAT: scanning game DLL: RobloxPlayerBeta.dll");
            DWORD pp = 0;
            auto [s, o] = scan_module(*mi);
            if (s && o && VirtualProtectEx(process, (void*)s, 8, PAGE_READWRITE, &pp)) {
                VirtualProtectEx(process, (void*)s, 8, pp, &pp);
                iat_slot = s;
                original_fn = o;
                VT_LOG(L"IAT: writable slot in RobloxPlayerBeta.dll");
            } else if (s) {
                VT_WARN(L"IAT: RobloxPlayerBeta.dll slot locked (err=" +
                        std::to_wstring(GetLastError()) + L")");
            }
        }
    }
    if (!iat_slot) {
        for (auto& mi : mods) {
            if (iat_slot)
                break;
            try_mod(mi);
        }
    }

    if (!iat_slot || !original_fn) { VT_WARN(L"IAT: no writable IAT slot found"); return false; }

    // Two pages:
    // hook_page: PAGE_EXECUTE_READ — the stub code (IAT points here)
    // flag_page: PAGE_READWRITE    — 8-byte one-shot flag (auto-zeroed by MEM_COMMIT)
    //
    // The previous stub attempted "mov [iat_slot], orig_fn" inside the stub to
    // restore the IAT in one shot.  The IAT is PAGE_READONLY after we restore its
    // protection, so that write caused an immediate access violation before DllMain
    // was ever called.  The beacon never fired because the stub crashed on that line.
    //
    // Fix: no inline IAT restore.  A separate writable page holds the one-shot flag.
    // The stub atomically sets the flag (lock xchg) and only calls DllMain on the
    // first invocation.  VoidTrace.exe restores the IAT externally after the beacon.
    void* hook_page = VirtualAllocEx(process, nullptr, 0x1000,
                                     MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!hook_page) { VT_WARN(L"IAT: VirtualAllocEx(hook) failed err=" + std::to_wstring(GetLastError())); return false; }

    void* flag_page = VirtualAllocEx(process, nullptr, 0x1000,
                                     MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!flag_page) {
        VirtualFreeEx(process, hook_page, 0, MEM_RELEASE);
        VT_WARN(L"IAT: VirtualAllocEx(flag) failed err=" + std::to_wstring(GetLastError()));
        return false;
    }
    const uintptr_t flag_addr = (uintptr_t)flag_page; // uint64_t at flag_page[0], zeroed by MEM_COMMIT

    // Stub layout (no TLS callbacks — DLL has none; keeps block size fixed for jnz):
    //
    //   push r15/r14/r13/r12/rbx/rsi   ; save non-volatile scratch regs
    //   sub rsp, 0x28                   ; shadow + align → RSP%16=0 before calls ✓
    //   mov r12,rcx / r13,rdx / r14,r8 / r15,r9  ; save original args
    //   mov rbx, flag_addr              ; one-shot flag address
    //   mov rax, 1
    //   lock xchg [rbx], rax           ; rax=old flag (0=first, 1=already ran)
    //   test rax, rax
    //   jnz +30                         ; skip DllMain block if already ran
    //   --- DllMain block (exactly 30 bytes) ---
    //   mov rcx, image_base (10)
    //   mov edx, 1         (5)
    //   xor r8d, r8d       (3)
    //   mov rax, entry     (10)
    //   call rax           (2)
    //   --- skip target ---
    //   mov rcx,r12 / rdx,r13 / r8,r14 / r9,r15  ; restore original args
    //   add rsp, 0x28 / pop rsi/rbx/r12/r13/r14/r15
    //   mov rax, orig_fn / jmp rax     ; tail-call original function with restored args

    uint8_t hook[384]{};
    size_t h = 0;
    auto hb = [&](const uint8_t* b, size_t n) { if (h+n<=sizeof(hook)){std::memcpy(hook+h,b,n);h+=n;} };

    // Entry: RSP%16=8. After 6 pushes (-48): RSP%16=0. sub 0x28 (-40, 40%16=8): RSP%16=8.
    // Wait: need RSP%16=0 BEFORE call. Let me recount:
    // On entry RSP%16=8. push×6 = -48. 8-48=-40; (-40)%16 = -40+48=8... ugh.
    // Cleaner: entry RSP%16=8. Each push flips between 0 and 8.
    // push r15→0, push r14→8, push r13→0, push r12→8, push rbx→0, push rsi→8.
    // sub rsp,0x28 (40): 40%16=8. RSP%16 = 8-8=0. ✓  RSP is 16-aligned → call OK.
    { static const uint8_t b[]={0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x56,
                                  0x48,0x83,0xEC,0x28}; hb(b,sizeof(b)); }
    // Save original args into non-volatile r12-r15
    { static const uint8_t b[]={0x4C,0x8B,0xE1, // mov r12,rcx
                                  0x4C,0x8B,0xEA, // mov r13,rdx
                                  0x4D,0x8B,0xF0, // mov r14,r8
                                  0x4D,0x8B,0xF9};// mov r15,r9
      hb(b,sizeof(b)); }
    // One-shot: lock xchg [flag_addr], 1 → rax=old value
    { uint8_t b[10]={0x48,0xBB}; std::memcpy(b+2,&flag_addr,8); hb(b,10); } // mov rbx,flag_addr
    { static const uint8_t b[]={0x48,0xB8,0x01,0,0,0,0,0,0,0}; hb(b,sizeof(b)); } // mov rax,1
    { static const uint8_t b[]={0xF0,0x48,0x87,0x03}; hb(b,sizeof(b)); }  // lock xchg [rbx],rax
    { static const uint8_t b[]={0x48,0x85,0xC0}; hb(b,sizeof(b)); }       // test rax,rax
    { static const uint8_t b[]={0x75,0x30}; hb(b,sizeof(b)); }             // jnz +48 (skip DllMain + done store)
    // DllMain block — 48 bytes: 10+5+3+10+2+10+8
    { uint8_t b[10]={0x48,0xB9}; std::memcpy(b+2,&image_base,8); hb(b,10); } // mov rcx,image_base
    { static const uint8_t b[]={0xBA,0x01,0x00,0x00,0x00}; hb(b,sizeof(b)); } // mov edx,1
    { static const uint8_t b[]={0x45,0x31,0xC0}; hb(b,sizeof(b)); }            // xor r8d,r8d
    { uint8_t b[10]={0x48,0xB8}; std::memcpy(b+2,&entry,8); hb(b,10); }        // mov rax,entry
    { static const uint8_t b[]={0xFF,0xD0}; hb(b,sizeof(b)); }                  // call rax
    { uint8_t b[10]={0x48,0xB8}; std::memcpy(b+2,&flag_addr,8); hb(b,10); }    // mov rax,flag_addr
    { static const uint8_t b[]={0x48,0xC7,0x40,0x08,0x01,0,0,0}; hb(b,sizeof(b)); } // mov qword [rax+8],1
    if (tick) {
        { uint8_t b[10]={0x48,0xB8}; std::memcpy(b+2,&tick,8); hb(b,10); } // mov rax,VT_TICK
        { static const uint8_t b[]={0xFF,0xD0}; hb(b,sizeof(b)); }          // call rax
    }
    { uint8_t b[10]={0x48,0xB8}; std::memcpy(b+2,&flag_addr,8); hb(b,10); } // mov rax,flag
    { static const uint8_t b[]={0x48,0xC7,0x40,0x10,0x01,0,0,0}; hb(b,sizeof(b)); } // mov qword [rax+16],1
    // Restore original args, unwind, tail-call
    { static const uint8_t b[]={0x4C,0x89,0xE1,  // mov rcx,r12
                                  0x4C,0x89,0xEA,  // mov rdx,r13
                                  0x4D,0x89,0xF0,  // mov r8,r14
                                  0x4D,0x89,0xF9}; // mov r9,r15
      hb(b,sizeof(b)); }
    { static const uint8_t b[]={0x48,0x83,0xC4,0x28, // add rsp,0x28
                                  0x5E,               // pop rsi
                                  0x5B,               // pop rbx
                                  0x41,0x5C,          // pop r12
                                  0x41,0x5D,          // pop r13
                                  0x41,0x5E,          // pop r14
                                  0x41,0x5F};         // pop r15
      hb(b,sizeof(b)); }
    { uint8_t b[10]={0x48,0xB8}; std::memcpy(b+2,&original_fn,8); hb(b,10); } // mov rax,orig_fn
    { static const uint8_t b[]={0xFF,0xE0}; hb(b,sizeof(b)); }                  // jmp rax

    if (!WriteProcessMemory(process, hook_page, hook, h, nullptr)) {
        VirtualFreeEx(process, hook_page, 0, MEM_RELEASE);
        VirtualFreeEx(process, flag_page, 0, MEM_RELEASE);
        VT_WARN(L"IAT: WPM hook stub failed err=" + std::to_wstring(GetLastError()));
        return false;
    }
    DWORD op = 0;
    VirtualProtectEx(process, hook_page, 0x1000, PAGE_EXECUTE_READ, &op);
    cfg_mark(process, hook_page);
    resolve_ntdll();
    if (s_NtFlush) s_NtFlush(process, hook_page, h);

    // Install the hook: temporarily make the IAT slot writable, write hook_page address.
    DWORD old_prot = 0;
    if (!VirtualProtectEx(process, (void*)iat_slot, 8, PAGE_READWRITE, &old_prot)) {
        VirtualFreeEx(process, hook_page, 0, MEM_RELEASE);
        VirtualFreeEx(process, flag_page, 0, MEM_RELEASE);
        VT_WARN(L"IAT: VirtualProtectEx(IAT writable) failed err=" + std::to_wstring(GetLastError()));
        return false;
    }
    const uintptr_t hook_addr = (uintptr_t)hook_page;
    const bool wpm_ok = WriteProcessMemory(process, (void*)iat_slot, &hook_addr, 8, nullptr);
    DWORD dummy = 0;
    VirtualProtectEx(process, (void*)iat_slot, 8, old_prot, &dummy); // restore original prot

    if (!wpm_ok) {
        VirtualFreeEx(process, hook_page, 0, MEM_RELEASE);
        VirtualFreeEx(process, flag_page, 0, MEM_RELEASE);
        VT_WARN(L"IAT: WPM to IAT slot failed err=" + std::to_wstring(GetLastError()));
        return false;
    }
    VT_LOG(L"IAT: hook installed — hook_addr=0x" +
           [&]{wchar_t b[20];swprintf_s(b,L"%llX",hook_addr);return std::wstring(b);}() +
           L" flag_addr=0x" +
           [&]{wchar_t b[20];swprintf_s(b,L"%llX",flag_addr);return std::wstring(b);}() +
           L" tick=0x" +
           [&]{wchar_t b[20];swprintf_s(b,L"%llX",(ULONGLONG)tick);return std::wstring(b);}() +
           L" — waiting for DllMain; stub stays as lasting tick");

    bool stub_ran = false, dllmain_ret = false, tick_done = false;
    for (int i = 0; i < 80; ++i) {
        uint64_t fl[3]{};
        ReadProcessMemory(process, flag_page, fl, sizeof(fl), nullptr);
        stub_ran = fl[0] != 0;
        dllmain_ret = fl[1] != 0;
        tick_done = fl[2] != 0;
        if (tick_done)
            break;
        if (dllmain_ret && i >= 15)
            break;
        Sleep(100);
    }

    auto restore_iat = [&](bool keep_pages) {
        DWORD rp = 0;
        if (VirtualProtectEx(process, (void*)iat_slot, 8, PAGE_READWRITE, &rp)) {
            WriteProcessMemory(process, (void*)iat_slot, &original_fn, 8, nullptr);
            VirtualProtectEx(process, (void*)iat_slot, 8, rp, &rp);
        }
        if (!keep_pages) {
            VirtualFreeEx(process, hook_page, 0, MEM_RELEASE);
            VirtualFreeEx(process, flag_page, 0, MEM_RELEASE);
        }
    };

    if (dllmain_ret) {
        // Leave IAT on hook_page. The stub already: one-shot DllMain, then
        // VT_TICK, then jmp original NtUserPeekMessage. Restoring orig killed
        // the pipe. Writing VT_TICK into the slot froze PeekMessage.
        if (out_slot)
            *out_slot = iat_slot;
        if (out_stub)
            *out_stub = hook_addr;
        if (out_orig)
            *out_orig = original_fn;
        VT_LOG(L"IAT: DllMain done — PeekMessage stub kept (lasting tick)");
        return true;
    }
    restore_iat(false);
    if (stub_ran)
        VT_WARN(L"IAT: stub ran but DllMain did not return — CRT/entry crashed");
    else
        VT_WARN(L"IAT: hooked import was never called");
    return false;
}

// KERNELBASE wait IAT — the script job thread waits here. PeekMessage is the
// render thread (kick/pcall there closed Roblox). Same stub style as USER32:
// CFG mark fails, but the call still lands. pulse() filters to the lua tid.
bool try_wait_pulse_hook(HANDLE process, uintptr_t pulse) {
    if (!pulse)
        return false;
    const DWORD pid = GetProcessId(process);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    struct WaitMod { uintptr_t base; wchar_t name[64]; };
    std::vector<WaitMod> want;
    MODULEENTRY32W me{ sizeof(me) };
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, L"KERNELBASE.dll") == 0 ||
                _wcsicmp(me.szModule, L"kernelbase.dll") == 0 ||
                _wcsicmp(me.szModule, L"KERNEL32.dll") == 0 ||
                _wcsicmp(me.szModule, L"kernel32.dll") == 0) {
                WaitMod w{};
                w.base = (uintptr_t)me.modBaseAddr;
                wcsncpy_s(w.name, me.szModule, 63);
                want.push_back(w);
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    std::sort(want.begin(), want.end(), [](const WaitMod& a, const WaitMod& b) {
        auto rank = [](const wchar_t* n) {
            // KERNEL32 IAT was writable from the host last time. KERNELBASE VP err=87.
            if (_wcsicmp(n, L"KERNEL32.dll") == 0 || _wcsicmp(n, L"kernel32.dll") == 0) return 0;
            return 1;
        };
        return rank(a.name) < rank(b.name);
    });
    if (want.empty()) {
        VT_WARN(L"wait-IAT: no candidate modules");
        return false;
    }

    static const char* const names[] = {
        "NtWaitForSingleObject", "NtDelayExecution", "NtWaitForMultipleObjects",
        "ZwWaitForSingleObject", "ZwDelayExecution",
        "WaitForSingleObject", "WaitForSingleObjectEx", "SleepEx", nullptr
    };

    struct Cand { uintptr_t slot, orig; std::wstring tag; };
    std::vector<Cand> cands;
    for (auto& wm : want) {
        const uintptr_t kb = wm.base;
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 nt{};
        ReadProcessMemory(process, (void*)kb, &dos, sizeof(dos), nullptr);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE)
            continue;
        ReadProcessMemory(process, (void*)(kb + dos.e_lfanew), &nt, sizeof(nt), nullptr);
        const auto& imp = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!imp.VirtualAddress)
            continue;
        for (size_t off = 0; off < imp.Size; off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IMAGE_IMPORT_DESCRIPTOR desc{};
            if (!ReadProcessMemory(process, (void*)(kb + imp.VirtualAddress + off),
                                   &desc, sizeof(desc), nullptr) || !desc.Name)
                break;
            if (!desc.OriginalFirstThunk)
                continue;
            const uintptr_t iat_base = kb + desc.FirstThunk;
            const uintptr_t int_base = kb + desc.OriginalFirstThunk;
            for (int i = 0; i < 4096; ++i) {
                ULONGLONG ord = 0;
                if (!ReadProcessMemory(process, (void*)(int_base + i * 8), &ord, 8, nullptr) || !ord)
                    break;
                if (IMAGE_SNAP_BY_ORDINAL64(ord))
                    continue;
                char fn[64]{};
                ReadProcessMemory(process, (void*)(kb + (ord & ~IMAGE_ORDINAL_FLAG64) + 2), fn, 63, nullptr);
                for (int t = 0; names[t]; ++t) {
                    if (strcmp(fn, names[t]) != 0)
                        continue;
                    ULONGLONG cur = 0;
                    if (!ReadProcessMemory(process, (void*)(iat_base + i * 8), &cur, 8, nullptr) || !cur)
                        break;
                    Cand c{};
                    c.slot = iat_base + (uintptr_t)i * 8;
                    c.orig = (uintptr_t)cur;
                    c.tag = std::wstring(wm.name) + L"!" + utf8_to_wide(fn);
                    cands.push_back(c);
                    break;
                }
            }
        }
    }
    if (cands.empty()) {
        VT_WARN(L"wait-IAT: no NtWait* import");
        return false;
    }

    void* page = nullptr;
    if (!SC_VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE, &page) || !page) {
        VT_WARN(L"wait-IAT: alloc failed");
        return false;
    }
    const uintptr_t hook = (uintptr_t)page;
    auto build_stub = [&](uintptr_t orig) {
        uint8_t s[512]{};
        size_t h = 0;
        auto hb = [&](const uint8_t* b, size_t n) { memcpy(s + h, b, n); h += n; };
        auto xmm_store = [&](int xm, int32_t disp) {
            if (xm >= 8)
                s[h++] = 0x44;
            s[h++] = 0x0F; s[h++] = 0x29;
            s[h++] = (uint8_t)(0x84 + (((xm & 7) << 3)));
            s[h++] = 0x24;
            memcpy(s + h, &disp, 4); h += 4;
        };
        auto xmm_load = [&](int xm, int32_t disp) {
            if (xm >= 8)
                s[h++] = 0x44;
            s[h++] = 0x0F; s[h++] = 0x28;
            s[h++] = (uint8_t)(0x84 + (((xm & 7) << 3)));
            s[h++] = 0x24;
            memcpy(s + h, &disp, 4); h += 4;
        };
        { static const uint8_t b[] = { 0x53,0x55,0x57,0x56,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57 }; hb(b, sizeof(b)); }
        { static const uint8_t b[] = { 0x4C,0x8B,0xE1,0x4C,0x8B,0xEA,0x4D,0x8B,0xF0,0x4D,0x8B,0xF9 }; hb(b, sizeof(b)); }
        { static const uint8_t b[] = { 0x48,0x81,0xEC,0x08,0x01,0x00,0x00 }; hb(b, sizeof(b)); }
        for (int i = 0; i < 10; ++i)
            xmm_store(6 + i, 0x20 + i * 16);
        { uint8_t b[10] = { 0x48,0xB8 }; memcpy(b + 2, &pulse, 8); hb(b, 10); }
        { static const uint8_t b[] = { 0xFF,0xD0 }; hb(b, sizeof(b)); }
        for (int i = 0; i < 10; ++i)
            xmm_load(6 + i, 0x20 + i * 16);
        { static const uint8_t b[] = { 0x48,0x81,0xC4,0x08,0x01,0x00,0x00 }; hb(b, sizeof(b)); }
        { static const uint8_t b[] = { 0x4C,0x89,0xE1,0x4C,0x89,0xEA,0x4D,0x89,0xF0,0x4D,0x89,0xF9 }; hb(b, sizeof(b)); }
        { static const uint8_t b[] = { 0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x5E,0x5F,0x5D,0x5B }; hb(b, sizeof(b)); }
        { uint8_t b[10] = { 0x48,0xB8 }; memcpy(b + 2, &orig, 8); hb(b, 10); }
        { static const uint8_t b[] = { 0xFF,0xE0 }; hb(b, sizeof(b)); }
        DWORD op = 0;
        SC_VirtualProtectEx(process, page, 0x1000, PAGE_EXECUTE_READWRITE, &op);
        const bool ok = SC_WriteProcessMemory(process, page, s, h, nullptr);
        SC_VirtualProtectEx(process, page, 0x1000, PAGE_EXECUTE_READ, &op);
        return ok;
    };

    for (auto& c : cands) {
        VT_LOG(L"wait-IAT try " + c.tag + L" slot=" + format_hex(c.slot));
        if (!build_stub(c.orig))
            continue;
        DWORD old = 0;
        if (!VirtualProtectEx(process, (void*)c.slot, 8, PAGE_READWRITE, &old)) {
            VT_WARN(L"wait-IAT: VirtualProtectEx " + c.tag + L" err=" +
                    std::to_wstring(GetLastError()));
            continue;
        }
        SIZE_T wr = 0;
        const bool ok = WriteProcessMemory(process, (void*)c.slot, &hook, 8, &wr) && wr == 8;
        DWORD dummy = 0;
        VirtualProtectEx(process, (void*)c.slot, 8, old, &dummy);
        if (!ok) {
            VT_WARN(L"wait-IAT: WPM " + c.tag + L" failed");
            continue;
        }
        VT_LOG(L"wait-IAT hooked " + c.tag + L" hook=" + format_hex(hook) +
               L" orig=" + format_hex(c.orig));
        return true;
    }
    VirtualFreeEx(process, page, 0, MEM_RELEASE);
    VT_WARN(L"wait-IAT: every candidate slot locked");
    return false;
}

void protect_sections(HANDLE process, uintptr_t base, PIMAGE_NT_HEADERS64 nt) {
    DWORD old = 0;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        const SIZE_T sz = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : 0x1000;
        DWORD prot = PAGE_READONLY;
        const auto ch = sec->Characteristics;
        if (ch & IMAGE_SCN_MEM_EXECUTE)
            prot = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        SC_VirtualProtectEx(process, (void*)(base + sec->VirtualAddress), sz, prot, &old);
    }
}

void wipe_headers(HANDLE process, uintptr_t base, PIMAGE_NT_HEADERS64 nt) {
    DWORD old = 0;
    const SIZE_T hdr = nt->OptionalHeader.SizeOfHeaders
        ? nt->OptionalHeader.SizeOfHeaders : 0x1000;
    SC_VirtualProtectEx(process, (void*)base, hdr, PAGE_READWRITE, &old);
    std::vector<uint8_t> zero(hdr, 0);
    remote_write(process, base, zero.data(), zero.size());
    SC_VirtualProtectEx(process, (void*)base, 0x1000, PAGE_NOACCESS, &old);
}

// Thread-hijacking entry path: redirect an existing Roblox thread instead of
// creating a new one.  This eliminates the PsSetCreateThreadNotifyRoutine
// signal that Hyperion watches for.
//
// NOTE: Hyperion's kernel driver can silently revert SetThreadContext even
// when the API returns success.  We detect this by checking whether the
// DllMain beacon event was signalled during the 2500 ms wait.  If not, we
// report failure so the caller can fall back to the APC or LoadLibrary path.
bool start_via_hijack(HANDLE process, PVOID start, PVOID param, DWORD pid) {
    auto r = ThreadHijacker::run(process, pid,
                                 start, param,
                                 nullptr,   // connect_event — we use timeout
                                 2500);
    if (!r.ok) {
        VT_WARN(L"thread hijack failed: " + r.error);
        return false;
    }
    // The hijack API call succeeded, but Hyperion may have reverted our context
    // at the kernel level without returning an error.  Verify by checking the
    // DllMain beacon event that dllmain.cpp signals on DLL_PROCESS_ATTACH.
    HANDLE beacon = OpenEventW(SYNCHRONIZE, FALSE, L"VT_Diag_DllMain");
    if (beacon) {
        const bool ran = (WaitForSingleObject(beacon, 50) == WAIT_OBJECT_0);
        CloseHandle(beacon);
        if (ran) {
            VT_LOG(L"thread hijack: DllMain beacon confirmed");
            return true;
        }
    }
    VT_WARN(L"thread hijack silently blocked — Hyperion reverted SetThreadContext");
    return false;
}

// NtCreateThreadEx fallback.
// 'start' should be an ntdll gadget (jmp rcx) so the kernel records an ntdll
// Win32StartAddress in the ETHREAD — indistinguishable from any normal thread.
// 'stub_clean' is a stub that ends with add rsp,28h / ret (no jmp-2 spin),
// so the thread exits naturally via RtlUserThreadStart when DllMain returns.
bool start_via_new_thread(HANDLE process, PVOID start, PVOID stub_clean) {
    using fmt = void*;
    auto try_nt = [&](NtCreateThreadEx_t fn, const wchar_t* label) -> bool {
        if (!fn) return false;
        HANDLE thread = nullptr;
        NTSTATUS ns = fn(&thread, THREAD_ALL_ACCESS, nullptr, process,
                         start, stub_clean, kHideFromDebugger, 0, 0, 0, nullptr);
        wchar_t nb[20]; swprintf_s(nb, L"0x%08X", (unsigned)ns);
        if (ns < 0 || !thread) {
            VT_WARN(std::wstring(label) + L" failed ns=" + nb);
            return false;
        }
        VT_LOG(std::wstring(label) + L" created ns=" + nb + L" — waiting 800 ms for DllMain beacon");
        Sleep(800);
        CloseHandle(thread);
        // Verify DllMain actually ran — thread creation succeeds but
        // RtlUserThreadStart's CFG check may kill the thread before it
        // reaches our stub if the start address isn't a CFG-bitmap entry.
        HANDLE beacon = OpenEventW(SYNCHRONIZE, FALSE, L"VT_Diag_DllMain");
        bool ran = false;
        if (beacon) { ran = (WaitForSingleObject(beacon, 50) == WAIT_OBJECT_0); CloseHandle(beacon); }
        if (!ran) { VT_WARN(std::wstring(label) + L" — thread created but DllMain not reached (CFG/kill)"); return false; }
        return true;
    };

    auto& sc = Syscalls::get();
    if (sc.ready() && sc.CreateThreadEx && try_nt(sc.CreateThreadEx, L"NtCreateThreadEx[sc]"))
        return true;

    resolve_ntdll();
    if (try_nt(s_NtCreateThreadEx, L"NtCreateThreadEx[ntdll]"))
        return true;

    // Bare CreateRemoteThread — fully visible, last resort.
    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)start, stub_clean, 0, nullptr);
    if (!thread) {
        VT_WARN(L"CreateRemoteThread failed");
        return false;
    }
    VT_LOG(L"CreateRemoteThread fallback — waiting 800 ms");
    Sleep(800);
    CloseHandle(thread);
    // Same CFG restriction applies: if start is not a CFG-bitmap entry the
    // thread is killed before our stub runs.  Check the beacon to be certain.
    {
        HANDLE beacon = OpenEventW(SYNCHRONIZE, FALSE, L"VT_Diag_DllMain");
        bool ran = false;
        if (beacon) { ran = (WaitForSingleObject(beacon, 50) == WAIT_OBJECT_0); CloseHandle(beacon); }
        if (!ran) { VT_WARN(L"CreateRemoteThread — DllMain not reached (CFG/kill)"); return false; }
    }
    return true;
}

// APC injection — queue a user-mode APC to every Roblox thread.
// Special User APCs fire immediately without requiring an alertable wait —
// they interrupt the thread at the next safe instruction boundary regardless
// of what it is doing.  This is the only reliable APC path for Roblox threads
// that never call SleepEx/WaitForSingleObjectEx with bAlertable=TRUE.
//
// Delivery order per thread:
//   1. NtQueueApcThreadEx2 (Win11 22H2+)  — SPECIAL_USER_APC flag
//   2. NtQueueApcThreadEx  (Win8.1+)      — UserApcReserveHandle=(HANDLE)1
//   3. NtQueueApcThread                    — regular alertable APC (fallback)
bool start_via_apc(HANDLE process, PVOID stub_clean, DWORD pid) {
    resolve_ntdll();

    // Regular APC baseline (always available)
    using NtQueueApcThread_t    = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, PVOID);
    // Extended APC: UserApcReserveHandle=(HANDLE)1 → Special User APC on Win10 19H1+
    using NtQueueApcThreadEx_t  = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID);
    // Win11 22H2+ variant with explicit QueueUserApcFlags ULONG
    using NtQueueApcThreadEx2_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, ULONG, PVOID, PVOID, PVOID, PVOID);

    constexpr ULONG kSpecialApc = 0x1; // QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC

    auto NtQueueApc    = (NtQueueApcThread_t)   GetProcAddress(s_ntdll, "NtQueueApcThread");
    auto NtQueueApcEx  = (NtQueueApcThreadEx_t) GetProcAddress(s_ntdll, "NtQueueApcThreadEx");
    auto NtQueueApcEx2 = (NtQueueApcThreadEx2_t)GetProcAddress(s_ntdll, "NtQueueApcThreadEx2");

    if (!NtQueueApc) { VT_WARN(L"NtQueueApcThread not resolved"); return false; }

    if (NtQueueApcEx2) VT_LOG(L"APC: NtQueueApcThreadEx2 available — will use Special User APC");
    else if (NtQueueApcEx) VT_LOG(L"APC: NtQueueApcThreadEx available — will use Special User APC (Ex)");
    else VT_WARN(L"APC: Special User APC not available — threads must enter alertable wait");

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    int queued_special = 0, queued_regular = 0;
    THREADENTRY32 te{sizeof(te)};
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE ht = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, te.th32ThreadID);
            if (!ht) continue;

            NTSTATUS ns = 0xC0000001; // STATUS_UNSUCCESSFUL default
            const wchar_t* method = L"?";

            if (NtQueueApcEx2) {
                // Special User APC via Ex2 — fires immediately, no alertable wait needed
                ns = NtQueueApcEx2(ht, nullptr, kSpecialApc, stub_clean, nullptr, nullptr, nullptr);
                method = L"Ex2-special";
            } else if (NtQueueApcEx) {
                // Older special: pass (HANDLE)1 as UserApcReserveHandle
                ns = NtQueueApcEx(ht, (HANDLE)1, stub_clean, nullptr, nullptr, nullptr);
                method = L"Ex-special";
            }

            if (ns < 0) {
                // Special APC failed — fall back to regular alertable APC
                ns = NtQueueApc(ht, stub_clean, nullptr, nullptr, nullptr);
                method = L"regular";
            }

            wchar_t nb[20]; swprintf_s(nb, L"0x%08X", (unsigned)ns);
            VT_LOG(L"APC[" + std::wstring(method) + L"] tid=" +
                   std::to_wstring(te.th32ThreadID) + L" ns=" + nb);

            if (ns >= 0) {
                if (method[0] == L'r') ++queued_regular; else ++queued_special;
            }
            CloseHandle(ht);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    const int total = queued_special + queued_regular;
    if (!total) { VT_WARN(L"APC: no threads accepted"); return false; }

    // Special APCs fire immediately — 1 s is generous.
    // Regular APCs need a thread to enter alertable state — 3 s.
    const DWORD wait_ms = queued_special > 0 ? 1000 : 3000;
    VT_LOG(L"APC: queued special=" + std::to_wstring(queued_special) +
           L" regular=" + std::to_wstring(queued_regular) +
           L" — waiting " + std::to_wstring(wait_ms) + L" ms");

    HANDLE beacon = OpenEventW(SYNCHRONIZE, FALSE, L"VT_Diag_DllMain");
    bool ran = false;
    if (beacon) {
        ran = (WaitForSingleObject(beacon, wait_ms) == WAIT_OBJECT_0);
        CloseHandle(beacon);
    }
    if (!ran) {
        VT_WARN(L"APC: DllMain beacon not signalled after " + std::to_wstring(wait_ms) + L" ms");
        return false;
    }
    VT_LOG(L"APC: DllMain confirmed");
    return true;
}


} // namespace

ManualMapper::Result ManualMapper::map(HANDLE process, const std::filesystem::path& dll) {
    Result r;
    std::vector<uint8_t> raw;
    if (!read_all(dll, raw)) {
        r.error = L"failed to read DLL";
        return r;
    }
    return map_buffer(process, raw.data(), raw.size());
}

ManualMapper::Result ManualMapper::map_buffer(HANDLE process, const uint8_t* pe, size_t pe_size) {
    Result r;
    if (!pe || pe_size < 64) {
        r.error = L"empty PE buffer";
        return r;
    }
    std::vector<uint8_t> raw(pe, pe + pe_size);

    auto* nt = nt_hdr(raw.data());
    if (!nt || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        r.error = L"not a 64-bit PE";
        return r;
    }

    const SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
    // +0x1000 extra for the entry stub (appended after the image).
    const SIZE_T alloc_size = image_size + 0x1000;

    // ── Ghost-section injection ───────────────────────────────────────────────
    // Create a pagefile-backed section instead of a private VirtualAlloc.
    // The kernel records this as a mapped-section VAD (not VadNone), which is
    // far less suspicious to Hyperion's NtQueryVirtualMemory walk.
    //
    // Steps:
    //  1. NtCreateSection  → section object (pagefile-backed, SEC_COMMIT RWX)
    //  2. NtMapViewOfSection into our process (RW) → write all PE content here
    //  3. NtMapViewOfSection into Roblox (RX initially) → remote_base
    //  4. Unmap from our process, close section handle
    //  5. Set per-section protections on the Roblox view
    // ─────────────────────────────────────────────────────────────────────────
    VT_LOG(L"ManualMap: resolving ntdll");
    resolve_ntdll();
    VT_LOG(L"ManualMap: ntdll resolved — NtCreateSection=" +
        [&]{ wchar_t b[20]; swprintf_s(b, L"%p", (void*)s_NtCreateSection); return std::wstring(b); }());

    HANDLE hsec = nullptr;
    LARGE_INTEGER sec_size{};
    sec_size.QuadPart = (LONGLONG)alloc_size;

    VT_LOG(L"ManualMap: calling NtCreateSection");
    NTSTATUS ns = s_NtCreateSection(
        &hsec,
        SECTION_ALL_ACCESS,
        nullptr,         // no ObjectAttributes → unnamed, pagefile-backed
        &sec_size,
        PAGE_EXECUTE_READWRITE,
        0x8000000,       // SEC_COMMIT
        nullptr          // no FileHandle → pagefile
    );

    uintptr_t remote_base = 0;
    uint8_t*  local_view  = nullptr;

    if (ns < 0 || !hsec) {
        // Fall back: private VirtualAllocEx.
        VT_WARN(L"NtCreateSection failed, falling back to VirtualAllocEx");
        void* fb = nullptr;
        if (!SC_VirtualAllocEx(process, nullptr, alloc_size,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, &fb) || !fb) {
            r.error = L"VirtualAllocEx fallback failed: " + last_error_text();
            return r;
        }
        remote_base = (uintptr_t)fb;
    } else {
        // Map locally for writing.
        SIZE_T view_size = 0;
        ns = s_NtMapView(hsec, GetCurrentProcess(), (PVOID*)&local_view,
                         0, 0, nullptr, &view_size, 2 /*ViewUnmap*/,
                         0, PAGE_READWRITE);
        if (ns < 0 || !local_view) {
            VT_WARN(L"NtMapViewOfSection (local) failed, falling back");
            CloseHandle(hsec);
            local_view = nullptr;
            void* fb = nullptr;
            if (!SC_VirtualAllocEx(process, nullptr, alloc_size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, &fb) || !fb) {
                r.error = L"VirtualAllocEx fallback failed: " + last_error_text();
                return r;
            }
            remote_base = (uintptr_t)fb;
        } else {
            // Map into Roblox.
            PVOID rb = nullptr;
            view_size = 0;
            ns = s_NtMapView(hsec, process, &rb,
                             0, 0, nullptr, &view_size, 2 /*ViewUnmap*/,
                             0, PAGE_EXECUTE_READWRITE);
            if (ns < 0 || !rb) {
                VT_WARN(L"NtMapViewOfSection (remote) failed, falling back");
                s_NtUnmapView(GetCurrentProcess(), local_view);
                CloseHandle(hsec);
                local_view = nullptr;
                void* fb = nullptr;
                if (!SC_VirtualAllocEx(process, nullptr, alloc_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, &fb) || !fb) {
                    r.error = L"VirtualAllocEx fallback failed: " + last_error_text();
                    return r;
                }
                remote_base = (uintptr_t)fb;
            } else {
                remote_base = (uintptr_t)rb;
                VT_LOG(L"Ghost section mapped — remote base: 0x" + [&]{
                    wchar_t b[32]; swprintf_s(b, L"%llX", (ULONGLONG)remote_base); return std::wstring(b);
                }());
            }
        }
    }

    const uintptr_t delta = remote_base - nt->OptionalHeader.ImageBase;

    // Helper: write to either the local section view or directly to remote.
    auto write_local = [&](uintptr_t dest_rva, const void* src, size_t n_bytes) -> bool {
        if (local_view) {
            std::memcpy(local_view + dest_rva, src, n_bytes);
            return true;
        }
        return remote_write(process, remote_base + dest_rva, src, n_bytes);
    };
    auto read_local = [&](uintptr_t src_rva, void* dst, size_t n_bytes) {
        if (local_view)
            std::memcpy(dst, local_view + src_rva, n_bytes);
        else
            SC_ReadProcessMemory(process, (void*)(remote_base + src_rva), dst, n_bytes, nullptr);
    };

    // Write PE headers and sections into the local view (zero-copy for remote).
    if (!write_local(0, raw.data(), nt->OptionalHeader.SizeOfHeaders)) {
        r.error = L"failed writing PE headers";
        return r;
    }

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData)
            continue;
        if (!write_local(sec->VirtualAddress, raw.data() + sec->PointerToRawData, sec->SizeOfRawData)) {
            r.error = L"failed writing section";
            return r;
        }
    }

    if (delta && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        auto* reloc = (PIMAGE_BASE_RELOCATION)rva_to_file(raw.data(), nt, rva);
        auto* end = (PIMAGE_BASE_RELOCATION)((uint8_t*)reloc +
                    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        while (reloc && reloc < end && reloc->VirtualAddress) {
            const DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            auto* entry = (WORD*)(reloc + 1);
            for (DWORD i = 0; i < count; ++i) {
                const int type = entry[i] >> 12;
                const int off  = entry[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    uintptr_t patch = 0;
                    read_local(reloc->VirtualAddress + off, &patch, sizeof(patch));
                    patch += delta;
                    write_local(reloc->VirtualAddress + off, &patch, sizeof(patch));
                }
            }
            reloc = (PIMAGE_BASE_RELOCATION)((uint8_t*)reloc + reloc->SizeOfBlock);
        }
    }

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        auto* desc = (PIMAGE_IMPORT_DESCRIPTOR)rva_to_file(raw.data(), nt, rva);
        if (!desc) {
            VT_WARN(L"ManualMap: import dir RVA not in any section — skipping imports");
        } else {
        for (; desc->Name; ++desc) {
            const char* mod_name = (const char*)rva_to_file(raw.data(), nt, desc->Name);
            if (!mod_name) {
                VT_WARN(L"ManualMap: import descriptor Name RVA 0x" +
                    [&]{ wchar_t b[16]; swprintf_s(b, L"%X", desc->Name); return std::wstring(b); }() +
                    L" not in any section — skipping");
                continue;
            }
            HMODULE local_mod = LoadLibraryA(mod_name);
            if (!local_mod) {
                r.error = L"import module missing: " + utf8_to_wide(mod_name);
                return r;
            }
            const DWORD pid = GetProcessId(process);
            wchar_t mod_w[MAX_PATH]{};
            MultiByteToWideChar(CP_ACP, 0, mod_name, -1, mod_w, MAX_PATH);
            uintptr_t remote_mod = (uintptr_t)local_mod;
            if (auto rm = find_module(pid, mod_w))
                remote_mod = rm->base;
            auto orig_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            auto* thunk = (PIMAGE_THUNK_DATA64)rva_to_file(raw.data(), nt, orig_rva);
            auto iat_rva = desc->FirstThunk;
            for (size_t idx = 0; thunk && thunk->u1.AddressOfData; ++thunk, ++idx) {
                FARPROC fn = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                    fn = GetProcAddress(local_mod, (LPCSTR)IMAGE_ORDINAL64(thunk->u1.Ordinal));
                } else {
                    const DWORD ibn_rva = (DWORD)thunk->u1.AddressOfData;
                    auto* ibn = (PIMAGE_IMPORT_BY_NAME)rva_to_file(raw.data(), nt, ibn_rva);
                    if (!ibn) {
                        VT_WARN(L"ManualMap: IMAGE_IMPORT_BY_NAME RVA not in section — skip");
                        continue;
                    }
                    fn = GetProcAddress(local_mod, ibn->Name);
                }
                if (!fn) {
                    r.error = L"unresolved import in " + utf8_to_wide(mod_name);
                    return r;
                }
                const uintptr_t addr = remote_mod + ((uintptr_t)fn - (uintptr_t)local_mod);
                write_local(iat_rva + idx * sizeof(uintptr_t), &addr, sizeof(addr));
            }
        }
        } // end else
    }

    if (DWORD boot = export_rva(raw.data(), nt, "VT_BOOT")) {
        auto pn = PipeKey::cached();
        if (!pn.empty()) {
            wchar_t slot[80]{};
            wcsncpy_s(slot, pn.c_str(), 79);
            write_local(boot, slot, sizeof(slot));
            VT_LOG(L"ManualMap: patched pipe name into module");
        }
    }
    if (DWORD orva = export_rva(raw.data(), nt, "VT_OFF")) {
        const auto& o = Config::instance().get().offsets;
        VTOffBlob blob{};
        memcpy(blob.mag, "VT_OFFS", 8);
        blob.task_scheduler   = o.task_scheduler;
        blob.job_name         = o.job_name;
        blob.job_start        = o.job_start;
        blob.job_end          = o.job_end;
        blob.script_context   = o.script_context;
        blob.extra_space      = o.extra_space;
        blob.lua_state        = o.lua_state;
        blob.identity         = o.identity;
        blob.luau_load        = o.luau_load;
        blob.lua_pcall        = o.lua_pcall;
        blob.lua_gettop       = o.lua_gettop;
        blob.lua_settop       = o.lua_settop;
        blob.lua_pushstring   = o.lua_pushstring;
        blob.lua_pushlstring  = o.lua_pushlstring;
        blob.lua_pushcclosure = o.lua_pushcclosure;
        blob.lua_tolstring    = o.lua_tolstring;
        blob.lua_pushnil      = o.lua_pushnil;
        blob.lua_pushnumber   = o.lua_pushnumber;
        blob.lua_pushboolean  = o.lua_pushboolean;
        blob.lua_type         = o.lua_type;
        blob.lua_getfield     = o.lua_getfield;
        blob.lua_setfield     = o.lua_setfield;
        blob.lua_createtable  = o.lua_createtable;
        blob.lua_setreadonly  = o.lua_setreadonly;
        blob.lua_newthread    = o.lua_newthread;
        blob.lua_pushvalue    = o.lua_pushvalue;
        {
            const auto g = scan_cfg_gadget_remote(process, GetProcessId(process));
            blob.cfg_gadget  = g.va;
            blob.cfg_disp    = (uint32_t)g.disp;
            blob.cfg_via_rax = g.via_rax ? 1u : 0u;
        }
        write_local(orva, &blob, sizeof(blob));
        VT_LOG(L"ManualMap: patched offsets load=" + format_hex(o.luau_load) +
               L" pcall=" + format_hex(o.lua_pcall) +
               L" cfg=" + format_hex(blob.cfg_gadget));
    }

    // Unmap the local view (content is now in the shared pages visible to Roblox).
    if (local_view && s_NtUnmapView)
        s_NtUnmapView(GetCurrentProcess(), local_view);
    if (hsec)
        CloseHandle(hsec);

    VT_LOG(L"ManualMap: imports resolved — applying section protections");
    protect_sections(process, remote_base, nt);

    const uintptr_t entry = remote_base + nt->OptionalHeader.AddressOfEntryPoint;
    const uintptr_t stub_addr = remote_base + image_size;

    std::vector<uintptr_t> tls_cbs;
    const auto& tlsdir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsdir.Size && tlsdir.VirtualAddress) {
        auto* tls = (PIMAGE_TLS_DIRECTORY64)rva_to_file(raw.data(), nt, tlsdir.VirtualAddress);
        if (tls && tls->AddressOfCallBacks >= nt->OptionalHeader.ImageBase) {
            const uintptr_t cbs_rva = (uintptr_t)tls->AddressOfCallBacks - nt->OptionalHeader.ImageBase;
            auto* cbs = (ULONGLONG*)rva_to_file(raw.data(), nt, (DWORD)cbs_rva);
            for (int i = 0; cbs && i < 8 && cbs[i]; ++i) {
                const uintptr_t va = (uintptr_t)cbs[i];
                const uintptr_t relocated = va >= nt->OptionalHeader.ImageBase
                    ? remote_base + (va - nt->OptionalHeader.ImageBase)
                    : remote_base + va;
                tls_cbs.push_back(relocated);
            }
        }
    }

    // Gadget path: start=ntdll!jmp rcx, param=stub (so RIP in ntdll).
    // TLS callbacks first, then DllMain(image, DLL_PROCESS_ATTACH, 0).
    uint8_t stub[384]{};
    size_t n = 0;
    auto emit = [&](const uint8_t* b, size_t c) {
        if (n + c < sizeof(stub)) {
            std::memcpy(stub + n, b, c);
            n += c;
        }
    };
    auto emit_call = [&](uintptr_t fn) {
        const uint8_t head[] = {
            0x48, 0xB9, 0,0,0,0,0,0,0,0,          // mov rcx, image
            0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, // mov rdx, 1
            0x4D, 0x31, 0xC0,                     // xor r8, r8
            0x48, 0xB8, 0,0,0,0,0,0,0,0,          // mov rax, fn
            0xFF, 0xD0                            // call rax
        };
        uint8_t buf[sizeof(head)];
        std::memcpy(buf, head, sizeof(head));
        std::memcpy(buf + 2, &remote_base, 8);
        std::memcpy(buf + 22, &fn, 8);
        emit(buf, sizeof(buf));
    };
    // ── Stub A: hijack stub (ends with jmp -2 spin) ──────────────────────────
    // Used when the victim thread's context is redirected.  The hijacker
    // restores the original context after 2500 ms; the spin keeps the thread
    // idle and harmless until then.
    const uint8_t sub[]   = {0x48, 0x83, 0xEC, 0x28};           // sub rsp, 0x28
    const uint8_t align[] = {0x48, 0x83, 0xE4, 0xF0};           // and rsp, -16
    const uint8_t spin[]  = {0xEB, 0xFE};                        // jmp -2

    emit(sub,   sizeof(sub));
    emit(align, sizeof(align));
    for (auto cb : tls_cbs)
        emit_call(cb);
    emit_call(entry);
    emit(spin, sizeof(spin));

    // ── Stub B: clean-exit stub (ends with add rsp,0x28 / ret) ───────────────
    // Used by NtCreateThreadEx and APC paths.  After DllMain returns the stub
    // restores RSP and returns cleanly to RtlUserThreadStart / the APC
    // dispatcher — no TerminateThread needed.
    // Layout: starts 0x100 bytes after stub A.
    const uintptr_t stub_addr_b = stub_addr + 0x100;
    uint8_t stub_b[384]{};
    size_t  nb = 0;
    auto emit_b = [&](const uint8_t* p, size_t c) {
        if (nb + c < sizeof(stub_b)) { std::memcpy(stub_b + nb, p, c); nb += c; }
    };
    auto emit_call_b = [&](uintptr_t fn) {
        const uint8_t head[] = {
            0x48, 0xB9, 0,0,0,0,0,0,0,0,
            0x48, 0xC7, 0xC2, 0x01,0x00,0x00,0x00,
            0x4D, 0x31, 0xC0,
            0x48, 0xB8, 0,0,0,0,0,0,0,0,
            0xFF, 0xD0
        };
        uint8_t buf[sizeof(head)];
        std::memcpy(buf, head, sizeof(head));
        std::memcpy(buf + 2,  &remote_base, 8);
        std::memcpy(buf + 22, &fn, 8);
        emit_b(buf, sizeof(buf));
    };
    const uint8_t restore[] = {0x48, 0x83, 0xC4, 0x28, 0xC3}; // add rsp,0x28 / ret
    emit_b(sub,     sizeof(sub));
    emit_b(align,   sizeof(align));
    for (auto cb : tls_cbs)
        emit_call_b(cb);
    emit_call_b(entry);
    emit_b(restore, sizeof(restore));

    // Write both stubs into the extra page at remote_base + image_size.
    if (!remote_write(process, stub_addr,   stub,   n ? n : 64) ||
        !remote_write(process, stub_addr_b, stub_b, nb ? nb : 64)) {
        r.error = L"failed to write entry stubs";
        return r;
    }
    DWORD old = 0;
    SC_VirtualProtectEx(process, (void*)stub_addr, 0x1000, PAGE_EXECUTE_READ, &old);

    auto& sc = Syscalls::get();
    // Allocate a SEPARATE VirtualAllocEx page to hold stub B for CFG registration.
    // SetProcessValidCallTargets requires MEM_PRIVATE memory (VirtualAlloc-style).
    // The ghost section is MEM_MAPPED (NtMapViewOfSection) and always returns
    // ERROR_INVALID_PARAMETER (87). Copy stub B here at offset 0 so we can
    // mark it CFG-valid for RtlUserThreadStart's bitmap check.
    uintptr_t stub_valloc_b = 0;
    {
        void* svpage = VirtualAllocEx(process, nullptr, 0x1000,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (svpage) {
            if (WriteProcessMemory(process, svpage, stub_b, nb ? nb : 64, nullptr)) {
                DWORD old2 = 0;
                VirtualProtectEx(process, svpage, 0x1000, PAGE_EXECUTE_READ, &old2);
                if (sc.ready() && sc.FlushInstructionCache)
                    sc.FlushInstructionCache(process, svpage, 0x100);
                else { resolve_ntdll(); if (s_NtFlush) s_NtFlush(process, svpage, 0x100); }
                stub_valloc_b = (uintptr_t)svpage;
                VT_LOG(L"ManualMap: stub_valloc=0x" + [&]{ wchar_t b[20]; swprintf_s(b, L"%llX", (ULONGLONG)stub_valloc_b); return std::wstring(b); }());
            } else {
                VirtualFreeEx(process, svpage, 0, MEM_RELEASE);
                VT_WARN(L"ManualMap: WPM to stub_valloc failed err=" + std::to_wstring(GetLastError()));
            }
        } else {
            VT_WARN(L"ManualMap: VirtualAllocEx stub page failed err=" + std::to_wstring(GetLastError()));
        }
    }
    if (sc.ready() && sc.FlushInstructionCache) {
        sc.FlushInstructionCache(process, (void*)stub_addr, 0x200);
    } else {
        resolve_ntdll();
        if (s_NtFlush)
            s_NtFlush(process, (void*)stub_addr, 0x200);
    }

    VT_LOG(L"ManualMap: stubs written — finding jmp rcx gadget");
    const uintptr_t gadget = ntdll_jmp_rcx();
    VT_LOG(L"ManualMap: gadget=0x" + [&]{ wchar_t b[20]; swprintf_s(b, L"%llX", (ULONGLONG)gadget); return std::wstring(b); }() +
           L"  stub_spin=0x" + [&]{ wchar_t b[20]; swprintf_s(b, L"%llX", (ULONGLONG)stub_addr); return std::wstring(b); }() +
           L"  stub_ret=0x"  + [&]{ wchar_t b[20]; swprintf_s(b, L"%llX", (ULONGLONG)stub_addr_b); return std::wstring(b); }());
    const DWORD pid = GetProcessId(process);
    bool started = false;

    // 1. IAT hook — MUST be tried first, before any thread operation.
    //    Thread hijack, APC, and NtCreateThreadEx all trigger Hyperion's
    //    shutdown response (STATUS_PROCESS_IS_TERMINATING / threads killed).
    //    The ghost section mapping alone does NOT trigger termination, so the
    //    IAT hook has a clean window here.  An existing Roblox thread calls
    //    the hooked import naturally. Stub stays installed as the lasting tick.
    uintptr_t tick = 0;
    if (DWORD trva = export_rva(raw.data(), nt, "VT_TICK"))
        tick = remote_base + trva;

    VT_LOG(L"ManualMap: trying IAT hook path (primary — no thread ops)");
    uintptr_t iat_slot = 0, iat_stub = 0, iat_orig = 0;
    started = try_iat_hook(process, remote_base, entry, tick, tls_cbs, &iat_slot, &iat_stub, &iat_orig);

    if (!started) {
        r.error = L"DllMain did not run — IAT hook never fired";
        return r;
    }
    // Do not IAT-hook KERNEL32 NtWaitForSingleObject. That import is process-wide;
    // calling C++ from it closed Roblox even with a full nonvolatile stub.
    r.wait_hooked = false;

    r.ok = true;
    r.base = remote_base;
    r.iat_slot = iat_slot;
    r.iat_stub = iat_stub;
    r.iat_orig = iat_orig;
    return r;
}

} // namespace vt
