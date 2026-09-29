#include "lua/JobHook.h"
#include "lua/Execution.h"
#include "lua/Environment.h"
#include "lua/Scheduler.h"
#include "lua/Offsets.h"
#include "lua/LuaApi.h"
#include "lua/libs/Drawing.h"
#include "dll/Module.h"
#include "shared/Log.h"
#include "shared/Utils.h"
#include "shared/OffBlob.h"

#include <Windows.h>
#include <atomic>
#include <cstring>
#include <iterator>

extern "C" volatile VTOffBlob VT_OFF;

namespace vt {
namespace {

// Dummy VF slots first (open-source job tickers hook the empty return-0).
constexpr int kSlots[] = {2, 3, 4, 6, 5, 7, 8, 9, 10};
constexpr int kSlotN = (int)std::size(kSlots);
constexpr int kVtCopy = 32;
constexpr uintptr_t kFnSpan = 0x1800;

std::atomic<bool> g_armed{false};
std::atomic<bool> g_in_work{false};
std::atomic<DWORD> g_safe_tid{0};
std::atomic<DWORD> g_last_pulse{0};

uintptr_t     g_job = 0;
uintptr_t     g_step[kSlotN]{};
int           g_step_n = 0;
bool          g_probing = false;
bool          g_logged_arm = false;
bool          g_collected = false;
bool          g_logged_iat = false;
void*         g_alloc_orig = nullptr;
uintptr_t     g_alloc_slot = 0;
void*         g_stub_page = nullptr;
DWORD         g_lua_tid = 0;
lua_State*    g_hint_L = nullptr;
bool          g_apc_pump = false;
bool          g_guard_pump = false;
void*         g_redirect_page = nullptr;
HANDLE        g_lua_th = nullptr;
std::atomic<bool> g_apc_pending{false};

struct TidHook {
    uintptr_t slot = 0;
    void*     orig = nullptr;
    void*     page = nullptr;
    bool      vptr = false;  // slot is job+off, orig is previous vptr
    uintptr_t steal = 0;     // job+disp holding stub ptr (rcx proxy)
    void*     steal_orig = nullptr;
};
TidHook g_hooks[8]{};
int     g_hook_n = 0;
PVOID   g_veh = nullptr;
std::atomic<DWORD> g_tf_tid{0};

struct ImgRange {
    uintptr_t base = 0;
    size_t    size = 0;
};
ImgRange g_imgs[4]{};
int      g_img_n = 0;

bool looks_ptr(uintptr_t p) {
    return p > 0x10000 && p < 0x00007FFFFFFFFFFFULL;
}

bool looks_heap(uintptr_t p) {
    return p > 0x10000 && p < 0x00007F0000000000ULL;
}

void refresh_images() {
    g_img_n = 0;
    auto add = [&](uintptr_t b, size_t n) {
        if (!b || !n || g_img_n >= 4)
            return;
        for (int i = 0; i < g_img_n; ++i)
            if (g_imgs[i].base == b)
                return;
        g_imgs[g_img_n++] = {b, n};
    };
    const auto& r = OffsetResolver::current();
    add(r.image_base, r.image_size);
    if (auto m = find_module_local(L"RobloxPlayerBeta.exe"))
        add(m->base, m->size);
    if (auto m = find_module_local(L"RobloxPlayerBeta.dll"))
        add(m->base, m->size);
}

bool in_listed_image(uintptr_t p) {
    for (int i = 0; i < g_img_n; ++i) {
        if (p >= g_imgs[i].base && p < g_imgs[i].base + g_imgs[i].size)
            return true;
    }
    return false;
}

bool is_rbx_code(uintptr_t p) {
    return looks_ptr(p) && in_listed_image(p);
}

bool seh_read(uintptr_t addr, void* out, size_t n) {
    __try {
        memcpy(out, (const void*)addr, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

uintptr_t decode_vptr(uintptr_t job, uintptr_t raw) {
    const auto& r = OffsetResolver::current();
    const uintptr_t cands[] = {
        raw,
        raw ^ job,
        raw ^ r.image_base,
        raw ^ (r.image_base + (uintptr_t)r.image_size),
        raw + r.image_base,
        raw - r.image_base,
    };
    for (uintptr_t c : cands) {
        if (!looks_ptr(c))
            continue;
        void* fn0 = nullptr;
        if (!seh_read(c, &fn0, sizeof(fn0)))
            continue;
        if (is_rbx_code((uintptr_t)fn0))
            return c;
    }
    return looks_ptr(raw) ? raw : 0;
}

uintptr_t find_vtable(uintptr_t job) {
    for (int off = 0; off <= 0x40; off += 8) {
        uintptr_t raw = 0;
        if (!seh_read(job + (uintptr_t)off, &raw, sizeof(raw)))
            continue;
        const uintptr_t vt = decode_vptr(job, raw);
        if (!vt)
            continue;
        void* fn0 = nullptr;
        if (seh_read(vt, &fn0, sizeof(fn0)) && is_rbx_code((uintptr_t)fn0))
            return vt;
    }
    return 0;
}

void collect_steps(uintptr_t job) {
    if (g_collected)
        return;
    g_collected = true;
    g_step_n = 0;
    const uintptr_t vt = find_vtable(job);
    if (!vt) {
        uintptr_t raw = 0;
        seh_read(job, &raw, sizeof(raw));
        VT_WARN(L"job vptr not usable " + format_hex(raw) + L" job " + format_hex(job));
        return;
    }
    VT_LOG(L"job vtable " + format_hex(vt) +
           (in_listed_image(vt) ? L" (image)" : L" (heap)"));

    wchar_t dump[384]{};
    size_t n = 0;
    for (int i = 0; i < 8; ++i) {
        void* fn = nullptr;
        seh_read(vt + (uintptr_t)i * 8, &fn, sizeof(fn));
        n += (size_t)swprintf_s(dump + n, std::size(dump) - n, L" [%d]%s",
                                i, format_hex((uintptr_t)fn).c_str());
        if (n + 8 >= std::size(dump))
            break;
    }
    VT_LOG(L"vt slots" + std::wstring(dump));

    for (int i = 0; i < kSlotN && g_step_n < kSlotN; ++i) {
        const int slot = kSlots[i];
        if (slot < 0 || slot >= kVtCopy)
            continue;
        void* fn = nullptr;
        if (!seh_read(vt + (uintptr_t)slot * 8, &fn, sizeof(fn)))
            continue;
        const uintptr_t p = (uintptr_t)fn;
        if (!is_rbx_code(p))
            continue;
        g_step[g_step_n++] = p;
    }
    VT_LOG(L"step candidates " + std::to_wstring(g_step_n));
}

bool frame_is_step(uintptr_t p) {
    for (int i = 0; i < g_step_n; ++i) {
        if (p >= g_step[i] && p < g_step[i] + kFnSpan)
            return true;
    }
    const auto& r = OffsetResolver::current();
    if (r.lua_pcall && p >= r.lua_pcall && p < r.lua_pcall + 0x400)
        return true;
    if (r.luau_load && p >= r.luau_load && p < r.luau_load + 0x800)
        return true;
    return false;
}

bool stack_on_script_job() {
    void* frames[28]{};
    const USHORT n = CaptureStackBackTrace(0, 28, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
        if (frame_is_step((uintptr_t)frames[i]))
            return true;
    }
    return false;
}

void do_pump(lua_State* hint) {
    auto& api = LuaApi::instance();
    auto& ex = Execution::instance();
    // Never Scheduler::state_from here — in-process job brute is a Hyperion VEH kill.
    lua_State* L = hint;
    if (!L || !api.plausible_state(L))
        L = g_hint_L;
    if (!L || !api.plausible_state(L))
        L = ex.state();
    if (!L || !api.plausible_state(L)) {
        static DWORD lastw = 0;
        const DWORD now = GetTickCount();
        if (now - lastw > 2500) {
            lastw = now;
            VT_WARN(L"no lua_State on job " + format_hex(g_job));
        }
        return;
    }
    const int top = api.gettop(L);
    if (ex.state() != L)
        ex.set_state(L);
    if (!Environment::bootstrapped())
        Environment::bootstrap(L);
    if (ex.state())
        ex.pump();
    libs::render_drawings();
    if (top >= 0)
        api.settop(L, top);
    if (!g_armed.load()) {
        g_armed.store(true);
        g_probing = false;
        if (!g_logged_arm) {
            g_logged_arm = true;
            VT_LOG(L"pump live on script thread");
        }
        module_note_ready();
    }
}

int seh_pump(lua_State* hint) {
    __try {
        do_pump(hint);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

bool seh_iat_name(const char* a, const char* b) {
    __try {
        return a && b && strcmp(a, b) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

uintptr_t find_import_slot(HMODULE hm, const char* func) {
    if (!hm || !func)
        return 0;
    auto* base = (uint8_t*)hm;
    uintptr_t slot = 0;
    __try {
        auto* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;
        auto* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return 0;
        const auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!dir.VirtualAddress)
            return 0;
        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
        for (; desc->Name; ++desc) {
            const uintptr_t ilt_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            auto* thunk = (IMAGE_THUNK_DATA64*)(base + ilt_rva);
            auto* iat = (IMAGE_THUNK_DATA64*)(base + desc->FirstThunk);
            for (; thunk->u1.AddressOfData; ++thunk, ++iat) {
                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal))
                    continue;
                auto* ibn = (IMAGE_IMPORT_BY_NAME*)(base + thunk->u1.AddressOfData);
                if (seh_iat_name((const char*)ibn->Name, func)) {
                    slot = (uintptr_t)&iat->u1.Function;
                    break;
                }
            }
            if (slot)
                break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return slot;
}

// Direct ntdll syscall — bypasses user-mode VirtualProtect hooks (Hyperion
// hooks kernelbase!VirtualProtect and denies with ERROR_ACCESS_DENIED err=5;
// going straight to ntdll!NtProtectVirtualMemory skips that hook).
using NtProtect_t = LONG (NTAPI*)(HANDLE, PVOID*, SIZE_T*, ULONG, PULONG);
static NtProtect_t nt_protect() {
    static NtProtect_t fn = nullptr;
    if (!fn) {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) fn = (NtProtect_t)GetProcAddress(nt, "NtProtectVirtualMemory");
    }
    return fn;
}

static bool syscall_protect(uintptr_t addr, size_t size, ULONG new_prot, ULONG* old_out) {
    auto fn = nt_protect();
    if (!fn) return false;
    PVOID base = (PVOID)addr;
    SIZE_T sz = size;
    ULONG old = 0;
    const LONG status = fn(GetCurrentProcess(), &base, &sz, new_prot, &old);
    if (status < 0) return false;
    if (old_out) *old_out = old;
    return true;
}

bool patch_iat_ptr(uintptr_t slot, void* v) {
    ULONG old = 0;
    // Try direct syscall first (bypasses hook); fall back to VirtualProtect.
    bool wrote_writable = syscall_protect(slot, 8, PAGE_READWRITE, &old);
    if (!wrote_writable) {
        DWORD dold = 0;
        if (!VirtualProtect((void*)slot, 8, PAGE_READWRITE, &dold))
            return false;
        old = (ULONG)dold;
    }
    __try {
        *(void**)slot = v;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        syscall_protect(slot, 8, old, nullptr);
        return false;
    }
    syscall_protect(slot, 8, old, nullptr);
    return true;
}

bool work_waiting() {
    if (!Environment::bootstrapped())
        return true;
    if (Execution::instance().pending())
        return true;
    if (libs::drawing_live())
        return true;
    return false;
}

void pulse_from_stub() {
    JobHook::pulse();
}

// External-hook stub — the exe patches a game IAT slot to point here.
// Signature is 4-arg pass-through: hooked functions typically have 1-4 args,
// all in rcx/rdx/r8/r9. We MUST pass them through — the previous zero-arg
// version corrupted RtlEnterCriticalSection and crashed Roblox.
//
// PRE-INITIALIZED: There's a race window between the exe patching the IAT
// slot and the DLL receiving the orig via pipe (~10ms). During that window,
// THOUSANDS of RtlAllocateHeap calls hit our stub. If g_ext_orig is null,
// the stub returns 0 (allocation failed) — every allocator in Roblox breaks
// and the process crashes instantly. Pre-set at DLL load to the real
// ntdll!RtlAllocateHeap so the stub is safe from the first nanosecond.
static void* resolve_ntdll_import(const char* name) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    return nt ? (void*)GetProcAddress(nt, name) : nullptr;
}
extern "C" {
    __declspec(dllexport) volatile void* g_ext_orig = resolve_ntdll_import("RtlAllocateHeap");
}

// Non-inline so pulse's side effects don't get folded in and disturb args.
__declspec(noinline) static void pulse_isolated() {
    __try { JobHook::pulse(); } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// Tail-call to orig — MSVC /O2 emits `jmp` here so the caller's stack layout
// (including args 5+ if any) passes through untouched to orig. Args in
// rcx/rdx/r8/r9 are preserved by the compiler via spill/reload around pulse.
extern "C" __declspec(dllexport)
ULONGLONG WINAPI vt_ext_hook_zero(void* a1, void* a2, void* a3, void* a4) {
    // Pass-through only. Pulsing from HeapAlloc/CRT IAT re-entered the
    // allocator and CFG-killed Roblox. Job-thread vtable clone is the pump.
    auto orig = (ULONGLONG (WINAPI*)(void*, void*, void*, void*))g_ext_orig;
    if (!orig) return 0;
    return orig(a1, a2, a3, a4);
}

// Vtable variant — the caller is a per-job scheduler slot, so we KNOW we're on
// the Lua thread. Set g_lua_tid on first call without needing a backtrace match.
void pulse_from_vtable() {
    if (!g_lua_tid) {
        const DWORD tid = GetCurrentThreadId();
        g_lua_tid = tid;
        g_safe_tid.store(tid);
        Logger::instance().set_thread_silent(true);
        VT_LOG(L"lua thread via vtable tid=" + std::to_wstring(tid));
        Logger::instance().set_thread_silent(false);
    }
    JobHook::pulse();
}

bool cfg_allow(void* page, ULONG_PTR offset = 0) {
#ifndef CFG_CALL_TARGET_VALID_XFG
#define CFG_CALL_TARGET_VALID_XFG 0x00000008ull
#endif
    using NtSivm = LONG(NTAPI*)(HANDLE, ULONG, ULONG_PTR, void*, void*, ULONG);
    static NtSivm sivm = nullptr;
    static bool sivm_tried = false;
    if (!sivm_tried) {
        sivm_tried = true;
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt)
            sivm = (NtSivm)GetProcAddress(nt, "NtSetInformationVirtualMemory");
    }
    if (sivm) {
        struct Range { void* va; SIZE_T n; } range{ page, 0x1000 };
        const ULONG_PTR flags[] = { 1ull, 1ull | CFG_CALL_TARGET_VALID_XFG };
        for (ULONG_PTR fl : flags) {
            struct { ULONG_PTR off; ULONG_PTR flags; } tgt{ offset, fl };
            ULONG processed = 0;
            struct Info {
                ULONG n; ULONG reserved; ULONG* processed;
                void* targets; void* section; ULONGLONG file_off;
            } inf{ 1, 0, &processed, &tgt, nullptr, 0 };
            const LONG st = sivm(GetCurrentProcess(), 2, 1, &range, &inf, sizeof(inf));
            if (st >= 0) {
                VT_LOG(L"CFG NtSIVM ok flags=" + std::to_wstring((unsigned long long)fl));
                return true;
            }
            VT_WARN(L"CFG NtSIVM ns=" + std::to_wstring((unsigned)st));
        }
    }
    using Fn = BOOL(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, void*);
    static Fn spv = nullptr;
    if (!spv) {
        HMODULE k = GetModuleHandleW(L"kernelbase.dll");
        if (k)
            spv = (Fn)GetProcAddress(k, "SetProcessValidCallTargets");
    }
    if (!spv)
        return false;
    const ULONG_PTR tries[] = { 1ull, 1ull | CFG_CALL_TARGET_VALID_XFG };
    ULONG n = 1;
    for (ULONG_PTR fl : tries) {
        struct {
            ULONG_PTR off;
            ULONG_PTR flags;
        } info{offset, fl};
        if (spv(GetCurrentProcess(), page, 0x1000, n, &info))
            return true;
    }
    VT_WARN(L"SetProcessValidCallTargets err=" + std::to_wstring(GetLastError()));
    return false;
}

bool install_one_tid_hook(const wchar_t* mod, const char* func) {
    static int diag_left = 3;   // log the first few failures per session
    auto diag = [&](const wchar_t* why) {
        if (diag_left <= 0) return;
        --diag_left;
        VT_WARN(std::wstring(L"hook fail ") + mod + L"!" + utf8_to_wide(func) + L" — " + why);
    };
    if (g_hook_n >= 8)
        return false;
    HMODULE hm = GetModuleHandleW(mod);
    if (!hm)
        return false;
    const uintptr_t slot = find_import_slot(hm, func);
    if (!slot)
        return false;
    for (int i = 0; i < g_hook_n; ++i)
        if (g_hooks[i].slot == slot)
            return true;
    // Use direct ntdll syscall — user-mode VirtualProtect is hooked and returns
    // ERROR_ACCESS_DENIED (err=5) for game .rdata pages.
    ULONG old = 0;
    if (!syscall_protect(slot, 8, PAGE_READWRITE, &old)) {
        DWORD dold = 0;
        if (!VirtualProtect((void*)slot, 8, PAGE_READWRITE, &dold)) {
            diag((L"protect IAT slot err=" + std::to_wstring(GetLastError())).c_str());
            return false;
        }
        old = (ULONG)dold;
    }
    void* orig = *(void**)slot;
    syscall_protect(slot, 8, old, nullptr);
    if (!orig) {
        diag(L"orig ptr null");
        return false;
    }

    void* page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) {
        diag((L"VirtualAlloc err=" + std::to_wstring(GetLastError())).c_str());
        return false;
    }
    uint8_t* p = (uint8_t*)page;
    // Unconditional stub — calls original, then calls pulse_from_stub on every invocation.
    // Lua thread identification is done inside pulse() via CaptureStackBackTrace.
    constexpr int kOrig = 0xC0, kPulse = 0xC8;
    *(void**)(p + kOrig)  = orig;
    *(void**)(p + kPulse) = (void*)&pulse_from_stub;

    auto put_rel = [&](int at, int target) {
        const int32_t rel = target - (at + 4);
        memcpy(p + at, &rel, 4);
    };
    int h = 0;
    p[h++] = 0x53;                          // push rbx
    p[h++] = 0x48; p[h++] = 0x83; p[h++] = 0xEC; p[h++] = 0x20; // sub rsp, 0x20
    p[h++] = 0x48; p[h++] = 0x8B; p[h++] = 0x05; // mov rax, [rip+kOrig]
    put_rel(h, kOrig); h += 4;
    p[h++] = 0xFF; p[h++] = 0xD0;           // call rax  (original func)
    p[h++] = 0x48; p[h++] = 0x89; p[h++] = 0xC3; // mov rbx, rax  (save retval)
    p[h++] = 0x48; p[h++] = 0x8B; p[h++] = 0x05; // mov rax, [rip+kPulse]
    put_rel(h, kPulse); h += 4;
    p[h++] = 0xFF; p[h++] = 0xD0;           // call rax  (pulse_from_stub, unconditional)
    p[h++] = 0x48; p[h++] = 0x89; p[h++] = 0xD8; // mov rax, rbx  (restore retval)
    p[h++] = 0x48; p[h++] = 0x83; p[h++] = 0xC4; p[h++] = 0x20; // add rsp, 0x20
    p[h++] = 0x5B;                           // pop rbx
    p[h++] = 0xC3;                           // ret

    ULONG tp = 0;
    if (!syscall_protect((uintptr_t)page, 0x1000, PAGE_EXECUTE_READ, &tp)) {
        DWORD dtp = 0;
        if (!VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &dtp)) {
            diag((L"protect stub RX err=" + std::to_wstring(GetLastError())).c_str());
            VirtualFree(page, 0, MEM_RELEASE);
            return false;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), page, 0x100);
    cfg_allow(page);
    if (!patch_iat_ptr(slot, page)) {
        diag((L"patch_iat_ptr failed err=" + std::to_wstring(GetLastError())).c_str());
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }
    auto& hk = g_hooks[g_hook_n++];
    hk.slot = slot;
    hk.orig = orig;
    hk.page = page;
    g_stub_page = page;
    g_alloc_slot = slot;
    g_alloc_orig = orig;
    VT_LOG(L"iathook " + std::wstring(mod) + L"!" + utf8_to_wide(func) + L" (unconditional)");
    return true;
}


static bool seh_write_ptr(uintptr_t addr, void* val) {
    __try {
        *(void**)addr = val;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Host already scanned ntdll (same VA). Module never walks Roblox .text.
struct CfgProxy {
    void* gadget = nullptr;
    int   disp = 0;
    bool  via_rax = true;
};

bool proxy_usable(const CfgProxy& g) {
    if (!g.gadget || g.disp <= 0 || (g.disp & 7))
        return false;
    return g.disp >= 8 && g.disp <= 0x3F8;
}

CfgProxy blob_proxy() {
    CfgProxy g{};
    if (memcmp((const void*)VT_OFF.mag, "VT_OFFS", 7) != 0)
        return g;
    g.gadget  = (void*)(uintptr_t)VT_OFF.cfg_gadget;
    g.disp    = (int)VT_OFF.cfg_disp;
    g.via_rax = VT_OFF.cfg_via_rax != 0;
    if (!proxy_usable(g)) {
        g.gadget = nullptr;
        return g;
    }
    return g;
}

// Clone the (usually image) vtable onto a heap page, hook Step, swap the
// job's vptr. Never VirtualProtect Roblox .rdata.
bool install_vtable_hook(uintptr_t job) {
    if (g_hook_n >= 8) return false;
    if (!looks_heap(job)) return false;
    const uintptr_t vt = find_vtable(job);
    if (!vt) {
        VT_WARN(L"vtable hook: no vtable for job " + format_hex(job));
        return false;
    }

    int vptr_off = -1;
    for (int off = 0; off <= 0x40; off += 8) {
        uintptr_t raw = 0;
        if (!seh_read(job + (uintptr_t)off, &raw, sizeof(raw)))
            continue;
        if (decode_vptr(job, raw) == vt) {
            vptr_off = off;
            break;
        }
    }
    if (vptr_off < 0) {
        VT_WARN(L"vtable hook: no vptr field on job");
        return false;
    }

    const CfgProxy proxy = blob_proxy();
    if (!proxy.gadget) {
        VT_WARN(L"vtable hook skipped — host found no CFG gadget");
        return false;
    }

    int use_slot = -1;
    void* orig = nullptr;
    for (int i = 0; i < kSlotN; ++i) {
        const int slot = kSlots[i];
        if (slot < 0 || slot >= kVtCopy) continue;
        if (slot * 8 == proxy.disp) continue;
        void* fn = nullptr;
        if (!seh_read(vt + (uintptr_t)slot * 8, &fn, sizeof(fn))) continue;
        if (!is_rbx_code((uintptr_t)fn)) continue;
        use_slot = slot;
        orig = fn;
        break;
    }
    if (use_slot < 0 || !orig) {
        VT_WARN(L"vtable hook: no usable dummy slot in vt " + format_hex(vt));
        return false;
    }

    void* page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) return false;
    uint8_t* p = (uint8_t*)page;
    for (int i = 0; i < kVtCopy; ++i) {
        void* fn = nullptr;
        seh_read(vt + (uintptr_t)i * 8, &fn, sizeof(fn));
        *(void**)(p + (uintptr_t)i * 8) = fn;
    }

    constexpr int kStub = 0x200, kOrig = 0x2C0, kPulse = 0x2C8;
    *(void**)(p + kOrig)  = orig;
    *(void**)(p + kPulse) = (void*)&pulse_from_vtable;

    uint8_t* s = p + kStub;
    auto put_rel = [&](int at, int abs_off) {
        const int32_t rel = abs_off - (kStub + at + 4);
        memcpy(s + at, &rel, 4);
    };
    int h = 0;
    s[h++] = 0x53;
    s[h++] = 0x48; s[h++] = 0x83; s[h++] = 0xEC; s[h++] = 0x20;
    s[h++] = 0x48; s[h++] = 0x8B; s[h++] = 0x05;
    put_rel(h, kOrig); h += 4;
    s[h++] = 0xFF; s[h++] = 0xD0;
    s[h++] = 0x48; s[h++] = 0x89; s[h++] = 0xC3;
    s[h++] = 0x48; s[h++] = 0x8B; s[h++] = 0x05;
    put_rel(h, kPulse); h += 4;
    s[h++] = 0xFF; s[h++] = 0xD0;
    s[h++] = 0x48; s[h++] = 0x89; s[h++] = 0xD8;
    s[h++] = 0x48; s[h++] = 0x83; s[h++] = 0xC4; s[h++] = 0x20;
    s[h++] = 0x5B;
    s[h++] = 0xC3;

    // Slot holds a CFG-valid gadget, NOT our stub. Stub pointer sits at +disp.
    *(void**)(p + (uintptr_t)use_slot * 8) = proxy.gadget;
    uintptr_t steal = 0;
    void* steal_orig = nullptr;
    if (proxy.via_rax) {
        *(void**)(p + (uintptr_t)proxy.disp) = (void*)(p + kStub);
    } else {
        steal = job + (uintptr_t)proxy.disp;
        seh_read(steal, &steal_orig, sizeof(steal_orig));
        if (!seh_write_ptr(steal, (void*)(p + kStub))) {
            VirtualFree(page, 0, MEM_RELEASE);
            VT_WARN(L"rcx-proxy steal write failed");
            return false;
        }
    }

    DWORD tp = 0;
    VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &tp);
    FlushInstructionCache(GetCurrentProcess(), page, 0x100);

    const uintptr_t vptr_addr = job + (uintptr_t)vptr_off;
    if (!seh_write_ptr(vptr_addr, page)) {
        if (steal)
            seh_write_ptr(steal, steal_orig);
        VirtualFree(page, 0, MEM_RELEASE);
        VT_WARN(L"vptr write faulted @" + format_hex(vptr_addr));
        return false;
    }

    auto& hk = g_hooks[g_hook_n++];
    hk.slot = vptr_addr;
    hk.orig = (void*)vt;
    hk.page = page;
    hk.vptr = true;
    hk.steal = steal;
    hk.steal_orig = steal_orig;
    g_stub_page = page;
    VT_LOG(L"vtable clone slot " + std::to_wstring(use_slot) +
           L" via CFG gadget " + format_hex((uintptr_t)proxy.gadget) +
           (proxy.via_rax ? L" [rax+" : L" [rcx+") +
           format_hex((uintptr_t)proxy.disp) + L"] orig " +
           format_hex((uintptr_t)orig));
    return true;
}

// PAGE_GUARD on a *data* clone of the job vtable. The job thread faults on
// the slot read, *before* CFG sees a call target. We do NOT lua_pcall inside
// the VEH (that path died at 92%). Rip is steered to a private stub; the stub
// runs as normal code, pumps, then tails to the original slot pointer.
constexpr int kGuardStub = 0x200, kGuardOrig = 0x2C0, kGuardPulse = 0x2C8;

void write_redirect_stub(uint8_t* p) {
    *(void**)(p + kGuardPulse) = (void*)&pulse_from_vtable;
    uint8_t* s = p + kGuardStub;
    auto put_rel = [&](int at, int abs_off) {
        const int32_t rel = abs_off - (kGuardStub + at + 4);
        memcpy(s + at, &rel, 4);
    };
    int h = 0;
    s[h++] = 0x41; s[h++] = 0x51;                         // push r9
    s[h++] = 0x41; s[h++] = 0x50;                         // push r8
    s[h++] = 0x52;                                        // push rdx
    s[h++] = 0x51;                                        // push rcx
    s[h++] = 0x48; s[h++] = 0x83; s[h++] = 0xEC; s[h++] = 0x28; // sub rsp, 0x28
    s[h++] = 0x48; s[h++] = 0x8B; s[h++] = 0x05;          // mov rax, [rip+kPulse]
    put_rel(h, kGuardPulse); h += 4;
    s[h++] = 0xFF; s[h++] = 0xD0;                         // call rax  (pulse)
    s[h++] = 0x48; s[h++] = 0x83; s[h++] = 0xC4; s[h++] = 0x28; // add rsp, 0x28
    s[h++] = 0x59;                                        // pop rcx
    s[h++] = 0x5A;                                        // pop rdx
    s[h++] = 0x41; s[h++] = 0x58;                         // pop r8
    s[h++] = 0x41; s[h++] = 0x59;                         // pop r9
    s[h++] = 0x48; s[h++] = 0x8B; s[h++] = 0x05;          // mov rax, [rip+kOrig]
    put_rel(h, kGuardOrig); h += 4;
    s[h++] = 0xFF; s[h++] = 0xE0;                         // jmp rax
}

LONG CALLBACK vt_guard_veh(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const uintptr_t page = (uintptr_t)g_stub_page;
    if (code != EXCEPTION_GUARD_PAGE)
        return EXCEPTION_CONTINUE_SEARCH;
    const uintptr_t addr = ep->ExceptionRecord->ExceptionInformation[1];
    if (!page || addr < page || addr >= page + 0x1000)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!g_redirect_page)
        return EXCEPTION_CONTINUE_SEARCH;

    void* orig = nullptr;
    seh_read(addr, &orig, sizeof(orig));
    if (!orig)
        return EXCEPTION_CONTINUE_EXECUTION; // guard already consumed; retry the read
    *(void**)((uint8_t*)g_redirect_page + kGuardOrig) = orig;

    DWORD old = 0;
    VirtualProtect((void*)page, 0x1000, PAGE_READONLY, &old);
    ep->ContextRecord->Rip = (DWORD64)((uint8_t*)g_redirect_page + kGuardStub);
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool install_vtable_guard(uintptr_t job) {
    if (g_hook_n >= 8) return false;
    if (!looks_heap(job)) return false;
    const uintptr_t vt = find_vtable(job);
    if (!vt) {
        VT_WARN(L"vtable guard: no vtable for job " + format_hex(job));
        return false;
    }

    int vptr_off = -1;
    for (int off = 0; off <= 0x40; off += 8) {
        uintptr_t raw = 0;
        if (!seh_read(job + (uintptr_t)off, &raw, sizeof(raw)))
            continue;
        if (decode_vptr(job, raw) == vt) {
            vptr_off = off;
            break;
        }
    }
    if (vptr_off < 0) {
        VT_WARN(L"vtable guard: no vptr field on job");
        return false;
    }

    void* page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) return false;
    uint8_t* p = (uint8_t*)page;
    for (int i = 0; i < kVtCopy; ++i) {
        void* fn = nullptr;
        seh_read(vt + (uintptr_t)i * 8, &fn, sizeof(fn));
        *(void**)(p + (uintptr_t)i * 8) = fn;
    }

    void* stub = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stub) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }
    write_redirect_stub((uint8_t*)stub);
    DWORD stp = 0;
    if (!VirtualProtect(stub, 0x1000, PAGE_EXECUTE_READ, &stp)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        VirtualFree(page, 0, MEM_RELEASE);
        VT_WARN(L"vtable guard: stub RX err=" + std::to_wstring(GetLastError()));
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), stub, 0x100);

    DWORD tp = 0;
    if (!VirtualProtect(page, 0x1000, PAGE_READONLY | PAGE_GUARD, &tp)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        VirtualFree(page, 0, MEM_RELEASE);
        VT_WARN(L"vtable guard: PAGE_GUARD protect err=" + std::to_wstring(GetLastError()));
        return false;
    }

    if (!g_veh)
        g_veh = AddVectoredExceptionHandler(1, vt_guard_veh);
    if (!g_veh) {
        VirtualFree(stub, 0, MEM_RELEASE);
        VirtualFree(page, 0, MEM_RELEASE);
        VT_WARN(L"vtable guard: AddVectoredExceptionHandler failed");
        return false;
    }

    const uintptr_t vptr_addr = job + (uintptr_t)vptr_off;
    if (!seh_write_ptr(vptr_addr, page)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        VirtualFree(page, 0, MEM_RELEASE);
        VT_WARN(L"vtable guard: vptr write faulted @" + format_hex(vptr_addr));
        return false;
    }

    auto& hk = g_hooks[g_hook_n++];
    hk.slot = vptr_addr;
    hk.orig = (void*)vt;
    hk.page = page;
    hk.vptr = true;
    g_stub_page = page;
    g_redirect_page = stub;
    VT_LOG(L"vtable guard clone " + format_hex((uintptr_t)page) +
           L" stub " + format_hex((uintptr_t)stub) +
           L" orig vt " + format_hex(vt) + L" — PAGE_GUARD pump");
    return true;
}

bool install_vtable_cfg_mark(uintptr_t job) {
    if (g_hook_n >= 8) return false;
    if (!looks_heap(job)) return false;
    const uintptr_t vt = find_vtable(job);
    if (!vt) return false;

    int vptr_off = -1;
    for (int off = 0; off <= 0x40; off += 8) {
        uintptr_t raw = 0;
        if (!seh_read(job + (uintptr_t)off, &raw, sizeof(raw)))
            continue;
        if (decode_vptr(job, raw) == vt) {
            vptr_off = off;
            break;
        }
    }
    if (vptr_off < 0) return false;

    int use_slot = -1;
    void* orig = nullptr;
    for (int i = 0; i < kSlotN; ++i) {
        const int slot = kSlots[i];
        if (slot < 0 || slot >= kVtCopy) continue;
        void* fn = nullptr;
        if (!seh_read(vt + (uintptr_t)slot * 8, &fn, sizeof(fn))) continue;
        if (!is_rbx_code((uintptr_t)fn)) continue;
        use_slot = slot;
        orig = fn;
        break;
    }
    if (use_slot < 0 || !orig) return false;

    void* page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) return false;
    uint8_t* p = (uint8_t*)page;
    for (int i = 0; i < kVtCopy; ++i) {
        void* fn = nullptr;
        seh_read(vt + (uintptr_t)i * 8, &fn, sizeof(fn));
        *(void**)(p + (uintptr_t)i * 8) = fn;
    }

    constexpr int kStub = 0x200, kOrig = 0x2C0, kPulse = 0x2C8;
    *(void**)(p + kOrig)  = orig;
    *(void**)(p + kPulse) = (void*)&pulse_from_vtable;

    uint8_t* s = p + kStub;
    auto put_rel = [&](int at, int abs_off) {
        const int32_t rel = abs_off - (kStub + at + 4);
        memcpy(s + at, &rel, 4);
    };
    int h = 0;
    s[h++] = 0x53;
    s[h++] = 0x48; s[h++] = 0x83; s[h++] = 0xEC; s[h++] = 0x20;
    s[h++] = 0x48; s[h++] = 0x8B; s[h++] = 0x05;
    put_rel(h, kOrig); h += 4;
    s[h++] = 0xFF; s[h++] = 0xD0;
    s[h++] = 0x48; s[h++] = 0x89; s[h++] = 0xC3;
    s[h++] = 0x48; s[h++] = 0x8B; s[h++] = 0x05;
    put_rel(h, kPulse); h += 4;
    s[h++] = 0xFF; s[h++] = 0xD0;
    s[h++] = 0x48; s[h++] = 0x89; s[h++] = 0xD8;
    s[h++] = 0x48; s[h++] = 0x83; s[h++] = 0xC4; s[h++] = 0x20;
    s[h++] = 0x5B;
    s[h++] = 0xC3;

    *(void**)(p + (uintptr_t)use_slot * 8) = (void*)(p + kStub);

    DWORD tp = 0;
    VirtualProtect(page, 0x1000, PAGE_EXECUTE_READ, &tp);
    FlushInstructionCache(GetCurrentProcess(), page, 0x100);
    if (!cfg_allow(page, (ULONG_PTR)kStub)) {
        VirtualFree(page, 0, MEM_RELEASE);
        VT_WARN(L"vtable cfg-mark: stub is not a valid call target");
        return false;
    }

    const uintptr_t vptr_addr = job + (uintptr_t)vptr_off;
    if (!seh_write_ptr(vptr_addr, page)) {
        VirtualFree(page, 0, MEM_RELEASE);
        VT_WARN(L"vtable cfg-mark: vptr write faulted");
        return false;
    }

    auto& hk = g_hooks[g_hook_n++];
    hk.slot = vptr_addr;
    hk.orig = (void*)vt;
    hk.page = page;
    hk.vptr = true;
    g_stub_page = page;
    VT_LOG(L"vtable cfg-mark stub slot " + std::to_wstring(use_slot) +
           L" page " + format_hex((uintptr_t)page));
    return true;
}

bool install_alloc_iat() {
    if (g_hook_n > 0)
        return true;
    // GAME-ONLY hooks. Never patch system DLLs (kernelbase/ucrtbase) — Hyperion
    // aggressively monitors those and kills. Game modules write their own IAT
    // during normal load, so patching those is invisible.
    static const wchar_t* const mods[] = {
        L"RobloxPlayerBeta.dll",
        L"RobloxPlayerBeta.exe",
        nullptr
    };
    // Modern Roblox imports via API sets. These are the most common names any
    // game IAT will carry — try many, take the first four that resolve.
    static const char* const funcs[] = {
        "GetLastError",
        "GetCurrentThreadId",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "Sleep",
        "SleepEx",
        "WaitForSingleObject",
        "WaitForSingleObjectEx",
        "GetSystemTimeAsFileTime",
        "GetSystemTimePreciseAsFileTime",
        "SetLastError",
        "LeaveCriticalSection",
        "EnterCriticalSection",
        "TlsGetValue",
        "TlsSetValue",
        "HeapAlloc",
        "HeapFree",
        "RtlAllocateHeap",
        "InterlockedIncrement",
        "InterlockedDecrement",
        nullptr
    };
    // Try in this order: game DLL first (script scheduler lives here), then exe.
    int tried = 0, resolved = 0;
    for (int m = 0; mods[m] && g_hook_n < 4; ++m) {
        HMODULE hm = GetModuleHandleW(mods[m]);
        if (!hm) continue;
        for (int f = 0; funcs[f] && g_hook_n < 4; ++f) {
            ++tried;
            const uintptr_t s = find_import_slot(hm, funcs[f]);
            if (s) ++resolved;
            install_one_tid_hook(mods[m], funcs[f]);
        }
    }
    if (g_hook_n == 0 && !g_logged_iat) {
        g_logged_iat = true;
        VT_WARN(L"no writable game IAT (tried " + std::to_wstring(tried) +
                L" name/mod pairs, " + std::to_wstring(resolved) + L" resolved)");
    } else if (g_hook_n > 0) {
        VT_LOG(L"game IAT hooks installed: " + std::to_wstring(g_hook_n) +
               L" (of " + std::to_wstring(resolved) + L" resolved slots)");
    }
    return g_hook_n > 0;
}

using NtGetNextThread_t = LONG(NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
using NtQIT_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueueApc_t = LONG(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, PVOID);
using NtQueueApcEx_t = LONG(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID);
using NtQueueApcEx2_t = LONG(NTAPI*)(HANDLE, HANDLE, ULONG, PVOID, PVOID, PVOID, PVOID);

struct ApcNt {
    NtGetNextThread_t next = nullptr;
    NtQIT_t           qit  = nullptr;
    NtQueueApc_t      apc  = nullptr;
    NtQueueApcEx_t    apc_ex = nullptr;
    NtQueueApcEx2_t   apc_ex2 = nullptr;
};

ApcNt& apc_nt() {
    static ApcNt n;
    static bool once = false;
    if (once)
        return n;
    once = true;
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt)
        return n;
    n.next    = (NtGetNextThread_t)GetProcAddress(nt, "NtGetNextThread");
    n.qit     = (NtQIT_t)GetProcAddress(nt, "NtQueryInformationThread");
    n.apc     = (NtQueueApc_t)GetProcAddress(nt, "NtQueueApcThread");
    n.apc_ex  = (NtQueueApcEx_t)GetProcAddress(nt, "NtQueueApcThreadEx");
    n.apc_ex2 = (NtQueueApcEx2_t)GetProcAddress(nt, "NtQueueApcThreadEx2");
    return n;
}

bool pcall_on_stack() {
    const auto& r = OffsetResolver::current();
    if (!r.lua_pcall)
        return false;
    void* frames[32]{};
    const USHORT n = CaptureStackBackTrace(0, 32, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
        const uintptr_t fp = (uintptr_t)frames[i];
        if (fp >= r.lua_pcall && fp < r.lua_pcall + 0x800)
            return true;
    }
    return false;
}

VOID NTAPI pump_apc(PVOID, PVOID, PVOID) {
    g_apc_pending.store(false, std::memory_order_release);
    if (pcall_on_stack())
        return;
    pulse_from_vtable();
}

int score_thread_stack(uintptr_t stack_base, uintptr_t stack_lim) {
    if (!looks_ptr(stack_base) || stack_base <= stack_lim)
        return 0;
    uintptr_t start = stack_base - 0x10000;
    if (start < stack_lim)
        start = stack_lim;
    const size_t n = (size_t)(stack_base - start);
    if (n < 16 || n > 0x20000)
        return 0;
    const auto& r = OffsetResolver::current();
    int hits = 0;
    __try {
        const auto* w = (const uintptr_t*)start;
        const size_t nw = n / 8;
        for (size_t i = 0; i < nw; ++i) {
            const uintptr_t v = w[i];
            if (g_hint_L && v == (uintptr_t)g_hint_L)
                hits += 8;
            if (g_job && v == g_job)
                hits += 2;
            if (r.lua_pcall && v >= r.lua_pcall && v < r.lua_pcall + 0x800)
                hits += 6;
            if (r.luau_load && v >= r.luau_load && v < r.luau_load + 0x1000)
                hits += 4;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return hits;
}

void bind_lua_thread(DWORD tid) {
    if (!tid)
        return;
    g_lua_tid = tid;
    g_safe_tid.store(tid);
    if (g_lua_th) {
        CloseHandle(g_lua_th);
        g_lua_th = nullptr;
    }
    g_lua_th = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
}

void discover_lua_tid() {
    if (g_lua_tid)
        return;
    static DWORD last = 0;
    const DWORD now = GetTickCount();
    if (now - last < 250)
        return;
    last = now;

    auto& nt = apc_nt();
    if (!nt.next || !nt.qit)
        return;

    struct Tbi {
        LONG exit_status;
        void* teb;
        void* cid_proc;
        void* cid_thread;
        ULONG_PTR aff;
        LONG prio;
        LONG base_prio;
    };

    const DWORD self = GetCurrentThreadId();
    HANDLE prev = nullptr;
    DWORD best_tid = 0;
    int best = 0;
    for (int n = 0; n < 96; ++n) {
        HANDLE cur = nullptr;
        const LONG st = nt.next(GetCurrentProcess(), prev,
                                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                                0, 0, &cur);
        if (prev)
            CloseHandle(prev);
        prev = cur;
        if (st < 0 || !cur)
            break;
        const DWORD tid = GetThreadId(cur);
        if (!tid || tid == self)
            continue;
        Tbi tbi{};
        if (nt.qit(cur, 0, &tbi, sizeof(tbi), nullptr) < 0 || !looks_ptr((uintptr_t)tbi.teb))
            continue;
        uintptr_t stack_base = 0, stack_lim = 0;
        if (!seh_read((uintptr_t)tbi.teb + 0x08, &stack_base, 8))
            continue;
        if (!seh_read((uintptr_t)tbi.teb + 0x10, &stack_lim, 8))
            continue;
        const int hits = score_thread_stack(stack_base, stack_lim);
        if (hits > best) {
            best = hits;
            best_tid = tid;
        }
    }
    if (prev)
        CloseHandle(prev);

    // Need L or lua_pcall on the stack — job pointer alone is any scheduler thread.
    if (best_tid && best >= 6) {
        bind_lua_thread(best_tid);
        VT_LOG(L"lua tid via stack scan " + std::to_wstring(best_tid) +
               L" hits=" + std::to_wstring(best));
    }
}

void queue_lua_apc() {
    if (!g_lua_tid)
        return;
    const DWORD now = GetTickCount();
    const DWORD prev = g_last_pulse.load(std::memory_order_relaxed);
    if (now - prev < 32)
        return;
    if (g_apc_pending.load(std::memory_order_acquire))
        return;
    if (!g_lua_th)
        g_lua_th = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, g_lua_tid);
    if (!g_lua_th)
        return;

    auto& nt = apc_nt();
    g_apc_pending.store(true, std::memory_order_release);
    LONG st = (LONG)0xC0000001;
    constexpr ULONG kSpecial = 1;
    if (nt.apc_ex2)
        st = nt.apc_ex2(g_lua_th, nullptr, kSpecial, (void*)pump_apc, nullptr, nullptr, nullptr);
    if (st < 0 && nt.apc_ex)
        st = nt.apc_ex(g_lua_th, (HANDLE)1, (void*)pump_apc, nullptr, nullptr, nullptr);
    if (st < 0 && nt.apc)
        st = nt.apc(g_lua_th, (void*)pump_apc, nullptr, nullptr, nullptr);
    if (st < 0) {
        g_apc_pending.store(false, std::memory_order_release);
        static DWORD lastf = 0;
        if (now - lastf > 3000) {
            lastf = now;
            VT_WARN(L"job APC queue failed ns=" + std::to_wstring((unsigned)st));
        }
        return;
    }
    static bool once = false;
    if (!once) {
        once = true;
        VT_LOG(L"job APC armed tid=" + std::to_wstring(g_lua_tid) +
               (nt.apc_ex2 ? L" Ex2-special" : (nt.apc_ex ? L" Ex-special" : L" regular")));
    }
}


} // namespace

void JobHook::install_game_hooks() {
    // Game-IAT patching from inside is dead — Hyperion returns err=5 on every
    // VirtualProtect attempt on Roblox module IATs. 42 loud VirtualProtect
    // failures per session were a huge detection signal. Skip entirely; the
    // ExtHook (patched from the exe externally, on KERNEL32.dll's IAT which
    // is NOT CIG-protected) is the only working pump path.
    refresh_images();
}

void JobHook::arm(uintptr_t job) {
    // Don't wipe existing game-IAT hooks if they're already installed.
    if (g_hook_n == 0) {
        remove();
    }
    refresh_images();
    g_job = looks_ptr(job) ? job : 0;
    g_probing = true;
    g_armed = false;
    g_logged_arm = false;
    g_collected = false;    // allow collect_steps() to re-run for this arm
    g_step_n = 0;
    g_last_pulse = 0;
    if (g_lua_tid)
        g_safe_tid.store(g_lua_tid);
    // PeekMessage is the render thread — never lua_pcall there.
    // Only a CF-table gadget is a safe job-thread entry. APC and PAGE_GUARD
    // both closed Roblox (CFG kill / Hyperion VEH).
    g_apc_pump = false;
    g_guard_pump = false;
    if (g_job) {
        collect_steps(g_job);
        if (blob_proxy().gadget)
            install_vtable_hook(g_job);
        if (g_hook_n == 0 && install_vtable_cfg_mark(g_job))
            VT_LOG(L"vtable stub CFG-marked — job-thread pump");
        if (g_hook_n == 0)
            VT_WARN(L"no CFG entry for stub — not swapping vtable");
    }
    VT_LOG(L"pump arm job " + format_hex(g_job) +
           L" hooks=" + std::to_wstring(g_hook_n) +
           (g_guard_pump ? L" guard=1" : L" guard=0") +
           L" apc=0");
}

void JobHook::set_lua_tid(DWORD tid) {
    if (!tid)
        return;
    bind_lua_thread(tid);
}

void JobHook::set_lua_state(uintptr_t L) {
    if (!looks_heap(L))
        return;
    auto* s = (lua_State*)L;
    if (LuaApi::instance().plausible_state(s))
        g_hint_L = s;
}

// Check if lua_pcall is currently on the call stack. If yes, we are INSIDE
// the Lua VM already — reentering via seh_pump would recurse into lua_pcall
// on the same lua_State and crash (GC/stack corruption). Only pump when
// lua_pcall is NOT on the stack (i.e., between Roblox scheduler ticks).
static bool lua_pcall_on_stack() {
    const auto& r = OffsetResolver::current();
    if (!r.lua_pcall) return false;
    void* frames[40]{};
    const USHORT n = CaptureStackBackTrace(0, 40, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) {
        const uintptr_t fp = (uintptr_t)frames[i];
        if (fp >= r.lua_pcall && fp < r.lua_pcall + 0x800) return true;
    }
    return false;
}

// Diagnostic counter — read+cleared by render tick so we can tell whether
// the ExtHook stub is firing at all (vs Roblox not calling that IAT slot).
std::atomic<uint32_t> g_pulse_hits{0};

bool current_stack_has_job() {
    if (!g_job)
        return false;
    NT_TIB* tib = (NT_TIB*)NtCurrentTeb();
    if (!tib || !tib->StackBase || !tib->StackLimit)
        return false;
    const uintptr_t base = (uintptr_t)tib->StackBase;
    uintptr_t lim = (uintptr_t)tib->StackLimit;
    if (base <= lim)
        return false;
    uintptr_t start = base - 0x8000;
    if (start < lim)
        start = lim;
    __try {
        for (uintptr_t p = start; p + 8 <= base; p += 8) {
            if (*(uintptr_t*)p == g_job)
                return true;
            if (g_hint_L && *(uintptr_t*)p == (uintptr_t)g_hint_L)
                return true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
}

void JobHook::pulse() {
    g_pulse_hits.fetch_add(1, std::memory_order_relaxed);
    module_poll_pipe();
    if (!g_probing && !g_armed.load(std::memory_order_relaxed))
        return;
    if (pcall_on_stack())
        return;
    const DWORD tid = GetCurrentThreadId();
    if (g_lua_tid) {
        if (tid != g_lua_tid)
            return;
    } else if (current_stack_has_job()) {
        bind_lua_thread(tid);
        Logger::instance().set_thread_silent(true);
        VT_LOG(L"lua tid via wait-stack " + std::to_wstring(tid));
        Logger::instance().set_thread_silent(false);
    } else {
        // Lua thread not yet known — walk the call stack to see if lua_pcall is active.
        // Throttle so a broad hook doesn't flood us with CaptureStackBackTrace calls.
        static std::atomic<DWORD> s_last_bt{0};
        const DWORD now_bt = GetTickCount();
        if (now_bt - s_last_bt.load(std::memory_order_relaxed) < 2u)
            return;
        s_last_bt.store(now_bt, std::memory_order_relaxed);

        // STRICT detection ONLY: lua_pcall or luau_load on the stack. Loose
        // heuristics (frequency, "in Roblox image") caused false positives on
        // non-Lua threads, triggering cross-thread lua_pcall crashes. With
        // RtlAllocateHeap as the hook target (fires on every heap alloc), we
        // get enough hits on the Lua thread during script execution that
        // strict detection succeeds quickly.
        const auto& r = OffsetResolver::current();
        if (!r.lua_pcall && !r.luau_load)
            return;
        void* frames[40]{};
        const USHORT n = CaptureStackBackTrace(2, 40, frames, nullptr);
        bool on_lua = false;
        for (USHORT i = 0; i < n && !on_lua; ++i) {
            const uintptr_t fp = (uintptr_t)frames[i];
            if (r.lua_pcall && fp >= r.lua_pcall && fp < r.lua_pcall + 0x4000)
                on_lua = true;
            if (r.luau_load && fp >= r.luau_load && fp < r.luau_load + 0x4000)
                on_lua = true;
        }
        if (!on_lua)
            return;
        g_lua_tid = tid;
        g_safe_tid.store(tid);
        // Safe to log here — silent-mode buffer catches this and the render
        // tick flushes it a moment later. No pipe write on the Lua thread.
        Logger::instance().set_thread_silent(true);
        VT_LOG(L"lua thread via backtrace tid=" + std::to_wstring(tid));
        Logger::instance().set_thread_silent(false);
    }
    // Re-entry guard REMOVED — Lua thread almost always calls NtWaitForSingleObject
    // from inside lua_pcall (Wait(), event yields, etc), so blocking on stack
    // check means we NEVER pump. Instead, we accept reentrant lua_pcall — the
    // seh_pump SEH handler catches any GC/stack corruption.
    if (g_in_work.exchange(true, std::memory_order_acq_rel))
        return;
    const DWORD now = GetTickCount();
    const DWORD prev = g_last_pulse.load(std::memory_order_relaxed);
    if (now - prev < 16u) {
        g_in_work.store(false, std::memory_order_release);
        return;
    }
    g_last_pulse.store(now, std::memory_order_relaxed);
    Logger::instance().set_thread_silent(true);
    module_poll_pipe();
    lua_State* L = g_hint_L;
    if (!L)
        L = Execution::instance().state();
    if (L && LuaApi::instance().plausible_state(L))
        seh_pump(L);
    Logger::instance().set_thread_silent(false);
    g_in_work.store(false, std::memory_order_release);
    // Signal exe to unpatch — one pump was enough to run all queued scripts.
    g_pump_ran.store(true, std::memory_order_release);
}

void JobHook::kick(uintptr_t) {
    // PeekMessage is the render thread. lua_pcall here closed Roblox.
    // hunt_L() probing job heap closed it at 85% (Hyperion VEH).
}

void JobHook::tick() {
    if (!g_probing && !g_armed)
        return;
    discover_lua_tid();
}

void JobHook::remove() {
    g_armed = false;
    g_probing = false;
    g_apc_pump = false;
    g_guard_pump = false;
    g_apc_pending.store(false, std::memory_order_release);
    if (g_lua_th) {
        CloseHandle(g_lua_th);
        g_lua_th = nullptr;
    }
    g_tf_tid.store(0, std::memory_order_release);
    for (int i = 0; i < g_hook_n; ++i) {
        if (g_hooks[i].steal)
            seh_write_ptr(g_hooks[i].steal, g_hooks[i].steal_orig);
        if (g_hooks[i].slot && g_hooks[i].orig) {
            if (g_hooks[i].vptr)
                seh_write_ptr(g_hooks[i].slot, g_hooks[i].orig);
            else
                patch_iat_ptr(g_hooks[i].slot, g_hooks[i].orig);
        }
    }
    if (g_veh) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = nullptr;
    }
    for (int i = 0; i < g_hook_n; ++i) {
        if (g_hooks[i].page)
            VirtualFree(g_hooks[i].page, 0, MEM_RELEASE);
        g_hooks[i] = {};
    }
    g_hook_n = 0;
    g_alloc_slot = 0;
    g_alloc_orig = nullptr;
    g_stub_page = nullptr;
    if (g_redirect_page) {
        VirtualFree(g_redirect_page, 0, MEM_RELEASE);
        g_redirect_page = nullptr;
    }
    g_job = 0;
    g_step_n = 0;
    g_logged_arm = false;
    g_collected = false;
}

bool JobHook::armed() {
    return g_armed.load();
}

bool JobHook::probing() {
    return g_probing;
}

} // namespace vt
