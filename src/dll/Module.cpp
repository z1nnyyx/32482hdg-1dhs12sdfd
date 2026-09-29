#include "dll/Module.h"

#include "core/Pipe.h"
#include "lua/Offsets.h"
#include "lua/AutoResolve.h"
#include "lua/LuaApi.h"
#include "shared/OffBlob.h"
#include "lua/Execution.h"
#include "lua/Environment.h"
#include "lua/JobHook.h"
#include "lua/Scheduler.h"
#include "shared/Config.h"
#include "shared/Log.h"
#include "shared/Obfuscate.h"
#include "shared/PipeKey.h"
#include "shared/Utils.h"
#include "lua/libs/Drawing.h"
#include "shared/Protocol.h"

#include <filesystem>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" volatile wchar_t VT_BOOT[80];
extern "C" volatile VTOffBlob VT_OFF;
extern "C" void VT_TICK();
extern "C" volatile void* g_ext_orig;
extern "C" ULONGLONG WINAPI vt_ext_hook_zero();

void apply_patched_offsets(vt::OffsetTable& o) {
    if (memcmp((const void*)VT_OFF.mag, "VT_OFFS", 7) != 0)
        return;
    auto take = [](uintptr_t& d, uint64_t s) { if (s) d = (uintptr_t)s; };
    take(o.task_scheduler, VT_OFF.task_scheduler);
    take(o.job_name, VT_OFF.job_name);
    take(o.job_start, VT_OFF.job_start);
    take(o.job_end, VT_OFF.job_end);
    take(o.script_context, VT_OFF.script_context);
    take(o.extra_space, VT_OFF.extra_space);
    take(o.lua_state, VT_OFF.lua_state);
    take(o.identity, VT_OFF.identity);
    take(o.luau_load, VT_OFF.luau_load);
    take(o.lua_pcall, VT_OFF.lua_pcall);
    take(o.lua_gettop, VT_OFF.lua_gettop);
    take(o.lua_settop, VT_OFF.lua_settop);
    take(o.lua_pushstring, VT_OFF.lua_pushstring);
    take(o.lua_pushlstring, VT_OFF.lua_pushlstring);
    take(o.lua_pushcclosure, VT_OFF.lua_pushcclosure);
    take(o.lua_tolstring, VT_OFF.lua_tolstring);
    take(o.lua_pushnil, VT_OFF.lua_pushnil);
    take(o.lua_pushnumber, VT_OFF.lua_pushnumber);
    take(o.lua_pushboolean, VT_OFF.lua_pushboolean);
    take(o.lua_type, VT_OFF.lua_type);
    take(o.lua_getfield, VT_OFF.lua_getfield);
    take(o.lua_setfield, VT_OFF.lua_setfield);
    take(o.lua_createtable, VT_OFF.lua_createtable);
    take(o.lua_setreadonly, VT_OFF.lua_setreadonly);
    take(o.lua_newthread, VT_OFF.lua_newthread);
    take(o.lua_pushvalue, VT_OFF.lua_pushvalue);
}

namespace vt {
namespace {

std::atomic<bool> g_run{true};
std::atomic<bool> g_in_tick{false};
std::atomic<bool> g_parked{false};
PipeClient g_pipe;
HMODULE g_self = nullptr;
uintptr_t g_image = 0;
size_t g_image_size = 0;
int g_scan_ticks = 0;
bool g_ready = false;
bool g_announced_ready = false;
bool g_bound = false;
bool g_scan_done = false;
uintptr_t g_hint_job = 0;
int g_hint_age = 0;
bool g_tick_iat = false;
void* g_tick_orig = nullptr;
void* g_tick_thunk = nullptr;
uintptr_t g_tick_slot = 0;
std::wstring g_pipe_name;

std::filesystem::path module_dir() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(g_self, buf, MAX_PATH);
    return std::filesystem::path(buf).parent_path();
}

void send_log(LogLevel level, const std::wstring& text) {
    std::string tag = "I";
    if (level == LogLevel::Warn) tag = "W";
    if (level == LogLevel::Error) tag = "E";
    g_pipe.send({MsgType::Log, tag + "|" + wide_to_utf8(text)});
}

void send_status(const std::string& s) {
    static std::string last;
    if (s == last)
        return;
    last = s;
    g_pipe.send({MsgType::Status, s});
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

bool patch_iat_ptr(uintptr_t slot, void* v) {
    DWORD old = 0;
    if (!VirtualProtect((void*)slot, 8, PAGE_READWRITE, &old))
        return false;
    __try {
        *(void**)slot = v;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        VirtualProtect((void*)slot, 8, old, &old);
        return false;
    }
    VirtualProtect((void*)slot, 8, old, &old);
    return true;
}

// .text thunks — never VirtualProtect our image to RWX (that closed Roblox).
// Tick is a pipe/scan pump, not per-call work. Skip the extra CALL on every cursor/alloc.
void maybe_tick() {
    static std::atomic<DWORD> last{0};
    const DWORD now = GetTickCount();
    const DWORD prev = last.load(std::memory_order_relaxed);
    if (now - prev < 50)
        return;
    last.store(now, std::memory_order_relaxed);
    VT_TICK();
}

void* hook_malloc(size_t n) {
    maybe_tick();
    return ((void*(*)(size_t))g_tick_orig)(n);
}
void hook_free(void* p) {
    maybe_tick();
    ((void(*)(void*))g_tick_orig)(p);
}
LPVOID WINAPI hook_heapalloc(HANDLE h, DWORD f, SIZE_T n) {
    maybe_tick();
    return ((LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T))g_tick_orig)(h, f, n);
}
BOOL WINAPI hook_heapfree(HANDLE h, DWORD f, LPVOID p) {
    maybe_tick();
    return ((BOOL(WINAPI*)(HANDLE, DWORD, LPVOID))g_tick_orig)(h, f, p);
}
BOOL WINAPI hook_qpc(LARGE_INTEGER* t) {
    maybe_tick();
    return ((BOOL(WINAPI*)(LARGE_INTEGER*))g_tick_orig)(t);
}
ULONGLONG WINAPI hook_tick64() {
    maybe_tick();
    return ((ULONGLONG(WINAPI*)())g_tick_orig)();
}
BOOL WINAPI hook_cursor(LPPOINT p) {
    maybe_tick();
    return ((BOOL(WINAPI*)(LPPOINT))g_tick_orig)(p);
}
SHORT WINAPI hook_async_key(int v) {
    maybe_tick();
    return ((SHORT(WINAPI*)(int))g_tick_orig)(v);
}
BOOL WINAPI hook_peek(LPMSG m, HWND h, UINT min, UINT max, UINT rm) {
    maybe_tick();
    return ((BOOL(WINAPI*)(LPMSG, HWND, UINT, UINT, UINT))g_tick_orig)(m, h, min, max, rm);
}
BOOL WINAPI hook_getmsg(LPMSG m, HWND h, UINT min, UINT max) {
    maybe_tick();
    return ((BOOL(WINAPI*)(LPMSG, HWND, UINT, UINT))g_tick_orig)(m, h, min, max);
}

void* thunk_for(const char* fn) {
    if (!strcmp(fn, "malloc")) return (void*)hook_malloc;
    if (!strcmp(fn, "free")) return (void*)hook_free;
    if (!strcmp(fn, "HeapAlloc")) return (void*)hook_heapalloc;
    if (!strcmp(fn, "HeapFree")) return (void*)hook_heapfree;
    if (!strcmp(fn, "QueryPerformanceCounter")) return (void*)hook_qpc;
    if (!strcmp(fn, "GetTickCount64")) return (void*)hook_tick64;
    if (!strcmp(fn, "NtUserGetCursorPos") || !strcmp(fn, "GetCursorPos"))
        return (void*)hook_cursor;
    if (!strcmp(fn, "GetAsyncKeyState") || !strcmp(fn, "NtUserGetAsyncKeyState"))
        return (void*)hook_async_key;
    if (!strcmp(fn, "PeekMessageW") || !strcmp(fn, "PeekMessageA") ||
        !strcmp(fn, "NtUserPeekMessage"))
        return (void*)hook_peek;
    if (!strcmp(fn, "GetMessageW") || !strcmp(fn, "NtUserGetMessage"))
        return (void*)hook_getmsg;
    return nullptr;
}

// Mapper keeps USER32 PeekMessage on its stub (VT_TICK then orig). Do not steal
// that USER32 slot — restoring it is what killed JobHint/Execute. Fallback is
// the game image only (often Hyperion-locked; fine if the stub is live).
void ensure_tick_iat() {
    if (g_tick_iat)
        return;
    static const wchar_t* const mods[] = {
        L"RobloxPlayerBeta.exe", L"RobloxPlayerBeta.dll",
        nullptr
    };
    static const char* const funcs[] = {
        "PeekMessageW", "PeekMessageA", "GetMessageW",
        "NtUserPeekMessage", "NtUserGetMessage",
        nullptr
    };
    uintptr_t slot = 0;
    void* orig = nullptr;
    void* thunk = nullptr;
    const wchar_t* hit_mod = nullptr;
    const char* hit_fn = nullptr;
    for (int m = 0; mods[m] && !slot; ++m) {
        HMODULE hm = GetModuleHandleW(mods[m]);
        if (!hm)
            continue;
        for (int f = 0; funcs[f]; ++f) {
            void* th = thunk_for(funcs[f]);
            if (!th)
                continue;
            const uintptr_t s = find_import_slot(hm, funcs[f]);
            if (!s)
                continue;
            DWORD old = 0;
            if (!VirtualProtect((void*)s, 8, PAGE_READWRITE, &old))
                continue;
            orig = *(void**)s;
            VirtualProtect((void*)s, 8, old, &old);
            if (!orig)
                continue;
            slot = s;
            thunk = th;
            hit_mod = mods[m];
            hit_fn = funcs[f];
            break;
        }
    }
    if (!slot || !orig || !thunk) {
        VT_WARN(L"no writable tick IAT — pipe dies after PeekMessage unhook");
        return;
    }
    g_tick_orig = orig;
    g_tick_thunk = thunk;
    if (!patch_iat_ptr(slot, thunk)) {
        g_tick_orig = nullptr;
        g_tick_thunk = nullptr;
        VT_WARN(L"tick IAT write failed err=" + std::to_wstring(GetLastError()));
        return;
    }
    g_tick_slot = slot;
    g_tick_iat = true;
    VT_LOG(L"tick IAT " + std::wstring(hit_mod) + L"!" +
           utf8_to_wide(hit_fn) + L" -> .text thunk");
}

void rearm_tick_iat() {
    if (!g_tick_iat || !g_tick_slot || !g_tick_thunk)
        return;
    __try {
        void* cur = *(void**)g_tick_slot;
        if (cur == g_tick_thunk)
            return;
        if (cur && cur != g_tick_orig)
            g_tick_orig = cur;
        patch_iat_ptr(g_tick_slot, g_tick_thunk);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void try_acquire() {
    auto& api = LuaApi::instance();
    if (g_ready) {
        auto* L = Execution::instance().state();
        if (!L || !api.plausible_state(L)) {
            g_ready = false;
            g_announced_ready = false;
            Environment::reset();
            JobHook::remove();
            Execution::instance().set_state(nullptr);
            send_status("reacquire");
            VT_WARN(L"lua_State died — teleport or leave. Re-hooking.");
        } else {
            JobHook::tick();
        }
        return;
    }
    if (!g_scan_done || !api.ready()) {
        send_status("injected;scanning");
        return;
    }
    if (JobHook::armed() || JobHook::probing()) {
        JobHook::tick();
        if (JobHook::armed() && Execution::instance().state() && !g_ready) {
            g_ready = true;
            send_status("hooking");
        }
        return;
    }

    uintptr_t first_L = 0;
    if (!g_hint_job) {
        // No JobHint yet — do NOT call Scheduler::acquire_job here (it walks
        // Roblox's TaskScheduler in-process with SEH-faulting reads, which
        // Hyperion's VEH catches before our __except and kills). Wait for the
        // exe's RPM-based hint on the next tick.
        static int wait_ticks = 0;
        if (++wait_ticks == 1)
            VT_LOG(L"waiting for JobHint from host");
        send_status("injected;waiting_state");
        return;
    }
    VT_LOG(L"got JobHint job=" + format_hex(g_hint_job));
    if (g_hint_age < 4)
        ++g_hint_age;

    send_status("arming");
    VT_LOG(L"script job (hint) " + format_hex(g_hint_job));
    JobHook::arm(g_hint_job);
    (void)first_L;
    // PeekMessage IAT stays until g_pump_ran. Restoring it here left Execute
    // sitting in the host queue (no READY, no tick).
    send_status("hooking");
}

void on_message(const Message& m) {
    switch (m.type) {
    case MsgType::Ping:
        g_pipe.send({MsgType::Pong, {}});
        break;
    case MsgType::Execute:
        Execution::instance().enqueue(m.payload, "=chunk");
        send_status("queued");
        VT_LOG(L"execute queued (" + std::to_wstring(m.payload.size()) + L" bytes)");
        break;
    case MsgType::AutoExec:
        Execution::instance().enqueue(m.payload, "=autoexec");
        break;
    case MsgType::Shutdown:
        g_run = false;
        break;
    case MsgType::Park:
        g_parked = true;
        VT_LOG(L"parked — host restoring PeekMessage");
        break;
    case MsgType::ExtHookAck: {
        const uintptr_t orig = (uintptr_t)strtoull(m.payload.c_str(), nullptr, 0);
        if (orig && !g_ext_orig) {
            g_ext_orig = (void*)orig;
            VT_LOG(L"ExtHook wired orig=" + format_hex(orig));
        } else if (orig) {
            // Already wired from an earlier successful ack — nothing to do.
        } else {
            static int ext_fails = 0;
            if (++ext_fails <= 5)
                VT_WARN(L"ExtHook attempt failed (#" + std::to_wstring(ext_fails) + L")");
        }
        break;
    }
    case MsgType::JobHint: {
        char* end = nullptr;
        const uintptr_t job = (uintptr_t)strtoull(m.payload.c_str(), &end, 0);
        DWORD tid = 0;
        uintptr_t L = 0;
        if (end) {
            while (*end == ' ')
                ++end;
            if (*end)
                tid = (DWORD)strtoul(end, &end, 0);
            while (end && *end == ' ')
                ++end;
            if (end && *end)
                L = (uintptr_t)strtoull(end, nullptr, 0);
        }
        // Log only on first arrival or when payload changes — not every message.
        static uintptr_t last_job = 0;
        static uintptr_t last_L = 0;
        if (job != last_job || L != last_L) {
            last_job = job; last_L = L;
            VT_LOG(L"RX JobHint job=" + format_hex(job) +
                   L" L=" + format_hex(L));
        }
        if (tid)
            JobHook::set_lua_tid(tid);
        if (L && job && L + 0x400 > job && L < job + 0x400)
            L = 0;
        if (L)
            JobHook::set_lua_state(L);
        if (job) {
            g_hint_job = job;
            g_hint_age = 4;
        }
        break;
    }
    default:
        break;
    }
}

void tick_inner() {
    if (!g_run || !g_self)
        return;

    if (g_pipe_name.empty()) {
        if (VT_BOOT[0] == L'\\' && VT_BOOT[1] == L'\\')
            g_pipe_name.assign((const wchar_t*)VT_BOOT);
        else
            g_pipe_name = PipeKey::open(0);
        if (g_pipe_name.empty())
            return;
    }

    if (!g_pipe.connected()) {
        if (!g_pipe.attach_poll(g_pipe_name, on_message))
            return;
        Logger::instance().set_sink([](const LogLine& l) { send_log(l.level, l.text); });
        VT_LOG(L"module online");
        send_status("injected");
    }

    g_pipe.poll();

    // Flush any logs buffered by the silent pump on the Lua thread. Render
    // thread has time budget — safe to do pipe writes here.
    Logger::instance().drain_silent();

    // If pulse successfully pumped scripts on the Lua thread, tell the exe to
    // restore the IAT slot — pump ran, callbacks are registered, we're done
    // needing the hook. Clean IAT = Hyperion's integrity scan passes.
    static bool s_unpatch_sent = false;
    if (!s_unpatch_sent && g_pump_ran.load(std::memory_order_acquire)) {
        s_unpatch_sent = true;
        g_pipe.send({MsgType::ExtHookUnpatch, ""});
        VT_LOG(L"pump ran — requested ExtHook unpatch (survive integrity scan)");
    }

    // Report ExtHook stub hit rate every 3s so we can tell if the stub is
    // firing at all vs Roblox bypassing the patched IAT slot.
    {
        static DWORD s_last_stat = 0;
        static uint32_t s_last_hits = 0;
        const DWORD now_stat = GetTickCount();
        if (now_stat - s_last_stat > 3000) {
            const uint32_t hits = g_pulse_hits.load(std::memory_order_relaxed);
            if (hits != s_last_hits || hits == 0) {
                VT_LOG(L"ExtHook stub hits: " + std::to_wstring(hits) +
                       L" (+" + std::to_wstring(hits - s_last_hits) + L" in 3s)");
                s_last_hits = hits;
            }
            s_last_stat = now_stat;
        }
    }

    // Heartbeat every 5s only if not yet ready (once ready, no need to spam).
    if (!g_ready) {
        static DWORD s_last_hb = 0;
        const DWORD now_hb = GetTickCount();
        if (now_hb - s_last_hb > 5000) {
            s_last_hb = now_hb;
            static int hb = 0;
            VT_LOG(L"heartbeat #" + std::to_wstring(++hb) +
                   L" bound=" + std::to_wstring(g_bound ? 1 : 0) +
                   L" hint=" + std::to_wstring(g_hint_job ? 1 : 0));
        }
    }

    if (!g_bound) {
        const auto rbx_name = WOBF(L"RobloxPlayerBeta.exe");
        auto mod = find_module_local(rbx_name.c_str());
        if (!mod)
            return;
        g_image = mod->base;
        g_image_size = mod->size;
        OffsetTable offs{};
        apply_patched_offsets(offs);
        OffsetResolver::resolve(g_image, g_image_size, offs);
        libs::set_draw_sink([](std::string p) {
            g_pipe.send({MsgType::DrawFrame, std::move(p)});
        });
        Execution::instance().set_sink([](const ExecResult& r) {
            if (!r.ok)
                g_pipe.send({MsgType::ExecuteErr, r.error});
            else
                g_pipe.send({MsgType::ExecuteOk, {}});
        });
        LuaApi::instance().bind();
        g_bound = true;
        g_scan_done = LuaApi::instance().ready();
        g_tick_iat = true; // mapper PeekMessage stub is the lasting tick

        // Belt-and-suspenders: manual mapper may skip global initializers.
        // Ensure g_ext_orig is preset to real ntdll!RtlAllocateHeap so the
        // stub returns real allocations even before the exe's ack arrives.
        if (!g_ext_orig) {
            HMODULE nt = GetModuleHandleW(L"ntdll.dll");
            if (nt) g_ext_orig = (void*)GetProcAddress(nt, "RtlAllocateHeap");
            VT_LOG(L"g_ext_orig pre-init = " + format_hex((uintptr_t)g_ext_orig));
        }

        // Tell the host the exact VAs of lua_pcall/luau_load so it can
        // run find_lua_tid with correct addresses (config offsets may be 0).
        {
            const auto& resolved = OffsetResolver::current();
            if (resolved.lua_pcall || resolved.luau_load) {
                char buf[128]{};
                sprintf_s(buf, "0x%llX 0x%llX",
                          (unsigned long long)resolved.lua_pcall,
                          (unsigned long long)resolved.luau_load);
                g_pipe.send({MsgType::OffsetReport, buf});
            }
        }
        JobHook::install_game_hooks();
        // Do not ExtHook HeapAlloc / CRT IAT. That was a CFG + re-entry kill
        // last run. Pump is the script-job vtable clone on that job's thread.
        VT_LOG(L"bind complete — waiting JobHint for job-thread pump");
        return;
    }

    if (!g_scan_done) {
        send_status("injected;scanning");
        if (!auto_resolve_tick(OffsetResolver::current()))
            return;
        LuaApi::instance().bind();
        g_scan_done = true;
        {
            const auto& resolved = OffsetResolver::current();
            if (resolved.lua_pcall || resolved.luau_load) {
                char buf[128]{};
                sprintf_s(buf, "0x%llX 0x%llX",
                          (unsigned long long)resolved.lua_pcall,
                          (unsigned long long)resolved.luau_load);
                g_pipe.send({MsgType::OffsetReport, buf});
            }
        }
        if (!LuaApi::instance().ready())
            VT_WARN(L"Lua API still incomplete after auto-scan");
        else
            VT_LOG(L"Lua API bound after auto-scan");
        return;
    }

    try_acquire();
}

} // namespace

void module_main(HMODULE self) {
    g_self = self;
}

void module_note_ready() {
    if (g_announced_ready)
        return;
    g_announced_ready = true;
    g_ready = true;
    send_status("ready");
    g_pipe.send({MsgType::Ready, "lua_state"});
    VT_LOG(L"READY on job thread");
}

void module_poll_pipe() {
    if (g_pipe.connected())
        g_pipe.poll();
}

void module_tick() {
    if (g_parked.load(std::memory_order_acquire))
        return;
    if (g_in_tick.exchange(true))
        return;
    static DWORD last = 0;
    const DWORD now = GetTickCount();
    if (now - last < 50) {
        g_in_tick = false;
        return;
    }
    last = now;
    __try {
        tick_inner();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    g_in_tick = false;
}

void module_shutdown() {
    g_run = false;
    if (g_tick_iat && g_tick_slot && g_tick_orig)
        patch_iat_ptr(g_tick_slot, g_tick_orig);
    JobHook::remove();
    g_pipe.stop();
}

} // namespace vt
