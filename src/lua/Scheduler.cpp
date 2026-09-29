#include "lua/Scheduler.h"
#include "lua/Offsets.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <Windows.h>
#include <cstring>

namespace vt {
namespace {

const int kJobStartCands[] = {
    0xC8, 0xD0, 0xF0, 0x100, 0x118, 0x120, 0x128, 0x140,
    0x188, 0x198, 0x1B0, 0x1C8, 0x1D0, 0x1D8, 0x1E0, 0x208, 0x218
};
const int kNameCands[]     = { 0x18, 0x10, 0x20, 0x28, 0x30, 0x08 };
const int kScCands[]       = {
    0x1F0, 0x1F8, 0x200, 0x208, 0x210, 0x218, 0x220, 0x228,
    0x1A0, 0x1A8, 0x1B0, 0x1B8, 0x1C0, 0x1C8, 0x1D0, 0x1D8,
    0x3B0, 0x3F0, 0x2A0, 0x2B0, 0x2C0, 0x180, 0x190
};
const int kStateCands[]    = {
    0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138,
    0x140, 0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x178,
    0x180, 0x188, 0x190, 0x198, 0x1A0, 0x1A8, 0x1B0, 0x1B8
};

bool looks_ptr(uintptr_t p) {
    return p > 0x10000 && p < 0x00007FFFFFFFFFFFULL;
}

bool looks_heap(uintptr_t p) {
    return p > 0x10000 && p < 0x00007F0000000000ULL;
}

bool seh_read_u64(uintptr_t addr, uintptr_t* out) {
    __try {
        *out = *(uintptr_t*)addr;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool seh_bytes(uintptr_t addr, uint8_t* out, size_t n) {
    __try {
        memcpy(out, (const void*)addr, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool seh_read_cstr(uintptr_t addr, char* out, size_t cap) {
    __try {
        const size_t size = *(size_t*)(addr + 0x10);
        const size_t capy = *(size_t*)(addr + 0x18);
        if (size > 0 && size < cap && capy < 4096) {
            const char* data = capy < 16 ? (const char*)addr : *(const char**)addr;
            if (data) {
                memcpy(out, data, size);
                out[size] = 0;
                return true;
            }
        }
        const char* p = *(const char**)addr;
        const size_t n = *(size_t*)(addr + 8);
        if (p && n > 0 && n < cap) {
            memcpy(out, p, n);
            out[n] = 0;
            return true;
        }
        const char* raw = (const char*)addr;
        size_t i = 0;
        while (i + 1 < cap && raw[i] && (unsigned char)raw[i] >= 32 && (unsigned char)raw[i] < 127)
            ++i;
        if (i >= 3 && i < 80) {
            memcpy(out, raw, i);
            out[i] = 0;
            return true;
        }
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

std::string read_std_string(uintptr_t addr) {
    if (!looks_ptr(addr))
        return {};
    char buf[260]{};
    if (!seh_read_cstr(addr, buf, sizeof(buf)))
        return {};
    return buf;
}

std::string job_name_at(uintptr_t job, int name_off) {
    return read_std_string(job + name_off);
}

bool interesting_name(const std::string& n) {
    return n.find("WaitingHybrid") != std::string::npos ||
           n.find("ScriptContext") != std::string::npos ||
           n.find("Luau") != std::string::npos ||
           n.find("WaitingScript") != std::string::npos ||
           n.find("LuaGc") != std::string::npos ||
           n.find("ScriptJob") != std::string::npos;
}

bool live_state(lua_State* L) {
    return LuaApi::instance().plausible_state(L);
}

lua_State* decode_state(uintptr_t sc, uintptr_t raw) {
    if (!raw)
        return nullptr;
    const uintptr_t cands[] = {
        raw,
        raw ^ sc,
        raw + sc,
        raw - sc,
        sc - raw,
    };
    for (uintptr_t c : cands) {
        if (looks_heap(c) && live_state((lua_State*)c))
            return (lua_State*)c;
    }
    uintptr_t key = 0;
    if (seh_read_u64(sc + 8, &key) && looks_heap(raw ^ key) && live_state((lua_State*)(raw ^ key)))
        return (lua_State*)(raw ^ key);
    if (looks_heap(raw) && live_state((lua_State*)raw))
        return (lua_State*)raw;
    return nullptr;
}

lua_State* state_from_sc(uintptr_t sc) {
    if (!looks_ptr(sc))
        return nullptr;
    for (int off : kStateCands) {
        uintptr_t raw = 0;
        if (!seh_read_u64(sc + off, &raw))
            continue;
        if (auto* L = decode_state(sc, raw))
            return L;
    }
    return nullptr;
}

lua_State* state_from_job(uintptr_t job) {
    if (!looks_ptr(job))
        return nullptr;
    for (int off : kScCands) {
        uintptr_t sc = 0;
        if (!seh_read_u64(job + off, &sc) || !looks_ptr(sc))
            continue;
        if (auto* L = state_from_sc(sc))
            return L;
        if (auto* L = decode_state(job, sc))
            return L;
    }
    return nullptr;
}

bool walk_vector(uintptr_t begin, uintptr_t end, int name_off, std::vector<ScriptJob>& out) {
    if (!looks_ptr(begin) || !looks_ptr(end) || end <= begin || (end - begin) > 0x8000)
        return false;
    int named = 0;
    for (uintptr_t it = begin; it < end; it += sizeof(uintptr_t)) {
        uintptr_t job = 0;
        if (!seh_read_u64(it, &job) || !looks_ptr(job))
            continue;
        ScriptJob j;
        j.job = job;
        j.name = job_name_at(job, name_off);
        if (j.name.empty())
            continue;
        ++named;
        out.push_back(std::move(j));
    }
    return named > 0;
}

} // namespace

bool has_script_jobs(uintptr_t ts) {
    if (!looks_ptr(ts))
        return false;
    for (int st : kJobStartCands) {
        uintptr_t begin = 0, end = 0;
        if (!seh_read_u64(ts + st, &begin) || !seh_read_u64(ts + st + 8, &end))
            continue;
        std::vector<ScriptJob> tmp;
        if (!walk_vector(begin, end, 0x18, tmp) && !walk_vector(begin, end, 0x10, tmp))
            continue;
        for (auto& j : tmp)
            if (interesting_name(j.name))
                return true;
    }
    return false;
}

uintptr_t find_ts_inproc() {
    auto& r = OffsetResolver::current();
    if (!r.image_base || !r.image_size)
        return 0;
    const uintptr_t base = r.image_base;
    const uintptr_t end = base + r.image_size;
    const int disps[] = {
        0xC8, 0xD0, 0x118, 0x120, 0x128, 0x188, 0x198, 0x1D0, 0x208, 0x1A0
    };
    MEMORY_BASIC_INFORMATION mbi{};
    for (uintptr_t addr = base; addr < end; ) {
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi)))
            break;
        const uintptr_t rsz = (uintptr_t)mbi.RegionSize;
        const bool rx = mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_EXECUTE_WRITECOPY));
        if (rx && rsz >= 16) {
            const size_t n = (addr + rsz > end) ? (end - addr) : rsz;
            for (size_t i = 0; i + 14 < n; ++i) {
                uint8_t b[15]{};
                if (!seh_bytes(addr + i, b, sizeof(b)))
                    continue;
                if (b[0] != 0x48 || b[1] != 0x8B)
                    continue;
                if (b[2] != 0x0D && b[2] != 0x05)
                    continue;
                if (b[7] != 0x48 || b[8] != 0x8B)
                    continue;
                if (b[9] != 0x80 && b[9] != 0x81 && b[9] != 0x88 && b[9] != 0x89)
                    continue;
                int disp = 0;
                memcpy(&disp, b + 10, 4);
                bool want = false;
                for (int d : disps)
                    if (d == disp)
                        want = true;
                if (!want)
                    continue;
                int32_t rel = 0;
                memcpy(&rel, b + 3, 4);
                const uintptr_t tgt = addr + i + 7 + (intptr_t)rel;
                if (tgt < base || tgt >= end)
                    continue;
                uintptr_t val = 0;
                if (!seh_read_u64(tgt, &val))
                    continue;
                const uintptr_t obj = looks_ptr(val) ? val : tgt;
                if (has_script_jobs(obj)) {
                    VT_LOG(L"TaskScheduler in-proc " + format_hex(obj));
                    return obj;
                }
            }
        }
        const uintptr_t next = (uintptr_t)mbi.BaseAddress + rsz;
        if (next <= addr)
            break;
        addr = next;
    }
    return 0;
}

uintptr_t Scheduler::task_scheduler() {
    auto& r = OffsetResolver::current();
    if (r.task_scheduler) {
        uintptr_t p = 0;
        if (seh_read_u64(r.task_scheduler, &p) && looks_ptr(p))
            return p;
        if (looks_ptr(r.task_scheduler))
            return r.task_scheduler;
    }
    return 0;
}

std::vector<ScriptJob> Scheduler::jobs() {
    std::vector<ScriptJob> out;
    const auto ts = task_scheduler();
    if (!ts)
        return out;

    const auto& t = OffsetResolver::current().table;

    auto try_pair = [&](int st, int name, bool stop_useful) -> bool {
        uintptr_t begin = 0, end = 0;
        if (!seh_read_u64(ts + st, &begin) || !seh_read_u64(ts + st + 8, &end))
            return false;
        std::vector<ScriptJob> try_out;
        if (!walk_vector(begin, end, name, try_out))
            return false;
        bool useful = false;
        for (auto& job : try_out)
            if (interesting_name(job.name)) { useful = true; break; }
        if (useful) {
            out = std::move(try_out);
            return true;
        }
        if (out.empty() && try_out.size() >= 4)
            out = std::move(try_out);
        return stop_useful && useful;
    };

    // Brute-forcing 16×8 layouts triggers Hyperion's VEH on SEH-faulting reads
    // and kills the process instantly. Only scan when we have a validated job_start.
    // Without it, return empty and let the host-side RPM job hint fill g_hint_job.
    const int cfg_st = (int)t.job_start;
    const int cfg_nm = t.job_name ? (int)t.job_name : 0x18;
    if (!cfg_st)
        return out;

    if (try_pair(cfg_st, cfg_nm, true) && !out.empty())
        return out;

    if (out.empty())
        VT_WARN(L"TaskScheduler walk found no script jobs — job_start offset wrong");
    return out;
}

ScriptJob Scheduler::acquire_job() {
    ScriptJob best;
    auto list = jobs();
    auto take = [&](ScriptJob& j, const wchar_t* how) {
        VT_LOG(std::wstring(how) + L" '" + utf8_to_wide(j.name) + L"' " +
               format_hex((uintptr_t)j.state) + L" job " + format_hex(j.job));
        best = j;
    };
    for (auto& j : list) {
        if (j.state && live_state(j.state) && interesting_name(j.name)) {
            take(j, L"Lua state from job");
            return best;
        }
    }
    for (auto& j : list) {
        if (j.state && live_state(j.state)) {
            take(j, L"Lua state from job");
            return best;
        }
    }
    for (auto& j : list) {
        if (auto* L = state_from_job(j.job)) {
            if (!live_state(L))
                continue;
            j.state = L;
            take(j, L"Lua state brute from");
            return best;
        }
    }
    VT_WARN(L"No lua_State — join a game, then Inject. If still dead, this week's decrypt moved.");
    return best;
}

lua_State* Scheduler::acquire_state() {
    return acquire_job().state;
}

lua_State* Scheduler::state_from(uintptr_t job) {
    return state_from_job(job);
}

int Scheduler::hook_rank(const std::string& n) {
    if (n.empty())
        return 0;
    // TaskQueue is a drain job — wrong vtable, first-match used to grab it and
    // Hyperion killed on the heap-vtable swap. Prefer the script stepper.
    if (n.find("TaskQueue") != std::string::npos)
        return 15;
    if (n.find("LuaGc") != std::string::npos || n.find("GCJob") != std::string::npos)
        return 0;
    if (n.find("WaitingHybrid") != std::string::npos)
        return 100;
    if (n.find("Luau") != std::string::npos)
        return 90;
    if (n.find("WaitingScript") != std::string::npos)
        return 80;
    if (n.find("ScriptContext") != std::string::npos)
        return 70;
    if (n.find("ScriptJob") != std::string::npos)
        return 60;
    if (n.find("Script") != std::string::npos)
        return 30;
    return 0;
}

} // namespace vt
