#include "ext/World.h"
#include "ext/Bytecode.h"
#include "core/ThreadHijack.h"
#include "core/Syscall.h"
#include "lua/CoreShim.h"
#include "shared/Config.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <TlHelp32.h>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <initializer_list>
#include <vector>

using NtCreateSection_t = LONG(NTAPI*)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
using NtMapViewOfSection_t = LONG(NTAPI*)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
    ULONG, ULONG, ULONG);
using NtUnmapViewOfSection_t = LONG(NTAPI*)(HANDLE, PVOID);

namespace vt::ext {

static std::atomic<uintptr_t> g_name_off_hint{0};
static std::atomic<bool> g_name_reprobe{false};

namespace {

const uintptr_t kFakeDm[]   = { 0x8CA9CC8, 0x8B79B58, 0x7A8F908, 0x7A8F910 };
const uintptr_t kFakeOff[]  = { 0x1F8, 0x1D8, 0x1C0, 0x1B8, 0x1E0 };
const uintptr_t kVeRva[]    = { 0x8136228, 0x763D3D0, 0x7B2EE10 };
const uintptr_t kChildOff[] = { 0x78, 0x70, 0x80, 0x68, 0x60, 0x88 };
const uintptr_t kNameOff[]  = {
    0xB0, 0x70, 0x48, 0x50, 0x78, 0x88, 0x90, 0x98, 0xA0, 0xA8,
    0x28, 0x30, 0x38, 0x40, 0x58, 0x60, 0x68, 0x80, 0xB8, 0xC0,
    0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0x08, 0x10, 0x18, 0x20,
    0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138, 0x140, 0x148
};
const uintptr_t kCharOff[]  = { 0x298, 0x330, 0x328, 0x318, 0x2C0 };
const uintptr_t kLocalOff[] = { 0x130, 0x118, 0x128, 0x108 };
const uintptr_t kPrimOff[]  = { 0x188, 0x148, 0x150, 0x1A0 };
const uintptr_t kPosOff[]   = { 0xEC, 0xE4, 0xF0, 0xC0 };

std::vector<uintptr_t> prefer(uintptr_t first, const uintptr_t* rest, int n) {
    std::vector<uintptr_t> o;
    if (first)
        o.push_back(first);
    for (int i = 0; i < n; ++i)
        if (rest[i] != first)
            o.push_back(rest[i]);
    return o;
}

const OffsetTable& off() {
    return Config::instance().get().offsets;
}

} // namespace

bool World::attach(DWORD pid, uintptr_t image_base, size_t image_size) {
    detach();
    if (!image_base || !mem_.open(pid))
        return false;
    base_ = image_base;
    size_ = image_size;
    dm_scan_done_ = false;
    stats_.attached = true;
    return true;
}

void World::detach() {
    mem_.close();
    base_ = 0;
    size_ = 0;
    dm_scan_done_ = false;
    cached_dm_ = cached_ve_ = cached_players_ = 0;
    last_dm_check_ = last_tree_ = 0;
    tracked_.clear();
    stats_ = {};
}

std::string World::class_name(uintptr_t inst) const {
    if (!mem_.looks(inst))
        return {};
    const uintptr_t cd = mem_.read_ptr(inst + (off().class_desc ? off().class_desc : 0x18));
    if (!mem_.looks(cd))
        return {};
    for (uintptr_t off : { 0x8ull, 0x0ull, 0x10ull }) {
        auto s = mem_.rstring(cd + off);
        if (!s.empty())
            return s;
        const uintptr_t np = mem_.read_ptr(cd + off);
        s = mem_.rstring(np);
        if (!s.empty())
            return s;
        s = mem_.rstring_ptr(np);
        if (!s.empty())
            return s;
    }
    return {};
}

std::string World::inst_name(uintptr_t inst) const {
    if (!mem_.looks(inst))
        return {};
    static std::atomic<uintptr_t> s_cal{0};
    if (g_name_reprobe.exchange(false, std::memory_order_relaxed))
        s_cal.store(0, std::memory_order_relaxed);
    auto good = [](const std::string& s) {
        if (s.size() < 4 || s.size() > 80)
            return false;
        if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') || s[0] == '_'))
            return false;
        for (unsigned char c : s) {
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_'))
                return false;
        }
        return true;
    };
    auto try_at = [&](uintptr_t addr) -> std::string {
        auto s = mem_.rstring(addr);
        if (good(s))
            return s;
        const uintptr_t np = mem_.read_ptr(addr);
        if (mem_.looks(np)) {
            s = mem_.rstring(np);
            if (good(s))
                return s;
            s = mem_.rstring_ptr(np);
            if (good(s))
                return s;
            for (int lo : {4, 8, 12, 16, 20, 24, 28, 32}) {
                uint32_t len = mem_.read<uint32_t>(np + lo);
                if (len >= 4 && len <= 80) {
                    char buf[82]{};
                    if (mem_.read(np + lo + 4, buf, len)) {
                        std::string ss(buf, len);
                        if (good(ss)) return ss;
                    }
                }
            }
            for (int lo : {8, 4}) {
                s = mem_.rstring_ptr(np + lo);
                if (good(s)) return s;
            }
            const uintptr_t np2 = mem_.read_ptr(np);
            if (mem_.looks(np2) && np2 != np) {
                s = mem_.rstring(np2);
                if (good(s)) return s;
                s = mem_.rstring_ptr(np2);
                if (good(s)) return s;
            }
        }
        return {};
    };
    const uintptr_t cal = s_cal.load(std::memory_order_relaxed);
    if (cal) {
        if (auto s = try_at(inst + cal); !s.empty())
            return s;
    }
    const uintptr_t hint = g_name_off_hint.load(std::memory_order_relaxed);
    if (hint && hint != cal) {
        if (auto s = try_at(inst + hint); !s.empty()) {
            s_cal.store(hint, std::memory_order_relaxed);
            return s;
        }
    }
    static int s_log_n = 0;
    for (uintptr_t offv : prefer(off().name_off, kNameOff, (int)std::size(kNameOff))) {
        if (offv == cal || offv == hint) continue;
        if (auto s = try_at(inst + offv); !s.empty()) {
            if (!cal) {
                s_cal.store(offv, std::memory_order_relaxed);
                if (s_log_n++ < 3)
                    VT_LOG(L"inst_name: cached +0x" + format_hex(offv) + L" → " + utf8_to_wide(s));
            }
            return s;
        }
    }
    return {};
}

bool World::looks_instance(uintptr_t p) const {
    if (!mem_.looks(p) || (p & 7))
        return false;
    const uintptr_t vt = mem_.read_ptr(p);
    if (base_ && size_ && vt >= base_ && vt < base_ + size_)
        return true;
    // RobloxPlayerBeta.dll / other image vtables (not heap 0x1xxxx)
    if (vt >= 0x00007FF000000000ULL && vt < 0x00007FFFFFFFFFFFULL && (vt & 0xF) == 0)
        return true;
    return false;
}

uintptr_t World::find_service(uintptr_t dm, const char* name) const {
    if (!mem_.looks(dm) || !name)
        return 0;
    if (auto c = find_child_name(dm, name))
        return c;
    if (auto c = find_child_class(dm, name))
        return c;
    for (uintptr_t o = 0x40; o < 0x600; o += 8) {
        const uintptr_t p = mem_.read_ptr(dm + o);
        if (!looks_instance(p) || p == dm)
            continue;
        if (inst_name(p) == name || class_name(p) == name)
            return p;
    }
    return 0;
}

void World::children_of(uintptr_t inst, std::vector<uintptr_t>& out) const {
    out.clear();
    if (!mem_.looks(inst))
        return;
    std::vector<uintptr_t> best;
    int best_score = -1;
    auto consider = [&](uintptr_t begin, uintptr_t end, uintptr_t stride) {
        if (stride != 8 && stride != 16)
            return;
        if ((begin & 7) || (end & 7) || end <= begin)
            return;
        const uintptr_t bytes = end - begin;
        if (bytes < stride || bytes > 0x1800)
            return;
        if ((begin ^ end) > 0x4000)
            return;
        // Array addresses are not Instance objects. Two instance pointers
        // as begin/end were a heap span that scored "Players" by accident.
        if (looks_instance(begin) || looks_instance(end))
            return;
        const size_t n = (size_t)(bytes / stride);
        if (n < 1 || n > 192)
            return;
        std::vector<uintptr_t> got;
        got.reserve(n);
        int named = 0, hits = 0;
        for (uintptr_t it = begin; it + 8 <= end; it += stride) {
            const uintptr_t ch = mem_.read_ptr(it);
            if (!looks_instance(ch) || ch == inst)
                continue;
            const auto nm = inst_name(ch);
            const auto cl = class_name(ch);
            if (nm.empty() && cl.empty())
                continue;
            got.push_back(ch);
            ++named;
            auto hit = [&](const char* a) { return nm == a || cl == a; };
            if (hit("Players"))
                hits += 1000;
            else if (hit("StarterPlayer") || hit("Workspace") || hit("CoreGui"))
                hits += 50;
        }
        if (got.empty())
            return;
        const int score = hits + named * 50 - (int)n;
        if (score > best_score) {
            best = std::move(got);
            best_score = score;
        }
    };
    for (uintptr_t offv : prefer(off().child_off, kChildOff, (int)std::size(kChildOff))) {
        const uintptr_t a = mem_.read_ptr(inst + offv);
        const uintptr_t b = mem_.read_ptr(inst + offv + 8);
        consider(a, b, 8);
        consider(a, b, 16);
        if (mem_.looks(a) && !looks_instance(a)) {
            consider(mem_.read_ptr(a), mem_.read_ptr(a + 8), 8);
            consider(mem_.read_ptr(a), mem_.read_ptr(a + 8), 16);
        }
    }
    out = std::move(best);
}

uintptr_t World::find_child_class(uintptr_t inst, const char* cls) const {
    std::vector<uintptr_t> ch;
    children_of(inst, ch);
    for (uintptr_t c : ch)
        if (class_name(c) == cls)
            return c;
    return 0;
}

uintptr_t World::find_child_name(uintptr_t inst, const char* name) const {
    std::vector<uintptr_t> ch;
    children_of(inst, ch);
    for (uintptr_t c : ch)
        if (inst_name(c) == name)
            return c;
    return 0;
}

bool World::part_pos(uintptr_t part, Vec3& out) const {
    if (!mem_.looks(part))
        return false;
    for (uintptr_t po : prefer(off().primitive, kPrimOff, (int)std::size(kPrimOff))) {
        uintptr_t prim = mem_.read_ptr(part + po);
        if (!mem_.looks(prim))
            prim = part;
        for (uintptr_t yo : prefer(off().position, kPosOff, (int)std::size(kPosOff))) {
            Vec3 v{};
            if (!mem_.read(prim + yo, &v, sizeof(v)))
                continue;
            if (v.x == 0 && v.y == 0 && v.z == 0)
                continue;
            if (v.x > 1e6f || v.y > 1e6f || v.z > 1e6f)
                continue;
            out = v;
            return true;
        }
    }
    return false;
}

int World::place_score(uintptr_t dm) const {
    if (!mem_.looks(dm))
        return 0;
    std::vector<uintptr_t> ch;
    children_of(dm, ch);
    if (ch.size() < 2)
        return 0;
    int s = 0;
    for (uintptr_t c : ch) {
        const auto n = inst_name(c);
        const auto cl = class_name(c);
        auto hit = [&](const char* a) { return n == a || cl == a; };
        if (hit("Players"))
            s += 80;
        if (hit("StarterPlayer"))
            s += 40;
        if (hit("CoreGui"))
            s += 20;
        if (hit("Workspace"))
            s += 8;
        if (hit("Lighting") || hit("ReplicatedStorage") || hit("StarterGui") || hit("Teams"))
            s += 6;
    }
    if (class_name(dm) == "DataModel" || inst_name(dm) == "Game" || inst_name(dm) == "Ugc")
        s += 4;
    return s;
}

bool World::looks_dm(uintptr_t dm) const {
    return place_score(dm) >= 8;
}

bool World::looks_place(uintptr_t dm) const {
    return place_score(dm) >= 80;
}

uintptr_t World::find_script_job() const {
    const auto ts_rva = off().task_scheduler;
    if (!ts_rva || !base_)
        return 0;
    uintptr_t slot = mem_.read_ptr(base_ + ts_rva);
    uintptr_t ts = mem_.looks(slot) ? slot : (base_ + ts_rva);
    const int starts[] = {
        (int)off().job_start,
        0xC8, 0xD0, 0xF0, 0x100, 0x118, 0x120, 0x128, 0x140,
        0x188, 0x198, 0x1B0, 0x1C8, 0x1D0, 0x1D8, 0x1E0, 0x208, 0x218
    };
    const int names[] = { (int)off().job_name, 0x18, 0x10, 0x20, 0x28, 0x30 };

    auto name_at = [&](uintptr_t job, int no) -> std::string {
        auto s = mem_.rstring(job + no);
        if (!s.empty())
            return s;
        const uintptr_t p = mem_.read_ptr(job + no);
        s = mem_.rstring(p);
        if (!s.empty())
            return s;
        return mem_.rstring_ptr(p);
    };
    auto rank_name = [](const std::string& nm) -> int {
        if (nm.empty() || nm == "Method" || nm == "function" || nm.size() < 4)
            return 0;
        if (nm.find("WaitingHybrid") != std::string::npos) return 100;
        if (nm.find("Luau") != std::string::npos) return 90;
        if (nm.find("WaitingScript") != std::string::npos) return 80;
        if (nm.find("Waiting") != std::string::npos) return 85;
        if (nm.find("ScriptContext") != std::string::npos) return 70;
        if (nm.find("ScriptJob") != std::string::npos) return 60;
        if (nm.find("Heartbeat") != std::string::npos) return 25;
        if (nm.find("Render") != std::string::npos) return 20;
        if (nm.find("Script") != std::string::npos) return 30;
        if (nm.find("TaskQueue") != std::string::npos) return 15;
        return 0;
    };

    uintptr_t best = 0;
    int best_rank = 0;
    int named = 0;
    std::string samples;
    int sample_n = 0;
    for (int st : starts) {
        if (st <= 0)
            continue;
        const uintptr_t begin = mem_.read_ptr(ts + st);
        const uintptr_t end   = mem_.read_ptr(ts + st + 8);
        if (!mem_.looks(begin) || !mem_.looks(end) || end <= begin || (end - begin) > 0x8000)
            continue;
        for (uintptr_t it = begin; it < end; it += sizeof(uintptr_t)) {
            const uintptr_t job = mem_.read_ptr(it);
            if (!mem_.looks(job))
                continue;
            std::string nm;
            int nm_rank = 0;
            for (int no : names) {
                if (no <= 0)
                    continue;
                auto cand = name_at(job, no);
                int r = rank_name(cand);
                if (r > nm_rank) {
                    nm_rank = r;
                    nm = std::move(cand);
                } else if (nm.empty() && !cand.empty() && cand != "Method") {
                    nm = std::move(cand);
                }
            }
            if (nm.empty())
                continue;
            ++named;
            if (sample_n < 8 && samples.find(nm) == std::string::npos) {
                if (!samples.empty()) samples += ",";
                samples += nm;
                ++sample_n;
            }
            const uintptr_t vptr = mem_.read_ptr(job);
            const bool image_vt = base_ && size_ && vptr >= base_ && vptr < base_ + size_;
            int rank = nm_rank;
            if (image_vt && rank > 0)
                rank += 20;
            if (rank > best_rank) {
                best_rank = rank;
                best = job;
            }
        }
        if (best_rank >= 100)
            return best;
    }
    static DWORD last_miss = 0;
    if (!best) {
        const DWORD now = GetTickCount();
        if (now - last_miss > 2000) {
            last_miss = now;
            VT_WARN(L"no script job  TS " + format_hex(ts) +
                    L" named=" + std::to_wstring(named) +
                    (samples.empty() ? L"" : (L" names=" + utf8_to_wide(samples))));
        }
    }
    return best;
}

DWORD World::find_lua_tid(uintptr_t lua_pcall, uintptr_t luau_load) const {
    if (!mem_.ok())
        return 0;
    const DWORD pid = GetProcessId(mem_.handle());
    if (!pid)
        return 0;

    using NtQIT = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static NtQIT NtQueryInformationThread = nullptr;
    if (!NtQueryInformationThread) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
            NtQueryInformationThread = (NtQIT)GetProcAddress(ntdll, "NtQueryInformationThread");
    }
    if (!NtQueryInformationThread)
        return 0;

    struct Tbi {
        LONG exit_status;
        void* teb;
        void* cid_proc;
        void* cid_thread;
        ULONG_PTR aff;
        LONG prio;
        LONG base_prio;
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD best_tid = 0;
    int best_hits = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid)
                continue;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                                   FALSE, te.th32ThreadID);
            if (!th)
                continue;
            Tbi tbi{};
            LONG st = NtQueryInformationThread(th, 0, &tbi, sizeof(tbi), nullptr);
            CloseHandle(th);
            if (st < 0 || !mem_.looks((uintptr_t)tbi.teb))
                continue;
            const uintptr_t stack_base = mem_.read_ptr((uintptr_t)tbi.teb + 0x08);
            const uintptr_t stack_lim  = mem_.read_ptr((uintptr_t)tbi.teb + 0x10);
            if (!mem_.looks(stack_base) || stack_base <= stack_lim)
                continue;
            uintptr_t start = stack_base - 0x20000;
            if (start < stack_lim)
                start = stack_lim;
            const size_t n = (size_t)(stack_base - start);
            if (n < 16 || n > 0x20000)
                continue;
            std::vector<uintptr_t> words(n / 8);
            if (!mem_.read(start, words.data(), words.size() * 8))
                continue;
            int hits = 0;
            for (uintptr_t w : words) {
                if (lua_pcall && w >= lua_pcall && w < lua_pcall + 0x800)
                    ++hits;
                if (luau_load && w >= luau_load && w < luau_load + 0x1000)
                    ++hits;
            }
            if (hits > best_hits) {
                best_hits = hits;
                best_tid = te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (best_hits <= 0)
        return 0;
    return best_tid;
}

uintptr_t World::find_lua_state(uintptr_t job) const {
    if (!mem_.looks(job))
        return 0;

    const int scs[] = {
        (int)off().script_context,
        0x180, 0x188, 0x190, 0x198, 0x1A0, 0x1A8, 0x1B0, 0x1B8,
        0x1C0, 0x1C8, 0x1D0, 0x1D8, 0x1E0, 0x1E8, 0x1F0, 0x1F8,
        0x200, 0x208, 0x210, 0x218, 0x220, 0x228, 0x230, 0x238,
        0x240, 0x248, 0x250, 0x258, 0x260, 0x268, 0x270, 0x278,
        0x280, 0x288, 0x290, 0x298, 0x2A0, 0x2A8, 0x2B0, 0x2B8,
        0x2C0, 0x2C8, 0x2D0, 0x2D8, 0x2E0, 0x2E8, 0x2F0, 0x2F8,
        0x300, 0x308, 0x310, 0x318, 0x320, 0x328, 0x330, 0x338,
        0x340, 0x348, 0x350, 0x358, 0x360, 0x368, 0x370, 0x378,
        0x380, 0x388, 0x390, 0x398, 0x3A0, 0x3A8, 0x3B0, 0x3B8,
        0x3C0, 0x3C8, 0x3D0, 0x3D8, 0x3E0, 0x3E8, 0x3F0, 0x3F8,
        0x400, 0x408, 0x410, 0x418, 0x420, 0x428, 0x430, 0x438,
        0x440, 0x448, 0x450, 0x458, 0x460, 0x468, 0x470, 0x478,
        0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138,
        0x140, 0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x178,
        0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78,
        0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0, 0xC8
    };
    const int sts[] = {
        (int)off().lua_state,
        0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8,
        0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8,
        0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138,
        0x140, 0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x178,
        0x180, 0x188, 0x190, 0x198, 0x1A0, 0x1A8, 0x1B0, 0x1B8,
        0x1C0, 0x1C8, 0x1D0, 0x1D8, 0x1E0, 0x1E8, 0x1F0, 0x1F8,
        0x200, 0x208, 0x210, 0x218, 0x220, 0x228, 0x230, 0x238,
        0x240, 0x248, 0x250, 0x258, 0x260, 0x268, 0x270, 0x278,
        0x280, 0x288, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78
    };
    auto heap = [](uintptr_t p) {
        return p > 0x10000 && p < 0x00007F0000000000ULL;
    };
    auto looks_state = [&](uintptr_t L) -> bool {
        if (!heap(L))
            return false;
        if (L + 0x400 > job && L < job + 0x400)
            return false;
        const int pair[][2] = { {16, 24}, {24, 32}, {8, 16}, {32, 40}, {0x20, 0x28} };
        for (auto& pr : pair) {
            const uintptr_t base = mem_.read_ptr(L + (uintptr_t)pr[0]);
            const uintptr_t top  = mem_.read_ptr(L + (uintptr_t)pr[1]);
            if (!heap(base) || !heap(top) || top < base)
                continue;
            if ((base & 15) || (top & 15) || (L & 7))
                continue;
            const size_t n = (size_t)(top - base) / 16;
            if (n >= 1 && n < 10000)
                return true;
        }
        return false;
    };
    auto decode = [&](uintptr_t sc, uintptr_t raw) -> uintptr_t {
        const uintptr_t cands[] = { raw, raw ^ sc, raw + sc, raw - sc, sc - raw };
        for (uintptr_t c : cands) {
            if (looks_state(c))
                return c;
        }
        const uintptr_t key = mem_.read_ptr(sc + 8);
        if (key && looks_state(raw ^ key))
            return raw ^ key;
        return 0;
    };
    auto hunt = [&](uintptr_t sc) -> uintptr_t {
        if (!heap(sc))
            return 0;
        for (int st_off : sts) {
            if (st_off <= 0)
                continue;
            const uintptr_t raw = mem_.read_ptr(sc + (uintptr_t)st_off);
            if (const uintptr_t L = decode(sc, raw))
                return L;
        }
        return 0;
    };

    // Diagnostic: dump heap-looking pointers from the job object
    int heap_count = 0;
    std::wstring diag;
    for (int sc_off : scs) {
        if (sc_off <= 0)
            continue;
        const uintptr_t sc = mem_.read_ptr(job + (uintptr_t)sc_off);
        if (heap(sc)) {
            ++heap_count;
            if (heap_count <= 12) {
                wchar_t buf[80];
                swprintf_s(buf, L" +%X->%llX", sc_off, (unsigned long long)sc);
                diag += buf;
            }
        }
        if (const uintptr_t L = hunt(sc))
            return L;
    }
    VT_WARN(L"find_lua_state FAILED  job=" + format_hex(job) +
            L"  heap_ptrs=" + std::to_wstring(heap_count) + diag);

    // Second pass: try treating job ITSELF as ScriptContext
    if (const uintptr_t L = hunt(job)) {
        VT_LOG(L"find_lua_state: job-as-SC hit  L=" + format_hex(L));
        return L;
    }

    // Third pass: follow one level of indirection from each heap pointer
    for (int sc_off : scs) {
        if (sc_off <= 0)
            continue;
        const uintptr_t ptr1 = mem_.read_ptr(job + (uintptr_t)sc_off);
        if (!heap(ptr1))
            continue;
        for (int inner : {0x0, 0x8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48,
                          0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98}) {
            const uintptr_t sc2 = mem_.read_ptr(ptr1 + inner);
            if (const uintptr_t L = hunt(sc2)) {
                VT_LOG(L"find_lua_state: double-deref hit  job+" +
                       format_hex(sc_off) + L"->" + format_hex(ptr1) +
                       L"+" + format_hex(inner) + L"->SC " + format_hex(sc2) +
                       L"  L=" + format_hex(L));
                return L;
            }
        }
    }

    return 0;
}

uintptr_t World::resolve_from_scheduler() {
    const auto ts_rva = off().task_scheduler;
    if (!ts_rva || !base_)
        return 0;
    uintptr_t slot = mem_.read_ptr(base_ + ts_rva);
    uintptr_t ts = mem_.looks(slot) ? slot : (base_ + ts_rva);
    const int starts[] = {
        (int)off().job_start, 0xC8, 0xD0, 0x118, 0x120, 0x128, 0x188, 0x198, 0x1D0, 0x1C8, 0x208
    };
    const int names[] = { (int)off().job_name, 0x18, 0x10, 0x20, 0x90 };
    const int scs[] = {
        0x1F0, 0x1F8, 0x200, 0x208, 0x210, 0x218, 0x1A8, 0x1B0, 0x1B8, 0x1C0, 0x1D8,
        0x38, 0x1C8, 0x3B0, 0x3A8, 0x220
    };
    const int pars[] = { 0x50, 0x48, 0x60, 0x68, 0x70, 0x80, 0x40, 0x58 };

    uintptr_t best = 0;
    int best_s = 0;
    uintptr_t app = 0;
    int jobs_seen = 0;
    std::string job_sample;

    auto consider = [&](uintptr_t p) {
        if (!mem_.looks(p))
            return;
        const int s = place_score(p);
        if (s >= 80 && s > best_s) {
            best_s = s;
            best = p;
        } else if (s >= 8 && !app)
            app = p;
        if (mem_.looks(p)) {
            for (int po : pars) {
                const uintptr_t p2 = mem_.read_ptr(p + po);
                const int s2 = place_score(p2);
                if (s2 >= 80 && s2 > best_s) {
                    best_s = s2;
                    best = p2;
                } else if (s2 >= 8 && !app)
                    app = p2;
            }
        }
    };

    for (int st : starts) {
        if (st <= 0)
            continue;
        const uintptr_t begin = mem_.read_ptr(ts + st);
        const uintptr_t end   = mem_.read_ptr(ts + st + 8);
        if (!mem_.looks(begin) || !mem_.looks(end) || end <= begin || (end - begin) > 0x8000)
            continue;
        for (uintptr_t it = begin; it < end; it += sizeof(uintptr_t)) {
            const uintptr_t job = mem_.read_ptr(it);
            if (!mem_.looks(job))
                continue;
            ++jobs_seen;
            std::string nm;
            for (int no : names) {
                nm = mem_.rstring(job + no);
                if (nm.size() >= 3)
                    break;
            }
            if (job_sample.size() < 120 && !nm.empty()) {
                if (!job_sample.empty())
                    job_sample += ",";
                job_sample += nm;
            }
            consider(job);
            for (int so : scs)
                consider(mem_.read_ptr(job + so));
        }
        if (best)
            break;
    }
    if (best) {
        VT_LOG(L"place DataModel " + format_hex(best) + L" score " + std::to_wstring(best_s));
        return best;
    }
    VT_WARN(L"no place DataModel (Players)  jobs=" + std::to_wstring(jobs_seen) +
            (job_sample.empty() ? L"" : (L" names=" + utf8_to_wide(job_sample.substr(0, 160)))));
    if (job_sample.find("Enable") != std::string::npos ||
        job_sample.find("FFlag") != std::string::npos ||
        job_sample.find("DevAsset") != std::string::npos)
        VT_WARN(L"task_scheduler looks like an FFlag list — offset is wrong, not Studio");
    else if (jobs_seen < 100)
        VT_WARN(L"only " + std::to_wstring(jobs_seen) + L" jobs — are you in a game server? (need 100+)");
    if (app)
        VT_WARN(L"app DataModel " + format_hex(app) + L" — home tree, not the place");
    return 0;
}

uintptr_t World::resolve_datamodel() {
    const DWORD now = GetTickCount();
    if (mem_.looks(cached_dm_)) {
        if (now - last_dm_check_ < 2000)
            return cached_dm_;
        if (looks_place(cached_dm_)) {
            last_dm_check_ = now;
            return cached_dm_;
        }
        cached_dm_ = 0;
    }
    auto take = [&](uintptr_t dm) -> uintptr_t {
        if (!looks_place(dm))
            return 0;
        cached_dm_ = dm;
        last_dm_check_ = GetTickCount();
        return dm;
    };
    for (uintptr_t rva : prefer(off().fake_datamodel, kFakeDm, (int)std::size(kFakeDm))) {
        const uintptr_t fake = mem_.read_ptr(base_ + rva);
        if (!mem_.looks(fake))
            continue;
        for (uintptr_t offv : prefer(off().fake_dm_off, kFakeOff, (int)std::size(kFakeOff))) {
            if (auto dm = take(mem_.read_ptr(fake + offv)))
                return dm;
        }
    }
    if (auto dm = resolve_from_scheduler())
        return take(dm) ? dm : 0;
    if (!dm_scan_done_) {
        dm_scan_done_ = true;
        if (auto dm = discover_datamodel())
            return take(dm) ? dm : 0;
    }
    return 0;
}

uintptr_t World::discover_datamodel() {
    if (!mem_.handle() || !base_ || !size_)
        return 0;
    auto cheap = [&](uintptr_t dm) {
        if (!mem_.looks(dm))
            return false;
        for (uintptr_t co : { 0x68ull, 0x70ull, 0x78ull, 0x80ull }) {
            const uintptr_t b = mem_.read_ptr(dm + co);
            const uintptr_t e = mem_.read_ptr(dm + co + 8);
            if (!mem_.looks(b) || !mem_.looks(e) || e <= b)
                continue;
            const uintptr_t n = (e - b) / 8;
            if (n >= 3 && n <= 48)
                return true;
        }
        return false;
    };

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = base_;
    const uintptr_t end = base_ + size_;
    int tries = 0;
    const uintptr_t foffs[] = { 0x1D8, 0x1C0, 0x1B8, 0, 0x1E0, 0x198 };
    while (addr < end) {
        if (!VirtualQueryEx(mem_.handle(), (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;
        const uintptr_t rsz = (uintptr_t)mbi.RegionSize;
        const bool rw = mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY);
        if (rw && rsz >= 0x1000 && rsz <= 0x800000) {
            std::vector<uint8_t> buf(rsz);
            if (mem_.read((uintptr_t)mbi.BaseAddress, buf.data(), rsz)) {
                for (size_t i = 0; i + 8 <= rsz; i += 8) {
                    const uintptr_t fake = *(uintptr_t*)(buf.data() + i);
                    if (fake < 0x10000000000ULL || fake > 0x00007FFFFFFFFFFULL)
                        continue;
                    if (fake >= base_ && fake < end)
                        continue;
                    if (++tries > 40000)
                        goto done;
                    for (uintptr_t fo : foffs) {
                        const uintptr_t dm = fo ? mem_.read_ptr(fake + fo) : fake;
                        if (!cheap(dm))
                            continue;
                        if (looks_place(dm)) {
                            const uintptr_t rva = ((uintptr_t)mbi.BaseAddress + i) - base_;
                            VT_LOG(L"place DataModel scan  rva " + format_hex(rva) +
                                   L"  fakeOff " + format_hex(fo) + L"  dm " + format_hex(dm));
                            return dm;
                        }
                    }
                }
            }
        }
        const uintptr_t next = (uintptr_t)mbi.BaseAddress + rsz;
        if (next <= addr)
            break;
        addr = next;
    }
done:
    VT_WARN(L"DataModel scan miss — live RVAs are empty; Inject for Highlight ESP");
    return 0;
}

uintptr_t World::resolve_visual() {
    if (mem_.looks(cached_ve_))
        return cached_ve_;
    for (uintptr_t rva : prefer(off().visual_engine, kVeRva, (int)std::size(kVeRva))) {
        const uintptr_t ve = mem_.read_ptr(base_ + rva);
        if (!mem_.looks(ve))
            continue;
        float m[16]{};
        const uintptr_t vm = off().view_matrix ? off().view_matrix : 0x180;
        if (mem_.read(ve + vm, m, sizeof(m)) || mem_.read(ve + 0x180, m, sizeof(m)) ||
            mem_.read(ve + 0x130, m, sizeof(m))) {
            cached_ve_ = ve;
            return ve;
        }
    }
    return 0;
}

uintptr_t World::resolve_players(uintptr_t dm) {
    if (auto p = find_service(dm, "Players"))
        return p;
    if (auto p = find_child_class(dm, "Players"))
        return p;
    std::vector<uintptr_t> ch;
    children_of(dm, ch);
    for (uintptr_t c : ch) {
        const auto cn = class_name(c);
        const auto nm = inst_name(c);
        if (cn == "Players" || nm == "Players")
            return c;
    }
    return 0;
}

bool World::world_to_screen(const Vec3& w, Vec2& s) const {
    const float* m = view_;
    const float clip_x = w.x * m[0] + w.y * m[4] + w.z * m[8]  + m[12];
    const float clip_y = w.x * m[1] + w.y * m[5] + w.z * m[9]  + m[13];
    const float clip_w = w.x * m[3] + w.y * m[7] + w.z * m[11] + m[15];
    if (clip_w < 0.08f)
        return false;
    const float inv = 1.f / clip_w;
    s.x = (width_  * 0.5f) * (1.f + clip_x * inv);
    s.y = (height_ * 0.5f) * (1.f - clip_y * inv);
    return s.x >= -400 && s.y >= -400 && s.x <= width_ + 400 && s.y <= height_ + 400;
}

bool World::poll(std::vector<Entity>& out, int* screen_w, int* screen_h) {
    out.clear();
    stats_ = {};
    stats_.attached = ok();
    if (!ok()) {
        wcsncpy_s(stats_.note, L"no process", _TRUNCATE);
        return false;
    }

    const uintptr_t dm = resolve_datamodel();
    stats_.datamodel = mem_.looks(dm);
    if (!stats_.datamodel) {
        wcsncpy_s(stats_.note, L"no DataModel — join a server", _TRUNCATE);
        return false;
    }

    const uintptr_t ve = resolve_visual();
    stats_.visual = mem_.looks(ve);
    if (stats_.visual) {
        const uintptr_t vm = off().view_matrix ? off().view_matrix : 0x180;
        if (!mem_.read(ve + vm, view_, sizeof(view_)))
            mem_.read(ve + 0x130, view_, sizeof(view_));
        struct { float x, y; } dim{};
        if ((mem_.read(ve + 0xAE0, &dim, sizeof(dim)) || mem_.read(ve + 0xA60, &dim, sizeof(dim)))
            && dim.x > 64 && dim.y > 64) {
            width_ = dim.x;
            height_ = dim.y;
        }
    }
    if (screen_w) *screen_w = (int)width_;
    if (screen_h) *screen_h = (int)height_;

    uintptr_t players = cached_players_;
    if (!mem_.looks(players))
        players = resolve_players(dm);
    stats_.players_svc = mem_.looks(players);
    if (!players) {
        tracked_.clear();
        wcsncpy_s(stats_.note, L"DataModel ok, no Players", _TRUNCATE);
        return false;
    }
    cached_players_ = players;

    const DWORD now = GetTickCount();
    const bool rebuild = tracked_.empty() || (now - last_tree_ > 250);

    auto fill_hp = [&](Tracked& t) {
        if (!mem_.looks(t.hum))
            return;
        const uintptr_t hp = off().humanoid_hp ? off().humanoid_hp : 0x190;
        const uintptr_t mx = off().humanoid_maxhp ? off().humanoid_maxhp : 0x1A8;
        t.e.health = mem_.read<float>(t.hum + hp);
        t.e.max_health = mem_.read<float>(t.hum + mx);
        if (t.e.max_health < 1.f)
            t.e.max_health = mem_.read<float>(t.hum + 0x1B4);
    };

    if (rebuild) {
        last_tree_ = now;
        tracked_.clear();

        uintptr_t local = 0;
        for (uintptr_t offv : prefer(off().local_player, kLocalOff, (int)std::size(kLocalOff))) {
            local = mem_.read_ptr(players + offv);
            if (mem_.looks(local))
                break;
        }

        std::vector<uintptr_t> list;
        children_of(players, list);

        for (uintptr_t pl : list) {
            Tracked t;
            t.e.player = pl;
            t.e.local = (pl == local);
            t.e.name = inst_name(pl);
            if (t.e.name.empty())
                continue;

            for (uintptr_t offv : prefer(off().character, kCharOff, (int)std::size(kCharOff))) {
                t.e.character = mem_.read_ptr(pl + offv);
                if (mem_.looks(t.e.character))
                    break;
            }
            if (mem_.looks(t.e.character)) {
                const uintptr_t root = off().root_part ? off().root_part : 0x258;
                t.part = mem_.read_ptr(t.e.character + root);
                if (!mem_.looks(t.part))
                    t.part = find_child_name(t.e.character, "HumanoidRootPart");
                if (!mem_.looks(t.part))
                    t.part = find_child_name(t.e.character, "Head");
                if (!mem_.looks(t.part))
                    t.part = find_child_name(t.e.character, "Torso");
                t.hum = find_child_class(t.e.character, "Humanoid");
            }
            tracked_.push_back(std::move(t));
        }
    }

    for (auto& t : tracked_) {
        t.e.has_pos = false;
        if (mem_.looks(t.part) && part_pos(t.part, t.e.pos))
            t.e.has_pos = true;
        fill_hp(t);
        out.push_back(t.e);
    }

    stats_.entities = (int)out.size();
    if (out.empty())
        wcsncpy_s(stats_.note, L"in game? no characters yet", _TRUNCATE);
    else
        swprintf_s(stats_.note, L"%d players", stats_.entities);
    return true;
}

bool World::execute_script(const std::string& source, std::wstring* err) {
    auto fail = [&](const wchar_t* m) {
        if (err) *err = m;
        VT_WARN(std::wstring(L"corescript exec: ") + m);
        return false;
    };
    if (!ok())
        return fail(L"not attached");

    // Hyperion 26200: LocalScript stamp+respawn = 268; ModuleScript VA/section
    // pointer = unexpected error. APC/vtable/WM_TIMER already dead (no CFG gadget).
    return fail(L"in-game Lua stamp is 268 — overlay ESP only");

    const auto& tbl = off();
    const uintptr_t dm = resolve_datamodel();

    // --- Strategy A: Direct execution via NtCreateThreadEx / thread hijack ---
    // Preferred when we have luau_load + lua_pcall + a Lua state.
    // NtCreateThreadEx uses direct syscalls to bypass Hyperion's ntdll hooks.
    if (tbl.luau_load && tbl.lua_pcall) {
        const uintptr_t fn_load   = base_ + tbl.luau_load;
        const uintptr_t fn_pcall  = base_ + tbl.lua_pcall;
        const uintptr_t fn_newth  = tbl.lua_newthread ? (base_ + tbl.lua_newthread) : 0;
        const bool have_newthread = fn_newth != 0;

        uintptr_t job = find_script_job();
        uintptr_t L   = job ? find_lua_state(job) : 0;

        // NtCreateThreadEx + SetThreadContext are blocked by Hyperion kernel driver.
        // NtCreateThreadEx → STATUS_ACCESS_DENIED; hijack → crash at phase 0.
        // Skip straight to vtable hook (pure memory writes, no thread manipulation).
        constexpr bool kTryThreadExec = false;
        if (kTryThreadExec && L) {
            VT_LOG(L"hijack: job " + format_hex(job) + L" L " + format_hex(L) +
                   L" newthread=" + (have_newthread ? format_hex(fn_newth) : L"NONE(direct)"));

            const std::string hijack_src =
                std::string("if _G.__VT then return end;_G.__VT=true;task.spawn(function()\n") + kCoreShimTiny + source + "\nend)\n";
            auto raw_bc = compile_raw_luau_bytecode(hijack_src);
            if (!raw_bc.first) {
                raw_bc = compile_raw_luau_bytecode(
                    std::string("task.spawn(function()\n") + source + "\nend)\n");
            }

            if (raw_bc.first) {
                const size_t bc_len = raw_bc.second.size();
                const size_t sc_off  = 0x60;
                const size_t bc_off  = 0xE0;
                const size_t total   = bc_off + bc_len + 16;

                HANDLE hp = mem_.handle();
                void* remote = nullptr;
                SC_VirtualAllocEx(hp, nullptr, total,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE, &remote);
                if (remote) {
                    const uintptr_t rb = (uintptr_t)remote;
                    auto wr_r = [&](uintptr_t addr, const void* p, size_t n) -> bool {
                        SIZE_T w = 0;
                        return SC_WriteProcessMemory(hp, (LPVOID)addr, p, n, &w) && w == n;
                    };
                    const char chunk[] = "=VT";
                    wr_r(rb + 0x50, chunk, sizeof(chunk));
                    wr_r(rb + bc_off, raw_bc.second.data(), bc_len);

                    // Two shellcode variants:
                    // A) With lua_newthread: newthread(L)->nL, luau_load(nL,...), pcall(nL,...)
                    // B) Direct: luau_load(L,...), pcall(L,...) — fallback when newthread not found
                    // PB: +00 L  +08 name  +10 data  +18 sz  +20 fn_load  +28 fn_pcall  +30 fn_newthread
                    // Results: +38 phase  +3C load_result  +40 pcall_result

                    if (have_newthread) {
                        // Variant A: with lua_newthread
                        static const uint8_t sc_a[] = {
                            0x53,                                                   // push rbx
                            0x48, 0x83, 0xEC, 0x48,                                 // sub rsp, 48h
                            0x48, 0x89, 0xCB,                                       // mov rbx, rcx
                            0xC7, 0x43, 0x38, 0x01, 0x00, 0x00, 0x00,               // phase 1
                            0x48, 0x8B, 0x0B,                                       // mov rcx, [rbx]
                            0xFF, 0x53, 0x30,                                       // call [rbx+30h] newthread
                            0x48, 0x89, 0x44, 0x24, 0x40,                           // save nL to [rsp+40h]
                            0xC7, 0x43, 0x38, 0x02, 0x00, 0x00, 0x00,               // phase 2
                            0x48, 0x89, 0xC1,                                       // mov rcx, rax (nL)
                            0x48, 0x8B, 0x53, 0x08,                                 // mov rdx, [rbx+8]
                            0x4C, 0x8B, 0x43, 0x10,                                 // mov r8, [rbx+10h]
                            0x4C, 0x8B, 0x4B, 0x18,                                 // mov r9, [rbx+18h]
                            0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,   // [rsp+20h]=0
                            0xFF, 0x53, 0x20,                                       // call [rbx+20h] luau_load
                            0x89, 0x43, 0x3C,                                       // save load result
                            0xC7, 0x43, 0x38, 0x03, 0x00, 0x00, 0x00,               // phase 3
                            0x85, 0xC0,                                             // test eax, eax
                            0x75, 0x2C,                                             // jnz done (+44)
                            0x48, 0x8B, 0x4C, 0x24, 0x40,                           // mov rcx, [rsp+40h] nL
                            0x31, 0xD2,                                             // xor edx, edx
                            0x45, 0x31, 0xC0,                                       // xor r8d, r8d
                            0x45, 0x31, 0xC9,                                       // xor r9d, r9d
                            0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,   // [rsp+20h]=0
                            0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,   // [rsp+28h]=0
                            0xFF, 0x53, 0x28,                                       // call [rbx+28h] pcall
                            0x89, 0x43, 0x40,                                       // save pcall result
                            0xC7, 0x43, 0x38, 0x04, 0x00, 0x00, 0x00,               // phase 4
                            // done:
                            0x48, 0x83, 0xC4, 0x48,                                 // add rsp, 48h
                            0x5B,                                                   // pop rbx
                            0xC3                                                    // ret
                        };
                        static_assert(sizeof(sc_a) <= 0x80, "shellcode A exceeds 128 bytes");
                        wr_r(rb + sc_off, sc_a, sizeof(sc_a));
                    } else {
                        // Variant B: direct on L (no newthread)
                        static const uint8_t sc_b[] = {
                            0x53,                                                   // push rbx
                            0x48, 0x83, 0xEC, 0x48,                                 // sub rsp, 48h
                            0x48, 0x89, 0xCB,                                       // mov rbx, rcx
                            0xC7, 0x43, 0x38, 0x01, 0x00, 0x00, 0x00,               // phase 1
                            // luau_load(L, name, data, sz, 0)
                            0x48, 0x8B, 0x0B,                                       // mov rcx, [rbx]
                            0x48, 0x8B, 0x53, 0x08,                                 // mov rdx, [rbx+8]
                            0x4C, 0x8B, 0x43, 0x10,                                 // mov r8, [rbx+10h]
                            0x4C, 0x8B, 0x4B, 0x18,                                 // mov r9, [rbx+18h]
                            0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,   // [rsp+20h]=0
                            0xFF, 0x53, 0x20,                                       // call [rbx+20h] luau_load
                            0x89, 0x43, 0x3C,                                       // save load result
                            0xC7, 0x43, 0x38, 0x02, 0x00, 0x00, 0x00,               // phase 2
                            0x85, 0xC0,                                             // test eax, eax
                            0x75, 0x2A,                                             // jnz done (+42)
                            // lua_pcall(L, 0, 0, 0, 0, 0)
                            0x48, 0x8B, 0x0B,                                       // mov rcx, [rbx]
                            0x31, 0xD2,                                             // xor edx, edx
                            0x45, 0x31, 0xC0,                                       // xor r8d, r8d
                            0x45, 0x31, 0xC9,                                       // xor r9d, r9d
                            0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,   // [rsp+20h]=0
                            0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,   // [rsp+28h]=0
                            0xFF, 0x53, 0x28,                                       // call [rbx+28h] pcall
                            0x89, 0x43, 0x40,                                       // save pcall result
                            0xC7, 0x43, 0x38, 0x03, 0x00, 0x00, 0x00,               // phase 3
                            // done:
                            0x48, 0x83, 0xC4, 0x48,                                 // add rsp, 48h
                            0x5B,                                                   // pop rbx
                            0xC3                                                    // ret
                        };
                        static_assert(sizeof(sc_b) <= 0x80, "shellcode B exceeds 128 bytes");
                        wr_r(rb + sc_off, sc_b, sizeof(sc_b));
                        VT_WARN(L"hijack: using DIRECT mode (no lua_newthread)");
                    }

                    struct alignas(8) PB {
                        uintptr_t L;
                        uintptr_t chunkname;
                        uintptr_t data;
                        uintptr_t size;
                        uintptr_t fn_load;
                        uintptr_t fn_pcall;
                        uintptr_t fn_newthread;
                    };
                    PB pb{};
                    pb.L            = L;
                    pb.chunkname    = rb + 0x50;
                    pb.data         = rb + bc_off;
                    pb.size         = bc_len;
                    pb.fn_load      = fn_load;
                    pb.fn_pcall     = fn_pcall;
                    pb.fn_newthread = fn_newth;
                    wr_r(rb, &pb, sizeof(pb));

                    VT_LOG(L"hijack: sc " + format_hex(rb + sc_off) +
                           L" pb " + format_hex(rb) +
                           L" L " + format_hex(L) +
                           L" load " + format_hex(fn_load) +
                           L" pcall " + format_hex(fn_pcall) +
                           (have_newthread ? (L" newthread " + format_hex(fn_newth)) : L" DIRECT") +
                           L" bc " + std::to_wstring(bc_len));

                    // --- read-back lambda for shellcode results ---
                    const int max_phase = have_newthread ? 4 : 3;
                    auto read_results = [&](const wchar_t* tag) -> bool {
                        DWORD exit_code = 0;
                        const bool alive = GetExitCodeProcess(hp, &exit_code)
                                           && exit_code == STILL_ACTIVE;
                        uint32_t phase = 0, res_load = 0, res_pcall = 0;
                        SIZE_T rd = 0;
                        if (alive) {
                            ReadProcessMemory(hp, (LPCVOID)(rb + 0x38), &phase, 4, &rd);
                            ReadProcessMemory(hp, (LPCVOID)(rb + 0x3C), &res_load, 4, &rd);
                            ReadProcessMemory(hp, (LPCVOID)(rb + 0x40), &res_pcall, 4, &rd);
                        }
                        VT_LOG(std::wstring(tag) + L" results: alive=" + std::to_wstring(alive) +
                               L" phase=" + std::to_wstring(phase) +
                               L" luau_load=" + std::to_wstring((int)res_load) +
                               L" lua_pcall=" + std::to_wstring((int)res_pcall));
                        if (phase >= (uint32_t)max_phase && res_load == 0) {
                            VT_LOG(std::wstring(tag) + L" SUCCESS — script executed");
                            return true;
                        }
                        if (!alive)
                            VT_WARN(std::wstring(tag) + L": Roblox crashed (phase " +
                                    std::to_wstring(phase) + L")");
                        else
                            VT_WARN(std::wstring(tag) + L": phase " + std::to_wstring(phase) +
                                    L"/" + std::to_wstring(max_phase));
                        return false;
                    };

                    // --- Strategy 1: NtCreateThreadEx via direct syscall ---
                    // Creates a new OS thread pointing at our shellcode.
                    // Bypasses Hyperion's ntdll hooks on NtCreateThreadEx.
                    bool exec_ok = false;
                    auto& sc = Syscalls::get();
                    if (sc.ready() && sc.CreateThreadEx) {
                        VT_LOG(L"NtCreateThreadEx: attempting direct-syscall thread creation");
                        HANDLE hNewThread = nullptr;
                        NTSTATUS nts = sc.CreateThreadEx(
                            &hNewThread, THREAD_ALL_ACCESS, nullptr, hp,
                            (PVOID)(rb + sc_off), (PVOID)rb,
                            0x00000004 /*CREATE_SUSPENDED*/, 0, 0, 0, nullptr);
                        if (nts >= 0 && hNewThread) {
                            VT_LOG(L"NtCreateThreadEx: thread created (suspended) — resuming");
                            ResumeThread(hNewThread);
                            DWORD wait = WaitForSingleObject(hNewThread, 5000);
                            if (wait == WAIT_TIMEOUT)
                                VT_WARN(L"NtCreateThreadEx: thread did not finish in 5s");
                            exec_ok = read_results(L"NtCreateThreadEx");
                            CloseHandle(hNewThread);
                        } else {
                            VT_WARN(L"NtCreateThreadEx failed: NTSTATUS " + format_hex((uintptr_t)(ULONG)nts));
                        }
                    }

                    // --- Strategy 2: thread hijack (SetThreadContext) ---
                    if (!exec_ok) {
                        VT_LOG(L"falling back to thread hijack (SetThreadContext)");
                        const DWORD pid = GetProcessId(hp);
                        auto hr = ThreadHijacker::run(hp, pid,
                                                       (LPVOID)(rb + sc_off),
                                                       (LPVOID)rb,
                                                       nullptr, 5000, 0);
                        if (hr.ok)
                            exec_ok = read_results(L"hijack");
                        else
                            VT_WARN(L"thread hijack failed: " + hr.error);
                    }

                    if (exec_ok)
                        return true;
                } else {
                    VT_WARN(L"hijack: remote alloc failed");
                }
            } else {
                VT_WARN(L"hijack: raw bytecode compile failed");
            }
        } else if (!L) {
            VT_WARN(L"no Lua state: " +
                    (job ? (L"job " + format_hex(job) + L" has no L")
                         : std::wstring(L"no script job in scheduler")));
        }
        // --- Strategy A: Vtable hook / APC / WM_TIMER / inline / IC ---
        // ALL direct execution paths are blocked by Hyperion on current builds:
        //   - NtCreateThreadEx: ACCESS_DENIED from kernel driver
        //   - SetThreadContext: crash at phase 0
        //   - Vtable hook: CFG bitmap blocked + Hyperion vtable checksum (exit 0xC0000141)
        //   - APC special: kernel driver intercepts NtQueueApcThreadEx2
        //   - APC regular: all threads use non-alertable waits
        //   - WM_TIMER: SetProcessMitigationPolicy blocks callback from non-module memory
        //   - Inline hook: VirtualProtectEx denied on code pages (err 998)
        //   - Instrumentation Callback: NtSetInformationProcess ACCESS_DENIED
        // Skip directly to container stamp + respawn (Strategy B).
        constexpr bool kTryDirectExec = false;
        if (kTryDirectExec && job && L) {
            HANDLE vhp = mem_.handle();
            const std::string vt_src =
                std::string("if _G.__VT then return end;_G.__VT=true;task.spawn(function()\n")
                + kCoreShimTiny + source + "\nend)\n";
            auto vt_bc = compile_raw_luau_bytecode(vt_src);
            if (!vt_bc.first)
                vt_bc = compile_raw_luau_bytecode(std::string("task.spawn(function()\n") + source + "\nend)\n");
            const size_t vt_bc_len = vt_bc.second.size();
            VT_LOG(L"vtable hook: attempting on job " + format_hex(job));
            auto is_module_addr = [&](uintptr_t addr) -> bool {
                if (!mem_.looks(addr)) return false;
                if (addr >= base_ && addr < base_ + size_) return true;
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx(vhp, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi))
                    return mbi.Type == MEM_IMAGE;
                return false;
            };
            // Try vtable at offset 0 (standard) and 8/16 (multi-inheritance)
            uintptr_t orig_vt = 0;
            for (int vto : {0, 8, 16}) {
                uintptr_t cand = mem_.read_ptr(job + vto);
                if (is_module_addr(cand)) {
                    orig_vt = cand;
                    if (vto > 0)
                        VT_LOG(L"vtable hook: vtable at job+" + std::to_wstring(vto));
                    break;
                }
            }
            if (orig_vt) {
                constexpr int VT_ENTRIES = 16;
                uintptr_t vt_buf[VT_ENTRIES]{};
                mem_.read(orig_vt, vt_buf, sizeof(vt_buf));

                int hook_idx = -1;
                // step() is typically at vtable index 3-8 in MSVC.
                // Index 0-2 are usually RTTI/destructors (rarely called).
                for (int i = 3; i <= 8; ++i) {
                    if (is_module_addr(vt_buf[i])) {
                        hook_idx = i;
                        break;
                    }
                }
                if (hook_idx < 0) {
                    for (int i = 1; i < VT_ENTRIES; ++i) {
                        if (is_module_addr(vt_buf[i])) {
                            hook_idx = i;
                            break;
                        }
                    }
                }

                if (hook_idx >= 0) {
                    const size_t vt_sc_off = 0x80;
                    const size_t vt_vt_off = 0x140;
                    const size_t vt_bc_off = 0x200;
                    const size_t apc_sc_off = vt_bc_off + vt_bc_len + 64;
                    const size_t timer_sc_off = apc_sc_off + 128;
                    const size_t vt_total = timer_sc_off + 32;
                    void* vt_remote = nullptr;
                    SC_VirtualAllocEx(vhp, nullptr, vt_total,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, &vt_remote);
                    if (vt_remote) {
                        const uintptr_t vrb = (uintptr_t)vt_remote;
                        auto wr_v = [&](uintptr_t a, const void* p, size_t n) {
                            SIZE_T w = 0;
                            SC_WriteProcessMemory(vhp, (LPVOID)a, p, n, &w);
                        };
                        // Write bytecode + chunkname
                        const char vchunk[] = "=VT";
                        wr_v(vrb + 0x60, vchunk, sizeof(vchunk));
                        wr_v(vrb + vt_bc_off, vt_bc.second.data(), vt_bc_len);

                        // Clone vtable, replace hook_idx with shellcode address
                        uintptr_t vt_clone[VT_ENTRIES];
                        memcpy(vt_clone, vt_buf, sizeof(vt_clone));
                        vt_clone[hook_idx] = vrb + vt_sc_off;
                        wr_v(vrb + vt_vt_off, vt_clone, sizeof(vt_clone));

                        // Parameter block (PB) at vrb+0x00:
                        //  +00 L  +08 name  +10 data  +18 sz  +20 fn_load
                        //  +28 fn_pcall  +30 fn_newthread  +38 phase  +3C load_result
                        //  +40 orig_vtable  +48 one_shot  +50 job_addr  +58 orig_step
                        struct alignas(8) VPB {
                            uintptr_t L, chunkname, data, size, fn_load, fn_pcall, fn_newthread;
                            uint32_t phase; uint32_t load_result;
                            uintptr_t orig_vtable;
                            uint32_t one_shot; uint32_t _pad;
                            uintptr_t job_addr;
                            uintptr_t orig_step;
                        };
                        VPB vpb{};
                        vpb.L           = L;
                        vpb.chunkname   = vrb + 0x60;
                        vpb.data        = vrb + vt_bc_off;
                        vpb.size        = vt_bc_len;
                        vpb.fn_load     = fn_load;
                        vpb.fn_pcall    = fn_pcall;
                        vpb.fn_newthread = fn_newth;
                        vpb.phase       = 0;
                        vpb.load_result = 0;
                        vpb.orig_vtable = orig_vt;
                        vpb.one_shot    = 0;
                        vpb.job_addr    = job;
                        vpb.orig_step   = vt_buf[hook_idx];
                        wr_v(vrb, &vpb, sizeof(vpb));
                        VT_LOG(L"PB: L=" + format_hex(L) + L" load=" + format_hex(fn_load) +
                               L" pcall=" + format_hex(fn_pcall) + L" bc=" + format_hex(vrb + vt_bc_off) +
                               L" sz=" + std::to_wstring(vt_bc_len) + L" vrb=" + format_hex(vrb));

                        // --- APC injection (tried FIRST — doesn't modify game objects) ---
                        // Hyperion checksums vtable pointers, so vtable hooks are detected.
                        // APC queues a callback to a thread — no game object modification.
                        // Primary: NtQueueApcThreadEx2 with SPECIAL_USER_APC flag (0x1)
                        //          fires immediately — no alertable wait required.
                        // Fallback: regular QueueUserAPC on all threads (needs alertable).
                        {
                            uint8_t apc_sc[] = {
                                0x53,                                           // push rbx
                                0x48,0x83,0xEC,0x40,                            // sub rsp,40h
                                0x48,0x89,0xCB,                                 // mov rbx,rcx (PB=dwData)
                                0xF0,0x0F,0xBA,0x6B,0x48,0x00,                  // lock bts [rbx+48h],0
                                0x0F,0x82,0x57,0x00,0x00,0x00,                  // jc .done (+0x57)
                                0xC7,0x43,0x38,0x01,0x00,0x00,0x00,             // phase=1 (sc started)
                                0x48,0x8B,0x0B,                                 // mov rcx,[rbx]
                                0x48,0x8B,0x53,0x08,                            // mov rdx,[rbx+8]
                                0x4C,0x8B,0x43,0x10,                            // mov r8,[rbx+10h]
                                0x4C,0x8B,0x4B,0x18,                            // mov r9,[rbx+18h]
                                0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,   // [rsp+20h]=0
                                0xFF,0x53,0x20,                                 // call [rbx+20h] (luau_load)
                                0x89,0x43,0x3C,                                 // [rbx+3Ch]=eax
                                0xC7,0x43,0x38,0x02,0x00,0x00,0x00,             // phase=2
                                0x85,0xC0,                                      // test eax,eax
                                0x75,0x27,                                      // jnz .done
                                0x48,0x8B,0x0B,                                 // mov rcx,[rbx]
                                0x31,0xD2,                                      // xor edx
                                0x45,0x31,0xC0,                                 // xor r8d
                                0x45,0x31,0xC9,                                 // xor r9d
                                0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,
                                0x48,0xC7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,
                                0xFF,0x53,0x28,                                 // call [rbx+28h] (lua_pcall)
                                0xC7,0x43,0x38,0x03,0x00,0x00,0x00,             // phase=3
                                // .done:
                                0x48,0x83,0xC4,0x40,                            // add rsp,40h
                                0x5B,                                           // pop rbx
                                0xC3                                            // ret
                            };
                            wr_v(vrb + apc_sc_off, apc_sc, sizeof(apc_sc));

                            DWORD rbx_pid = GetProcessId(vhp);
                            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                            if (snap != INVALID_HANDLE_VALUE) {
                                THREADENTRY32 te{sizeof(te)};
                                DWORD main_tid = 0;
                                std::vector<DWORD> all_tids;
                                if (Thread32First(snap, &te)) {
                                    do {
                                        if (te.th32OwnerProcessID == rbx_pid) {
                                            all_tids.push_back(te.th32ThreadID);
                                            if (!main_tid || te.th32ThreadID < main_tid)
                                                main_tid = te.th32ThreadID;
                                        }
                                    } while (Thread32Next(snap, &te));
                                }
                                CloseHandle(snap);

                                auto& sc = Syscalls::get();
                                bool apc_ok = false;

                                // --- Primary: NtQueueApcThreadEx2 + SPECIAL_USER_APC ---
                                if (sc.QueueApcThreadEx2) {
                                    int sp_queued = 0;
                                    std::vector<HANDLE> sp_handles;
                                    for (DWORD tid : all_tids) {
                                        if (tid == main_tid) continue;
                                        if (sp_queued >= 5) break;
                                        HANDLE h = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
                                        if (!h) continue;
                                        NTSTATUS ns = sc.QueueApcThreadEx2(
                                            h, nullptr, 1,
                                            (PVOID)(vrb + apc_sc_off),
                                            (PVOID)vrb, nullptr, nullptr);
                                        if (ns >= 0) {
                                            sp_handles.push_back(h);
                                            ++sp_queued;
                                        } else {
                                            CloseHandle(h);
                                        }
                                    }
                                    VT_LOG(L"special APC queued to " + std::to_wstring(sp_queued) +
                                           L"/" + std::to_wstring(all_tids.size()) + L" threads");

                                    if (sp_queued > 0) {
                                        for (int ap = 0; ap < 15; ++ap) {
                                            Sleep(100);
                                            uint32_t aph = 0; SIZE_T ard = 0;
                                            ReadProcessMemory(vhp, (LPCVOID)(vrb + 0x38), &aph, 4, &ard);
                                            DWORD aex = 0;
                                            if (!(GetExitCodeProcess(vhp, &aex) && aex == STILL_ACTIVE)) {
                                                VT_WARN(L"special APC: Roblox crashed (phase=" +
                                                        std::to_wstring(aph) + L" exit=0x" + format_hex(aex) + L")");
                                                break;
                                            }
                                            if (aph >= 2) {
                                                VT_LOG(L"special APC SUCCESS phase=" + std::to_wstring(aph));
                                                apc_ok = true;
                                                break;
                                            }
                                        }
                                        for (HANDLE h : sp_handles) CloseHandle(h);
                                        if (apc_ok) return true;
                                        {
                                            uint32_t final_ph = 0; SIZE_T frd = 0;
                                            ReadProcessMemory(vhp, (LPCVOID)(vrb + 0x38), &final_ph, 4, &frd);
                                            VT_WARN(L"special APC: timed out (phase=" + std::to_wstring(final_ph) + L")");
                                        }
                                    }
                                    // Reset one-shot flag for fallback
                                    uint32_t zero = 0;
                                    wr_v(vrb + 0x48, &zero, 4);
                                    wr_v(vrb + 0x38, &zero, 4);
                                } else {
                                    VT_WARN(L"NtQueueApcThreadEx2 stub not available");
                                }

                                // --- Fallback: regular QueueUserAPC (needs alertable wait) ---
                                if (!apc_ok) {
                                    std::vector<HANDLE> apc_handles;
                                    int queued = 0;
                                    for (DWORD tid : all_tids) {
                                        if (tid == main_tid) continue;
                                        HANDLE h = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
                                        if (!h) continue;
                                        if (QueueUserAPC((PAPCFUNC)(vrb + apc_sc_off), h, (ULONG_PTR)vrb)) {
                                            apc_handles.push_back(h);
                                            ++queued;
                                        } else {
                                            CloseHandle(h);
                                        }
                                    }
                                    VT_LOG(L"regular APC queued to " + std::to_wstring(queued) + L"/" +
                                           std::to_wstring(all_tids.size()) + L" threads (alertable)");

                                    if (queued > 0) {
                                        for (int ap = 0; ap < 15; ++ap) {
                                            Sleep(100);
                                            uint32_t aph = 0; SIZE_T ard = 0;
                                            ReadProcessMemory(vhp, (LPCVOID)(vrb + 0x38), &aph, 4, &ard);
                                            DWORD aex = 0;
                                            if (!(GetExitCodeProcess(vhp, &aex) && aex == STILL_ACTIVE)) {
                                                VT_WARN(L"APC: Roblox crashed (phase=" + std::to_wstring(aph) +
                                                        L" exit=0x" + format_hex(aex) + L")");
                                                break;
                                            }
                                            if (aph >= 2) {
                                                VT_LOG(L"APC SUCCESS phase=" + std::to_wstring(aph));
                                                apc_ok = true;
                                                break;
                                            }
                                        }
                                        for (HANDLE h : apc_handles) CloseHandle(h);
                                        if (apc_ok) return true;
                                        VT_WARN(L"APC: timed out — threads not alertable");
                                    }
                                }
                            }
                        }

                        // --- Check if Roblox is still alive before WM_TIMER ---
                        {
                            DWORD alive_chk = 0;
                            if (!(GetExitCodeProcess(vhp, &alive_chk) && alive_chk == STILL_ACTIVE)) {
                                VT_WARN(L"Roblox died — aborting remaining execution paths");
                                return fail(L"Roblox process terminated");
                            }
                        }

                        // --- WM_TIMER callback injection ---
                        // DispatchMessage calls lParam as a function pointer for WM_TIMER.
                        // RWX memory is auto-CFG-valid. No game objects modified.
                        {
                            // Reset phase/once for this attempt
                            uint32_t zero = 0;
                            wr_v(vrb + 0x38, &zero, 4);
                            wr_v(vrb + 0x48, &zero, 4);

                            // Timer trampoline: mov rcx,<vrb> ; jmp apc_sc
                            uint8_t tramp[15];
                            tramp[0] = 0x48; tramp[1] = 0xB9;
                            memcpy(&tramp[2], &vrb, 8);
                            tramp[10] = 0xE9;
                            int32_t jmp_rel = (int32_t)((int64_t)apc_sc_off - (int64_t)(timer_sc_off + 15));
                            memcpy(&tramp[11], &jmp_rel, 4);
                            wr_v(vrb + timer_sc_off, tramp, sizeof(tramp));

                            // Find Roblox window
                            DWORD rbx_pid = GetProcessId(vhp);
                            HWND rbx_wnd = nullptr;
                            {
                                struct Ctx { DWORD pid; HWND wnd; };
                                Ctx fc{ rbx_pid, nullptr };
                                EnumWindows([](HWND h, LPARAM lp) -> BOOL {
                                    auto* c = (Ctx*)lp;
                                    DWORD p = 0;
                                    GetWindowThreadProcessId(h, &p);
                                    if (p == c->pid && IsWindowVisible(h))
                                        { c->wnd = h; return FALSE; }
                                    return TRUE;
                                }, (LPARAM)&fc);
                                rbx_wnd = fc.wnd;
                            }

                            if (rbx_wnd) {
                                VT_LOG(L"WM_TIMER injection: hwnd=" + format_hex((uintptr_t)rbx_wnd) +
                                       L" tramp=" + format_hex(vrb + timer_sc_off));
                                PostMessageW(rbx_wnd, WM_TIMER, 0, (LPARAM)(vrb + timer_sc_off));
                                bool tm_ok = false;
                                for (int tp = 0; tp < 15; ++tp) {
                                    Sleep(100);
                                    uint32_t tph = 0; SIZE_T trd = 0;
                                    ReadProcessMemory(vhp, (LPCVOID)(vrb + 0x38), &tph, 4, &trd);
                                    DWORD tex = 0;
                                    if (!(GetExitCodeProcess(vhp, &tex) && tex == STILL_ACTIVE)) {
                                        VT_WARN(L"WM_TIMER: Roblox crashed (phase=" + std::to_wstring(tph) +
                                                L" exit=0x" + format_hex(tex) + L")");
                                        break;
                                    }
                                    if (tph >= 2) {
                                        VT_LOG(L"WM_TIMER SUCCESS phase=" + std::to_wstring(tph));
                                        tm_ok = true;
                                        break;
                                    }
                                }
                                if (tm_ok) return true;
                                if (!tm_ok) {
                                    // Also try SendMessage variant
                                    zero = 0;
                                    wr_v(vrb + 0x38, &zero, 4);
                                    wr_v(vrb + 0x48, &zero, 4);
                                    VT_LOG(L"WM_TIMER: PostMessage timed out — trying SendMessage");
                                    SendMessageW(rbx_wnd, WM_TIMER, 0, (LPARAM)(vrb + timer_sc_off));
                                    Sleep(200);
                                    uint32_t sph = 0; SIZE_T srd = 0;
                                    ReadProcessMemory(vhp, (LPCVOID)(vrb + 0x38), &sph, 4, &srd);
                                    if (sph >= 2) {
                                        VT_LOG(L"WM_TIMER (Send) SUCCESS phase=" + std::to_wstring(sph));
                                        return true;
                                    }
                                    VT_WARN(L"WM_TIMER: SendMessage also failed (phase=" +
                                            std::to_wstring(sph) + L")");
                                }
                            } else {
                                VT_WARN(L"WM_TIMER: no Roblox window found");
                            }
                        }

                        // --- Check alive before vtable hook ---
                        {
                            DWORD alive_chk2 = 0;
                            if (!(GetExitCodeProcess(vhp, &alive_chk2) && alive_chk2 == STILL_ACTIVE)) {
                                VT_WARN(L"Roblox died — aborting remaining execution paths");
                                return fail(L"Roblox process terminated");
                            }
                        }

                        // Shellcode: hooks step(), one-shot fires luau_load+lua_pcall,
                        // restores vtable, tail-calls original step.
                        uint8_t vt_sc[] = {
                            0x53,                                               // push rbx
                            0x57,                                               // push rdi
                            0x48,0x83,0xEC,0x48,                                // sub rsp,48h
                            0x48,0x89,0xCF,                                     // mov rdi,rcx
                            0x48,0xBB, 0,0,0,0,0,0,0,0,                         // mov rbx,<PB> (patched)
                            0x83,0x7B,0x48,0x00,                                // cmp dword[rbx+48h],0
                            0x0F,0x85,0x62,0x00,0x00,0x00,                      // jne skip (+0x62)
                            0xC7,0x43,0x48,0x01,0x00,0x00,0x00,                 // [rbx+48h]=1
                            0x48,0x8B,0x43,0x40,                                // mov rax,[rbx+40h]
                            0x48,0x8B,0x4B,0x50,                                // mov rcx,[rbx+50h]
                            0x48,0x89,0x01,                                     // mov [rcx],rax (unhook)
                            0x48,0x8B,0x0B,                                     // mov rcx,[rbx] (L)
                            0x48,0x8B,0x53,0x08,                                // mov rdx,[rbx+8]
                            0x4C,0x8B,0x43,0x10,                                // mov r8,[rbx+10h]
                            0x4C,0x8B,0x4B,0x18,                                // mov r9,[rbx+18h]
                            0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,       // [rsp+20h]=0
                            0xFF,0x53,0x20,                                     // call [rbx+20h]
                            0x89,0x43,0x3C,                                     // save load res
                            0xC7,0x43,0x38,0x02,0x00,0x00,0x00,                 // phase=2
                            0x85,0xC0,                                          // test eax,eax
                            0x75,0x27,                                          // jnz skip2 (+0x27)
                            0x48,0x8B,0x0B,                                     // mov rcx,[rbx]
                            0x31,0xD2,                                          // xor edx
                            0x45,0x31,0xC0,                                     // xor r8d
                            0x45,0x31,0xC9,                                     // xor r9d
                            0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,       // [rsp+20h]=0
                            0x48,0xC7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,       // [rsp+28h]=0
                            0xFF,0x53,0x28,                                     // call [rbx+28h]
                            0xC7,0x43,0x38,0x03,0x00,0x00,0x00,                 // phase=3
                            // skip:
                            0x48,0x8B,0x43,0x58,                                // mov rax,[rbx+58h]
                            0x48,0x89,0xF9,                                     // mov rcx,rdi
                            0x48,0x83,0xC4,0x48,                                // add rsp,48h
                            0x5F,                                               // pop rdi
                            0x5B,                                               // pop rbx
                            0xFF,0xE0                                           // jmp rax
                        };
                        // Patch PB absolute address into mov rbx instruction
                        memcpy(vt_sc + 11, &vrb, 8);

                        wr_v(vrb + vt_sc_off, vt_sc, sizeof(vt_sc));

                        // --- CFG bypass: mark shellcode as valid call target ---
                        {
                            struct { ULONG_PTR Offset; ULONG_PTR Flags; } cti{vt_sc_off, 1};
                            SIZE_T cfgSz = (vt_total + 0xFFF) & ~(SIZE_T)0xFFF;
                            bool cfg_ok = false;

                            // Primary: direct syscall with Win11-sized struct (40 bytes)
                            auto& sc_cfg = Syscalls::get();
                            if (sc_cfg.ready() && sc_cfg.SetInformationVirtualMemory) {
                                struct { PVOID addr; SIZE_T size; } range{vt_remote, cfgSz};
                                DWORD processed = 0;
                                struct {
                                    DWORD count; DWORD reserved; PDWORD pProcessed;
                                    void* targets; void* section; uint64_t fileOff;
                                } vminfo{1, 0, &processed, &cti, nullptr, 0};
                                NTSTATUS ns = sc_cfg.SetInformationVirtualMemory(
                                    vhp, 2 /*VmCfgCallTargetInformation*/,
                                    1, &range, &vminfo, (ULONG)sizeof(vminfo));
                                cfg_ok = ns >= 0;
                                VT_LOG(L"vtable hook: CFG syscall NTSTATUS=" +
                                       format_hex((uintptr_t)(ULONG)ns) +
                                       (cfg_ok ? L" OK" : L" FAIL"));
                            }

                            // Fallback: Win32 SetProcessValidCallTargets
                            if (!cfg_ok) {
                                using SetCfgFn = BOOL(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, PVOID);
                                static auto pSetCfg = []() -> SetCfgFn {
                                    auto p = (SetCfgFn)GetProcAddress(
                                        GetModuleHandleW(L"kernel32.dll"), "SetProcessValidCallTargets");
                                    if (!p) p = (SetCfgFn)GetProcAddress(
                                        GetModuleHandleW(L"kernelbase.dll"), "SetProcessValidCallTargets");
                                    return p;
                                }();
                                if (pSetCfg) {
                                    cfg_ok = pSetCfg(vhp, vt_remote, cfgSz, 1, &cti) != FALSE;
                                    if (!cfg_ok)
                                        VT_LOG(L"vtable hook: SetProcessValidCallTargets err=" +
                                               std::to_wstring(GetLastError()));
                                }
                            }

                            if (cfg_ok) {
                                VT_LOG(L"vtable hook: idx=" + std::to_wstring(hook_idx) +
                                       L" sc=" + format_hex(vrb + vt_sc_off) +
                                       L" vt=" + format_hex(vrb + vt_vt_off));
                                const uintptr_t new_vt = vrb + vt_vt_off;
                                SIZE_T vw = 0;
                                if (SC_WriteProcessMemory(vhp, (LPVOID)job, &new_vt, 8, &vw) && vw == 8) {
                                    VT_LOG(L"vtable hook ARMED — polling for scheduler call");
                                    bool vt_ok = false;
                                    for (int poll = 0; poll < 50; ++poll) {
                                        Sleep(100);
                                        uint32_t vt_phase = 0;
                                        SIZE_T rd2 = 0;
                                        ReadProcessMemory(vhp, (LPCVOID)(vrb + 0x38), &vt_phase, 4, &rd2);
                                        DWORD exit2 = 0;
                                        const bool alive2 = GetExitCodeProcess(vhp, &exit2) && exit2 == STILL_ACTIVE;
                                        if (!alive2) {
                                            VT_WARN(L"vtable hook: Roblox crashed (phase=" + std::to_wstring(vt_phase) +
                                                    L" exit=0x" + format_hex(exit2) + L")");
                                            break;
                                        }
                                        if (vt_phase >= 2) {
                                            VT_LOG(L"vtable hook SUCCESS — phase=" + std::to_wstring(vt_phase));
                                            vt_ok = true;
                                            break;
                                        }
                                    }
                                    if (vt_ok)
                                        return true;
                                    SC_WriteProcessMemory(vhp, (LPVOID)job, &orig_vt, 8, &vw);
                                }
                            } else {
                                VT_LOG(L"vtable hook: CFG+Hyperion blocked — skipping vtable hook");
                            }
                        }

                        // --- Inline hook: patch step() entry with JMP trampoline ---
                        // CFG checks indirect CALL targets, not JMP destinations.
                        // Scheduler calls vtable[idx]() → step() (CFG-valid address) →
                        // hits our JMP → shellcode runs. No CFG check on the JMP.
                        {
                            const uintptr_t step_addr = vt_buf[hook_idx];
                            uint8_t orig_14[16]{};
                            SIZE_T rd_orig = 0;
                            ReadProcessMemory(vhp, (LPCVOID)step_addr, orig_14, 14, &rd_orig);

                            // Rewrite PB for inline hook:
                            // +0x40 = step_addr, +0x50 = orig_bytes[0:8], +0x58 = orig_bytes[8:16]
                            wr_v(vrb + 0x40, &step_addr, 8);
                            wr_v(vrb + 0x50, orig_14, 8);
                            wr_v(vrb + 0x58, orig_14 + 8, 8);

                            // Inline shellcode: same payload but restores step()'s
                            // original bytes instead of unhooking the vtable.
                            uint8_t il_sc[] = {
                                0x53,                                               // push rbx
                                0x57,                                               // push rdi
                                0x48,0x83,0xEC,0x48,                                // sub rsp,48h
                                0x48,0x89,0xCF,                                     // mov rdi,rcx
                                0x48,0xBB, 0,0,0,0,0,0,0,0,                         // mov rbx,<PB>
                                0x83,0x7B,0x48,0x00,                                // cmp [rbx+48h],0
                                0x0F,0x85,0x6A,0x00,0x00,0x00,                      // jne .skip
                                0xC7,0x43,0x48,0x01,0x00,0x00,0x00,                 // one_shot=1
                                // restore step()'s original 16 bytes
                                0x48,0x8B,0x43,0x40,                                // mov rax,[rbx+40h] step_addr
                                0x48,0x8B,0x4B,0x50,                                // mov rcx,[rbx+50h] orig 0-7
                                0x48,0x89,0x08,                                     // mov [rax],rcx
                                0x48,0x8B,0x4B,0x58,                                // mov rcx,[rbx+58h] orig 8-15
                                0x48,0x89,0x48,0x08,                                // mov [rax+8],rcx
                                // luau_load(L, name, data, sz, 0)
                                0x48,0x8B,0x0B,                                     // mov rcx,[rbx]
                                0x48,0x8B,0x53,0x08,                                // mov rdx,[rbx+8]
                                0x4C,0x8B,0x43,0x10,                                // mov r8,[rbx+10h]
                                0x4C,0x8B,0x4B,0x18,                                // mov r9,[rbx+18h]
                                0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,       // [rsp+20h]=0
                                0xFF,0x53,0x20,                                     // call [rbx+20h]
                                0x89,0x43,0x3C,                                     // save load res
                                0xC7,0x43,0x38,0x02,0x00,0x00,0x00,                 // phase=2
                                0x85,0xC0,                                          // test eax
                                0x75,0x27,                                          // jnz .skip
                                // lua_pcall(L, 0, 0, 0, 0, 0)
                                0x48,0x8B,0x0B,
                                0x31,0xD2, 0x45,0x31,0xC0, 0x45,0x31,0xC9,
                                0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,
                                0x48,0xC7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,
                                0xFF,0x53,0x28,
                                0xC7,0x43,0x38,0x03,0x00,0x00,0x00,                 // phase=3
                                // .skip: tail-call restored step()
                                0x48,0x8B,0x43,0x40,                                // mov rax,[rbx+40h]
                                0x48,0x89,0xF9,                                     // mov rcx,rdi
                                0x48,0x83,0xC4,0x48,                                // add rsp,48h
                                0x5F, 0x5B, 0xFF,0xE0                               // pop rdi; pop rbx; jmp rax
                            };
                            memcpy(il_sc + 11, &vrb, 8);
                            wr_v(vrb + vt_sc_off, il_sc, sizeof(il_sc));

                            // Try multiple methods to make step()'s page writable
                            DWORD step_old = 0;
                            LPVOID step_page = (LPVOID)(step_addr & ~0xFFFull);
                            bool vp_ok = SC_VirtualProtectEx(vhp, step_page, 0x1000,
                                                              PAGE_EXECUTE_READWRITE, &step_old);
                            if (!vp_ok)
                                vp_ok = SC_VirtualProtectEx(vhp, step_page, 0x1000,
                                                            PAGE_READWRITE, &step_old);
                            if (!vp_ok)
                                vp_ok = VirtualProtectEx(vhp, step_page, 0x1000,
                                                         PAGE_EXECUTE_READWRITE, &step_old) != FALSE;
                            VT_LOG(L"inline hook: VProtectEx " + std::wstring(vp_ok ? L"ok" : L"FAIL") +
                                   L" err=" + std::to_wstring(GetLastError()));

                            // Write trampoline at step() entry: mov rax,<sc>; jmp rax
                            uint8_t tramp[14]{};
                            tramp[0] = 0x48; tramp[1] = 0xB8;
                            uintptr_t sc_dest = vrb + vt_sc_off;
                            memcpy(tramp + 2, &sc_dest, 8);
                            tramp[10] = 0xFF; tramp[11] = 0xE0;
                            tramp[12] = 0x90; tramp[13] = 0x90;
                            SIZE_T tw = 0;
                            bool wr_ok = SC_WriteProcessMemory(vhp, (LPVOID)step_addr, tramp, 14, &tw) && tw == 14;
                            if (!wr_ok) {
                                tw = 0;
                                wr_ok = WriteProcessMemory(vhp, (LPVOID)step_addr, tramp, 14, &tw) && tw == 14;
                            }
                            if (wr_ok) {
                                VT_LOG(L"inline hook ARMED at step " + format_hex(step_addr));
                                bool il_ok = false;
                                for (int poll = 0; poll < 50; ++poll) {
                                    Sleep(100);
                                    uint32_t il_phase = 0;
                                    SIZE_T rd2 = 0;
                                    ReadProcessMemory(vhp, (LPCVOID)(vrb + 0x38), &il_phase, 4, &rd2);
                                    DWORD exit2 = 0;
                                    const bool alive2 = GetExitCodeProcess(vhp, &exit2) && exit2 == STILL_ACTIVE;
                                    if (!alive2) {
                                        VT_WARN(L"inline hook: Roblox crashed (phase=" + std::to_wstring(il_phase) +
                                                L" exit=0x" + format_hex(exit2) + L")");
                                        break;
                                    }
                                    if (il_phase >= 2) {
                                        VT_LOG(L"inline hook SUCCESS — phase=" + std::to_wstring(il_phase));
                                        il_ok = true;
                                        break;
                                    }
                                }
                                if (!il_ok) {
                                    SC_WriteProcessMemory(vhp, (LPVOID)step_addr, orig_14, 14, &tw);
                                    VT_WARN(L"inline hook: timed out");
                                }
                                if (step_old)
                                    SC_VirtualProtectEx(vhp, step_page, 0x1000, step_old, &step_old);
                                if (il_ok)
                                    return true;
                            } else {
                                VT_WARN(L"inline hook: write FAIL tw=" + std::to_wstring(tw) +
                                        L" err=" + std::to_wstring(GetLastError()));
                            }
                        }

                        // --- Instrumentation Callback: kernel-dispatched, bypasses CFG ---
                        // NtSetInformationProcess(ProcessInstrumentationCallback) sets a
                        // callback the kernel invokes on every kernel→user transition.
                        // The dispatch sets RIP directly — no indirect call, no CFG check.
                        {
                            uint32_t zero = 0;
                            wr_v(vrb + 0x38, &zero, 4);
                            wr_v(vrb + 0x48, &zero, 4);

                            uint8_t ic_sc[] = {
                                0x50,                                           // push rax
                                0x53,                                           // push rbx
                                0x48,0xBB, 0,0,0,0,0,0,0,0,                    // mov rbx,<PB>
                                0x83,0x7B,0x48,0x00,                            // cmp dword[rbx+48h],0
                                0x0F,0x85,0x84,0x00,0x00,0x00,                  // jne .fast_skip
                                0xF0,0x0F,0xBA,0x6B,0x48,0x00,                  // lock bts [rbx+48h],0
                                0x0F,0x82,0x78,0x00,0x00,0x00,                  // jc .fast_skip
                                0x51,0x52,                                      // push rcx,rdx
                                0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,        // push r8-r11
                                0x56,0x57,0x55,                                 // push rsi,rdi,rbp
                                0x48,0x89,0xE5,                                 // mov rbp,rsp
                                0x48,0x83,0xE4,0xF0,                            // and rsp,-16
                                0x48,0x83,0xEC,0x30,                            // sub rsp,30h
                                0x48,0x8B,0x0B,                                 // mov rcx,[rbx]
                                0x48,0x8B,0x53,0x08,                            // mov rdx,[rbx+8]
                                0x4C,0x8B,0x43,0x10,                            // mov r8,[rbx+10h]
                                0x4C,0x8B,0x4B,0x18,                            // mov r9,[rbx+18h]
                                0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,   // [rsp+20h]=0
                                0xFF,0x53,0x20,                                 // call [rbx+20h]
                                0x89,0x43,0x3C,                                 // mov [rbx+3Ch],eax
                                0xC7,0x43,0x38,0x02,0x00,0x00,0x00,             // phase=2
                                0x85,0xC0,                                      // test eax
                                0x75,0x27,                                      // jnz .done
                                0x48,0x8B,0x0B,                                 // mov rcx,[rbx]
                                0x31,0xD2,0x45,0x31,0xC0,0x45,0x31,0xC9,        // xor edx,r8d,r9d
                                0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,   // [rsp+20h]=0
                                0x48,0xC7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,   // [rsp+28h]=0
                                0xFF,0x53,0x28,                                 // call [rbx+28h]
                                0xC7,0x43,0x38,0x03,0x00,0x00,0x00,             // phase=3
                                // .done:
                                0x48,0x89,0xEC,                                 // mov rsp,rbp
                                0x5D,0x5F,0x5E,                                 // pop rbp,rdi,rsi
                                0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,        // pop r11-r8
                                0x5A,0x59,                                      // pop rdx,rcx
                                // .fast_skip:
                                0x5B,0x58,                                      // pop rbx,rax
                                0x41,0xFF,0xE2                                  // jmp r10
                            };
                            memcpy(ic_sc + 4, &vrb, 8);
                            wr_v(vrb + vt_sc_off, ic_sc, sizeof(ic_sc));

                            using NtSetInfoProc_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
                            auto pNtSIP = (NtSetInfoProc_t)GetProcAddress(
                                GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
                            if (pNtSIP) {
                                struct { ULONG Version; ULONG Reserved; PVOID Callback; }
                                    ic_info{0, 0, (PVOID)(vrb + vt_sc_off)};
                                NTSTATUS ns = pNtSIP(vhp, 40, &ic_info, sizeof(ic_info));
                                if (ns >= 0) {
                                    VT_LOG(L"instrumentation callback SET");
                                    bool ic_ok = false;
                                    for (int p = 0; p < 50; ++p) {
                                        Sleep(100);
                                        uint32_t ph = 0; SIZE_T rd = 0;
                                        ReadProcessMemory(vhp, (LPCVOID)(vrb + 0x38), &ph, 4, &rd);
                                        DWORD ex = 0;
                                        if (!(GetExitCodeProcess(vhp, &ex) && ex == STILL_ACTIVE)) {
                                            VT_WARN(L"IC: Roblox crashed phase=" + std::to_wstring(ph) +
                                                    L" exit=0x" + format_hex(ex) + L")");
                                            break;
                                        }
                                        if (ph >= 2) {
                                            VT_LOG(L"instrumentation callback SUCCESS phase=" +
                                                   std::to_wstring(ph));
                                            ic_ok = true;
                                            break;
                                        }
                                    }
                                    struct { ULONG V; ULONG R; PVOID C; } clr{0, 0, nullptr};
                                    pNtSIP(vhp, 40, &clr, sizeof(clr));
                                    if (ic_ok) return true;
                                    VT_WARN(L"instrumentation callback timed out");
                                } else {
                                    VT_WARN(L"IC: NtSetInformationProcess NTSTATUS=" +
                                            format_hex((uintptr_t)(ULONG)ns));
                                }
                            }
                        }

                        // (old APC block removed — APC now runs before vtable hook)
                    }
                } else {
                    VT_WARN(L"vtable hook: no suitable vtable entry found");
                }
            } else {
                uintptr_t raw0 = mem_.read_ptr(job);
                VT_WARN(L"vtable hook: job " + format_hex(job) +
                        L" raw[0]=" + format_hex(raw0) +
                        L" — not a valid vtable (may be Studio or not in-game)");
            }
        }
        VT_LOG(L"all execution paths exhausted — falling back to container stamp");
    }

    // --- Strategy B: Container bytecode overwrite + UI trigger ---
    g_name_reprobe.store(true, std::memory_order_relaxed);
    if (!looks_place(dm))
        return fail(L"no place DataModel (Players) — join a server, wait for the character");
    VT_LOG(L"container stamp path: DM " + format_hex(dm));

    auto walk = [&](uintptr_t from, std::initializer_list<const char*> names) -> uintptr_t {
        uintptr_t cur = from;
        for (const char* n : names) {
            uintptr_t nxt = find_child_name(cur, n);
            if (!nxt)
                nxt = find_child_class(cur, n);
            if (!nxt)
                return 0;
            cur = nxt;
        }
        return cur;
    };

    auto named_bfs = [&](uintptr_t root, const char* want, int maxn) -> uintptr_t {
        if (!mem_.looks(root) || !want)
            return 0;
        std::vector<uintptr_t> q;
        q.reserve((size_t)maxn);
        q.push_back(root);
        for (size_t i = 0; i < q.size() && (int)q.size() < maxn; ++i) {
            if (inst_name(q[i]) == want)
                return q[i];
            std::vector<uintptr_t> ch;
            children_of(q[i], ch);
            for (uintptr_t c : ch)
                q.push_back(c);
        }
        return 0;
    };

    g_name_reprobe.store(true, std::memory_order_relaxed);
    const uintptr_t sp = find_service(dm, "StarterPlayer");
    const uintptr_t pl = find_service(dm, "Players");
    const uintptr_t cg = find_service(dm, "CoreGui");
    VT_LOG(L"services Players=" + format_hex(pl) + L" StarterPlayer=" + format_hex(sp) +
           L" CoreGui=" + format_hex(cg));

    if (inst_name(cg).empty() && inst_name(sp).empty() && inst_name(pl).empty()) {
        VT_LOG(L"Name offset stale — auto-calibrating...");
        bool found = false;
        for (uintptr_t test_off = 0x20; test_off <= 0x200 && !found; test_off += 8) {
            for (uintptr_t svc : {cg, sp, pl}) {
                if (!mem_.looks(svc)) continue;
                const auto cn = class_name(svc);
                if (cn.empty()) continue;
                auto s = mem_.rstring(svc + test_off);
                if (s == cn) { found = true; VT_LOG(L"Name cal: std::string +0x" + format_hex(test_off)); break; }
                const uintptr_t np = mem_.read_ptr(svc + test_off);
                if (!mem_.looks(np)) continue;
                s = mem_.rstring(np);
                if (s == cn) { found = true; VT_LOG(L"Name cal: ptr->string +0x" + format_hex(test_off)); break; }
                s = mem_.rstring_ptr(np);
                if (s == cn) { found = true; VT_LOG(L"Name cal: ptr->cstr +0x" + format_hex(test_off)); break; }
                for (int lo : {4, 8, 12, 16, 20, 24, 28, 32}) {
                    uint32_t len = mem_.read<uint32_t>(np + lo);
                    if (len != cn.size()) continue;
                    char buf[128]{};
                    if (mem_.read(np + lo + 4, buf, len) && std::string(buf, len) == cn) {
                        found = true;
                        VT_LOG(L"Name cal: SharedString +0x" + format_hex(test_off) +
                               L" len@" + std::to_wstring(lo) + L" data@" + std::to_wstring(lo + 4));
                        break;
                    }
                }
                if (found) break;
                for (int inner : {4, 8, 12, 16, 20, 24, 28, 32}) {
                    s = mem_.rstring_ptr(np + inner);
                    if (s == cn) {
                        found = true;
                        VT_LOG(L"Name cal: ptr->cstr+" + std::to_wstring(inner) + L" +0x" + format_hex(test_off));
                        break;
                    }
                }
                if (found) break;
                const uintptr_t np2 = mem_.read_ptr(np);
                if (mem_.looks(np2) && np2 != np) {
                    s = mem_.rstring(np2);
                    if (s == cn) { found = true; VT_LOG(L"Name cal: ptr->ptr->str +0x" + format_hex(test_off)); break; }
                    s = mem_.rstring_ptr(np2);
                    if (s == cn) { found = true; VT_LOG(L"Name cal: ptr->ptr->cstr +0x" + format_hex(test_off)); break; }
                    for (int inner : {4, 8, 12, 16, 20, 24}) {
                        s = mem_.rstring_ptr(np2 + inner);
                        if (s == cn) { found = true; VT_LOG(L"Name cal: ptr->ptr->cstr+" + std::to_wstring(inner) + L" +0x" + format_hex(test_off)); break; }
                    }
                    if (found) break;
                }
            }
        }
        if (!found) {
            VT_LOG(L"Pattern scan failed — ASCII byte scan...");
            for (uintptr_t svc : {cg, sp, pl}) {
                if (!mem_.looks(svc) || found) continue;
                const auto cn = class_name(svc);
                if (cn.size() < 3 || cn.size() > 30) continue;
                uint8_t raw[512]{};
                if (!mem_.read(svc, raw, sizeof(raw))) continue;
                for (int i = 0; i + (int)cn.size() < 512 && !found; ++i) {
                    if (memcmp(raw + i, cn.c_str(), cn.size()) == 0 && raw[i + cn.size()] == 0) {
                        uintptr_t aligned = (uintptr_t)(i & ~7);
                        VT_LOG(L"ASCII inline +" + format_hex(i) + L" (align +" + format_hex(aligned) + L")");
                        g_name_off_hint.store(aligned, std::memory_order_relaxed);
                        auto v = inst_name(svc);
                        if (!v.empty()) { found = true; VT_LOG(L"Verified: \"" + utf8_to_wide(v) + L"\""); }
                    }
                }
                for (int off = 0; off + 8 <= 512 && !found; off += 8) {
                    uintptr_t ptr = *(uintptr_t*)(raw + off);
                    if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFFULL || (ptr & 3)) continue;
                    char buf[256]{};
                    if (!mem_.read(ptr, buf, sizeof(buf))) continue;
                    for (int j = 0; j + (int)cn.size() < 256 && !found; ++j) {
                        if (memcmp(buf + j, cn.c_str(), cn.size()) == 0 && buf[j + cn.size()] == 0) {
                            VT_LOG(L"ASCII ptr +" + format_hex(off) + L"→" + format_hex(ptr) + L"+" + format_hex(j));
                            g_name_off_hint.store(off, std::memory_order_relaxed);
                            auto v = inst_name(svc);
                            if (!v.empty()) { found = true; VT_LOG(L"Verified: \"" + utf8_to_wide(v) + L"\""); }
                        }
                    }
                }
            }
        }
        if (!found) {
            VT_WARN(L"Name offset not found — extended dump");
            uintptr_t dump_inst = mem_.looks(cg) ? cg : (mem_.looks(sp) ? sp : pl);
            if (mem_.looks(dump_inst)) {
                uint8_t raw[512]{};
                if (mem_.read(dump_inst, raw, sizeof(raw))) {
                    for (int row = 0; row < 512; row += 32) {
                        std::wstring hex;
                        for (int col = 0; col < 32 && row + col < 512; col += 8) {
                            uintptr_t v = *(uintptr_t*)(raw + row + col);
                            hex += L"+" + format_hex(row + col) + L"=" + format_hex(v) + L" ";
                        }
                        std::wstring asc;
                        for (int col = 0; col < 32 && row + col < 512; ++col) {
                            char c = (char)raw[row + col];
                            asc += (c >= 0x20 && c < 0x7F) ? (wchar_t)c : L'.';
                        }
                        VT_LOG(L"  " + hex + L" |" + asc + L"|");
                    }
                }
            }
        }
    }

    auto dump_kids = [&](const wchar_t* lab, uintptr_t inst) {
        if (!mem_.looks(inst)) {
            VT_LOG(std::wstring(lab) + L" (null)");
            return;
        }
        std::vector<uintptr_t> ch;
        children_of(inst, ch);
        std::string sample;
        for (size_t i = 0; i < ch.size() && i < 14; ++i) {
            auto n = inst_name(ch[i]);
            auto cl = class_name(ch[i]);
            if (n.empty())
                n = "-";
            if (!sample.empty())
                sample += ",";
            sample += n + "(" + (cl.empty() ? "?" : cl) + ")";
        }
        VT_LOG(std::wstring(lab) + L" " + format_hex(inst) + L" class " +
               utf8_to_wide(class_name(inst)) + L" n=" + std::to_wstring(ch.size()) +
               (sample.empty() ? L"" : (L" " + utf8_to_wide(sample))));
    };

    auto scan_class = [&](uintptr_t obj, const char* cls, uintptr_t max_off = 0x500) -> uintptr_t {
        if (!mem_.looks(obj) || !cls)
            return 0;
        if (auto c = find_child_class(obj, cls))
            return c;
        if (auto c = find_child_name(obj, cls))
            return c;
        for (uintptr_t o = 0x40; o < max_off; o += 8) {
            const uintptr_t p = mem_.read_ptr(obj + o);
            if (!looks_instance(p) || p == obj)
                continue;
            if (class_name(p) == cls || inst_name(p) == cls)
                return p;
        }
        return 0;
    };

    auto scan_script = [&](uintptr_t root, int maxn) -> uintptr_t {
        if (!mem_.looks(root))
            return 0;
        std::vector<uintptr_t> q;
        q.push_back(root);
        uintptr_t any_mod = 0, any_loc = 0, loc_ok = 0;
        for (size_t i = 0; i < q.size() && (int)q.size() < maxn; ++i) {
            const auto cl = class_name(q[i]);
            const auto nm = inst_name(q[i]);
            if (i && cl == "ModuleScript" && !any_mod)
                any_mod = q[i];
            if (i && cl == "LocalScript") {
                if (nm != "Replication" && nm != "HandleReplicator" && !loc_ok)
                    loc_ok = q[i];
                if (!any_loc)
                    any_loc = q[i];
            }
            std::vector<uintptr_t> ch;
            children_of(q[i], ch);
            for (uintptr_t c : ch)
                q.push_back(c);
            if (ch.empty() && i) {
                for (uintptr_t o = 0x40; o < 0x280; o += 8) {
                    const uintptr_t p = mem_.read_ptr(q[i] + o);
                    if (!looks_instance(p) || p == q[i])
                        continue;
                    const auto pcl = class_name(p);
                    if (pcl.empty())
                        continue;
                    q.push_back(p);
                }
            }
        }
        if (any_mod)
            return any_mod;
        if (loc_ok)
            return loc_ok;
        return any_loc;
    };

    auto class_bfs = [&](uintptr_t root, const char* cls, int maxn) -> uintptr_t {
        if (!mem_.looks(root) || !cls)
            return 0;
        std::vector<uintptr_t> q;
        q.push_back(root);
        for (size_t i = 0; i < q.size() && (int)q.size() < maxn; ++i) {
            if (i && class_name(q[i]) == cls && !inst_name(q[i]).empty())
                return q[i];
            std::vector<uintptr_t> ch;
            children_of(q[i], ch);
            for (uintptr_t c : ch)
                q.push_back(c);
        }
        return 0;
    };

    auto first_named = [&](uintptr_t root, std::initializer_list<const char*> names, int maxn) -> uintptr_t {
        for (const char* n : names) {
            if (auto h = named_bfs(root, n, maxn))
                return h;
        }
        return 0;
    };

    dump_kids(L"StarterPlayer", sp);
    const uintptr_t sps = scan_class(sp, "StarterPlayerScripts");
    dump_kids(L"SPS", sps);
    dump_kids(L"PlayerModule", scan_class(sps ? sps : sp, "PlayerModule"));

    uintptr_t vr = 0;
    bool sps_target = false;

    // --- Prefer SPS templates: stamped bytecode is cloned fresh on respawn ---
    if (sps) {
        std::vector<uintptr_t> sps_ch;
        children_of(sps, sps_ch);
        for (uintptr_t c : sps_ch) {
            auto cl = class_name(c);
            if (cl == "LocalScript") {
                vr = c;
                sps_target = true;
                VT_LOG(L"SPS LocalScript template: " + utf8_to_wide(inst_name(c)) + L" " + format_hex(c));
                break;
            }
        }
        if (!vr) {
            for (uintptr_t c : sps_ch) {
                auto cl = class_name(c);
                if (cl == "ModuleScript") {
                    vr = c;
                    sps_target = true;
                    VT_LOG(L"SPS ModuleScript template: " + utf8_to_wide(inst_name(c)) + L" " + format_hex(c));
                    break;
                }
            }
        }
        if (!vr) {
            auto f = class_bfs(sps, "LocalScript", 200);
            if (!f) f = class_bfs(sps, "ModuleScript", 200);
            if (f) {
                vr = f;
                sps_target = true;
                VT_LOG(L"SPS template (BFS): " + utf8_to_wide(inst_name(f)) +
                       L" (" + utf8_to_wide(class_name(f)) + L") " + format_hex(f));
            }
        }
    }

    dump_kids(L"CoreGui", cg);
    if (cg) {
        const uintptr_t rg = scan_class(cg, "RobloxGui");
        dump_kids(L"RobloxGui", rg);
        vr = walk(cg, {"RobloxGui", "Modules", "PlayerList", "PlayerListManager"});
        if (!vr && rg)
            vr = scan_class(rg, "PlayerListManager");
        if (!vr)
            vr = first_named(cg, {"PlayerListManager", "SettingsHub"}, 1000);
    }
    if (!vr && cg) {
        const uintptr_t rg2 = scan_class(cg, "RobloxGui");
        if (rg2) {
            const uintptr_t mods = find_child_name(rg2, "Modules");
            if (mods) {
                dump_kids(L"Modules", mods);
                // Target modules known to be loaded on ESC / UI toggle
                for (const char* want : {"SettingsHub", "InGameMenu", "Settings",
                                          "TopBar", "PlayerListManager", "ChatMain",
                                          "SettingsScript", "GameSettings"}) {
                    vr = named_bfs(mods, want, 400);
                    if (vr && class_name(vr) == "ModuleScript") {
                        VT_LOG(L"found ESC-triggered ModuleScript: " +
                               utf8_to_wide(inst_name(vr)) + L" " + format_hex(vr));
                        break;
                    }
                    vr = 0;
                }
                // Wider scan: any ModuleScript with a real name (not a hash)
                if (!vr) {
                    std::vector<uintptr_t> q;
                    q.push_back(mods);
                    for (size_t i = 0; i < q.size() && (int)q.size() < 400; ++i) {
                        if (i && class_name(q[i]) == "ModuleScript") {
                            const auto nm = inst_name(q[i]);
                            if (!nm.empty() && nm.size() < 40 && nm.find_first_of("0123456789abcdef") != 0) {
                                vr = q[i];
                                VT_LOG(L"found ModuleScript in Modules: " +
                                       utf8_to_wide(nm) + L" " + format_hex(vr));
                                break;
                            }
                        }
                        std::vector<uintptr_t> ch;
                        children_of(q[i], ch);
                        for (uintptr_t c : ch)
                            q.push_back(c);
                    }
                }
            }
        }
    }
    if (!vr && sps) {
        vr = scan_class(sps, "ModuleScript");
        if (!vr)
            vr = scan_class(sps, "PlayerModule");
    }
    if (!vr && pl) {
        dump_kids(L"Players", pl);
        std::vector<uintptr_t> pch;
        children_of(pl, pch);
        if (pch.empty()) {
            if (auto p = scan_class(pl, "Player"))
                pch.push_back(p);
        }
        for (uintptr_t player : pch) {
            dump_kids(L"Player", player);
            const uintptr_t ps = scan_class(player, "PlayerScripts");
            dump_kids(L"PlayerScripts", ps);
            if (ps) {
                // Do not patch a live ModuleScript — the VM is already using it.
                vr = scan_class(ps, "PlayerModule");
                if (!vr)
                    vr = scan_class(ps, "ControlModule");
                if (!vr)
                    vr = scan_script(ps, 400);
            }
            if (!vr)
                vr = scan_script(player, 400);
            if (vr)
                break;
        }
    }
    if (!vr && sp) {
        vr = walk(sp, {"PlayerModule", "ControlModule", "VRNavigation"});
        if (!vr)
            vr = walk(sp, {"StarterPlayerScripts", "PlayerModule", "ControlModule", "VRNavigation"});
        if (!vr)
            vr = scan_class(sps ? sps : sp, "VRNavigation");
        if (!vr)
            vr = scan_class(sps ? sps : sp, "ControlModule");
        if (!vr)
            vr = scan_class(sps ? sps : sp, "PlayerModule");
        if (!vr && sps)
            vr = scan_script(sps, 400);
        if (!vr)
            vr = scan_script(sp, 500);
    }
    if (!vr && sp)
        vr = first_named(sp, {"VRNavigation", "ControlModule", "PlayerModule", "CameraModule", "Keyboard"}, 400);
    if (!vr && cg) {
        dump_kids(L"CoreGui", cg);
        const uintptr_t rg = scan_class(cg, "RobloxGui");
        dump_kids(L"RobloxGui", rg);
        if (rg)
            vr = walk(rg, {"Modules", "PlayerList", "PlayerListManager"});
        if (!vr)
            vr = scan_class(rg ? rg : cg, "PlayerListManager");
        if (!vr)
            vr = first_named(cg, {"PlayerListManager", "SettingsHub", "TopBar", "RobloxGui"}, 1000);
        if (!vr)
            vr = scan_script(cg, 1200);
    }
    if (!vr) {
        if (auto sg = find_service(dm, "StarterGui"))
            vr = scan_script(sg, 400);
    }
    if (!vr) {
        if (auto rf = find_service(dm, "ReplicatedFirst"))
            vr = scan_script(rf, 400);
    }
    if (!vr && sp)
        vr = class_bfs(sp, "ModuleScript", 400);
    if (!vr)
        vr = named_bfs(dm, "VRNavigation", 1200);
    if (!vr) {
        dump_kids(L"DM", dm);
        return fail(L"no ModuleScript host (PlayerModule/VRNavigation/PlayerList)");
    }
    const std::string host_cls = class_name(vr);
    const bool local_host = (host_cls == "LocalScript" || host_cls == "Script");
    VT_LOG(L"corescript host " + utf8_to_wide(inst_name(vr)) + L" class " +
           utf8_to_wide(host_cls) + L" " + format_hex(vr));
    HANDLE hp = mem_.handle();

    // --- Fallback: container bytecode overwrite (corrupts host script) ---
    auto wr = [&](uintptr_t addr, const void* p, size_t n) -> bool {
        if (!addr || !p || !n)
            return false;
        DWORD old = 0;
        const uintptr_t page = addr & ~0xFFFull;
        const SIZE_T pn = ((addr + n + 0xFFF) & ~0xFFFull) - page;
        VirtualProtectEx(hp, (LPVOID)page, pn, PAGE_READWRITE, &old);
        const bool ok = mem_.write(addr, p, n);
        if (old)
            VirtualProtectEx(hp, (LPVOID)page, pn, old, &old);
        return ok;
    };

    const uintptr_t bc_pairs[][2] = {
        {0x10, 0x20}, {0x18, 0x28}, {0x10, 0x18},
        {0x08, 0x18}, {0x08, 0x10}, {0x20, 0x30},
        {0x20, 0x28}, {0x28, 0x38}, {0x30, 0x40},
        {0x10, 0x28}, {0x18, 0x30}
    };
    constexpr size_t bc_npairs = 11;

    auto looks_bc = [&](uintptr_t e, uintptr_t* p_doff, uintptr_t* p_soff, bool relaxed = false) -> bool {
        if (!mem_.looks(e) || looks_instance(e))
            return false;
        for (size_t i = 0; i < bc_npairs; ++i) {
            const uintptr_t data = mem_.read_ptr(e + bc_pairs[i][0]);
            uint64_t bsz = mem_.read<uint64_t>(e + bc_pairs[i][1]);
            if (bsz > 0x400000ull)
                bsz = mem_.read<uint32_t>(e + bc_pairs[i][1]);
            if (mem_.looks(data) && bsz >= 8 && bsz < 0x400000) {
                uint8_t hdr[4]{};
                if (mem_.read(data, hdr, 4) && hdr[0] == 0) {
                    if (p_doff) *p_doff = bc_pairs[i][0];
                    if (p_soff) *p_soff = bc_pairs[i][1];
                    return true;
                }
            }
        }
        for (size_t i = 0; i < bc_npairs; ++i) {
            const uintptr_t data = mem_.read_ptr(e + bc_pairs[i][0]);
            uint64_t bsz = mem_.read<uint64_t>(e + bc_pairs[i][1]);
            if (bsz > 0x400000ull)
                bsz = mem_.read<uint32_t>(e + bc_pairs[i][1]);
            if (mem_.looks(data) && bsz >= 8 && bsz < 0x400000) {
                if (p_doff) *p_doff = bc_pairs[i][0];
                if (p_soff) *p_soff = bc_pairs[i][1];
                return true;
            }
        }
        if (relaxed) {
            for (size_t i = 0; i < bc_npairs; ++i) {
                const uintptr_t data = mem_.read_ptr(e + bc_pairs[i][0]);
                uint64_t bsz = mem_.read<uint64_t>(e + bc_pairs[i][1]);
                if (bsz > 0x400000ull)
                    bsz = mem_.read<uint32_t>(e + bc_pairs[i][1]);
                if (data != 0 && bsz >= 4 && bsz < 0x400000) {
                    if (p_doff) *p_doff = bc_pairs[i][0];
                    if (p_soff) *p_soff = bc_pairs[i][1];
                    return true;
                }
            }
        }
        return false;
    };

    uintptr_t embedded = 0, field_off = 0, data_off = 0x10, size_off = 0x20;
    bool bc_confirmed = false;
    std::vector<uintptr_t> field_try;
    if (local_host) {
        for (uintptr_t o : {0x1A8ull, 0x190ull, 0x1C8ull, 0x1B0ull, 0x1B8ull,
                            0x1D0ull, 0x1D8ull, 0x1E0ull, 0x198ull, 0x180ull,
                            0x1E8ull, 0x1F0ull, 0x1F8ull, 0x200ull, 0x208ull,
                            0x210ull, 0x170ull, 0x168ull, 0x160ull, 0x158ull,
                            0x150ull, 0x148ull, 0x140ull, 0x218ull, 0x220ull})
            field_try.push_back(o);
    } else {
        for (uintptr_t o : {0x150ull, 0x138ull, 0x158ull, 0x170ull, 0x140ull,
                            0x148ull, 0x160ull, 0x168ull, 0x178ull, 0x128ull,
                            0x180ull, 0x188ull, 0x190ull, 0x198ull, 0x1A0ull,
                            0x1A8ull, 0x118ull, 0x110ull, 0x108ull, 0x100ull})
            field_try.push_back(o);
    }
    for (uintptr_t o : field_try) {
        const uintptr_t e = mem_.read_ptr(vr + o);
        if (looks_bc(e, &data_off, &size_off)) {
            embedded = e;
            field_off = o;
            bc_confirmed = true;
            VT_LOG(L"bytecode container field+" + format_hex(o) + L" box " + format_hex(e) +
                   L" data_off=" + format_hex(data_off) + L" size_off=" + format_hex(size_off));
            break;
        }
    }
    if (!bc_confirmed) {
        for (uintptr_t o : field_try) {
            const uintptr_t e = mem_.read_ptr(vr + o);
            if (looks_bc(e, &data_off, &size_off, true)) {
                embedded = e;
                field_off = o;
                bc_confirmed = true;
                VT_WARN(L"relaxed bc match field+" + format_hex(o) + L" box " + format_hex(e) +
                         L" data_off=" + format_hex(data_off) + L" size_off=" + format_hex(size_off));
                break;
            }
        }
    }
    if (!bc_confirmed) {
        VT_WARN(L"looks_bc: no bytecode container — dumping fields");
        for (uintptr_t o : field_try) {
            const uintptr_t e = mem_.read_ptr(vr + o);
            if (!mem_.looks(e) || looks_instance(e))
                continue;
            uint8_t raw[72]{};
            mem_.read(e, raw, sizeof(raw));
            std::wstring hex;
            for (int i = 0; i < 72; i += 8) {
                uintptr_t v = *(uintptr_t*)(raw + i);
                hex += L"+" + format_hex(i) + L"=" + format_hex(v) + L" ";
            }
            VT_LOG(L"  +" + format_hex(o) + L" → " + format_hex(e) + L" " + hex);
        }
    }

    SIZE_T blob_n = 0;
    uintptr_t rp = 0;
    bool inplace = false;
    std::pair<bool, std::string> packed;

    if (bc_confirmed) {
        const uintptr_t existing_data = mem_.read_ptr(embedded + data_off);
        uint64_t existing_size = mem_.read<uint64_t>(embedded + size_off);
        if (existing_size > 0x400000ull)
            existing_size = mem_.read<uint32_t>(embedded + size_off);
        VT_LOG(L"existing bytecode: " + std::to_wstring((unsigned)existing_size) +
               L" bytes at " + format_hex(existing_data));

        if (mem_.looks(existing_data) && existing_size >= 8 && existing_size < 0x400000) {
            const char* shims[] = { kCoreShimTiny, kCoreShimMin };
            const wchar_t* labels[] = { L"tiny", L"min" };
            for (int pass = 0; pass < 2 && !inplace; ++pass) {
                const std::string wrapped = local_host
                    ? (std::string("if _G.__VT then return end;_G.__VT=true;task.spawn(function()\n") + shims[pass] + source + "\nend)\n")
                    : (std::string("if _G.__VT then return{}end;_G.__VT=true;script.Parent=nil;task.spawn(function()\n") + shims[pass] + source + "\nend);return {}");
                auto p = compile_rbx_bytecode(wrapped);
                if (!p.first) continue;
                VT_LOG(std::wstring(L"bytecode (") + labels[pass] + L" shim): " +
                       std::to_wstring(p.second.size()) + L" bytes");
                if (p.second.size() <= existing_size) {
                    if (wr(existing_data, p.second.data(), p.second.size())) {
                        const uint64_t new_sz = (uint64_t)p.second.size();
                        const uint32_t new_sz32 = (uint32_t)p.second.size();
                        wr(embedded + size_off, &new_sz, 8);
                        if (size_off + 8 <= 0x30)
                            wr(embedded + size_off, &new_sz32, 4);
                        packed = std::move(p);
                        blob_n = packed.second.size();
                        rp = existing_data;
                        inplace = true;
                        VT_LOG(std::wstring(L"in-place (") + labels[pass] + L"): " +
                               std::to_wstring(blob_n) + L"/" + std::to_wstring((unsigned)existing_size) +
                               L" bytes at " + format_hex(existing_data));
                    }
                }
            }
            if (!inplace)
                VT_LOG(L"in-place: all shims too large for " +
                       std::to_wstring((unsigned)existing_size) + L" — remote alloc");
        }
    }

    if (!rp) {
        const std::string wrapped_full = local_host
            ? (std::string("if _G.__VT then return end;_G.__VT=true;task.spawn(function()\n") + kCoreShim + source + "\nend)\n")
            : (std::string("if _G.__VT then return{}end;_G.__VT=true;script.Parent=nil;task.spawn(function()\n") + kCoreShim + source + "\nend);return {}");
        packed = compile_rbx_bytecode(wrapped_full);
        if (!packed.first)
            return fail(utf8_to_wide(packed.second).c_str());
        blob_n = packed.second.size();
        VT_LOG(L"bytecode (full shim): " + std::to_wstring(blob_n) + L" bytes — remote alloc");

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto pCreateSec = ntdll ? (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection") : nullptr;
        auto pMapView   = ntdll ? (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection") : nullptr;
        auto pUnmapView = ntdll ? (NtUnmapViewOfSection_t)GetProcAddress(ntdll, "NtUnmapViewOfSection") : nullptr;

        if (pCreateSec && pMapView) {
            HANDLE hsec = nullptr;
            LARGE_INTEGER sec_size{};
            sec_size.QuadPart = (LONGLONG)((blob_n + 0xFFF) & ~0xFFFull);
            LONG ns = pCreateSec(&hsec, SECTION_ALL_ACCESS, nullptr, &sec_size,
                                 PAGE_READWRITE, 0x8000000 /*SEC_COMMIT*/, nullptr);
            if (ns >= 0 && hsec) {
                uint8_t* local_view = nullptr;
                SIZE_T view_size = 0;
                ns = pMapView(hsec, GetCurrentProcess(), (PVOID*)&local_view,
                              0, 0, nullptr, &view_size, 2, 0, PAGE_READWRITE);
                if (ns >= 0 && local_view) {
                    memcpy(local_view, packed.second.data(), blob_n);
                    PVOID remote_view = nullptr;
                    SIZE_T rv_size = 0;
                    ns = pMapView(hsec, hp, &remote_view,
                                  0, 0, nullptr, &rv_size, 2, 0, PAGE_READWRITE);
                    if (ns >= 0 && remote_view) {
                        rp = (uintptr_t)remote_view;
                        VT_LOG(L"section-mapped bytecode at " + format_hex(rp) +
                               L" size " + std::to_wstring(blob_n));
                    }
                    if (pUnmapView)
                        pUnmapView(GetCurrentProcess(), local_view);
                }
                CloseHandle(hsec);
            }
        }
    }

    if (!rp) {
        void* remote = VirtualAllocEx(hp, nullptr, blob_n + 0x80,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote)
            return fail(L"VirtualAllocEx bytecode failed");
        if (!wr((uintptr_t)remote, packed.second.data(), blob_n)) {
            VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
            return fail(L"WPM bytecode failed");
        }
        rp = (uintptr_t)remote;
        VT_LOG(L"VirtualAllocEx bytecode at " + format_hex(rp));
    }

    const uint64_t sz = (uint64_t)blob_n;

    if (!inplace && bc_confirmed) {
        auto stamp_box = [&](uintptr_t box) -> bool {
            if (!mem_.looks(box))
                return false;
            const uint32_t sz32 = (uint32_t)sz;
            const bool ok = wr(box + data_off, &rp, 8);
            if (data_off == 0x10) wr(box + 0x18, &rp, 8);
            wr(box + size_off, &sz, 8);
            if (size_off + 8 <= 0x30) wr(box + size_off, &sz32, 4);
            return ok;
        };
        int nstamp = 0;
        for (uintptr_t o : field_try) {
            const uintptr_t e = mem_.read_ptr(vr + o);
            if (looks_bc(e, nullptr, nullptr, true)) {
                if (stamp_box(e)) {
                    ++nstamp;
                    if (!field_off) { embedded = e; field_off = o; }
                    VT_LOG(L"stamped field+" + format_hex(o) + L" box " + format_hex(e));
                }
            }
        }
        if (!nstamp)
            nstamp = stamp_box(embedded) ? 1 : 0;
        if (!nstamp)
            return fail(L"bytecode container not writable");
        const uintptr_t check = mem_.read_ptr(embedded + data_off);
        VT_LOG(L"corescript: bytecode " + format_hex(rp) + L" size " + std::to_wstring((unsigned)sz) +
               L" field+" + format_hex(field_off) + L" n=" + std::to_wstring(nstamp) +
               L" verify=" + format_hex(check) + (check == rp ? L" ok" : L" MISMATCH"));
        if (check != rp)
            return fail(L"bytecode pointer did not stick");
    } else if (!inplace && !bc_confirmed) {
        VT_WARN(L"bytecode written to remote but no confirmed container to stamp — script may not run");
    }

    VT_LOG(L"corescript: container stamped — host " + utf8_to_wide(host_cls) +
           L" bytecode overwritten"
           + (sps_target ? L" (SPS template — will respawn)" : L""));

    // --- Respawn trigger: force character death so SPS templates re-clone ---
    // Stamped bytecode in SPS is only effective after respawn creates fresh clones.
    if (sps_target && pl) {
        uintptr_t local_player = 0;
        {
            std::vector<uintptr_t> player_ch;
            children_of(pl, player_ch);
            for (uintptr_t p : player_ch) {
                if (class_name(p) == "Player") {
                    local_player = p;
                    break;
                }
            }
        }
        if (local_player) {
            uintptr_t character = 0;
            uintptr_t char_off_used = 0;
            for (uintptr_t co : kCharOff) {
                uintptr_t ch = mem_.read_ptr(local_player + co);
                if (looks_instance(ch)) {
                    auto cn = class_name(ch);
                    if (cn == "Model" || cn == "Character" || !cn.empty()) {
                        character = ch;
                        char_off_used = co;
                        break;
                    }
                }
            }
            if (character) {
                uintptr_t humanoid = find_child_class(character, "Humanoid");
                if (!humanoid)
                    humanoid = find_child_name(character, "Humanoid");
                if (humanoid) {
                    VT_LOG(L"respawn: Humanoid " + format_hex(humanoid) +
                           L" Character " + format_hex(character));
                    uint8_t hraw[0x400]{};
                    if (mem_.read(humanoid, hraw, sizeof(hraw))) {
                        const float target_val = 100.0f;
                        int health_hits = 0;
                        for (int hoff = 0x80; hoff < 0x380; hoff += 4) {
                            float val;
                            memcpy(&val, hraw + hoff, 4);
                            if (val == target_val && health_hits < 2) {
                                float zero = 0.0f;
                                wr(humanoid + hoff, &zero, 4);
                                VT_LOG(L"respawn: zeroed float at Humanoid+" + format_hex(hoff));
                                ++health_hits;
                            }
                        }
                        if (health_hits > 0) {
                            VT_LOG(L"respawn: wrote Health=0 (" + std::to_wstring(health_hits) +
                                   L" candidates) — waiting for death + re-clone");
                            Sleep(1500);
                        } else {
                            VT_WARN(L"respawn: no 100.0 float found in Humanoid — "
                                    L"press ESC > Reset Character manually");
                        }
                    }
                } else {
                    VT_WARN(L"respawn: Humanoid not found in Character");
                }
            } else {
                VT_WARN(L"respawn: Character not found on Player");
            }
        } else {
            VT_WARN(L"respawn: LocalPlayer not found");
        }
    }

    // --- Post-stamp direct execution (vtable/IC) ---
    // Blocked by Hyperion on current builds — skip to avoid freeze.
    constexpr bool kTryPostStampDirect = false;
    if (kTryPostStampDirect && tbl.luau_load && tbl.lua_pcall) {
        uintptr_t ps_job = find_script_job();
        uintptr_t ps_L   = ps_job ? find_lua_state(ps_job) : 0;
        if (ps_job && ps_L) {
            const uintptr_t ps_fn_load  = base_ + tbl.luau_load;
            const uintptr_t ps_fn_pcall = base_ + tbl.lua_pcall;
            const uintptr_t ps_fn_newth = tbl.lua_newthread ? (base_ + tbl.lua_newthread) : 0;

            const std::string direct_src =
                std::string("if _G.__VT then return end;_G.__VT=true;task.spawn(function()\n")
                + kCoreShimTiny + source + "\nend)\n";
            auto ps_bc = compile_raw_luau_bytecode(direct_src);
            if (ps_bc.first) {
                const size_t ps_bc_len = ps_bc.second.size();
                auto ps_module_addr = [&](uintptr_t addr) -> bool {
                    if (!mem_.looks(addr)) return false;
                    if (addr >= base_ && addr < base_ + size_) return true;
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (VirtualQueryEx(hp, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi))
                        return mbi.Type == MEM_IMAGE;
                    return false;
                };
                uintptr_t ps_orig_vt = 0;
                for (int vto : {0, 8, 16}) {
                    uintptr_t c = mem_.read_ptr(ps_job + vto);
                    if (ps_module_addr(c)) { ps_orig_vt = c; break; }
                }
                if (ps_orig_vt) {
                    constexpr int VT_N = 16;
                    uintptr_t ps_vt_buf[VT_N]{};
                    mem_.read(ps_orig_vt, ps_vt_buf, sizeof(ps_vt_buf));
                    int ps_idx = -1;
                    for (int i = 3; i <= 8 && ps_idx < 0; ++i)
                        if (ps_module_addr(ps_vt_buf[i])) ps_idx = i;
                    if (ps_idx < 0)
                        for (int i = 1; i < VT_N; ++i)
                            if (ps_module_addr(ps_vt_buf[i])) { ps_idx = i; break; }

                    if (ps_idx >= 0) {
                        const size_t ps_sc_off = 0x80, ps_vt_off = 0x140, ps_bc_off = 0x200;
                        const size_t ps_total = ps_bc_off + ps_bc_len + 64;
                        void* ps_remote = nullptr;
                        SC_VirtualAllocEx(hp, nullptr, ps_total,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, &ps_remote);
                        if (ps_remote) {
                            const uintptr_t prb = (uintptr_t)ps_remote;
                            auto wr_ps = [&](uintptr_t a, const void* p, size_t n) {
                                SIZE_T w = 0;
                                SC_WriteProcessMemory(hp, (LPVOID)a, p, n, &w);
                            };
                            const char pchunk[] = "=VT";
                            wr_ps(prb + 0x60, pchunk, sizeof(pchunk));
                            wr_ps(prb + ps_bc_off, ps_bc.second.data(), ps_bc_len);

                            uintptr_t ps_clone[VT_N];
                            memcpy(ps_clone, ps_vt_buf, sizeof(ps_clone));
                            ps_clone[ps_idx] = prb + ps_sc_off;
                            wr_ps(prb + ps_vt_off, ps_clone, sizeof(ps_clone));

                            struct alignas(8) PSPB {
                                uintptr_t L, chunkname, data, size, fn_load, fn_pcall, fn_newthread;
                                uint32_t phase; uint32_t load_result;
                                uintptr_t orig_vtable;
                                uint32_t one_shot; uint32_t _pad;
                                uintptr_t job_addr;
                                uintptr_t orig_step;
                            };
                            PSPB pspb{};
                            pspb.L = ps_L; pspb.chunkname = prb + 0x60;
                            pspb.data = prb + ps_bc_off; pspb.size = ps_bc_len;
                            pspb.fn_load = ps_fn_load; pspb.fn_pcall = ps_fn_pcall;
                            pspb.fn_newthread = ps_fn_newth;
                            pspb.orig_vtable = ps_orig_vt; pspb.job_addr = ps_job;
                            pspb.orig_step = ps_vt_buf[ps_idx];
                            wr_ps(prb, &pspb, sizeof(pspb));

                            uint8_t ps_sc[] = {
                                0x53, 0x57, 0x48,0x83,0xEC,0x48, 0x48,0x89,0xCF,
                                0x48,0xBB, 0,0,0,0,0,0,0,0,
                                0x83,0x7B,0x48,0x00,
                                0x0F,0x85,0x62,0x00,0x00,0x00,
                                0xC7,0x43,0x48,0x01,0x00,0x00,0x00,
                                0x48,0x8B,0x43,0x40, 0x48,0x8B,0x4B,0x50,
                                0x48,0x89,0x01,
                                0x48,0x8B,0x0B,
                                0x48,0x8B,0x53,0x08,
                                0x4C,0x8B,0x43,0x10, 0x4C,0x8B,0x4B,0x18,
                                0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,
                                0xFF,0x53,0x20,
                                0x89,0x43,0x3C,
                                0xC7,0x43,0x38,0x02,0x00,0x00,0x00,
                                0x85,0xC0,
                                0x75,0x27,
                                0x48,0x8B,0x0B,
                                0x31,0xD2, 0x45,0x31,0xC0, 0x45,0x31,0xC9,
                                0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,
                                0x48,0xC7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,
                                0xFF,0x53,0x28,
                                0xC7,0x43,0x38,0x03,0x00,0x00,0x00,
                                0x48,0x8B,0x43,0x58, 0x48,0x89,0xF9,
                                0x48,0x83,0xC4,0x48, 0x5F, 0x5B, 0xFF,0xE0
                            };
                            memcpy(ps_sc + 11, &prb, 8);
                            wr_ps(prb + ps_sc_off, ps_sc, sizeof(ps_sc));

                            bool ps_cfg = false;
                            {
                                struct { ULONG_PTR Offset; ULONG_PTR Flags; } ps_cti{ps_sc_off, 1};
                                SIZE_T ps_cfgSz = (ps_total + 0xFFF) & ~(SIZE_T)0xFFF;
                                auto& sc_ps = Syscalls::get();
                                if (sc_ps.ready() && sc_ps.SetInformationVirtualMemory) {
                                    struct { PVOID addr; SIZE_T size; } rng{ps_remote, ps_cfgSz};
                                    DWORD proc2 = 0;
                                    struct { DWORD c; DWORD r; PDWORD p; void* t; void* s; uint64_t f; }
                                        vi{1, 0, &proc2, &ps_cti, nullptr, 0};
                                    NTSTATUS ns2 = sc_ps.SetInformationVirtualMemory(
                                        hp, 2, 1, &rng, &vi, (ULONG)sizeof(vi));
                                    ps_cfg = ns2 >= 0;
                                }
                                if (!ps_cfg) {
                                    using SetCfgFn = BOOL(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG, PVOID);
                                    static auto pSetCfg2 = []() -> SetCfgFn {
                                        auto p = (SetCfgFn)GetProcAddress(
                                            GetModuleHandleW(L"kernel32.dll"), "SetProcessValidCallTargets");
                                        if (!p) p = (SetCfgFn)GetProcAddress(
                                            GetModuleHandleW(L"kernelbase.dll"), "SetProcessValidCallTargets");
                                        return p;
                                    }();
                                    if (pSetCfg2)
                                        ps_cfg = pSetCfg2(hp, ps_remote, ps_cfgSz, 1, &ps_cti) != FALSE;
                                }
                                if (ps_cfg)
                                    VT_LOG(L"post-stamp: CFG target validated");
                            }

                            if (ps_cfg) {
                                const uintptr_t ps_new_vt = prb + ps_vt_off;
                                SIZE_T pvw = 0;
                                if (SC_WriteProcessMemory(hp, (LPVOID)ps_job, &ps_new_vt, 8, &pvw) && pvw == 8) {
                                    VT_LOG(L"post-stamp vtable hook ARMED idx=" + std::to_wstring(ps_idx));
                                    bool ps_vt_ok = false;
                                    for (int p = 0; p < 50; ++p) {
                                        Sleep(100);
                                        uint32_t ph = 0; SIZE_T rd = 0;
                                        ReadProcessMemory(hp, (LPCVOID)(prb + 0x38), &ph, 4, &rd);
                                        DWORD ex = 0;
                                        if (!(GetExitCodeProcess(hp, &ex) && ex == STILL_ACTIVE)) {
                                            VT_WARN(L"post-stamp vtable: crashed (phase=" + std::to_wstring(ph) +
                                                    L" exit=0x" + format_hex(ex) + L")");
                                            break;
                                        }
                                        if (ph >= 2) {
                                            VT_LOG(L"post-stamp vtable hook SUCCESS");
                                            ps_vt_ok = true;
                                            break;
                                        }
                                    }
                                    if (ps_vt_ok)
                                        return true;
                                    SC_WriteProcessMemory(hp, (LPVOID)ps_job, &ps_orig_vt, 8, &pvw);
                                }
                            } else {
                                VT_LOG(L"post-stamp: CFG+Hyperion blocked — skipping vtable hook");
                            }

                            // --- Post-stamp Instrumentation Callback fallback ---
                            {
                                uint32_t zero = 0;
                                wr_ps(prb + 0x38, &zero, 4);
                                wr_ps(prb + 0x48, &zero, 4);

                                uint8_t ic_sc[] = {
                                    0x50,0x53,
                                    0x48,0xBB, 0,0,0,0,0,0,0,0,
                                    0x83,0x7B,0x48,0x00,
                                    0x0F,0x85,0x84,0x00,0x00,0x00,
                                    0xF0,0x0F,0xBA,0x6B,0x48,0x00,
                                    0x0F,0x82,0x78,0x00,0x00,0x00,
                                    0x51,0x52,
                                    0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
                                    0x56,0x57,0x55,
                                    0x48,0x89,0xE5,
                                    0x48,0x83,0xE4,0xF0,
                                    0x48,0x83,0xEC,0x30,
                                    0x48,0x8B,0x0B,
                                    0x48,0x8B,0x53,0x08,
                                    0x4C,0x8B,0x43,0x10,
                                    0x4C,0x8B,0x4B,0x18,
                                    0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,
                                    0xFF,0x53,0x20,
                                    0x89,0x43,0x3C,
                                    0xC7,0x43,0x38,0x02,0x00,0x00,0x00,
                                    0x85,0xC0,
                                    0x75,0x27,
                                    0x48,0x8B,0x0B,
                                    0x31,0xD2,0x45,0x31,0xC0,0x45,0x31,0xC9,
                                    0x48,0xC7,0x44,0x24,0x20,0x00,0x00,0x00,0x00,
                                    0x48,0xC7,0x44,0x24,0x28,0x00,0x00,0x00,0x00,
                                    0xFF,0x53,0x28,
                                    0xC7,0x43,0x38,0x03,0x00,0x00,0x00,
                                    0x48,0x89,0xEC,
                                    0x5D,0x5F,0x5E,
                                    0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,
                                    0x5A,0x59,
                                    0x5B,0x58,
                                    0x41,0xFF,0xE2
                                };
                                memcpy(ic_sc + 4, &prb, 8);
                                wr_ps(prb + ps_sc_off, ic_sc, sizeof(ic_sc));

                                using NtSetInfoProc_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
                                auto pNtSIP = (NtSetInfoProc_t)GetProcAddress(
                                    GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess");
                                if (pNtSIP) {
                                    struct { ULONG V; ULONG R; PVOID C; }
                                        ic{0, 0, (PVOID)(prb + ps_sc_off)};
                                    NTSTATUS ns = pNtSIP(hp, 40, &ic, sizeof(ic));
                                    if (ns >= 0) {
                                        VT_LOG(L"post-stamp IC SET");
                                        bool ic_ok = false;
                                        for (int p = 0; p < 50; ++p) {
                                            Sleep(100);
                                            uint32_t ph = 0; SIZE_T rd = 0;
                                            ReadProcessMemory(hp, (LPCVOID)(prb + 0x38), &ph, 4, &rd);
                                            DWORD ex = 0;
                                            if (!(GetExitCodeProcess(hp, &ex) && ex == STILL_ACTIVE)) {
                                                VT_WARN(L"post-stamp IC: crashed phase=" +
                                                        std::to_wstring(ph) +
                                                        L" exit=0x" + format_hex(ex) + L")");
                                                break;
                                            }
                                            if (ph >= 2) {
                                                VT_LOG(L"post-stamp IC SUCCESS phase=" +
                                                       std::to_wstring(ph));
                                                ic_ok = true;
                                                break;
                                            }
                                        }
                                        struct { ULONG V; ULONG R; PVOID C; } clr{0,0,nullptr};
                                        pNtSIP(hp, 40, &clr, sizeof(clr));
                                        if (ic_ok) return true;
                                        VT_WARN(L"post-stamp IC timed out");
                                    } else {
                                        VT_WARN(L"post-stamp IC: NTSTATUS=" +
                                                format_hex((uintptr_t)(ULONG)ns));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // --- UI triggers: ESC (menu toggle) + F9 (console) ---
    HWND rbx_wnd = nullptr;
    {
        struct FindCtx { DWORD pid; HWND wnd; };
        FindCtx fc{ GetProcessId(hp), nullptr };
        EnumWindows([](HWND h, LPARAM lp) -> BOOL {
            auto* ctx = (FindCtx*)lp;
            DWORD p = 0;
            GetWindowThreadProcessId(h, &p);
            if (p == ctx->pid && IsWindowVisible(h)) {
                ctx->wnd = h;
                return FALSE;
            }
            return TRUE;
        }, (LPARAM)&fc);
        rbx_wnd = fc.wnd;

        if (!rbx_wnd) {
            for (const wchar_t* cls : {L"WINDOWSCLIENT", L"Win32 Window Class"}) {
                HWND h = FindWindowW(cls, nullptr);
                while (h) {
                    DWORD p = 0;
                    GetWindowThreadProcessId(h, &p);
                    if (p == fc.pid) { rbx_wnd = h; break; }
                    h = FindWindowExW(nullptr, h, cls, nullptr);
                }
                if (rbx_wnd) break;
            }
        }
        if (!rbx_wnd) {
            fc.wnd = nullptr;
            EnumWindows([](HWND h, LPARAM lp) -> BOOL {
                auto* ctx = (FindCtx*)lp;
                DWORD p = 0;
                GetWindowThreadProcessId(h, &p);
                if (p == ctx->pid) { ctx->wnd = h; return FALSE; }
                return TRUE;
            }, (LPARAM)&fc);
            rbx_wnd = fc.wnd;
        }
    }
    if (rbx_wnd) {
        VT_LOG(L"corescript: Roblox window " + format_hex((uintptr_t)rbx_wnd));

        if (sps_target) {
            // SPS target: open ESC menu and attempt "Reset Character" via keyboard nav.
            // Menu layout (top→bottom): Resume, avatar, Store, Settings, Report, Reset, Leave.
            // Reset Character is typically the 6th focusable item.
            PostMessageW(rbx_wnd, WM_KEYDOWN, VK_ESCAPE, 0x00010001);
            Sleep(80);
            PostMessageW(rbx_wnd, WM_KEYUP, VK_ESCAPE, 0xC0010001);
            Sleep(400);
            // Tab down to Reset Character (skip Resume, Store, Settings, Report)
            for (int i = 0; i < 5; ++i) {
                PostMessageW(rbx_wnd, WM_KEYDOWN, VK_TAB, 0x000F0001);
                Sleep(30);
                PostMessageW(rbx_wnd, WM_KEYUP, VK_TAB, 0xC00F0001);
                Sleep(60);
            }
            // Press Enter on "Reset Character"
            PostMessageW(rbx_wnd, WM_KEYDOWN, VK_RETURN, 0x001C0001);
            Sleep(30);
            PostMessageW(rbx_wnd, WM_KEYUP, VK_RETURN, 0xC01C0001);
            Sleep(300);
            // Confirm reset — Enter on "Reset" button in dialog
            PostMessageW(rbx_wnd, WM_KEYDOWN, VK_RETURN, 0x001C0001);
            Sleep(30);
            PostMessageW(rbx_wnd, WM_KEYUP, VK_RETURN, 0xC01C0001);
            VT_LOG(L"corescript: Reset Character sequence sent — "
                   L"if script doesn't appear, press ESC > Reset Character manually");
            Sleep(2000);
        } else {
            // Non-SPS target: ESC double-tap (trigger lazy module loading)
            PostMessageW(rbx_wnd, WM_KEYDOWN, VK_ESCAPE, 0x00010001);
            Sleep(80);
            PostMessageW(rbx_wnd, WM_KEYUP, VK_ESCAPE, 0xC0010001);
            Sleep(200);
            PostMessageW(rbx_wnd, WM_KEYDOWN, VK_ESCAPE, 0x00010001);
            Sleep(80);
            PostMessageW(rbx_wnd, WM_KEYUP, VK_ESCAPE, 0xC0010001);
            // F9 (developer console toggle — may load lazy console modules)
            Sleep(150);
            PostMessageW(rbx_wnd, WM_KEYDOWN, VK_F9, 0x00430001);
            Sleep(80);
            PostMessageW(rbx_wnd, WM_KEYUP, VK_F9, 0xC0430001);
            Sleep(200);
            PostMessageW(rbx_wnd, WM_KEYDOWN, VK_F9, 0x00430001);
            Sleep(80);
            PostMessageW(rbx_wnd, WM_KEYUP, VK_F9, 0xC0430001);
            VT_LOG(L"corescript: ESC+F9 triggers sent");
        }
    } else {
        VT_WARN(L"corescript: Roblox window not found — "
                L"press ESC > Reset Character to trigger execution");
    }

    return true;
}

} // namespace vt::ext
