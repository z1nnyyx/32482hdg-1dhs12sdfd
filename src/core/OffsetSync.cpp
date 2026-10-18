#include "core/OffsetSync.h"
#include "core/Process.h"
#include "ext/Memory.h"
#include "shared/Config.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <Windows.h>
#include <vector>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <functional>

namespace vt {
namespace {

bool parse_ida(const char* ida, std::vector<uint8_t>& bytes, std::vector<bool>& mask) {
    bytes.clear();
    mask.clear();
    const char* s = ida;
    for (size_t i = 0; s[i];) {
        while (s[i] && std::isspace((unsigned char)s[i]))
            ++i;
        if (!s[i])
            break;
        if (s[i] == '?') {
            bytes.push_back(0);
            mask.push_back(false);
            ++i;
            if (s[i] == '?')
                ++i;
            continue;
        }
        if (!s[i + 1])
            return false;
        char tmp[3] = { s[i], s[i + 1], 0 };
        bytes.push_back((uint8_t)std::strtoul(tmp, nullptr, 16));
        mask.push_back(true);
        i += 2;
    }
    return !bytes.empty();
}

uintptr_t find_in(const uint8_t* img, size_t sz, const char* ida) {
    std::vector<uint8_t> b;
    std::vector<bool> m;
    if (!parse_ida(ida, b, m) || b.size() > sz)
        return 0;
    const size_t n = b.size();
    for (size_t i = 0; i + n <= sz; ++i) {
        bool ok = true;
        for (size_t j = 0; j < n; ++j) {
            if (m[j] && img[i + j] != b[j]) {
                ok = false;
                break;
            }
        }
        if (ok)
            return (uintptr_t)i;
    }
    return 0;
}

bool looks_heap(uintptr_t p) {
    return p > 0x10000000000ULL && p < 0x00007FFFFFFFFFFFULL;
}

bool looks_code_byte(uint8_t b) {
    return b == 0x40 || b == 0x41 || b == 0x48 || b == 0x4C ||
           b == 0x53 || b == 0x55 || b == 0x56 || b == 0x57 || b == 0x85;
}

std::string job_name(ext::Memory& mem, uintptr_t job) {
    const int offs[] = { 0x18, 0x10, 0x20, 0x28, 0x30 };
    for (int o : offs) {
        auto s = mem.rstring(job + o);
        if (s.size() >= 3)
            return s;
    }
    return {};
}

int score_task_scheduler(ext::Memory& mem, uintptr_t ts) {
    if (!looks_heap(ts) && !(ts > 0x10000 && ts < 0x00007FFFFFFFFFFFULL))
        return 0;
    const int starts[] = { 0xC8, 0xD0, 0x118, 0x120, 0x128, 0x188, 0x198, 0x1D0, 0x208 };
    int best = 0;
    for (int st : starts) {
        const uintptr_t b = mem.read_ptr(ts + st);
        const uintptr_t e = mem.read_ptr(ts + st + 8);
        if (!looks_heap(b) || !looks_heap(e) || e <= b || (e - b) > 0x8000)
            continue;
        const int n = (int)((e - b) / 8);
        if (n < 8 || n > 400)
            continue;
        int joblike = 0, fflag = 0, named = 0;
        for (uintptr_t it = b; it < e && named < 32; it += 8) {
            const uintptr_t job = mem.read_ptr(it);
            if (!looks_heap(job) && !(job > 0x10000 && job < 0x00007FFFFFFFFFFFULL))
                continue;
            const auto nm = job_name(mem, job);
            if (nm.size() < 3)
                continue;
            ++named;
            int strong = 0;
            if (nm.find("WaitingHybrid") != std::string::npos ||
                nm.find("Heartbeat") != std::string::npos ||
                nm.find("RenderJob") != std::string::npos ||
                nm.find("PhysicsJob") != std::string::npos ||
                nm.find("Luau") != std::string::npos)
                strong = 3;
            joblike += strong;
            if (nm.find("Enable") != std::string::npos || nm.find("Disable") != std::string::npos ||
                nm.find("FFlag") != std::string::npos || nm.find("DevAsset") != std::string::npos ||
                nm.find("StandaloneDm") != std::string::npos ||
                (nm.size() > 18 && nm.find("Flag") != std::string::npos))
                ++fflag;
        }
        if (joblike < 6 || fflag >= 2)
            continue;
        const int sc = joblike * 10 - fflag * 8;
        if (sc > best)
            best = sc;
    }
    return best;
}

bool is_task_scheduler(ext::Memory& mem, uintptr_t ts) {
    return score_task_scheduler(mem, ts) >= 80;
}

bool is_datamodel(ext::Memory& mem, uintptr_t dm) {
    if (!looks_heap(dm))
        return false;
    const uintptr_t child[] = { 0x60, 0x68, 0x70, 0x78, 0x80, 0x88 };
    const uintptr_t names[] = { 0xB0, 0x70, 0x48, 0x50, 0x88, 0x8, 0x28, 0x30 };
    auto has_players = [&](uintptr_t b, uintptr_t e, uintptr_t stride) {
        if (!looks_heap(b) || !looks_heap(e) || e <= b)
            return false;
        const uintptr_t n = (e - b) / stride;
        if (n < 3 || n > 256)
            return false;
        int step = 0;
        for (uintptr_t it = b; it + 8 <= e && step < 80; it += stride, ++step) {
            const uintptr_t ch = mem.read_ptr(it);
            if (!looks_heap(ch))
                continue;
            for (uintptr_t no : names) {
                auto s = mem.rstring(ch + no);
                if (s.empty()) {
                    const uintptr_t p = mem.read_ptr(ch + no);
                    if (p > 0x10000)
                        s = mem.rstring_ptr(p);
                }
                if (s == "Players")
                    return true;
            }
        }
        return false;
    };
    for (uintptr_t co : child) {
        const uintptr_t a = mem.read_ptr(dm + co);
        const uintptr_t b = mem.read_ptr(dm + co + 8);
        if (has_players(a, b, 8) || has_players(a, b, 16))
            return true;
        if (looks_heap(a)) {
            const uintptr_t w0 = mem.read_ptr(a);
            const uintptr_t w1 = mem.read_ptr(a + 8);
            if (has_players(w0, w1, 8) || has_players(w0, w1, 16))
                return true;
        }
    }
    return false;
}

uintptr_t follow_fake(ext::Memory& mem, uintptr_t fake, uintptr_t& used_off) {
    const uintptr_t offs[] = { 0x1D8, 0x1C0, 0x1B8, 0x1E0, 0x198, 0x1A8, 0x1F0, 0x200, 0 };
    for (uintptr_t o : offs) {
        const uintptr_t dm = o ? mem.read_ptr(fake + o) : fake;
        if (is_datamodel(mem, dm)) {
            used_off = o;
            return dm;
        }
    }
    return 0;
}

void each_region(HANDLE proc, uintptr_t base, size_t size, DWORD want_prot,
                 const std::function<void(uintptr_t, const uint8_t*, size_t)>& fn) {
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = base;
    const uintptr_t end = base + size;
    while (addr < end) {
        if (!VirtualQueryEx(proc, (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;
        const uintptr_t rsz = (uintptr_t)mbi.RegionSize;
        const bool ok = mbi.State == MEM_COMMIT &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
            (mbi.Protect & want_prot);
        if (ok && rsz >= 16 && rsz <= 0x800000) {
            std::vector<uint8_t> buf(rsz);
            SIZE_T got = 0;
            if (ReadProcessMemory(proc, mbi.BaseAddress, buf.data(), rsz, &got) && got >= 16)
                fn((uintptr_t)mbi.BaseAddress, buf.data(), (size_t)got);
        }
        const uintptr_t next = (uintptr_t)mbi.BaseAddress + rsz;
        if (next <= addr)
            break;
        addr = next;
    }
}

void take_lua(uintptr_t& slot, HANDLE proc, uintptr_t base, size_t size,
              std::initializer_list<const char*> pats, const wchar_t* name) {
    if (slot)
        return;
    std::vector<std::pair<std::vector<uint8_t>, std::vector<bool>>> compiled;
    for (auto* p : pats) {
        std::vector<uint8_t> b;
        std::vector<bool> m;
        if (parse_ida(p, b, m))
            compiled.push_back({ std::move(b), std::move(m) });
    }
    each_region(proc, base, size, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE,
        [&](uintptr_t at, const uint8_t* img, size_t n) {
            if (slot)
                return;
            for (auto& c : compiled) {
                const size_t pn = c.first.size();
                if (pn > n)
                    continue;
                for (size_t i = 0; i + pn <= n; ++i) {
                    bool ok = true;
                    for (size_t j = 0; j < pn; ++j) {
                        if (c.second[j] && img[i + j] != c.first[j]) {
                            ok = false;
                            break;
                        }
                    }
                    if (ok && looks_code_byte(img[i])) {
                        slot = (at + i) - base;
                        VT_LOG(std::wstring(L"auto ") + name + L" " + format_hex(slot));
                        return;
                    }
                }
            }
        });
}

} // namespace

std::filesystem::path OffsetSync::find_roblox_exe() {
    if (auto p = ProcessFinder::find()) {
        if (!p->path.empty() && file_exists(p->path))
            return p->path;
    }
    wchar_t appdata[MAX_PATH]{};
    GetEnvironmentVariableW(L"LOCALAPPDATA", appdata, MAX_PATH);
    std::filesystem::path versions = std::filesystem::path(appdata) / L"Roblox" / L"Versions";
    std::error_code ec;
    std::filesystem::path best;
    std::filesystem::file_time_type best_t{};
    if (std::filesystem::exists(versions, ec)) {
        for (auto& e : std::filesystem::directory_iterator(versions, ec)) {
            auto exe = e.path() / L"RobloxPlayerBeta.exe";
            if (!file_exists(exe))
                continue;
            auto t = std::filesystem::last_write_time(exe, ec);
            if (best.empty() || t > best_t) {
                best = exe;
                best_t = t;
            }
        }
    }
    return best;
}

bool OffsetSync::refresh() {
    auto rp = ProcessFinder::find();
    if (!rp || !rp->base || !rp->size) {
        VT_WARN(L"Offset sync: join a game first");
        return false;
    }

    ext::Memory mem;
    if (!mem.open(rp->pid)) {
        VT_WARN(L"Offset sync: OpenProcess failed — run as Administrator");
        return false;
    }

    auto& o = Config::instance().get().offsets;
    o.roblox_version = rp->path.empty()
        ? o.roblox_version
        : std::filesystem::path(rp->path).parent_path().filename().string();

    auto drop = [&](uintptr_t& rva, const wchar_t* what) {
        if (!rva)
            return;
        const uintptr_t v = mem.read_ptr(rp->base + rva);
        if (!v) {
            VT_WARN(std::wstring(L"drop dead ") + what + L" " + format_hex(rva));
            rva = 0;
        }
    };
    drop(o.task_scheduler, L"task_scheduler");
    drop(o.fake_datamodel, L"fake_datamodel");
    drop(o.visual_engine, L"visual_engine");
    if (o.task_scheduler && !is_task_scheduler(mem, mem.read_ptr(rp->base + o.task_scheduler)))
        o.task_scheduler = 0;
    if (o.fake_datamodel) {
        uintptr_t used = 0;
        if (!follow_fake(mem, mem.read_ptr(rp->base + o.fake_datamodel), used))
            o.fake_datamodel = 0;
    }

    HANDLE proc = mem.handle();
    const bool lua_ok = o.luau_load && o.lua_pcall;
    if (!lua_ok) {
    take_lua(o.lua_gettop, proc, rp->base, rp->size, {
        "48 8B 41 ?? 48 2B 41 ?? 48 C1 F8 04 C3",
        "48 8B 41 ?? 48 2B 41 ?? C1 F8 04 C3",
        "48 8B 41 ?? 48 2B 41 ?? 48 D1 F8 C3",
        "48 8B 51 ?? 48 8B 41 ?? 48 2B D0 48 C1 FA 04",
        "48 8B 81 ?? ?? ?? ?? 48 2B 81 ?? ?? ?? ?? 48 C1 F8 04 C3",
    }, L"lua_gettop");
    take_lua(o.lua_pcall, proc, rp->base, rp->size, {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F2",
        "40 53 56 57 48 83 EC ?? 8B F2 49 8B D8",
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F2 49 8B F8",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 48 83 EC ?? 8B F2",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 56 48 83 EC ?? 8B F2",
        "48 89 5C 24 ?? 55 56 57 41 54 41 55 48 83 EC ?? 8B F2",
    }, L"lua_pcall");
    take_lua(o.luau_load, proc, rp->base, rp->size, {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 41 8B E9",
        "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 41 56 41 57 48 83 EC ?? 41 8B E9",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
        "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 56 41 57 48 83 EC ?? 41 8B E9",
    }, L"luau_load");
    take_lua(o.lua_pushnil, proc, rp->base, rp->size, {
        "48 8B 41 ?? 48 C7 00 00 00 00 00 48 83 41 ?? 10",
        "48 8B 41 ?? C7 00 00 00 00 00 C7 40 ?? 00 00 00 00 48 83 41 ?? 10",
        "48 8B 81 ?? ?? ?? ?? 48 C7 00 00 00 00 00 48 83 81 ?? ?? ?? ?? 10",
    }, L"lua_pushnil");
    take_lua(o.lua_pushnumber, proc, rp->base, rp->size, {
        "48 8B 41 ?? F2 0F 11 00 C7 40 0C 03 00 00 00 48 83 41 ?? 10",
        "48 8B 41 ?? F2 0F 11 00 C7 40 ?? 03 00 00 00 48 83 41 ?? 10",
        "48 8B 81 ?? ?? ?? ?? F2 0F 11 00 C7 40 ?? 03 00 00 00",
    }, L"lua_pushnumber");
    take_lua(o.lua_settop, proc, rp->base, rp->size, {
        "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 14 D0 48 3B 51",
        "85 D2 78 ?? 48 8B 41 ?? 48 63 D2 48 C1 E2 04",
    }, L"lua_settop");
    take_lua(o.lua_type, proc, rp->base, rp->size, {
        "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 44 D0 F0 8B 40 0C",
        "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 C1 E2 04 48 03 D0 8B 42",
        "85 D2 78 ?? 48 8B 41 ?? 48 63 D2 48 8D 44 D0 ?? 8B 40",
    }, L"lua_type");
    take_lua(o.lua_pushstring, proc, rp->base, rp->size, {
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 48 85 D2",
        "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B D9 48 85 D2 75",
    }, L"lua_pushstring");
    take_lua(o.lua_pushlstring, proc, rp->base, rp->size, {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B E8 48 8B FA",
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F0 48 8B FA 48 8B D9",
    }, L"lua_pushlstring");
    take_lua(o.lua_newthread, proc, rp->base, rp->size, {
        "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B 4F",
        "40 53 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 4B",
        "40 53 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 48 8B D3 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0",
        "48 89 5C 24 ?? 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 48 8B D3 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0",
        "56 48 83 EC ?? 48 8B F1 E8 ?? ?? ?? ?? 48 8B CE E8 ?? ?? ?? ?? 48 85 C0 74",
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0",
        "40 53 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 48 8B 4B ?? E8 ?? ?? ?? ?? 48 85 C0",
        "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 48 8B 49 ?? E8 ?? ?? ?? ?? 48 85 C0 74",
        "40 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B 4F",
        "40 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ?? 48 8B CF E8 ?? ?? ?? ?? 48 85 C0",
    }, L"lua_newthread");
    take_lua(o.lua_pushcclosure, proc, rp->base, rp->size, {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 4D 8B F9 49 8B F0",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 41 56 41 57 48 83 EC ?? 4D 8B F9 49 8B F0",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 41 57 48 83 EC ?? 4D 8B F9",
    }, L"lua_pushcclosure");
    take_lua(o.lua_tolstring, proc, rp->base, rp->size, {
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F8 8B DA 48 8B F1",
        "48 89 5C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 48 83 EC ?? 49 8B F8 8B DA",
        "48 89 5C 24 ?? 57 48 83 EC ?? 49 8B F8 8B DA 48 8B D9",
    }, L"lua_tolstring");
    take_lua(o.lua_setreadonly, proc, rp->base, rp->size, {
        "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 08 84 D2 74 ?? 80 48",
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 08 84 D2",
        "40 53 48 83 EC ?? 8B DA 48 8B D1 E8 ?? ?? ?? ?? 80 48 ?? 01",
    }, L"lua_setreadonly");
    }

    {
        const int have = o.task_scheduler
            ? score_task_scheduler(mem, mem.read_ptr(rp->base + o.task_scheduler)) : 0;
        if (o.task_scheduler && have < 80) {
            VT_WARN(L"drop fake task_scheduler " + format_hex(o.task_scheduler) +
                    L" (FFlag list, not jobs)");
            o.task_scheduler = 0;
        }
        uintptr_t best_rva = have >= 80 ? o.task_scheduler : 0;
        int best_sc = have >= 80 ? have : 0;
        const uintptr_t kTsTry[] = {
            0x83B1A00, 0x8ABD728, 0x8A44D68, 0x8CA9CC8
        };
        for (uintptr_t rva : kTsTry) {
            const uintptr_t val = mem.read_ptr(rp->base + rva);
            if (!looks_heap(val))
                continue;
            const int sc = score_task_scheduler(mem, val);
            if (sc > best_sc) {
                best_sc = sc;
                best_rva = rva;
            }
        }
        const DWORD ts0 = GetTickCount();
        if (best_sc < 80)
        each_region(proc, rp->base, rp->size, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE,
            [&](uintptr_t at, const uint8_t* img, size_t n) {
                if (GetTickCount() - ts0 > 4000)
                    return;
                for (size_t i = 0; i + 7 < n; ++i) {
                    if (img[i] != 0x48 || img[i + 1] != 0x8B)
                        continue;
                    if (img[i + 2] != 0x0D && img[i + 2] != 0x05)
                        continue;
                    const int32_t rel = *(const int32_t*)(img + i + 3);
                    const uintptr_t tgt = at + i + 7 + (intptr_t)rel;
                    if (tgt < rp->base || tgt + 8 > rp->base + rp->size)
                        continue;
                    const uintptr_t val = mem.read_ptr(tgt);
                    if (!looks_heap(val))
                        continue;
                    const int sc = score_task_scheduler(mem, val);
                    if (sc > best_sc) {
                        best_sc = sc;
                        best_rva = tgt - rp->base;
                    }
                }
            });
        if (best_rva && best_sc >= 80) {
            o.task_scheduler = best_rva;
            VT_LOG(L"auto task_scheduler " + format_hex(o.task_scheduler) +
                   L" score " + std::to_wstring(best_sc));
        }
    }

    const auto out = data_root() / L"config" / L"offsets.json";
    Config::instance().save(out);
    hide_path(out);
    VT_LOG(L"Offset sync " + utf8_to_wide(o.roblox_version) +
           L"  TS " + format_hex(o.task_scheduler) +
           L"  DM " + format_hex(o.fake_datamodel) +
           L"  load " + format_hex(o.luau_load) +
           L"  pcall " + format_hex(o.lua_pcall) +
           L"  newthread " + format_hex(o.lua_newthread));
    return o.luau_load || o.lua_pcall || o.task_scheduler || o.fake_datamodel;
}

} // namespace vt
