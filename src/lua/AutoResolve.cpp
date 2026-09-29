#include "lua/AutoResolve.h"
#include "lua/Scanner.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <Windows.h>
#include <cstring>

namespace vt {
namespace {

uintptr_t first_pat(uintptr_t image, size_t size, const char* const* pats, int n) {
    for (int i = 0; i < n; ++i) {
        if (auto hit = PatternScanner::find(image, size, pats[i]))
            return hit;
    }
    return 0;
}

bool looks_code(uintptr_t p) {
    uint8_t b = 0;
    __try {
        b = *(const uint8_t*)p;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return b == 0x40 || b == 0x41 || b == 0x48 || b == 0x4C ||
           b == 0x53 || b == 0x55 || b == 0x56 || b == 0x57 || b == 0x85;
}

void take(uintptr_t& slot, uintptr_t image, size_t size, const char* const* pats, int n, const wchar_t* name) {
    if (slot)
        return;
    slot = first_pat(image, size, pats, n);
    if (slot && !looks_code(slot)) {
        VT_WARN(std::wstring(L"auto ") + name + L" rejected " + format_hex(slot));
        slot = 0;
        return;
    }
    if (slot)
        VT_LOG(std::wstring(L"auto ") + name + L" " + format_hex(slot));
}

bool bytes_has(uintptr_t fn, size_t n, const uint8_t* seq, size_t sn) {
    uint8_t buf[256]{};
    if (n > sizeof(buf))
        n = sizeof(buf);
    __try {
        memcpy(buf, (const void*)fn, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    for (size_t i = 0; i + sn <= n; ++i) {
        if (memcmp(buf + i, seq, sn) == 0)
            return true;
    }
    return false;
}

bool looks_like_pcall(uintptr_t fn) {
    if (!looks_code(fn))
        return false;
    const uint8_t nargs[] = {0x8B, 0xF2}; // mov esi, edx
    const uint8_t top18[] = {0x48, 0x8B, 0x41, 0x18};
    const uint8_t top20[] = {0x48, 0x8B, 0x41, 0x20};
    const uint8_t top10[] = {0x48, 0x8B, 0x41, 0x10};
    if (!bytes_has(fn, 0xC0, nargs, 2))
        return false;
    return bytes_has(fn, 0xC0, top18, 4) ||
           bytes_has(fn, 0xC0, top20, 4) ||
           bytes_has(fn, 0xC0, top10, 4);
}

void take_pcall(uintptr_t& slot, uintptr_t image, size_t size, const char* const* pats, int n) {
    if (slot)
        return;
    uintptr_t cur = image;
    const uintptr_t end = image + size;
    for (int attempt = 0; attempt < 4 && cur + 16 < end; ++attempt) {
        uintptr_t hit = 0;
        for (int i = 0; i < n; ++i) {
            const uintptr_t h = PatternScanner::find(cur, end - cur, pats[i]);
            if (h && (!hit || h < hit))
                hit = h;
        }
        if (!hit)
            break;
        if (looks_like_pcall(hit)) {
            slot = hit;
            VT_LOG(L"auto lua_pcall " + format_hex(slot));
            return;
        }
        cur = hit + 1;
    }
    VT_WARN(L"auto lua_pcall: no candidate reads lua_State top — first pattern is not pcall");
}

void scan_lua_api(Resolved& r) {
    if (!r.image_base || !r.image_size)
        return;
    const uintptr_t img = r.image_base;
    const size_t sz = r.image_size;

    const char* gettop[] = {
        "48 8B 41 ?? 48 2B 41 ?? 48 C1 F8 04 C3",
        "48 8B 41 ?? 48 2B 41 ?? C1 F8 04 C3",
        "48 8B 41 ?? 48 2B 41 ?? 48 D1 F8 C3",
        "48 8B 51 ?? 48 8B 41 ?? 48 2B D0 48 C1 FA 04",
        "48 8B 81 ?? ?? ?? ?? 48 2B 81 ?? ?? ?? ?? 48 C1 F8 04 C3",
        "48 8B 41 ?? 48 2B 41 ?? 48 C1 F8 04 48 98 C3",
    };
    take(r.lua_gettop, img, sz, gettop, 6, L"lua_gettop");

    const char* pushnil[] = {
        "48 8B 41 ?? 48 C7 00 00 00 00 00 48 83 41 ?? 10",
        "48 8B 41 ?? C7 40 0C 00 00 00 00 48 83 41 ?? 10",
        "48 8B 41 ?? 48 C7 00 00 00 00 00 C7 40 0C 00 00 00 00 48 83 41 ?? 10",
    };
    take(r.lua_pushnil, img, sz, pushnil, 3, L"lua_pushnil");

    const char* pcall[] = {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F2",
        "40 53 56 57 48 83 EC ?? 8B F2 49 8B D8",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 48 83 EC ?? 8B F2",
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F2 49 8B F8",
        "40 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 8B F2",
    };
    take_pcall(r.lua_pcall, img, sz, pcall, 5);

    const char* load[] = {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 41 8B E9",
        "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
        "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 4D 8B E1",
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F9 49 8B F0 48 8B DA E8",
    };
    take(r.luau_load, img, sz, load, 5, L"luau_load");

    const char* pushnum[] = {
        "48 8B 41 ?? F2 0F 11 00 C7 40 0C 03 00 00 00 48 83 41 ?? 10",
        "48 8B 41 ?? F2 0F 11 00 C7 40 08 03 00 00 00 48 83 41 ?? 10",
        "48 8B 41 ?? 66 0F D6 00 C7 40 0C 03 00 00 00",
    };
    take(r.lua_pushnumber, img, sz, pushnum, 3, L"lua_pushnumber");

    const char* pushbool[] = {
        "48 8B 41 ?? 89 10 C7 40 0C 01 00 00 00 48 83 41 ?? 10",
        "48 8B 41 ?? 89 10 C7 40 08 01 00 00 00 48 83 41 ?? 10",
    };
    take(r.lua_pushboolean, img, sz, pushbool, 2, L"lua_pushboolean");

    const char* settop[] = {
        "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 14 D0 48 3B 51",
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 85 D2 78",
        "85 D2 78 ?? 48 8B 41 ?? 48 63 D2 48 C1 E2 04",
    };
    take(r.lua_settop, img, sz, settop, 3, L"lua_settop");

    const char* typep[] = {
        "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 44 D0 F0 8B 40 0C",
        "85 D2 7E ?? 48 8B 41 ?? 4C 63 C2 49 C1 E0 04 4C 03 C0",
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 85 D2 7E ?? 48 8B 41",
    };
    take(r.lua_type, img, sz, typep, 3, L"lua_type");

    const char* pushval[] = {
        "48 8B 41 ?? 4C 8B C9 85 D2 7E ?? 48 63 D2 48 8D 14 D0 48 3B",
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 4F",
    };
    take(r.lua_pushvalue, img, sz, pushval, 2, L"lua_pushvalue");

    const char* pushstr[] = {
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 48 85 D2",
        "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B D9 48 85 D2 75",
    };
    take(r.lua_pushstring, img, sz, pushstr, 2, L"lua_pushstring");

    const char* pushlstr[] = {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B E8 48 8B FA",
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F0 48 8B FA 48 8B D9",
    };
    take(r.lua_pushlstring, img, sz, pushlstr, 2, L"lua_pushlstring");

    const char* pushc[] = {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 4D 8B F9 49 8B F0",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 4C 8B FA 4C 8B F1",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 48 83 EC ?? 4D 8B F1 49 8B F0 48 8B EA",
        "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1 4C 8B EA 4C 8B F1",
    };
    take(r.lua_pushcclosure, img, sz, pushc, 4, L"lua_pushcclosure");

    const char* createt[] = {
        "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 48 83 EC ?? 41 8B F0 8B EA 48 8B F9",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 48 83 EC ?? 8B F2 49 8B F8",
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 4F ?? 45 33 C0",
    };
    take(r.lua_createtable, img, sz, createt, 3, L"lua_createtable");

    const char* getfield[] = {
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F0 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B D6",
        "48 89 5C 24 ?? 57 48 83 EC ?? 49 8B D8 48 8B F9 8B D2 E8 ?? ?? ?? ?? 48 8B D3 E8",
    };
    take(r.lua_getfield, img, sz, getfield, 2, L"lua_getfield");

    const char* setfield[] = {
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F0 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B D6 E8",
        "48 89 5C 24 ?? 57 48 83 EC ?? 49 8B D8 8B FA 48 8B E9 E8 ?? ?? ?? ?? 48 8B D3",
    };
    take(r.lua_setfield, img, sz, setfield, 2, L"lua_setfield");

    const char* gettable[] = {
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 57 F0",
        "40 53 48 83 EC ?? 8B DA 48 8B D1 E8 ?? ?? ?? ?? 48 8B 48",
    };
    take(r.lua_gettable, img, sz, gettable, 2, L"lua_gettable");

    const char* settable[] = {
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 57 E0",
        "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 48 ?? 48 8B 53",
    };
    take(r.lua_settable, img, sz, settable, 2, L"lua_settable");

    const char* newud[] = {
        "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 4F",
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F2 48 8B F9 48 83 FA",
    };
    take(r.lua_newuserdata, img, sz, newud, 2, L"lua_newuserdata");

    const char* setmt[] = {
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 4F ?? 48 85 C9",
        "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 08 48 85 C9 74",
    };
    take(r.lua_setmetatable, img, sz, setmt, 2, L"lua_setmetatable");

    const char* getmt[] = {
        "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 08 48 85 C9 74 ?? 48 8B 41",
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 08",
    };
    take(r.lua_getmetatable, img, sz, getmt, 2, L"lua_getmetatable");

    const char* tolstr[] = {
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F8 8B DA 48 8B F1",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B E8 8B DA",
    };
    take(r.lua_tolstring, img, sz, tolstr, 2, L"lua_tolstring");

    const char* tobool[] = {
        "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 44 D0 F0 83 78 0C 01",
        "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 83 78 0C 00 74",
    };
    take(r.lua_toboolean, img, sz, tobool, 2, L"lua_toboolean");

    const char* tonum[] = {
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 83 78 0C 03",
        "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 83 78 0C 03 75",
    };
    take(r.lua_tonumber, img, sz, tonum, 2, L"lua_tonumber");

    const char* touser[] = {
        "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 83 78 0C 08 75 ?? 48 8B 00",
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 83 78 0C 08",
    };
    take(r.lua_touserdata, img, sz, touser, 2, L"lua_touserdata");

    const char* newth[] = {
        "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B 4F",
        "40 53 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 4B",
    };
    take(r.lua_newthread, img, sz, newth, 2, L"lua_newthread");

    const char* setro[] = {
        "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 08 84 D2 74 ?? 80 48",
        "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 08 84 D2",
        "40 53 48 83 EC ?? 8B DA 48 8B D1 E8 ?? ?? ?? ?? 80 48 ?? 01",
    };
    take(r.lua_setreadonly, img, sz, setro, 3, L"lua_setreadonly");
}

void scan_task_scheduler(Resolved& r) {
    if (r.task_scheduler || !r.image_base)
        return;
    const char* pats[] = {
        "48 8B 0D ?? ?? ?? ?? 48 8B 81 ?? ?? ?? ?? 48 85 C0 74 ?? 44 8B",
        "48 8B 05 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 0F 10 40",
        "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B ?? 48 85 C0 74 ?? 80",
    };
    for (auto* p : pats) {
        if (auto hit = PatternScanner::find_rip32(r.image_base, r.image_size, p, 3)) {
            r.task_scheduler = hit;
            VT_LOG(L"auto TaskScheduler " + format_hex(hit));
            return;
        }
    }
}

} // namespace

void auto_resolve(Resolved& r) {
    while (!auto_resolve_tick(r)) {
    }
}

bool auto_resolve_tick(Resolved& r) {
    if (r.table.job_start == 0x1D0) {
        r.table.job_start = 0xC8;
        r.table.job_end   = 0xD0;
    }
    if (!r.table.job_name)
        r.table.job_name = 0x18;
    if (!r.task_scheduler && r.table.task_scheduler && r.image_base)
        r.task_scheduler = r.image_base + r.table.task_scheduler;

    if (!r.image_base)
        return true;

    static uintptr_t s_img = 0;
    static int s_step = 0;
    if (s_img != r.image_base) {
        s_img = r.image_base;
        s_step = 0;
    }

    const uintptr_t img = r.image_base;
    const size_t sz = r.image_size;

    switch (s_step++) {
    case 0:
        scan_task_scheduler(r);
        return false;
    case 1: {
        const char* gettop[] = {
            "48 8B 41 ?? 48 2B 41 ?? 48 C1 F8 04 C3",
            "48 8B 41 ?? 48 2B 41 ?? C1 F8 04 C3",
            "48 8B 41 ?? 48 2B 41 ?? 48 D1 F8 C3",
            "48 8B 51 ?? 48 8B 41 ?? 48 2B D0 48 C1 FA 04",
            "48 8B 81 ?? ?? ?? ?? 48 2B 81 ?? ?? ?? ?? 48 C1 F8 04 C3",
        };
        take(r.lua_gettop, img, sz, gettop, 5, L"lua_gettop");
        return false;
    }
    case 2: {
        const char* pcall[] = {
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F2",
            "40 53 56 57 48 83 EC ?? 8B F2 49 8B D8",
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 48 83 EC ?? 8B F2",
            "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F2 49 8B F8",
            "40 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 8B F2",
        };
        take_pcall(r.lua_pcall, img, sz, pcall, 5);
        return false;
    }
    case 3: {
        const char* load[] = {
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 41 8B E9",
            "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
            "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 4D 8B E1",
            "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F9 49 8B F0 48 8B DA E8",
        };
        take(r.luau_load, img, sz, load, 5, L"luau_load");
        return false;
    }
    case 4: {
        const char* settop[] = {
            "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 14 D0 48 3B 51",
            "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 85 D2 78",
            "85 D2 78 ?? 48 8B 41 ?? 48 63 D2 48 C1 E2 04",
        };
        take(r.lua_settop, img, sz, settop, 3, L"lua_settop");
        return false;
    }
    case 5: {
        const char* pushstr[] = {
            "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 48 85 D2",
            "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B D9 48 85 D2 75",
        };
        take(r.lua_pushstring, img, sz, pushstr, 2, L"lua_pushstring");
        const char* pushlstr[] = {
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B E8 48 8B FA",
            "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F0 48 8B FA 48 8B D9",
        };
        take(r.lua_pushlstring, img, sz, pushlstr, 2, L"lua_pushlstring");
        return false;
    }
    default: {
        const bool core = r.luau_load && r.lua_pcall &&
            (r.lua_pushstring || r.lua_pushlstring) &&
            (r.lua_settop || r.lua_gettop);
        if (!core)
            scan_lua_api(r);
        return true;
    }
    }
}

} // namespace vt
