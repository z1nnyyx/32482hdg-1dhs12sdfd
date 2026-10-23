#include "lua/AutoResolve.h"
#include "lua/Scanner.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <Windows.h>
#include <cstring>
#include <cstddef>

namespace vt {
namespace {

// --- byte sanity helpers -----------------------------------------------------

bool safe_read(uintptr_t p, void* dst, size_t n) {
    __try {
        memcpy(dst, (const void*)p, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Accepts common x64 prologue first bytes. Rejects data / padding.
bool looks_code(uintptr_t p) {
    uint8_t b = 0;
    if (!safe_read(p, &b, 1))
        return false;
    switch (b) {
    case 0x40: case 0x41: case 0x44: case 0x48: case 0x4C: case 0x4D:
    case 0x53: case 0x55: case 0x56: case 0x57:
    case 0x8B: case 0x85: case 0xFF: case 0xE9:
        return true;
    }
    return false;
}

bool bytes_has(uintptr_t fn, size_t scan_len, const uint8_t* seq, size_t sn) {
    uint8_t buf[256]{};
    if (scan_len > sizeof(buf))
        scan_len = sizeof(buf);
    if (!safe_read(fn, buf, scan_len))
        return false;
    for (size_t i = 0; i + sn <= scan_len; ++i) {
        if (memcmp(buf + i, seq, sn) == 0)
            return true;
    }
    return false;
}

// --- validators --------------------------------------------------------------

bool validate_default(uintptr_t fn) {
    return looks_code(fn);
}

// pcall takes (L, nargs=edx, nresults, errfunc). Prologue should move edx and
// read L->top (first qword of a user-usable field). Accepts the common forms.
bool validate_pcall(uintptr_t fn) {
    if (!looks_code(fn))
        return false;
    const uint8_t nargs_esi[] = {0x8B, 0xF2};  // mov esi, edx
    const uint8_t nargs_edi[] = {0x8B, 0xFA};  // mov edi, edx
    const uint8_t nargs_ebx[] = {0x8B, 0xDA};  // mov ebx, edx
    const uint8_t top18[]     = {0x48, 0x8B, 0x41, 0x18};
    const uint8_t top20[]     = {0x48, 0x8B, 0x41, 0x20};
    const uint8_t top10[]     = {0x48, 0x8B, 0x41, 0x10};
    const bool saves_nargs =
        bytes_has(fn, 0xC0, nargs_esi, 2) ||
        bytes_has(fn, 0xC0, nargs_edi, 2) ||
        bytes_has(fn, 0xC0, nargs_ebx, 2);
    const bool reads_top =
        bytes_has(fn, 0xC0, top18, 4) ||
        bytes_has(fn, 0xC0, top20, 4) ||
        bytes_has(fn, 0xC0, top10, 4);
    return saves_nargs && reads_top;
}

// --- pattern iteration -------------------------------------------------------

using Patterns = const char* const*;

uintptr_t first_match(uintptr_t image, size_t size, Patterns pats, int n,
                      bool (*validate)(uintptr_t)) {
    for (int i = 0; i < n; ++i) {
        if (!pats[i] || !pats[i][0])
            continue;
        // Walk every match; some pattern families collide with data or thunks.
        uintptr_t cur = image;
        const uintptr_t end = image + size;
        for (int attempt = 0; attempt < 6 && cur + 16 < end; ++attempt) {
            const uintptr_t hit = PatternScanner::find(cur, end - cur, pats[i]);
            if (!hit)
                break;
            if (validate(hit))
                return hit;
            cur = hit + 1;
        }
    }
    return 0;
}

// --- API table ---------------------------------------------------------------

struct ApiEntry {
    uintptr_t Resolved::* slot;
    std::string OffsetTable::* user_pat;  // optional user pattern in offsets.json
    const wchar_t* name;
    const char* const* pats;
    int pat_count;
    bool (*validate)(uintptr_t);
};

// Pattern groups. One per API.

static const char* P_gettop[] = {
    "48 8B 41 ?? 48 2B 41 ?? 48 C1 F8 04 C3",
    "48 8B 41 ?? 48 2B 41 ?? C1 F8 04 C3",
    "48 8B 41 ?? 48 2B 41 ?? 48 D1 F8 C3",
    "48 8B 51 ?? 48 8B 41 ?? 48 2B D0 48 C1 FA 04",
    "48 8B 81 ?? ?? ?? ?? 48 2B 81 ?? ?? ?? ?? 48 C1 F8 04 C3",
    "48 8B 41 ?? 48 2B 41 ?? 48 C1 F8 04 48 98 C3",
};
static const char* P_settop[] = {
    "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 14 D0 48 3B 51",
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 85 D2 78",
    "85 D2 78 ?? 48 8B 41 ?? 48 63 D2 48 C1 E2 04",
};
static const char* P_type[] = {
    "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 44 D0 F0 8B 40 0C",
    "85 D2 7E ?? 48 8B 41 ?? 4C 63 C2 49 C1 E0 04 4C 03 C0",
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 85 D2 7E ?? 48 8B 41",
};
static const char* P_pushnil[] = {
    "48 8B 41 ?? 48 C7 00 00 00 00 00 48 83 41 ?? 10",
    "48 8B 41 ?? C7 40 0C 00 00 00 00 48 83 41 ?? 10",
    "48 8B 41 ?? 48 C7 00 00 00 00 00 C7 40 0C 00 00 00 00 48 83 41 ?? 10",
};
static const char* P_pushnum[] = {
    "48 8B 41 ?? F2 0F 11 00 C7 40 0C 03 00 00 00 48 83 41 ?? 10",
    "48 8B 41 ?? F2 0F 11 00 C7 40 08 03 00 00 00 48 83 41 ?? 10",
    "48 8B 41 ?? 66 0F D6 00 C7 40 0C 03 00 00 00",
};
static const char* P_pushbool[] = {
    "48 8B 41 ?? 89 10 C7 40 0C 01 00 00 00 48 83 41 ?? 10",
    "48 8B 41 ?? 89 10 C7 40 08 01 00 00 00 48 83 41 ?? 10",
};
static const char* P_pushval[] = {
    "48 8B 41 ?? 4C 8B C9 85 D2 7E ?? 48 63 D2 48 8D 14 D0 48 3B",
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 4F",
};
static const char* P_pushstr[] = {
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B F1 48 85 D2",
    "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B FA 48 8B D9 48 85 D2 75",
};
static const char* P_pushlstr[] = {
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B E8 48 8B FA",
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F0 48 8B FA 48 8B D9",
};
static const char* P_pushcc[] = {
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 4D 8B F9 49 8B F0",
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 4C 8B FA 4C 8B F1",
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 48 83 EC ?? 4D 8B F1 49 8B F0 48 8B EA",
    "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1 4C 8B EA 4C 8B F1",
};
static const char* P_createt[] = {
    "48 89 5C 24 ?? 48 89 6C 24 ?? 56 57 41 56 48 83 EC ?? 41 8B F0 8B EA 48 8B F9",
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 48 83 EC ?? 8B F2 49 8B F8",
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 4F ?? 45 33 C0",
};
static const char* P_getfield[] = {
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F0 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B D6",
    "48 89 5C 24 ?? 57 48 83 EC ?? 49 8B D8 48 8B F9 8B D2 E8 ?? ?? ?? ?? 48 8B D3 E8",
};
static const char* P_setfield[] = {
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F0 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B D6 E8",
    "48 89 5C 24 ?? 57 48 83 EC ?? 49 8B D8 8B FA 48 8B E9 E8 ?? ?? ?? ?? 48 8B D3",
};
static const char* P_gettable[] = {
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 57 F0",
    "40 53 48 83 EC ?? 8B DA 48 8B D1 E8 ?? ?? ?? ?? 48 8B 48",
};
static const char* P_settable[] = {
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 57 E0",
    "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 48 ?? 48 8B 53",
};
static const char* P_newud[] = {
    "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 4F",
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B F2 48 8B F9 48 83 FA",
};
static const char* P_setmt[] = {
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 4F ?? 48 85 C9",
    "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 08 48 85 C9 74",
};
static const char* P_getmt[] = {
    "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 08 48 85 C9 74 ?? 48 8B 41",
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 08",
};
static const char* P_tolstr[] = {
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F8 8B DA 48 8B F1",
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B E8 8B DA",
};
static const char* P_tobool[] = {
    "85 D2 7E ?? 48 8B 41 ?? 48 63 D2 48 8D 44 D0 F0 83 78 0C 01",
    "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 83 78 0C 00 74",
};
static const char* P_tonum[] = {
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 83 78 0C 03",
    "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 83 78 0C 03 75",
};
static const char* P_touser[] = {
    "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 83 78 0C 08 75 ?? 48 8B 00",
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 83 78 0C 08",
};
static const char* P_newth[] = {
    "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 ?? 48 8B 4F",
    "40 53 48 83 EC ?? 48 8B D9 E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 4B",
};
static const char* P_setro[] = {
    "40 53 48 83 EC ?? 8B DA E8 ?? ?? ?? ?? 48 8B 08 84 D2 74 ?? 80 48",
    "48 89 5C 24 ?? 57 48 83 EC ?? 8B DA 48 8B F9 E8 ?? ?? ?? ?? 48 8B 08 84 D2",
    "40 53 48 83 EC ?? 8B DA 48 8B D1 E8 ?? ?? ?? ?? 80 48 ?? 01",
};
static const char* P_pcall[] = {
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F2",
    "40 53 56 57 48 83 EC ?? 8B F2 49 8B D8",
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 48 83 EC ?? 8B F2",
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 8B F2 49 8B F8",
    "40 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 8B F2",
};
static const char* P_load[] = {
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ?? 41 8B E9",
    "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
    "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 83 EC ?? 4D 8B E1",
    "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 4D 8B E1",
    "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F9 49 8B F0 48 8B DA E8",
};

#define VT_WIDE2(x) L##x
#define VT_WIDE(x)  VT_WIDE2(x)
#define API(slot, user, name, pats, validator) \
    { &Resolved::slot, &OffsetTable::user, VT_WIDE(#slot), pats, (int)(sizeof(pats)/sizeof(pats[0])), validator }

static const ApiEntry kApiTable[] = {
    API(lua_gettop,       pat_lua_gettop,       lua_gettop,       P_gettop,    validate_default),
    API(lua_settop,       pat_lua_settop,       lua_settop,       P_settop,    validate_default),
    API(lua_type,         pat_lua_type,         lua_type,         P_type,      validate_default),
    API(lua_pcall,        pat_lua_pcall,        lua_pcall,        P_pcall,     validate_pcall),
    API(luau_load,        pat_luau_load,        luau_load,        P_load,      validate_default),
    API(lua_pushnil,      pat_lua_pushnil,      lua_pushnil,      P_pushnil,   validate_default),
    API(lua_pushnumber,   pat_lua_pushnumber,   lua_pushnumber,   P_pushnum,   validate_default),
    API(lua_pushboolean,  pat_lua_pushboolean,  lua_pushboolean,  P_pushbool,  validate_default),
    API(lua_pushvalue,    pat_lua_pushvalue,    lua_pushvalue,    P_pushval,   validate_default),
    API(lua_pushstring,   pat_lua_pushstring,   lua_pushstring,   P_pushstr,   validate_default),
    API(lua_pushlstring,  pat_lua_pushlstring,  lua_pushlstring,  P_pushlstr,  validate_default),
    API(lua_pushcclosure, pat_lua_pushcclosure, lua_pushcclosure, P_pushcc,    validate_default),
    API(lua_createtable,  pat_lua_createtable,  lua_createtable,  P_createt,   validate_default),
    API(lua_getfield,     pat_lua_getfield,     lua_getfield,     P_getfield,  validate_default),
    API(lua_setfield,     pat_lua_setfield,     lua_setfield,     P_setfield,  validate_default),
    API(lua_gettable,     pat_lua_gettable,     lua_gettable,     P_gettable,  validate_default),
    API(lua_settable,     pat_lua_settable,     lua_settable,     P_settable,  validate_default),
    API(lua_newuserdata,  pat_lua_newuserdata,  lua_newuserdata,  P_newud,     validate_default),
    API(lua_setmetatable, pat_lua_setmetatable, lua_setmetatable, P_setmt,     validate_default),
    API(lua_getmetatable, pat_lua_getmetatable, lua_getmetatable, P_getmt,     validate_default),
    API(lua_tolstring,    pat_lua_tolstring,    lua_tolstring,    P_tolstr,    validate_default),
    API(lua_toboolean,    pat_lua_toboolean,    lua_toboolean,    P_tobool,    validate_default),
    API(lua_tonumber,     pat_lua_tonumber,     lua_tonumber,     P_tonum,     validate_default),
    API(lua_touserdata,   pat_lua_touserdata,   lua_touserdata,   P_touser,    validate_default),
    API(lua_newthread,    pat_lua_newthread,    lua_newthread,    P_newth,     validate_default),
    API(lua_setreadonly,  pat_lua_setreadonly,  lua_setreadonly,  P_setro,     validate_default),
};
static constexpr int kApiCount = (int)(sizeof(kApiTable) / sizeof(kApiTable[0]));

// --- resolver steps ----------------------------------------------------------

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

bool try_user_pattern(Resolved& r, const ApiEntry& e) {
    const auto& user = r.table.*(e.user_pat);
    if (user.empty())
        return false;
    const uintptr_t img = r.image_base;
    const size_t sz = r.image_size;
    uintptr_t cur = img;
    const uintptr_t end = img + sz;
    for (int attempt = 0; attempt < 6 && cur + 16 < end; ++attempt) {
        const uintptr_t hit = PatternScanner::find(cur, end - cur, user);
        if (!hit)
            return false;
        if (e.validate(hit)) {
            r.*(e.slot) = hit;
            VT_LOG(std::wstring(L"user ") + e.name + L" " + format_hex(hit));
            return true;
        }
        cur = hit + 1;
    }
    return false;
}

void resolve_one(Resolved& r, const ApiEntry& e) {
    if (r.*(e.slot))
        return;
    if (try_user_pattern(r, e))
        return;
    const uintptr_t hit = first_match(r.image_base, r.image_size, e.pats, e.pat_count, e.validate);
    if (!hit)
        return;
    r.*(e.slot) = hit;
    VT_LOG(std::wstring(L"auto ") + e.name + L" " + format_hex(hit));
}

void log_summary(const Resolved& r) {
    int have = 0, miss = 0;
    std::wstring missing;
    for (int i = 0; i < kApiCount; ++i) {
        if (r.*(kApiTable[i].slot))
            ++have;
        else {
            ++miss;
            if (!missing.empty())
                missing += L", ";
            missing += kApiTable[i].name;
        }
    }
    VT_LOG(L"AutoResolve: " + std::to_wstring(have) + L"/" + std::to_wstring(kApiCount) + L" Lua C API bound");
    if (miss) {
        VT_WARN(L"AutoResolve missing: " + missing);
        VT_WARN(L"  Paste IDA-style patterns into offsets.json under pat_<name> to force resolve.");
    }
    if (!r.task_scheduler)
        VT_WARN(L"AutoResolve: TaskScheduler unresolved — set task_scheduler RVA or pat_task_scheduler");
}

} // namespace

void auto_resolve(Resolved& r) {
    while (!auto_resolve_tick(r)) {
    }
}

bool auto_resolve_tick(Resolved& r) {
    // Fix up structure offsets once per image.
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

    // Step 0: TaskScheduler. Steps 1..kApiCount: one API per tick.
    // Final step: summary + done.
    if (s_step == 0) {
        scan_task_scheduler(r);
        ++s_step;
        return false;
    }
    const int idx = s_step - 1;
    if (idx < kApiCount) {
        resolve_one(r, kApiTable[idx]);
        ++s_step;
        return false;
    }
    log_summary(r);
    return true;
}

} // namespace vt
