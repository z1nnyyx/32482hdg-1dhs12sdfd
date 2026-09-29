#include "lua/Offsets.h"
#include "lua/Scanner.h"
#include "shared/Log.h"
#include "shared/Utils.h"

namespace vt {
namespace {

uintptr_t abs_or_scan(uintptr_t image, size_t size, uintptr_t rva, const std::string& pat, int rip = 3) {
    if (rva)
        return image + rva;
    if (!pat.empty()) {
        if (auto hit = PatternScanner::find_rip32(image, size, pat, rip))
            return hit;
        if (auto hit = PatternScanner::find(image, size, pat))
            return hit;
    }
    return 0;
}

} // namespace

Resolved& OffsetResolver::current() {
    static Resolved g;
    return g;
}

bool OffsetResolver::resolve(uintptr_t image_base, size_t image_size, const OffsetTable& table) {
    auto& r = current();
    r = {};
    r.image_base = image_base;
    r.image_size = image_size;
    r.table = table;

    r.task_scheduler   = abs_or_scan(image_base, image_size, table.task_scheduler, table.pat_task_scheduler);
    r.luau_load        = abs_or_scan(image_base, image_size, table.luau_load, table.pat_luau_load);
    r.lua_pcall        = abs_or_scan(image_base, image_size, table.lua_pcall, table.pat_lua_pcall);
    r.lua_getfield     = table.lua_getfield     ? image_base + table.lua_getfield     : 0;
    r.lua_setfield     = table.lua_setfield     ? image_base + table.lua_setfield     : 0;
    r.lua_tolstring    = table.lua_tolstring    ? image_base + table.lua_tolstring    : 0;
    r.lua_pushvalue    = table.lua_pushvalue    ? image_base + table.lua_pushvalue    : 0;
    r.lua_pushnil      = table.lua_pushnil      ? image_base + table.lua_pushnil      : 0;
    r.lua_pushnumber   = table.lua_pushnumber   ? image_base + table.lua_pushnumber   : 0;
    r.lua_pushstring   = table.lua_pushstring   ? image_base + table.lua_pushstring   : 0;
    r.lua_pushboolean  = table.lua_pushboolean  ? image_base + table.lua_pushboolean  : 0;
    r.lua_pushcclosure = table.lua_pushcclosure ? image_base + table.lua_pushcclosure : 0;
    r.lua_newthread    = table.lua_newthread    ? image_base + table.lua_newthread    : 0;
    r.lua_settop       = table.lua_settop       ? image_base + table.lua_settop       : 0;
    r.lua_gettop       = table.lua_gettop       ? image_base + table.lua_gettop       : 0;
    r.lua_type         = table.lua_type         ? image_base + table.lua_type         : 0;
    r.lua_createtable  = table.lua_createtable  ? image_base + table.lua_createtable  : 0;
    r.lua_settable     = table.lua_settable     ? image_base + table.lua_settable     : 0;
    r.lua_gettable     = table.lua_gettable     ? image_base + table.lua_gettable     : 0;
    r.lua_newuserdata  = table.lua_newuserdata  ? image_base + table.lua_newuserdata  : 0;
    r.lua_setmetatable = table.lua_setmetatable ? image_base + table.lua_setmetatable : 0;
    r.lua_getmetatable = table.lua_getmetatable ? image_base + table.lua_getmetatable : 0;
    r.lua_toboolean    = table.lua_toboolean    ? image_base + table.lua_toboolean    : 0;
    r.lua_tonumber     = table.lua_tonumber     ? image_base + table.lua_tonumber     : 0;
    r.lua_pushlstring  = table.lua_pushlstring  ? image_base + table.lua_pushlstring  : 0;
    r.lua_xmove        = table.lua_xmove        ? image_base + table.lua_xmove        : 0;
    r.lua_touserdata   = table.lua_touserdata   ? image_base + table.lua_touserdata   : 0;
    r.lua_rawgeti      = table.lua_rawgeti      ? image_base + table.lua_rawgeti      : 0;
    r.lua_rawseti      = table.lua_rawseti      ? image_base + table.lua_rawseti      : 0;
    r.lua_next         = table.lua_next         ? image_base + table.lua_next         : 0;
    r.lua_objlen       = table.lua_objlen       ? image_base + table.lua_objlen       : 0;
    r.lua_insert       = table.lua_insert       ? image_base + table.lua_insert       : 0;
    r.lua_remove       = table.lua_remove       ? image_base + table.lua_remove       : 0;
    r.lua_pushthread   = table.lua_pushthread   ? image_base + table.lua_pushthread   : 0;
    r.lua_setreadonly  = table.lua_setreadonly  ? image_base + table.lua_setreadonly  : 0;

    VT_LOG(L"Resolved image " + format_hex(image_base) + L" size " + format_hex(image_size));
    VT_LOG(L"  TaskScheduler " + format_hex(r.task_scheduler));
    VT_LOG(L"  luau_load     " + format_hex(r.luau_load));
    VT_LOG(L"  lua_pcall     " + format_hex(r.lua_pcall));
    return r.usable();
}

} // namespace vt
