#pragma once

#include "shared/Config.h"

#include <cstdint>

namespace vt {

// Resolved addresses (base + RVA) used by the injected module.
struct Resolved {
    uintptr_t image_base = 0;
    size_t    image_size = 0;

    uintptr_t task_scheduler = 0;
    uintptr_t luau_load = 0;
    uintptr_t lua_pcall = 0;
    uintptr_t lua_getfield = 0;
    uintptr_t lua_setfield = 0;
    uintptr_t lua_tolstring = 0;
    uintptr_t lua_pushvalue = 0;
    uintptr_t lua_pushnil = 0;
    uintptr_t lua_pushnumber = 0;
    uintptr_t lua_pushstring = 0;
    uintptr_t lua_pushboolean = 0;
    uintptr_t lua_pushcclosure = 0;
    uintptr_t lua_newthread = 0;
    uintptr_t lua_settop = 0;
    uintptr_t lua_gettop = 0;
    uintptr_t lua_type = 0;
    uintptr_t lua_createtable = 0;
    uintptr_t lua_settable = 0;
    uintptr_t lua_gettable = 0;
    uintptr_t lua_newuserdata = 0;
    uintptr_t lua_setmetatable = 0;
    uintptr_t lua_getmetatable = 0;
    uintptr_t lua_toboolean = 0;
    uintptr_t lua_tonumber = 0;
    uintptr_t lua_pushlstring = 0;
    uintptr_t lua_xmove = 0;
    uintptr_t lua_touserdata = 0;
    uintptr_t lua_rawgeti = 0;
    uintptr_t lua_rawseti = 0;
    uintptr_t lua_next = 0;
    uintptr_t lua_objlen = 0;
    uintptr_t lua_insert = 0;
    uintptr_t lua_remove = 0;
    uintptr_t lua_pushthread = 0;
    uintptr_t lua_setreadonly = 0;

    OffsetTable table;
    bool usable() const { return image_base && (luau_load || lua_pcall); }
};

class OffsetResolver {
public:
    static Resolved& current();
    static bool resolve(uintptr_t image_base, size_t image_size, const OffsetTable& table);
};

} // namespace vt
