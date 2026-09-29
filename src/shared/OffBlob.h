#pragma once

#include <cstdint>

// Host patches this export in the mapped image so the module never reads
// offsets.json (AppContainer cannot see our LocalAppData file) and never
// pattern-scans 100MB of Roblox from PeekMessage.
#pragma pack(push, 1)
struct VTOffBlob {
    char     mag[8];
    uint64_t task_scheduler;
    uint64_t job_name;
    uint64_t job_start;
    uint64_t job_end;
    uint64_t script_context;
    uint64_t extra_space;
    uint64_t lua_state;
    uint64_t identity;
    uint64_t luau_load;
    uint64_t lua_pcall;
    uint64_t lua_gettop;
    uint64_t lua_settop;
    uint64_t lua_pushstring;
    uint64_t lua_pushlstring;
    uint64_t lua_pushcclosure;
    uint64_t lua_tolstring;
    uint64_t lua_pushnil;
    uint64_t lua_pushnumber;
    uint64_t lua_pushboolean;
    uint64_t lua_type;
    uint64_t lua_getfield;
    uint64_t lua_setfield;
    uint64_t lua_createtable;
    uint64_t lua_setreadonly;
    uint64_t lua_newthread;
    uint64_t lua_pushvalue;
    uint64_t cfg_gadget;
    uint32_t cfg_disp;
    uint32_t cfg_via_rax;
};
#pragma pack(pop)
