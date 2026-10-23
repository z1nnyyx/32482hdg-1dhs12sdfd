#pragma once

#include <string>
#include <filesystem>
#include <cstdint>

namespace vt {

// All RVAs / offsets are version-dependent. Roblox ships weekly.
// Put live values in config/offsets.json next to the exe.
struct OffsetTable {
    std::string roblox_version;          // e.g. "version-xxxxxxxx"
    uintptr_t   task_scheduler = 0;      // RVA
    uintptr_t   job_name       = 0x18;   // Job* + this -> std::string name
    uintptr_t   job_start      = 0xC8;   // 2026 TaskScheduler job list
    uintptr_t   job_end        = 0xD0;
    uintptr_t   script_context = 0;      // ScriptContext* from WaitingHybridScriptsJob
    uintptr_t   extra_space    = 0x78;   // ScriptContext extra space -> lua_State*
    uintptr_t   lua_state      = 0x110;

    // Luau C API RVAs (from RobloxPlayerBeta.exe)
    uintptr_t luau_load      = 0;
    uintptr_t lua_pcall      = 0;
    uintptr_t lua_getfield   = 0;
    uintptr_t lua_setfield   = 0;
    uintptr_t lua_getglobal  = 0; // often lua_getfield(L, LUA_GLOBALSINDEX, name)
    uintptr_t lua_setglobal  = 0;
    uintptr_t lua_tolstring  = 0;
    uintptr_t lua_touserdata = 0;
    uintptr_t lua_pushvalue  = 0;
    uintptr_t lua_pushnil    = 0;
    uintptr_t lua_pushnumber = 0;
    uintptr_t lua_pushstring = 0;
    uintptr_t lua_pushboolean= 0;
    uintptr_t lua_pushcclosure = 0;
    uintptr_t lua_newthread  = 0;
    uintptr_t lua_rawgeti    = 0;
    uintptr_t lua_rawseti    = 0;
    uintptr_t lua_settop     = 0;
    uintptr_t lua_gettop     = 0;
    uintptr_t lua_type       = 0;
    uintptr_t lua_settable   = 0;
    uintptr_t lua_gettable   = 0;
    uintptr_t lua_createtable= 0;
    uintptr_t lua_insert     = 0;
    uintptr_t lua_remove     = 0;
    uintptr_t lua_newuserdata= 0;
    uintptr_t lua_setmetatable = 0;
    uintptr_t lua_getmetatable = 0;
    uintptr_t lua_toboolean  = 0;
    uintptr_t lua_tonumber   = 0;
    uintptr_t lua_objlen     = 0;
    uintptr_t lua_next       = 0;
    uintptr_t lua_pushlstring= 0;
    uintptr_t lua_pushthread = 0;
    uintptr_t lua_xmove      = 0;
    uintptr_t lua_refcount   = 0; // extra space / identity
    uintptr_t identity       = 0x30;
    uintptr_t lua_setreadonly = 0;

    // External world / overlay (RVAs + structure offsets). Tried first, then fallbacks.
    uintptr_t fake_datamodel = 0x8B79B58;
    uintptr_t visual_engine  = 0x8136228;
    uintptr_t fake_dm_off    = 0x1D8;
    uintptr_t child_off      = 0x78;
    uintptr_t name_off       = 0x70;
    uintptr_t class_desc     = 0x18;
    uintptr_t character      = 0x298;
    uintptr_t local_player   = 0x130;
    uintptr_t primitive      = 0x188;
    uintptr_t position       = 0xEC;
    uintptr_t view_matrix    = 0x180;
    uintptr_t humanoid_hp    = 0x190;
    uintptr_t humanoid_maxhp = 0x1A8;
    uintptr_t root_part      = 0x258;

    // IDA-style patterns used when RVAs are 0. Any pat_<name> that is set wins
    // over the built-in heuristics in AutoResolve — paste one from IDA after a
    // Roblox update to force-resolve a stubborn API without a rebuild.
    std::string pat_task_scheduler;
    std::string pat_luau_load;
    std::string pat_lua_pcall;
    std::string pat_lua_gettop;
    std::string pat_lua_settop;
    std::string pat_lua_type;
    std::string pat_lua_pushnil;
    std::string pat_lua_pushnumber;
    std::string pat_lua_pushboolean;
    std::string pat_lua_pushvalue;
    std::string pat_lua_pushstring;
    std::string pat_lua_pushlstring;
    std::string pat_lua_pushcclosure;
    std::string pat_lua_createtable;
    std::string pat_lua_getfield;
    std::string pat_lua_setfield;
    std::string pat_lua_gettable;
    std::string pat_lua_settable;
    std::string pat_lua_newuserdata;
    std::string pat_lua_setmetatable;
    std::string pat_lua_getmetatable;
    std::string pat_lua_tolstring;
    std::string pat_lua_toboolean;
    std::string pat_lua_tonumber;
    std::string pat_lua_touserdata;
    std::string pat_lua_newthread;
    std::string pat_lua_setreadonly;
};

struct AppConfig {
    std::wstring process_name = L"RobloxPlayerBeta.exe";
    std::wstring pipe_name    = L"\\\\.\\pipe\\crashpad_44182_dmp";
    bool auto_attach          = false;
    bool auto_inject          = true;
    bool auto_exec_on_inject  = true;
    int  attach_poll_ms       = 750;
    OffsetTable offsets;
};

class Config {
public:
    static Config& instance();

    bool load(const std::filesystem::path& file);
    bool save(const std::filesystem::path& file) const;

    AppConfig& get() { return cfg_; }
    const AppConfig& get() const { return cfg_; }

private:
    AppConfig cfg_;
};

} // namespace vt
