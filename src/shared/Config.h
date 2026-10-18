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
    uintptr_t live_datamodel = 0;         // Direct heap address (from job walk)
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

    // IDA-style patterns used when RVAs are 0
    std::string pat_task_scheduler;
    std::string pat_luau_load;
    std::string pat_lua_pcall;
};

struct AppConfig {
    std::wstring process_name = L"RobloxPlayerBeta.exe";
    std::wstring pipe_name    = L"\\\\.\\pipe\\crashpad_44182_dmp";
    bool auto_attach          = false;
    bool auto_inject          = true;
    bool auto_exec_on_inject  = true;
    int  attach_poll_ms       = 750;
    // When true, ProcessFinder looks for the UWP (Microsoft Store) Roblox
    // install path only: %LOCALAPPDATA%\Packages\ROBLOXCORPORATION.ROBLOX_*\.
    // That build does NOT ship Hyperion's kernel driver (Store app policy),
    // so standard user-mode primitives work. This is the trick behind every
    // "it just works" open-source executor (Xeno, Celery, Electron, etc.).
    bool uwp_mode             = true;
    // When true, target Roblox Studio instead of the Player. Studio ships
    // no Hyperion component at all — every injection primitive just works.
    // Takes precedence over uwp_mode when set.
    bool studio_mode          = false;
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
