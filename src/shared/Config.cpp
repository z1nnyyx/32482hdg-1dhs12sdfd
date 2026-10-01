#include "shared/Config.h"
#include "shared/Utils.h"
#include "shared/Log.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace vt {
namespace {

// Tiny JSON subset: "key": number | "string"
// Enough for offsets.json without pulling nlohmann.
std::string extract_string(const std::string& json, const char* key) {
    const std::string pat = std::string("\"") + key + "\"";
    auto pos = json.find(pat);
    if (pos == std::string::npos)
        return {};
    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return {};
    pos = json.find('"', pos);
    if (pos == std::string::npos)
        return {};
    const auto end = json.find('"', pos + 1);
    if (end == std::string::npos)
        return {};
    return json.substr(pos + 1, end - pos - 1);
}

uintptr_t extract_hex(const std::string& json, const char* key, uintptr_t fallback = 0) {
    const std::string pat = std::string("\"") + key + "\"";
    auto pos = json.find(pat);
    if (pos == std::string::npos)
        return fallback;
    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return fallback;
    ++pos;
    while (pos < json.size() && std::isspace((unsigned char)json[pos]))
        ++pos;
    if (pos + 1 < json.size() && json[pos] == '0' && (json[pos + 1] == 'x' || json[pos + 1] == 'X'))
        return (uintptr_t)std::strtoull(json.c_str() + pos, nullptr, 16);
    if (pos < json.size() && (std::isdigit((unsigned char)json[pos]) || json[pos] == '-'))
        return (uintptr_t)std::strtoull(json.c_str() + pos, nullptr, 10);
    if (pos < json.size() && json[pos] == '"')
        return (uintptr_t)std::strtoull(json.c_str() + pos + 1, nullptr, 0);
    return fallback;
}

bool extract_bool(const std::string& json, const char* key, bool fallback) {
    const std::string pat = std::string("\"") + key + "\"";
    auto pos = json.find(pat);
    if (pos == std::string::npos)
        return fallback;
    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return fallback;
    const auto rest = json.substr(pos + 1, 16);
    if (rest.find("true") != std::string::npos)
        return true;
    if (rest.find("false") != std::string::npos)
        return false;
    return fallback;
}

} // namespace

Config& Config::instance() {
    static Config g;
    return g;
}

bool Config::load(const std::filesystem::path& file) {
    const auto json = read_file_utf8(file);
    if (json.empty()) {
        VT_WARN(L"offsets.json missing or empty — using compiled defaults (will not execute until updated)");
        return false;
    }

    auto& o = cfg_.offsets;
    o.roblox_version   = extract_string(json, "roblox_version");
    o.task_scheduler   = extract_hex(json, "task_scheduler");
    o.job_name         = extract_hex(json, "job_name", o.job_name);
    o.job_start        = extract_hex(json, "job_start", o.job_start);
    o.job_end          = extract_hex(json, "job_end", o.job_end);
    o.script_context   = extract_hex(json, "script_context");
    o.extra_space      = extract_hex(json, "extra_space", o.extra_space);
    o.lua_state        = extract_hex(json, "lua_state", o.lua_state);
    o.luau_load        = extract_hex(json, "luau_load");
    o.lua_pcall        = extract_hex(json, "lua_pcall");
    o.lua_getfield     = extract_hex(json, "lua_getfield");
    o.lua_setfield     = extract_hex(json, "lua_setfield");
    o.lua_tolstring    = extract_hex(json, "lua_tolstring");
    o.lua_pushvalue    = extract_hex(json, "lua_pushvalue");
    o.lua_pushnil      = extract_hex(json, "lua_pushnil");
    o.lua_pushnumber   = extract_hex(json, "lua_pushnumber");
    o.lua_pushstring   = extract_hex(json, "lua_pushstring");
    o.lua_pushboolean  = extract_hex(json, "lua_pushboolean");
    o.lua_pushcclosure = extract_hex(json, "lua_pushcclosure");
    o.lua_newthread    = extract_hex(json, "lua_newthread");
    o.lua_settop       = extract_hex(json, "lua_settop");
    o.lua_gettop       = extract_hex(json, "lua_gettop");
    o.lua_type         = extract_hex(json, "lua_type");
    o.lua_createtable  = extract_hex(json, "lua_createtable");
    o.lua_settable     = extract_hex(json, "lua_settable");
    o.lua_gettable     = extract_hex(json, "lua_gettable");
    o.lua_newuserdata  = extract_hex(json, "lua_newuserdata");
    o.lua_setmetatable = extract_hex(json, "lua_setmetatable");
    o.lua_getmetatable = extract_hex(json, "lua_getmetatable");
    o.lua_toboolean    = extract_hex(json, "lua_toboolean");
    o.lua_tonumber     = extract_hex(json, "lua_tonumber");
    o.lua_pushlstring  = extract_hex(json, "lua_pushlstring");
    o.lua_xmove        = extract_hex(json, "lua_xmove");
    o.lua_setreadonly  = extract_hex(json, "lua_setreadonly");
    o.identity         = extract_hex(json, "identity", o.identity);
    o.fake_datamodel   = extract_hex(json, "fake_datamodel", o.fake_datamodel);
    o.visual_engine    = extract_hex(json, "visual_engine", o.visual_engine);
    o.fake_dm_off      = extract_hex(json, "fake_dm_off", o.fake_dm_off);
    o.child_off        = extract_hex(json, "child_off", o.child_off);
    o.name_off         = extract_hex(json, "name_off", o.name_off);
    o.class_desc       = extract_hex(json, "class_desc", o.class_desc);
    o.character        = extract_hex(json, "character", o.character);
    o.local_player     = extract_hex(json, "local_player", o.local_player);
    o.primitive        = extract_hex(json, "primitive", o.primitive);
    o.position         = extract_hex(json, "position", o.position);
    o.view_matrix      = extract_hex(json, "view_matrix", o.view_matrix);
    o.humanoid_hp      = extract_hex(json, "humanoid_hp", o.humanoid_hp);
    o.humanoid_maxhp   = extract_hex(json, "humanoid_maxhp", o.humanoid_maxhp);
    o.root_part        = extract_hex(json, "root_part", o.root_part);
    o.pat_task_scheduler = extract_string(json, "pat_task_scheduler");
    o.pat_luau_load      = extract_string(json, "pat_luau_load");
    o.pat_lua_pcall      = extract_string(json, "pat_lua_pcall");

    cfg_.auto_attach  = extract_bool(json, "auto_attach", cfg_.auto_attach);
    cfg_.auto_inject  = extract_bool(json, "auto_inject", cfg_.auto_inject);
    cfg_.uwp_mode     = extract_bool(json, "uwp_mode",    cfg_.uwp_mode);

    VT_LOG(L"Loaded offsets for " + utf8_to_wide(o.roblox_version.empty() ? "unknown" : o.roblox_version));
    return true;
}

bool Config::save(const std::filesystem::path& file) const {
    const auto& o = cfg_.offsets;
    auto hx = [](uintptr_t v) {
        std::ostringstream s;
        s << "0x" << std::hex << std::uppercase << v;
        return s.str();
    };
    std::ostringstream ss;
    ss << "{\n"
       << "  \"roblox_version\": \"" << o.roblox_version << "\",\n"
       << "  \"auto_attach\": " << (cfg_.auto_attach ? "true" : "false") << ",\n"
       << "  \"auto_inject\": " << (cfg_.auto_inject ? "true" : "false") << ",\n"
       << "  \"uwp_mode\": "    << (cfg_.uwp_mode    ? "true" : "false") << ",\n"
       << "  \"task_scheduler\": \"" << hx(o.task_scheduler) << "\",\n"
       << "  \"job_name\": \"" << hx(o.job_name) << "\",\n"
       << "  \"job_start\": \"" << hx(o.job_start) << "\",\n"
       << "  \"job_end\": \"" << hx(o.job_end) << "\",\n"
       << "  \"extra_space\": \"" << hx(o.extra_space) << "\",\n"
       << "  \"lua_state\": \"" << hx(o.lua_state) << "\",\n"
       << "  \"identity\": \"" << hx(o.identity) << "\",\n"
       << "  \"luau_load\": \"" << hx(o.luau_load) << "\",\n"
       << "  \"lua_pcall\": \"" << hx(o.lua_pcall) << "\",\n"
       << "  \"lua_gettop\": \"" << hx(o.lua_gettop) << "\",\n"
       << "  \"lua_settop\": \"" << hx(o.lua_settop) << "\",\n"
       << "  \"lua_type\": \"" << hx(o.lua_type) << "\",\n"
       << "  \"lua_pushnil\": \"" << hx(o.lua_pushnil) << "\",\n"
       << "  \"lua_pushnumber\": \"" << hx(o.lua_pushnumber) << "\",\n"
       << "  \"lua_pushboolean\": \"" << hx(o.lua_pushboolean) << "\",\n"
       << "  \"lua_pushstring\": \"" << hx(o.lua_pushstring) << "\",\n"
       << "  \"lua_pushvalue\": \"" << hx(o.lua_pushvalue) << "\",\n"
       << "  \"lua_pushcclosure\": \"" << hx(o.lua_pushcclosure) << "\",\n"
       << "  \"lua_createtable\": \"" << hx(o.lua_createtable) << "\",\n"
       << "  \"lua_tolstring\": \"" << hx(o.lua_tolstring) << "\",\n"
       << "  \"fake_datamodel\": \"" << hx(o.fake_datamodel) << "\",\n"
       << "  \"visual_engine\": \"" << hx(o.visual_engine) << "\",\n"
       << "  \"fake_dm_off\": \"" << hx(o.fake_dm_off) << "\",\n"
       << "  \"child_off\": \"" << hx(o.child_off) << "\",\n"
       << "  \"name_off\": \"" << hx(o.name_off) << "\",\n"
       << "  \"class_desc\": \"" << hx(o.class_desc) << "\",\n"
       << "  \"character\": \"" << hx(o.character) << "\",\n"
       << "  \"local_player\": \"" << hx(o.local_player) << "\",\n"
       << "  \"primitive\": \"" << hx(o.primitive) << "\",\n"
       << "  \"position\": \"" << hx(o.position) << "\",\n"
       << "  \"view_matrix\": \"" << hx(o.view_matrix) << "\"\n"
       << "}\n";
    return write_file_utf8(file, ss.str());
}

} // namespace vt
