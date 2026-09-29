#include "lua/libs/Filesystem.h"
#include "shared/Utils.h"

#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <vector>

namespace vt::libs {
namespace fs = std::filesystem;

static fs::path workspace() {
    auto dir = data_root() / "workspace";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

static fs::path safe_join(const char* rel) {
    auto root = workspace().lexically_normal();
    auto p = (root / (rel ? rel : "")).lexically_normal();
    auto rel_to = p.lexically_relative(root);
    if (rel_to.empty() || *rel_to.begin() == "..")
        return {};
    return p;
}

static int l_isfolder(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    std::error_code ec;
    a.pushboolean(L, !p.empty() && fs::is_directory(p, ec) ? 1 : 0);
    return 1;
}

static int l_isfile(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    std::error_code ec;
    a.pushboolean(L, !p.empty() && fs::is_regular_file(p, ec) ? 1 : 0);
    return 1;
}

static int l_isfile_isfile(lua_State* L) { return l_isfile(L); }

static int l_makefolder(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    if (p.empty())
        return 0;
    std::error_code ec;
    fs::create_directories(p, ec);
    return 0;
}

static int l_readfile(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    if (p.empty()) {
        a.pushnil(L);
        return 1;
    }
    const auto data = read_file_utf8(p);
    a.pushlstring(L, data.data(), data.size());
    return 1;
}

static int l_writefile(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    size_t n = 0;
    const char* s = a.tolstring(L, 2, &n);
    if (p.empty())
        return 0;
    write_file_utf8(p, std::string(s ? s : "", n));
    return 0;
}

static int l_appendfile(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    size_t n = 0;
    const char* s = a.tolstring(L, 2, &n);
    if (p.empty())
        return 0;
    auto cur = read_file_utf8(p);
    cur.append(s ? s : "", n);
    write_file_utf8(p, cur);
    return 0;
}

static int l_delfile(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    std::error_code ec;
    if (!p.empty())
        fs::remove(p, ec);
    return 0;
}

static int l_delfolder(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    std::error_code ec;
    if (!p.empty())
        fs::remove_all(p, ec);
    return 0;
}

static int l_listfiles(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    a.newtable(L);
    if (p.empty())
        return 1;
    int i = 1;
    std::error_code ec;
    for (auto& e : fs::directory_iterator(p, ec)) {
        a.pushnumber(L, (lua_Number)i++);
        const auto rel = e.path().lexically_relative(workspace()).generic_string();
        a.pushstring(L, rel.c_str());
        a.settable(L, -3);
    }
    return 1;
}

static int l_loadfile(lua_State* L) {
    auto& a = LuaApi::instance();
    auto p = safe_join(a.tostring(L, 1));
    const auto src = p.empty() ? std::string{} : read_file_utf8(p);
    if (src.empty()) {
        a.pushnil(L);
        a.pushstring(L, "file not found");
        return 2;
    }
    const int st = a.load(L, p.filename().string().c_str(), src.data(), src.size(), 0);
    if (st != 0)
        return 1;
    return 1;
}

static int l_dofile(lua_State* L) {
    const int n = l_loadfile(L);
    if (n != 1)
        return n;
    auto& a = LuaApi::instance();
    if (a.type(L, -1) != LUA_TFUNCTION)
        return n;
    a.pcall(L, 0, LUA_MULTRET, 0);
    return a.gettop(L);
}

void register_filesystem(lua_State* L) {
    auto& a = LuaApi::instance();
    struct { const char* n; lua_CFunction f; } fns[] = {
        {"isfolder", l_isfolder},
        {"isfile", l_isfile_isfile},
        {"makefolder", l_makefolder},
        {"readfile", l_readfile},
        {"writefile", l_writefile},
        {"appendfile", l_appendfile},
        {"delfile", l_delfile},
        {"delfolder", l_delfolder},
        {"listfiles", l_listfiles},
        {"loadfile", l_loadfile},
        {"dofile", l_dofile},
    };
    for (auto& f : fns) {
        a.pushcfunction(L, f.f, f.n);
        a.setglobal(L, f.n);
    }
}

} // namespace vt::libs
