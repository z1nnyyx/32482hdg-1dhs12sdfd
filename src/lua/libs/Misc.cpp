#include "lua/libs/Misc.h"
#include "lua/Execution.h"
#include "shared/Utils.h"

#include <Windows.h>
#include <string>

namespace vt::libs {
namespace {

int l_identifyexecutor(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushstring(L, "VoidTrace");
    a.pushstring(L, "0.3.0");
    return 2;
}

int l_getexecutorname(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushstring(L, "VoidTrace");
    return 1;
}

int l_setclipboard(lua_State* L) {
    auto& a = LuaApi::instance();
    const std::string s = a.tostring(L, 1);
    if (!OpenClipboard(nullptr))
        return 0;
    EmptyClipboard();
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, s.size() + 1);
    if (mem) {
        memcpy(GlobalLock(mem), s.c_str(), s.size() + 1);
        GlobalUnlock(mem);
        SetClipboardData(CF_TEXT, mem);
    }
    CloseClipboard();
    return 0;
}

int l_getclipboard(lua_State* L) {
    auto& a = LuaApi::instance();
    if (!OpenClipboard(nullptr)) {
        a.pushstring(L, "");
        return 1;
    }
    HANDLE h = GetClipboardData(CF_TEXT);
    const char* p = h ? (const char*)GlobalLock(h) : "";
    a.pushstring(L, p ? p : "");
    if (h)
        GlobalUnlock(h);
    CloseClipboard();
    return 1;
}

int l_setfflag(lua_State* L) {
    (void)L;
    return 0;
}

int l_getfflag(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushnil(L);
    return 1;
}

int l_checkcaller(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushboolean(L, Execution::on_script_thread() ? 1 : 0);
    return 1;
}

int l_getgenv(lua_State* L) {
    auto& a = LuaApi::instance();
    a.getfield(L, LUA_REGISTRYINDEX, "VT_GENV");
    if (a.type(L, -1) != LUA_TTABLE) {
        a.pop(L, 1);
        a.newtable(L);
        a.pushvalue(L, -1);
        a.setfield(L, LUA_REGISTRYINDEX, "VT_GENV");
    }
    return 1;
}

int l_getrenv(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushvalue(L, LUA_GLOBALSINDEX);
    return 1;
}

int l_getreg(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushvalue(L, LUA_REGISTRYINDEX);
    return 1;
}

int l_queue_on_teleport(lua_State* L) {
    auto& a = LuaApi::instance();
    size_t n = 0;
    const char* s = a.tolstring(L, 1, &n);
    if (!s || !n)
        return 0;
    Execution::instance().queue_teleport(std::string(s, n));
    const auto path = data_root() / "scripts" / "autoexec" / "__teleport.lua";
    HANDLE h = CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0;
        WriteFile(h, s, (DWORD)n, &w, nullptr);
        CloseHandle(h);
    }
    return 0;
}

} // namespace

void register_misc(lua_State* L) {
    auto& a = LuaApi::instance();
    struct { const char* n; lua_CFunction f; } fns[] = {
        {"identifyexecutor", l_identifyexecutor},
        {"getexecutorname", l_getexecutorname},
        {"setclipboard", l_setclipboard},
        {"toclipboard", l_setclipboard},
        {"getclipboard", l_getclipboard},
        {"setfflag", l_setfflag},
        {"getfflag", l_getfflag},
        {"checkcaller", l_checkcaller},
        {"getgenv", l_getgenv},
        {"getrenv", l_getrenv},
        {"getreg", l_getreg},
        {"queue_on_teleport", l_queue_on_teleport},
        {"queueonteleport", l_queue_on_teleport},
    };
    for (auto& f : fns) {
        a.pushcfunction(L, f.f, f.n);
        a.setglobal(L, f.n);
    }
}

} // namespace vt::libs
