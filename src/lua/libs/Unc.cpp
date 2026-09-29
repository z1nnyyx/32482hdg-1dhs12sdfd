#include "lua/libs/Unc.h"
#include "lua/Execution.h"
#include "shared/Utils.h"
#include "shared/Log.h"

#include <Windows.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_set>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")

namespace vt::libs {
namespace {

std::mutex g_clos_mtx;
std::unordered_set<lua_CFunction> g_our_c;
thread_local std::string g_ncm;

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64enc(const uint8_t* p, size_t n) {
    std::string o;
    o.reserve(((n + 2) / 3) * 4);
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = p[i] << 16;
        if (i + 1 < n) v |= p[i + 1] << 8;
        if (i + 2 < n) v |= p[i + 2];
        o.push_back(kB64[(v >> 18) & 63]);
        o.push_back(kB64[(v >> 12) & 63]);
        o.push_back(i + 1 < n ? kB64[(v >> 6) & 63] : '=');
        o.push_back(i + 2 < n ? kB64[v & 63] : '=');
    }
    return o;
}

std::string b64dec(const char* s, size_t n) {
    int dec[256];
    memset(dec, -1, sizeof(dec));
    for (int i = 0; i < 64; ++i)
        dec[(unsigned char)kB64[i]] = i;
    std::string o;
    int val = 0, valb = -8;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (dec[c] == -1)
            break;
        val = (val << 6) + dec[c];
        valb += 6;
        if (valb >= 0) {
            o.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return o;
}

void mark(lua_CFunction f) {
    std::lock_guard lock(g_clos_mtx);
    g_our_c.insert(f);
}

int l_loadstring(lua_State* L) {
    auto& a = LuaApi::instance();
    size_t n = 0;
    const char* src = a.tolstring(L, 1, &n);
    const char* name = a.gettop(L) >= 2 ? a.tostring(L, 2) : "=VoidTrace";
    if (!src) {
        a.pushnil(L);
        a.pushstring(L, "bad argument");
        return 2;
    }
    const int st = a.load(L, name ? name : "=VoidTrace", src, n, 0);
    if (st != 0) {
        const char* e = a.tostring(L, -1);
        std::string err = e ? e : "luau_load failed";
        a.pop(L, 1);
        a.pushnil(L);
        a.pushstring(L, err.c_str());
        return 2;
    }
    return 1;
}

int ncc_thunk(lua_State* L) {
    auto& a = LuaApi::instance();
    const int n = a.gettop(L);
    a.pushvalue(L, lua_upvalueindex(1));
    if (a.type(L, -1) != LUA_TFUNCTION) {
        a.pop(L, 1);
        return 0;
    }
    a.insert(L, 1);
    const int rc = a.pcall(L, n, LUA_MULTRET, 0);
    if (rc != 0)
        return 1;
    return a.gettop(L);
}

int l_newcclosure(lua_State* L) {
    auto& a = LuaApi::instance();
    if (a.type(L, 1) != LUA_TFUNCTION) {
        a.pushnil(L);
        return 1;
    }
    a.pushvalue(L, 1);
    a.pushcclosure(L, ncc_thunk, "ncc", 1);
    mark(ncc_thunk);
    return 1;
}

int l_isexecutorclosure(lua_State* L) {
    auto& a = LuaApi::instance();
    if (a.type(L, 1) != LUA_TFUNCTION) {
        a.pushboolean(L, 0);
        return 1;
    }
    a.pushboolean(L, Execution::on_script_thread() ? 1 : 0);
    return 1;
}

int l_getidentity(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushnumber(L, (lua_Number)a.getidentity(L));
    return 1;
}

int l_setidentity(lua_State* L) {
    auto& a = LuaApi::instance();
    a.setidentity(L, (int)a.tonumber(L, 1));
    return 0;
}

int l_cloneref(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushvalue(L, 1);
    return 1;
}

int l_compareinstances(lua_State* L) {
    auto& a = LuaApi::instance();
    const void* x = a.touserdata(L, 1);
    const void* y = a.touserdata(L, 2);
    a.pushboolean(L, x && x == y ? 1 : 0);
    return 1;
}

int l_b64enc(lua_State* L) {
    auto& a = LuaApi::instance();
    size_t n = 0;
    const char* s = a.tolstring(L, 1, &n);
    auto out = b64enc((const uint8_t*)(s ? s : ""), n);
    a.pushlstring(L, out.data(), out.size());
    return 1;
}

int l_b64dec(lua_State* L) {
    auto& a = LuaApi::instance();
    size_t n = 0;
    const char* s = a.tolstring(L, 1, &n);
    auto out = b64dec(s ? s : "", n);
    a.pushlstring(L, out.data(), out.size());
    return 1;
}

int l_hash(lua_State* L) {
    auto& a = LuaApi::instance();
    size_t n = 0;
    const char* s = a.tolstring(L, 1, &n);
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    uint8_t digest[32]{};
    DWORD dlen = 32;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
            BCryptHashData(h, (PUCHAR)s, (ULONG)n, 0);
            BCryptFinishHash(h, digest, dlen, 0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    char hex[65]{};
    for (int i = 0; i < 32; ++i)
        sprintf_s(hex + i * 2, 3, "%02x", digest[i]);
    a.pushstring(L, hex);
    return 1;
}

int l_messagebox(lua_State* L) {
    auto& a = LuaApi::instance();
    const std::string text = a.tostring(L, 1);
    const std::string title = a.gettop(L) >= 2 ? a.tostring(L, 2) : "VoidTrace";
    const int flags = a.gettop(L) >= 3 ? (int)a.tonumber(L, 3) : 0;
    const int r = MessageBoxA(nullptr, text.c_str(), title.c_str(), (UINT)flags);
    a.pushnumber(L, (lua_Number)r);
    return 1;
}

int l_rconsoleprint(lua_State* L) {
    auto& a = LuaApi::instance();
    VT_LOG(utf8_to_wide(a.tostring(L, 1)));
    return 0;
}

int l_rconsolecreate(lua_State*) {
    AllocConsole();
    SetConsoleTitleW(L"Runtime");
    return 0;
}

int l_rconsoledestroy(lua_State*) {
    FreeConsole();
    return 0;
}

int l_getcustomasset(lua_State* L) {
    auto& a = LuaApi::instance();
    const std::string rel = a.tostring(L, 1);
    a.pushstring(L, ("rbxasset://VoidTrace/" + rel).c_str());
    return 1;
}

int l_iskeydown(lua_State* L) {
    auto& a = LuaApi::instance();
    const int vk = (int)a.tonumber(L, 1);
    a.pushboolean(L, (GetAsyncKeyState(vk) & 0x8000) ? 1 : 0);
    return 1;
}

int l_mousescroll(lua_State* L) {
    auto& a = LuaApi::instance();
    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.dwFlags = MOUSEEVENTF_WHEEL;
    in.mi.mouseData = (DWORD)(int)a.tonumber(L, 1);
    SendInput(1, &in, sizeof(INPUT));
    return 0;
}

int l_getrawmetatable(lua_State* L) {
    auto& a = LuaApi::instance();
    if (!a.getmetatable(L, 1))
        a.pushnil(L);
    return 1;
}

int l_setrawmetatable(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushvalue(L, 2);
    a.setmetatable(L, 1);
    a.pushvalue(L, 1);
    return 1;
}

int l_islclosure(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushboolean(L, a.type(L, 1) == LUA_TFUNCTION ? 1 : 0);
    return 1;
}

int l_iscclosure(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushboolean(L, 0);
    return 1;
}

int l_clonefunction(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushvalue(L, 1);
    return 1;
}

int g_fpscap = 60;

int l_setfpscap(lua_State* L) {
    auto& a = LuaApi::instance();
    g_fpscap = (int)a.tonumber(L, 1);
    if (g_fpscap < 0)
        g_fpscap = 0;
    return 0;
}

int l_getfpscap(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushnumber(L, (lua_Number)g_fpscap);
    return 1;
}

int l_crypt_xor(lua_State* L) {
    auto& a = LuaApi::instance();
    size_t n = 0, kn = 0;
    const char* s = a.tolstring(L, 1, &n);
    const char* k = a.tolstring(L, 2, &kn);
    if (!s || !k || kn == 0) {
        a.pushvalue(L, 1);
        return 1;
    }
    std::string o(s, n);
    for (size_t i = 0; i < n; ++i)
        o[i] = char(o[i] ^ k[i % kn]);
    a.pushlstring(L, o.data(), o.size());
    return 1;
}

int l_rconsoleclear(lua_State*) {
    return 0;
}

int l_getnamecallmethod(lua_State* L) {
    auto& a = LuaApi::instance();
    if (!g_ncm.empty()) {
        a.pushstring(L, g_ncm.c_str());
        return 1;
    }
    const char* s = a.namecall(L);
    a.pushstring(L, s ? s : "");
    return 1;
}

int l_setnamecallmethod(lua_State* L) {
    auto& a = LuaApi::instance();
    g_ncm = a.tostring(L, 1);
    return 0;
}

int l_setreadonly(lua_State* L) {
    auto& a = LuaApi::instance();
    a.setreadonly(L, 1, a.toboolean(L, 2));
    a.pushvalue(L, 1);
    return 1;
}

int l_isreadonly(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushboolean(L, 0);
    return 1;
}

int hmm_thunk(lua_State* L) {
    auto& a = LuaApi::instance();
    const int n = a.gettop(L);
    const char* nc = a.namecall(L);
    if (nc && nc[0])
        g_ncm = nc;
    else {
        a.pushvalue(L, lua_upvalueindex(3));
        if (a.type(L, -1) == LUA_TSTRING)
            g_ncm = a.tostring(L, -1);
        a.pop(L, 1);
    }

    a.pushvalue(L, lua_upvalueindex(1));
    if (a.type(L, -1) != LUA_TFUNCTION) {
        a.pop(L, 1);
        a.pushvalue(L, lua_upvalueindex(2));
        for (int i = 1; i <= n; ++i)
            a.pushvalue(L, i);
        a.pcall(L, n, LUA_MULTRET, 0);
        return a.gettop(L) - n;
    }
    a.insert(L, 1);
    const int rc = a.pcall(L, n, LUA_MULTRET, 0);
    if (rc != 0) {
        a.pop(L, 1);
        a.pushvalue(L, lua_upvalueindex(2));
        for (int i = 1; i <= n; ++i)
            a.pushvalue(L, i);
        a.pcall(L, n, LUA_MULTRET, 0);
        const int after = a.gettop(L);
        const int nres = after - n;
        for (int i = 0; i < n && nres >= 0; ++i)
            a.remove(L, 1);
        return a.gettop(L);
    }
    return a.gettop(L);
}

int l_hookmetamethod(lua_State* L) {
    auto& a = LuaApi::instance();
    if (a.type(L, 3) != LUA_TFUNCTION) {
        a.pushnil(L);
        return 1;
    }
    if (!a.getmetatable(L, 1)) {
        a.pushnil(L);
        return 1;
    }
    a.setreadonly(L, -1, 0);
    a.pushvalue(L, 2);
    a.gettable(L, -2);
    a.pushvalue(L, 3);
    a.pushvalue(L, -2);
    a.pushvalue(L, 2);
    a.pushcclosure(L, hmm_thunk, "vt_hmm", 3);
    mark(hmm_thunk);
    a.pushvalue(L, 2);
    a.pushvalue(L, -2);
    a.settable(L, -5);
    a.pop(L, 1);
    a.setreadonly(L, -2, 1);
    a.pushvalue(L, -1);
    a.setfield(L, LUA_REGISTRYINDEX, "VT_HMM_RET");
    a.settop(L, 0);
    a.getfield(L, LUA_REGISTRYINDEX, "VT_HMM_RET");
    return 1;
}

int l_hookfunction(lua_State* L) {
    auto& a = LuaApi::instance();
    if (a.type(L, 2) != LUA_TFUNCTION) {
        a.pushvalue(L, 1);
        return 1;
    }
    a.pushvalue(L, 2);
    a.pushvalue(L, 1);
    a.pushstring(L, "");
    a.pushcclosure(L, hmm_thunk, "vt_hf", 3);
    mark(hmm_thunk);
    a.pushvalue(L, -1);
    return 1;
}

} // namespace

void register_unc_extra(lua_State* L) {
    auto& a = LuaApi::instance();
    struct { const char* n; lua_CFunction f; } fns[] = {
        {"loadstring", l_loadstring},
        {"load", l_loadstring},
        {"newcclosure", l_newcclosure},
        {"isexecutorclosure", l_isexecutorclosure},
        {"checkclosure", l_isexecutorclosure},
        {"getidentity", l_getidentity},
        {"setidentity", l_setidentity},
        {"getthreadidentity", l_getidentity},
        {"setthreadidentity", l_setidentity},
        {"getthreadcontext", l_getidentity},
        {"setthreadcontext", l_setidentity},
        {"cloneref", l_cloneref},
        {"compareinstances", l_compareinstances},
        {"base64_encode", l_b64enc},
        {"base64_decode", l_b64dec},
        {"base64encode", l_b64enc},
        {"base64decode", l_b64dec},
        {"crypt_hash", l_hash},
        {"messagebox", l_messagebox},
        {"rconsoleprint", l_rconsoleprint},
        {"rconsoleinfo", l_rconsoleprint},
        {"rconsolewarn", l_rconsoleprint},
        {"rconsoleerr", l_rconsoleprint},
        {"rconsolecreate", l_rconsolecreate},
        {"rconsoledestroy", l_rconsoledestroy},
        {"setfpscap", l_setfpscap},
        {"getfpscap", l_getfpscap},
        {"getcustomasset", l_getcustomasset},
        {"iskeydown", l_iskeydown},
        {"mousescroll", l_mousescroll},
        {"getrawmetatable", l_getrawmetatable},
        {"setrawmetatable", l_setrawmetatable},
        {"islclosure", l_islclosure},
        {"iscclosure", l_iscclosure},
        {"clonefunction", l_clonefunction},
        {"getnamecallmethod", l_getnamecallmethod},
        {"setnamecallmethod", l_setnamecallmethod},
        {"setreadonly", l_setreadonly},
        {"isreadonly", l_isreadonly},
        {"makewritable", l_setreadonly},
        {"hookmetamethod", l_hookmetamethod},
        {"hookfunction", l_hookfunction},
        {"hookfunc", l_hookfunction},
        {"rconsoleclear", l_rconsoleclear},
        {"rconsolename", l_rconsoleclear},
    };
    for (auto& f : fns) {
        mark(f.f);
        a.pushcfunction(L, f.f, f.n);
        a.setglobal(L, f.n);
    }

    // crypt table
    a.newtable(L);
    a.pushcfunction(L, l_b64enc, "base64encode");
    a.setfield(L, -2, "base64encode");
    a.pushcfunction(L, l_b64dec, "base64decode");
    a.setfield(L, -2, "base64decode");
    a.pushcfunction(L, l_hash, "hash");
    a.setfield(L, -2, "hash");
    a.pushcfunction(L, l_crypt_xor, "encrypt");
    a.setfield(L, -2, "encrypt");
    a.pushcfunction(L, l_crypt_xor, "decrypt");
    a.setfield(L, -2, "decrypt");
    a.setglobal(L, "crypt");
}

} // namespace vt::libs
