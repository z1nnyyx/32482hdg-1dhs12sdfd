#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace vt {

// Opaque — this is Roblox's lua_State, never a standalone VM.
struct lua_State;

// Luau registry (lua.h): LUA_REGISTRYINDEX = -LUAI_MAXCSTACK - 2000
inline constexpr int LUA_REGISTRYINDEX = -10000;
inline constexpr int LUA_GLOBALSINDEX  = -10002;
// Match current Luau / Roblox tags (VECTOR sits before STRING).
inline constexpr int LUA_TNIL = 0;
inline constexpr int LUA_TBOOLEAN = 1;
inline constexpr int LUA_TLIGHTUSERDATA = 2;
inline constexpr int LUA_TNUMBER = 3;
inline constexpr int LUA_TVECTOR = 4;
inline constexpr int LUA_TSTRING = 5;
inline constexpr int LUA_TTABLE = 6;
inline constexpr int LUA_TFUNCTION = 7;
inline constexpr int LUA_TUSERDATA = 8;
inline constexpr int LUA_TTHREAD = 9;
inline constexpr int LUA_TBUFFER = 10;
inline constexpr int LUA_MULTRET = -1;
inline constexpr int lua_upvalueindex(int i) { return LUA_GLOBALSINDEX - i; }

using lua_CFunction = int (*)(lua_State*);
using lua_Number = double;

// Function-pointer facade over Roblox's Luau exports.
// Every pointer is version-dependent. Calls no-op / fail if unresolved.
class LuaApi {
public:
    static LuaApi& instance();
    void bind();
    bool ready() const;

    int  gettop(lua_State* L) const;
    void settop(lua_State* L, int idx) const;
    void pop(lua_State* L, int n) const { settop(L, -(n) - 1); }

    int  type(lua_State* L, int idx) const;
    const char* tolstring(lua_State* L, int idx, size_t* len) const;
    const char* tostring(lua_State* L, int idx) const { return tolstring(L, idx, nullptr); }
    int  toboolean(lua_State* L, int idx) const;
    lua_Number tonumber(lua_State* L, int idx) const;
    void* touserdata(lua_State* L, int idx) const;

    void pushnil(lua_State* L) const;
    void pushnumber(lua_State* L, lua_Number n) const;
    void pushboolean(lua_State* L, int b) const;
    void pushstring(lua_State* L, const char* s) const;
    void pushlstring(lua_State* L, const char* s, size_t n) const;
    void pushvalue(lua_State* L, int idx) const;
    void pushcclosure(lua_State* L, lua_CFunction fn, const char* debugname, int nup) const;
    void pushcfunction(lua_State* L, lua_CFunction fn, const char* debugname) const {
        pushcclosure(L, fn, debugname, 0);
    }

    void getfield(lua_State* L, int idx, const char* k) const;
    void setfield(lua_State* L, int idx, const char* k) const;
    void gettable(lua_State* L, int idx) const;
    void settable(lua_State* L, int idx) const;
    void createtable(lua_State* L, int narr, int nrec) const;
    void newtable(lua_State* L) const { createtable(L, 0, 0); }
    void* newuserdata(lua_State* L, size_t sz) const;
    int  setmetatable(lua_State* L, int idx) const;
    int  getmetatable(lua_State* L, int idx) const;
    int  rawgeti(lua_State* L, int idx, int n) const;
    void rawseti(lua_State* L, int idx, int n) const;

    lua_State* newthread(lua_State* L) const;
    void xmove(lua_State* from, lua_State* to, int n) const;

    // luau_load(L, chunkname, data, size, env) — env 0 = current env
    int load(lua_State* L, const char* chunkname, const char* data, size_t size, int env) const;
    int pcall(lua_State* L, int nargs, int nresults, int errfunc) const;

    void setglobal(lua_State* L, const char* name) const;
    void getglobal(lua_State* L, const char* name) const;

    void setidentity(lua_State* L, int identity) const;
    int  getidentity(lua_State* L) const;
    uint8_t* extraspace(lua_State* L) const;
    void setreadonly(lua_State* L, int idx, int enabled) const;
    const char* namecall(lua_State* L) const;
    bool plausible_state(lua_State* L) const;
    void insert(lua_State* L, int idx) const;
    void remove(lua_State* L, int idx) const;

    bool has(const void* fn) const { return fn != nullptr; }
    bool has_stack() const { return top_off_ != 0 && base_off_ != 0; }
    bool has_tables() const { return (bool)createtable_ && ((bool)setfield_ || (bool)settable_) && (bool)pushcclosure_; }

private:
    void learn_stack();
    int  fb_gettop(lua_State* L) const;
    void fb_settop(lua_State* L, int idx) const;
    int  fb_type(lua_State* L, int idx) const;
    void fb_pushnil(lua_State* L) const;
    void fb_pushnumber(lua_State* L, lua_Number n) const;
    void fb_pushboolean(lua_State* L, int b) const;
    void fb_pushvalue(lua_State* L, int idx) const;
    int  fb_toboolean(lua_State* L, int idx) const;
    lua_Number fb_tonumber(lua_State* L, int idx) const;
    void* fb_index(lua_State* L, int idx) const;

    int top_off_ = 0;
    int base_off_ = 0;
    // Roblox calling conventions — x64 MSVC.
    using gettop_t        = int(__fastcall*)(lua_State*);
    using settop_t        = void(__fastcall*)(lua_State*, int);
    using type_t          = int(__fastcall*)(lua_State*, int);
    using tolstring_t     = const char*(__fastcall*)(lua_State*, int, size_t*);
    using toboolean_t     = int(__fastcall*)(lua_State*, int);
    using tonumber_t      = lua_Number(__fastcall*)(lua_State*, int);
    using touserdata_t    = void*(__fastcall*)(lua_State*, int);
    using pushnil_t       = void(__fastcall*)(lua_State*);
    using pushnumber_t    = void(__fastcall*)(lua_State*, lua_Number);
    using pushboolean_t   = void(__fastcall*)(lua_State*, int);
    using pushstring_t    = void(__fastcall*)(lua_State*, const char*);
    using pushlstring_t   = void(__fastcall*)(lua_State*, const char*, size_t);
    using pushvalue_t     = void(__fastcall*)(lua_State*, int);
    using pushcclosure_t  = void(__fastcall*)(lua_State*, lua_CFunction, const char*, int, void*);
    using getfield_t      = void(__fastcall*)(lua_State*, int, const char*);
    using setfield_t      = void(__fastcall*)(lua_State*, int, const char*);
    using gettable_t      = void(__fastcall*)(lua_State*, int);
    using settable_t      = void(__fastcall*)(lua_State*, int);
    using createtable_t   = void(__fastcall*)(lua_State*, int, int);
    using newuserdata_t   = void*(__fastcall*)(lua_State*, size_t);
    using setmetatable_t  = int(__fastcall*)(lua_State*, int);
    using getmetatable_t  = int(__fastcall*)(lua_State*, int);
    using rawgeti_t       = int(__fastcall*)(lua_State*, int, int);
    using rawseti_t       = void(__fastcall*)(lua_State*, int, int);
    using newthread_t     = lua_State*(__fastcall*)(lua_State*);
    using xmove_t         = void(__fastcall*)(lua_State*, lua_State*, int);
    using load_t          = int(__fastcall*)(lua_State*, const char*, const char*, size_t, int);
    using pcall_t         = int(__fastcall*)(lua_State*, int, int, int, uintptr_t, void*);
    using setreadonly_t   = void(__fastcall*)(lua_State*, int, int);

    gettop_t       gettop_ = nullptr;
    settop_t       settop_ = nullptr;
    type_t         type_ = nullptr;
    tolstring_t    tolstring_ = nullptr;
    toboolean_t    toboolean_ = nullptr;
    tonumber_t     tonumber_ = nullptr;
    touserdata_t   touserdata_ = nullptr;
    pushnil_t      pushnil_ = nullptr;
    pushnumber_t   pushnumber_ = nullptr;
    pushboolean_t  pushboolean_ = nullptr;
    pushstring_t   pushstring_ = nullptr;
    pushlstring_t  pushlstring_ = nullptr;
    pushvalue_t    pushvalue_ = nullptr;
    pushcclosure_t pushcclosure_ = nullptr;
    getfield_t     getfield_ = nullptr;
    setfield_t     setfield_ = nullptr;
    gettable_t     gettable_ = nullptr;
    settable_t     settable_ = nullptr;
    createtable_t  createtable_ = nullptr;
    newuserdata_t  newuserdata_ = nullptr;
    setmetatable_t setmetatable_ = nullptr;
    getmetatable_t getmetatable_ = nullptr;
    rawgeti_t      rawgeti_ = nullptr;
    rawseti_t      rawseti_ = nullptr;
    newthread_t    newthread_ = nullptr;
    xmove_t        xmove_ = nullptr;
    load_t         load_ = nullptr;
    pcall_t        pcall_ = nullptr;
    setreadonly_t  setreadonly_ = nullptr;
};

} // namespace vt
