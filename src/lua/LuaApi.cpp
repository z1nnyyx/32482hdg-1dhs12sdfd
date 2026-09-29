#include "lua/LuaApi.h"
#include "lua/Offsets.h"
#include "shared/Log.h"

#include <Windows.h>
#include <cstring>
#include <string>

namespace vt {

inline constexpr int kLuaGlobalsIndex = LUA_GLOBALSINDEX;
inline constexpr int kTvSize = 16;

LuaApi& LuaApi::instance() {
    static LuaApi g;
    return g;
}

void LuaApi::bind() {
    const auto& r = OffsetResolver::current();
    gettop_        = r.lua_gettop        ? (gettop_t)r.lua_gettop : nullptr;
    settop_        = r.lua_settop        ? (settop_t)r.lua_settop : nullptr;
    type_          = r.lua_type          ? (type_t)r.lua_type : nullptr;
    tolstring_     = r.lua_tolstring     ? (tolstring_t)r.lua_tolstring : nullptr;
    toboolean_     = r.lua_toboolean     ? (toboolean_t)r.lua_toboolean : nullptr;
    tonumber_      = r.lua_tonumber      ? (tonumber_t)r.lua_tonumber : nullptr;
    touserdata_    = r.lua_touserdata    ? (touserdata_t)r.lua_touserdata : nullptr;
    pushnil_       = r.lua_pushnil       ? (pushnil_t)r.lua_pushnil : nullptr;
    pushnumber_    = r.lua_pushnumber    ? (pushnumber_t)r.lua_pushnumber : nullptr;
    pushboolean_   = r.lua_pushboolean   ? (pushboolean_t)r.lua_pushboolean : nullptr;
    pushstring_    = r.lua_pushstring    ? (pushstring_t)r.lua_pushstring : nullptr;
    pushlstring_   = r.lua_pushlstring   ? (pushlstring_t)r.lua_pushlstring : nullptr;
    pushvalue_     = r.lua_pushvalue     ? (pushvalue_t)r.lua_pushvalue : nullptr;
    pushcclosure_  = r.lua_pushcclosure  ? (pushcclosure_t)r.lua_pushcclosure : nullptr;
    getfield_      = r.lua_getfield      ? (getfield_t)r.lua_getfield : nullptr;
    setfield_      = r.lua_setfield      ? (setfield_t)r.lua_setfield : nullptr;
    gettable_      = r.lua_gettable      ? (gettable_t)r.lua_gettable : nullptr;
    settable_      = r.lua_settable      ? (settable_t)r.lua_settable : nullptr;
    createtable_   = r.lua_createtable   ? (createtable_t)r.lua_createtable : nullptr;
    newuserdata_   = r.lua_newuserdata   ? (newuserdata_t)r.lua_newuserdata : nullptr;
    setmetatable_  = r.lua_setmetatable  ? (setmetatable_t)r.lua_setmetatable : nullptr;
    getmetatable_  = r.lua_getmetatable  ? (getmetatable_t)r.lua_getmetatable : nullptr;
    rawgeti_       = r.lua_rawgeti       ? (rawgeti_t)r.lua_rawgeti : nullptr;
    rawseti_       = r.lua_rawseti       ? (rawseti_t)r.lua_rawseti : nullptr;
    newthread_     = r.lua_newthread     ? (newthread_t)r.lua_newthread : nullptr;
    xmove_         = r.lua_xmove         ? (xmove_t)r.lua_xmove : nullptr;
    load_          = r.luau_load         ? (load_t)r.luau_load : nullptr;
    pcall_         = r.lua_pcall         ? (pcall_t)r.lua_pcall : nullptr;
    setreadonly_   = r.lua_setreadonly   ? (setreadonly_t)r.lua_setreadonly : nullptr;

    learn_stack();

    if (!ready())
        VT_WARN(L"Lua API incomplete — fill config/offsets.json for this Roblox build");
    else
        VT_LOG(L"Lua API bound");
    if (has_stack())
        VT_LOG(L"stack  top+" + std::to_wstring(top_off_) +
               L" base+" + std::to_wstring(base_off_));
}

bool LuaApi::ready() const {
    return load_ && pcall_ && (settop_ || has_stack()) &&
           (pushstring_ || pushlstring_ || pushcclosure_);
}

void LuaApi::learn_stack() {
    top_off_ = 0;
    base_off_ = 0;
    auto try_fn = [&](const void* fn) {
        if (!fn || (top_off_ && base_off_))
            return;
        const uint8_t* p = (const uint8_t*)fn;
        __try {
            // gettop: mov rax,[rcx+top]; sub rax,[rcx+base]
            if (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x41) {
                if (!top_off_)
                    top_off_ = p[3];
                if (p[4] == 0x48 && p[5] == 0x2B && p[6] == 0x41)
                    base_off_ = p[7];
            }
            // pushnil/number: mov rax,[rcx+top]; ... add [rcx+top], 10h
            if (!base_off_ && p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x41)
                top_off_ = p[3];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    };
    try_fn(gettop_);
    try_fn(settop_);
    try_fn(pushnil_);
    try_fn(pushnumber_);
    try_fn(pushboolean_);
    if (top_off_ && !base_off_) {
        base_off_ = (int)top_off_ - 8;
        if (base_off_ < 0x10)
            base_off_ = 0;
    }
    if (!top_off_ || !base_off_) {
        top_off_ = 0x20;
        base_off_ = 0x18;
    }
}

void* LuaApi::fb_index(lua_State* L, int idx) const {
    if (!L || !has_stack())
        return nullptr;
    uint8_t* slot = nullptr;
    __try {
        auto* top  = *(uint8_t**)((uint8_t*)L + top_off_);
        auto* base = *(uint8_t**)((uint8_t*)L + base_off_);
        if (!top || !base)
            return nullptr;
        if (idx > 0)
            slot = base + (idx - 1) * kTvSize;
        else if (idx < 0 && idx > LUA_REGISTRYINDEX)
            slot = top + idx * kTvSize;
        else
            return nullptr;
        if (slot < base || slot >= top)
            return nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return slot;
}

int LuaApi::fb_gettop(lua_State* L) const {
    if (!L || !has_stack())
        return 0;
    int n = 0;
    __try {
        auto* top  = *(uint8_t**)((uint8_t*)L + top_off_);
        auto* base = *(uint8_t**)((uint8_t*)L + base_off_);
        if (top && base && top >= base)
            n = (int)((top - base) / kTvSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        n = 0;
    }
    return n;
}

void LuaApi::fb_settop(lua_State* L, int idx) const {
    if (!L || !has_stack())
        return;
    __try {
        auto* top  = *(uint8_t**)((uint8_t*)L + top_off_);
        auto* base = *(uint8_t**)((uint8_t*)L + base_off_);
        if (!top || !base)
            return;
        uint8_t* want = idx >= 0 ? base + idx * kTvSize : top + (idx + 1) * kTvSize;
        if (want > top) {
            for (uint8_t* s = top; s < want; s += kTvSize) {
                *(uint64_t*)s = 0;
                *(int*)(s + 12) = LUA_TNIL;
            }
        }
        *(uint8_t**)((uint8_t*)L + top_off_) = want;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

int LuaApi::fb_type(lua_State* L, int idx) const {
    auto* s = (uint8_t*)fb_index(L, idx);
    if (!s)
        return LUA_TNIL;
    int t = LUA_TNIL;
    __try { t = *(int*)(s + 12); } __except (EXCEPTION_EXECUTE_HANDLER) { t = LUA_TNIL; }
    return t;
}

void LuaApi::fb_pushnil(lua_State* L) const {
    if (!L || !has_stack())
        return;
    __try {
        auto* top = *(uint8_t**)((uint8_t*)L + top_off_);
        if (!top)
            return;
        *(uint64_t*)top = 0;
        *(int*)(top + 12) = LUA_TNIL;
        *(uint8_t**)((uint8_t*)L + top_off_) = top + kTvSize;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void LuaApi::fb_pushnumber(lua_State* L, lua_Number n) const {
    if (!L || !has_stack())
        return;
    __try {
        auto* top = *(uint8_t**)((uint8_t*)L + top_off_);
        if (!top)
            return;
        *(lua_Number*)top = n;
        *(int*)(top + 12) = LUA_TNUMBER;
        *(uint8_t**)((uint8_t*)L + top_off_) = top + kTvSize;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void LuaApi::fb_pushboolean(lua_State* L, int b) const {
    if (!L || !has_stack())
        return;
    __try {
        auto* top = *(uint8_t**)((uint8_t*)L + top_off_);
        if (!top)
            return;
        *(int*)top = b ? 1 : 0;
        *(int*)(top + 12) = LUA_TBOOLEAN;
        *(uint8_t**)((uint8_t*)L + top_off_) = top + kTvSize;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void LuaApi::fb_pushvalue(lua_State* L, int idx) const {
    auto* s = (uint8_t*)fb_index(L, idx);
    if (!s || !has_stack())
        return;
    __try {
        auto* top = *(uint8_t**)((uint8_t*)L + top_off_);
        if (!top)
            return;
        std::memcpy(top, s, kTvSize);
        *(uint8_t**)((uint8_t*)L + top_off_) = top + kTvSize;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

int LuaApi::fb_toboolean(lua_State* L, int idx) const {
    auto* s = (uint8_t*)fb_index(L, idx);
    if (!s)
        return 0;
    int t = LUA_TNIL, b = 0;
    __try {
        t = *(int*)(s + 12);
        b = *(int*)s;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    if (t == LUA_TNIL)
        return 0;
    if (t == LUA_TBOOLEAN)
        return b ? 1 : 0;
    return 1;
}

lua_Number LuaApi::fb_tonumber(lua_State* L, int idx) const {
    auto* s = (uint8_t*)fb_index(L, idx);
    if (!s)
        return 0;
    lua_Number n = 0;
    __try {
        if (*(int*)(s + 12) == LUA_TNUMBER)
            n = *(lua_Number*)s;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        n = 0;
    }
    return n;
}

int  LuaApi::gettop(lua_State* L) const {
    if (gettop_ && L) return gettop_(L);
    return fb_gettop(L);
}
void LuaApi::settop(lua_State* L, int idx) const {
    if (settop_ && L) { settop_(L, idx); return; }
    fb_settop(L, idx);
}
int LuaApi::type(lua_State* L, int idx) const {
    if (type_ && L) return type_(L, idx);
    return fb_type(L, idx);
}

const char* LuaApi::tolstring(lua_State* L, int idx, size_t* len) const {
    return tolstring_ && L ? tolstring_(L, idx, len) : "";
}
int LuaApi::toboolean(lua_State* L, int idx) const {
    if (toboolean_ && L) return toboolean_(L, idx);
    return fb_toboolean(L, idx);
}
lua_Number LuaApi::tonumber(lua_State* L, int idx) const {
    if (tonumber_ && L) return tonumber_(L, idx);
    return fb_tonumber(L, idx);
}
void* LuaApi::touserdata(lua_State* L, int idx) const {
    return touserdata_ && L ? touserdata_(L, idx) : nullptr;
}

void LuaApi::pushnil(lua_State* L) const {
    if (pushnil_ && L) { pushnil_(L); return; }
    fb_pushnil(L);
}
void LuaApi::pushnumber(lua_State* L, lua_Number n) const {
    if (pushnumber_ && L) { pushnumber_(L, n); return; }
    fb_pushnumber(L, n);
}
void LuaApi::pushboolean(lua_State* L, int b) const {
    if (pushboolean_ && L) { pushboolean_(L, b); return; }
    fb_pushboolean(L, b);
}
void LuaApi::pushstring(lua_State* L, const char* s) const {
    if (pushstring_ && L) { pushstring_(L, s ? s : ""); return; }
    if (pushlstring_ && L) {
        const char* p = s ? s : "";
        pushlstring_(L, p, std::strlen(p));
    }
}
void LuaApi::pushlstring(lua_State* L, const char* s, size_t n) const {
    if (pushlstring_ && L) { pushlstring_(L, s, n); return; }
    if (pushstring_ && L) pushstring_(L, s ? s : "");
}
void LuaApi::pushvalue(lua_State* L, int idx) const {
    if (pushvalue_ && L) { pushvalue_(L, idx); return; }
    fb_pushvalue(L, idx);
}
void LuaApi::pushcclosure(lua_State* L, lua_CFunction fn, const char* debugname, int nup) const {
    if (pushcclosure_ && L)
        pushcclosure_(L, fn, debugname ? debugname : "", nup, nullptr);
}

void LuaApi::getfield(lua_State* L, int idx, const char* k) const {
    if (getfield_ && L) { getfield_(L, idx, k); return; }
    if (!L || !k || !gettable_)
        return;
    int t = idx;
    pushstring(L, k);
    if (t < 0 && t > LUA_REGISTRYINDEX)
        --t;
    gettable_(L, t);
}
void LuaApi::setfield(lua_State* L, int idx, const char* k) const {
    if (setfield_ && L) { setfield_(L, idx, k); return; }
    if (!L || !k || !settable_)
        return;
    int t = idx;
    pushstring(L, k);
    if (t < 0 && t > LUA_REGISTRYINDEX)
        --t;
    pushvalue(L, -2);
    if (t < 0 && t > LUA_REGISTRYINDEX)
        --t;
    settable_(L, t);
    pop(L, 1);
}
void LuaApi::gettable(lua_State* L, int idx) const { if (gettable_ && L) gettable_(L, idx); }
void LuaApi::settable(lua_State* L, int idx) const { if (settable_ && L) settable_(L, idx); }
void LuaApi::createtable(lua_State* L, int narr, int nrec) const { if (createtable_ && L) createtable_(L, narr, nrec); }
void* LuaApi::newuserdata(lua_State* L, size_t sz) const { return newuserdata_ && L ? newuserdata_(L, sz) : nullptr; }
int  LuaApi::setmetatable(lua_State* L, int idx) const { return setmetatable_ && L ? setmetatable_(L, idx) : 0; }
int  LuaApi::getmetatable(lua_State* L, int idx) const { return getmetatable_ && L ? getmetatable_(L, idx) : 0; }
int  LuaApi::rawgeti(lua_State* L, int idx, int n) const { return rawgeti_ && L ? rawgeti_(L, idx, n) : 0; }
void LuaApi::rawseti(lua_State* L, int idx, int n) const { if (rawseti_ && L) rawseti_(L, idx, n); }

lua_State* LuaApi::newthread(lua_State* L) const {
    if (!newthread_ || !L)
        return nullptr;
    lua_State* t = nullptr;
    __try {
        t = newthread_(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        t = nullptr;
    }
    return t;
}
void LuaApi::xmove(lua_State* from, lua_State* to, int n) const { if (xmove_ && from && to) xmove_(from, to, n); }

int LuaApi::load(lua_State* L, const char* chunkname, const char* data, size_t size, int env) const {
    return load_ && L ? load_(L, chunkname, data, size, env) : 1;
}
int LuaApi::pcall(lua_State* L, int nargs, int nresults, int errfunc) const {
    return pcall_ && L ? pcall_(L, nargs, nresults, errfunc, 0, nullptr) : 1;
}

void LuaApi::setglobal(lua_State* L, const char* name) const {
    setfield(L, kLuaGlobalsIndex, name);
}

void LuaApi::getglobal(lua_State* L, const char* name) const {
    getfield(L, kLuaGlobalsIndex, name);
}

namespace {
int seh_write_identity(lua_State* L, uintptr_t extra, uintptr_t off, int identity) {
    __try {
        uint8_t* extra_ptr = extra ? *(uint8_t**)((uint8_t*)L - extra) : nullptr;
        if (!extra_ptr)
            extra_ptr = (uint8_t*)L + extra;
        *(int*)(extra_ptr + off) = identity;
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}
int seh_read_identity(lua_State* L, uintptr_t extra, uintptr_t off, int* out) {
    __try {
        uint8_t* extra_ptr = extra ? *(uint8_t**)((uint8_t*)L - extra) : nullptr;
        if (!extra_ptr)
            extra_ptr = (uint8_t*)L + extra;
        *out = *(int*)(extra_ptr + off);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}
} // namespace

void LuaApi::setidentity(lua_State* L, int identity) const {
    if (!L)
        return;
    const auto extra = OffsetResolver::current().table.extra_space;
    const auto off   = OffsetResolver::current().table.identity;
    seh_write_identity(L, extra, off, identity);
}

int LuaApi::getidentity(lua_State* L) const {
    if (!L)
        return 0;
    const auto extra = OffsetResolver::current().table.extra_space;
    const auto off   = OffsetResolver::current().table.identity;
    int v = 0;
    return seh_read_identity(L, extra, off, &v) ? v : 0;
}

uint8_t* LuaApi::extraspace(lua_State* L) const {
    if (!L)
        return nullptr;
    const auto extra = OffsetResolver::current().table.extra_space;
    uint8_t* p = nullptr;
    __try {
        p = extra ? *(uint8_t**)((uint8_t*)L - extra) : nullptr;
        if (!p)
            p = (uint8_t*)L + extra;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        p = nullptr;
    }
    return p;
}

void LuaApi::setreadonly(lua_State* L, int idx, int enabled) const {
    if (setreadonly_ && L)
        setreadonly_(L, idx, enabled);
}

void LuaApi::insert(lua_State* L, int idx) const {
    if (!L || !has_stack())
        return;
    __try {
        auto* basep = (uint8_t**)((uint8_t*)L + base_off_);
        auto* topp = (uint8_t**)((uint8_t*)L + top_off_);
        uint8_t* base = *basep;
        uint8_t* top = *topp;
        if (!base || !top || top < base + kTvSize)
            return;
        uint8_t* dst = nullptr;
        if (idx > 0)
            dst = base + (idx - 1) * kTvSize;
        else if (idx < 0 && idx > LUA_REGISTRYINDEX)
            dst = top + idx * kTvSize;
        if (!dst || dst < base || dst >= top)
            return;
        uint8_t tmp[16];
        memcpy(tmp, top - kTvSize, kTvSize);
        memmove(dst + kTvSize, dst, (size_t)((top - kTvSize) - dst));
        memcpy(dst, tmp, kTvSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

void LuaApi::remove(lua_State* L, int idx) const {
    if (!L || !has_stack())
        return;
    __try {
        auto* basep = (uint8_t**)((uint8_t*)L + base_off_);
        auto* topp = (uint8_t**)((uint8_t*)L + top_off_);
        uint8_t* base = *basep;
        uint8_t* top = *topp;
        if (!base || !top || top <= base)
            return;
        uint8_t* dst = nullptr;
        if (idx > 0)
            dst = base + (idx - 1) * kTvSize;
        else if (idx < 0 && idx > LUA_REGISTRYINDEX)
            dst = top + idx * kTvSize;
        if (!dst || dst < base || dst >= top)
            return;
        memmove(dst, dst + kTvSize, (size_t)(top - dst - kTvSize));
        *topp = top - kTvSize;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

const char* LuaApi::namecall(lua_State* L) const {
    uint8_t* extra = extraspace(L);
    if (!extra)
        return "";
    const int offs[] = { 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0xA0, 0xC0 };
    __try {
        for (int off : offs) {
            uintptr_t p = *(uintptr_t*)(extra + off);
            if (p < 0x10000 || p > 0x00007FFFFFFFFFFFULL)
                continue;
            const char* s = (const char*)p;
            // TString* — data often sits after a small header
            if ((unsigned char)s[0] < 32) {
                s = (const char*)(p + 0x18);
            }
            size_t n = 0;
            while (n < 48 && s[n] && (unsigned char)s[n] >= 32 && (unsigned char)s[n] < 127)
                ++n;
            if (n >= 2 && n < 40)
                return s;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return "";
    }
    return "";
}

bool LuaApi::plausible_state(lua_State* L) const {
    if (!L)
        return false;
    const uintptr_t p = (uintptr_t)L;
    // lua_State lives on the process heap. Image/DLL range (0x7FF…) was
    // matching random structures and READY'd a fake state — that crash.
    if (p <= 0x10000 || p >= 0x00007F0000000000ULL)
        return false;
    uint8_t* top = nullptr;
    uint8_t* base = nullptr;
    uintptr_t first = 0;
    const bool use_stack = has_stack();
    const int top_off = top_off_;
    const int base_off = base_off_;
    __try {
        if (use_stack) {
            top  = *(uint8_t**)((uint8_t*)L + top_off);
            base = *(uint8_t**)((uint8_t*)L + base_off);
        } else {
            first = *(const uintptr_t*)L;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    auto heapish = [](uintptr_t a) {
        return a > 0x10000 && a < 0x00007F0000000000ULL;
    };
    if (use_stack) {
        if (!heapish((uintptr_t)top) || !heapish((uintptr_t)base) || top < base)
            return false;
        if (((uintptr_t)top & 15) || ((uintptr_t)base & 15) || (p & 7))
            return false;
        const ptrdiff_t n = (top - base) / 16;
        return n >= 4 && n < 10000;
    }
    return heapish(first);
}

} // namespace vt
