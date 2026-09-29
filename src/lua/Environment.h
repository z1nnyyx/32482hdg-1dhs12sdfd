#pragma once

#include "lua/LuaApi.h"

namespace vt {

class Environment {
public:
    static void bootstrap(lua_State* L);
    static bool bootstrapped();
    static void reset();
    static lua_State* genv_owner() { return owner_; }

private:
    static void register_unc(lua_State* L);
    static inline lua_State* owner_ = nullptr;
    static inline bool done_ = false;
};

} // namespace vt
