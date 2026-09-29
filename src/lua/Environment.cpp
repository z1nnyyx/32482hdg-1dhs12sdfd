#include "lua/Environment.h"
#include "lua/InitScript.h"
#include "lua/Execution.h"
#include "lua/libs/Drawing.h"
#include "lua/libs/Input.h"
#include "lua/libs/Filesystem.h"
#include "lua/libs/Http.h"
#include "lua/libs/Misc.h"
#include "lua/libs/Unc.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <filesystem>

namespace vt {

bool Environment::bootstrapped() {
    return done_;
}

void Environment::reset() {
    done_ = false;
    owner_ = nullptr;
}

void Environment::register_unc(lua_State* L) {
    libs::register_misc(L);
    libs::register_filesystem(L);
    libs::register_input(L);
    libs::register_http(L);
    libs::register_drawing(L);
    libs::register_unc_extra(L);
}

void Environment::bootstrap(lua_State* L) {
    if (!L)
        return;
    owner_ = L;
    auto& a = LuaApi::instance();
    if (!a.ready())
        VT_WARN(L"Lua bind incomplete — scripts may fail until offsets scan");
    else if (!a.has_tables())
        VT_WARN(L"UNC partial — Drawing/C functions need lua_pushcclosure this week");

    a.newtable(L);
    a.pushvalue(L, -1);
    a.setfield(L, LUA_REGISTRYINDEX, "VT_GENV");
    a.pop(L, 1);

    a.newtable(L);
    a.setglobal(L, "shared");

    register_unc(L);
    Execution::instance().enqueue(kInitScript, "=VoidTrace/init");

    done_ = true;
    VT_LOG(L"Environment bootstrapped (UNC + hub aliases, no RAT)");
}

} // namespace vt
