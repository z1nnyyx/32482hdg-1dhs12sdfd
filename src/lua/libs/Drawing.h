#pragma once

#include "lua/LuaApi.h"

#include <functional>
#include <string>

namespace vt::libs {
void register_drawing(lua_State* L);
void render_drawings();
void set_draw_sink(std::function<void(std::string)> sink);
bool drawing_live();
}
