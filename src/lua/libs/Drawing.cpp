#include "lua/libs/Drawing.h"
#include "shared/DrawSnap.h"

#include <Windows.h>
#include <mutex>
#include <unordered_map>
#include <algorithm>
#include <atomic>
#include <cmath>
#include <functional>

namespace vt::libs {
namespace {

struct Color4 {
    float r = 1, g = 1, b = 1, a = 1;
};

struct DrawObject {
    DrawKind type = DK_LINE;
    bool visible = true;
    bool filled = false;
    bool outline = false;
    Color4 color{};
    Color4 ocol{0, 0, 0, 1};
    float thickness = 1;
    float size = 16;
    float radius = 0;
    float x1 = 0, y1 = 0, x2 = 0, y2 = 0, x3 = 0, y3 = 0, x4 = 0, y4 = 0;
    int font = 0;
    int z = 0;
    std::string text;
};

std::mutex g_mtx;
std::unordered_map<int, DrawObject> g_objects;
int g_next = 1;
std::atomic<int> g_nobj{0};
std::atomic<bool> g_sent_empty{false};
std::function<void(std::string)> g_sink;

void recount_locked() {
    g_nobj.store((int)g_objects.size(), std::memory_order_relaxed);
}

float chan(float v) {
    if (v > 1.f)
        return v / 255.f;
    if (v < 0.f)
        return 0.f;
    return v;
}

int obj_id(lua_State* L, int idx) {
    auto& a = LuaApi::instance();
    if (a.type(L, idx) == LUA_TUSERDATA) {
        if (auto* p = (int*)a.touserdata(L, idx))
            return *p;
    }
    a.pushstring(L, "__id");
    a.gettable(L, idx);
    const int id = (int)a.tonumber(L, -1);
    a.pop(L, 1);
    return id;
}

DrawObject* get_obj(int id) {
    auto it = g_objects.find(id);
    return it == g_objects.end() ? nullptr : &it->second;
}

void read_xy(lua_State* L, int idx, float& x, float& y) {
    auto& a = LuaApi::instance();
    auto grab = [&](const char* k, float& o) {
        a.pushstring(L, k);
        a.gettable(L, idx);
        if (a.type(L, -1) == LUA_TNUMBER)
            o = (float)a.tonumber(L, -1);
        a.pop(L, 1);
    };
    grab("X", x); grab("x", x);
    grab("Y", y); grab("y", y);
    a.pushnumber(L, 1);
    a.gettable(L, idx);
    if (a.type(L, -1) == LUA_TNUMBER)
        x = (float)a.tonumber(L, -1);
    a.pop(L, 1);
    a.pushnumber(L, 2);
    a.gettable(L, idx);
    if (a.type(L, -1) == LUA_TNUMBER)
        y = (float)a.tonumber(L, -1);
    a.pop(L, 1);
}

void read_color(lua_State* L, int idx, Color4& c) {
    auto& a = LuaApi::instance();
    auto grab = [&](const char* k, float& o) {
        a.pushstring(L, k);
        a.gettable(L, idx);
        if (a.type(L, -1) == LUA_TNUMBER)
            o = chan((float)a.tonumber(L, -1));
        a.pop(L, 1);
    };
    grab("R", c.r); grab("r", c.r);
    grab("G", c.g); grab("g", c.g);
    grab("B", c.b); grab("b", c.b);
    grab("A", c.a); grab("a", c.a);
}

int drawing_index(lua_State* L) {
    auto& a = LuaApi::instance();
    const int id = obj_id(L, 1);
    const char* k = a.tostring(L, 2);
    std::lock_guard lock(g_mtx);
    auto* o = get_obj(id);
    if (!o || !k)
        return 0;
    const std::string key = k;
    if (key == "Remove" || key == "Destroy") {
        a.getfield(L, LUA_GLOBALSINDEX, "__vt_draw_remove");
        return 1;
    }
    if (key == "Visible") { a.pushboolean(L, o->visible); return 1; }
    if (key == "Thickness") { a.pushnumber(L, o->thickness); return 1; }
    if (key == "Size") { a.pushnumber(L, o->size); return 1; }
    if (key == "Filled") { a.pushboolean(L, o->filled); return 1; }
    if (key == "Text") { a.pushstring(L, o->text.c_str()); return 1; }
    if (key == "Radius") { a.pushnumber(L, o->radius); return 1; }
    if (key == "Transparency") { a.pushnumber(L, 1.0 - o->color.a); return 1; }
    if (key == "ZIndex") { a.pushnumber(L, o->z); return 1; }
    if (key == "Font") { a.pushnumber(L, o->font); return 1; }
    if (key == "Outline") { a.pushboolean(L, o->outline); return 1; }
    if (key == "Center") { a.pushboolean(L, o->filled); return 1; }
    a.pushnil(L);
    return 1;
}

int drawing_newindex(lua_State* L) {
    auto& a = LuaApi::instance();
    const int id = obj_id(L, 1);
    const char* k = a.tostring(L, 2);
    std::lock_guard lock(g_mtx);
    auto* o = get_obj(id);
    if (!o || !k)
        return 0;
    const std::string key = k;
    if (key == "Visible") o->visible = a.toboolean(L, 3) != 0;
    else if (key == "Thickness") o->thickness = (float)a.tonumber(L, 3);
    else if (key == "Size") {
        if (a.type(L, 3) == LUA_TNUMBER)
            o->size = (float)a.tonumber(L, 3);
        else
            read_xy(L, 3, o->x2, o->y2);
    }
    else if (key == "Filled" || key == "Center") o->filled = a.toboolean(L, 3) != 0;
    else if (key == "Text") o->text = a.tostring(L, 3);
    else if (key == "Radius") o->radius = (float)a.tonumber(L, 3);
    else if (key == "Transparency") o->color.a = 1.f - (float)a.tonumber(L, 3);
    else if (key == "ZIndex") o->z = (int)a.tonumber(L, 3);
    else if (key == "Font") o->font = (int)a.tonumber(L, 3);
    else if (key == "Outline") o->outline = a.toboolean(L, 3) != 0;
    else if (key == "From" || key == "Position" || key == "PointA")
        read_xy(L, 3, o->x1, o->y1);
    else if (key == "To" || key == "PointB")
        read_xy(L, 3, o->x2, o->y2);
    else if (key == "PointC")
        read_xy(L, 3, o->x3, o->y3);
    else if (key == "PointD")
        read_xy(L, 3, o->x4, o->y4);
    else if (key == "Color")
        read_color(L, 3, o->color);
    else if (key == "OutlineColor")
        read_color(L, 3, o->ocol);
    return 0;
}

int drawing_remove(lua_State* L) {
    const int id = obj_id(L, 1);
    std::lock_guard lock(g_mtx);
    g_objects.erase(id);
    recount_locked();
    return 0;
}

int drawing_new(lua_State* L) {
    auto& a = LuaApi::instance();
    const std::string kind = a.tostring(L, 1);
    DrawObject o;
    if (kind == "Line") o.type = DK_LINE;
    else if (kind == "Square") o.type = DK_SQUARE;
    else if (kind == "Quad") o.type = DK_QUAD;
    else if (kind == "Circle") o.type = DK_CIRCLE;
    else if (kind == "Text") o.type = DK_TEXT;
    else if (kind == "Triangle") o.type = DK_TRIANGLE;
    else o.type = DK_LINE;

    int id = 0;
    {
        std::lock_guard lock(g_mtx);
        id = g_next++;
        g_objects[id] = std::move(o);
        recount_locked();
    }

    a.newtable(L);
    a.pushnumber(L, (lua_Number)id);
    a.setfield(L, -2, "__id");
    a.pushcfunction(L, drawing_remove, "Remove");
    a.setfield(L, -2, "Remove");
    a.pushcfunction(L, drawing_remove, "Destroy");
    a.setfield(L, -2, "Destroy");
    a.newtable(L);
    a.pushcfunction(L, drawing_index, "__index");
    a.setfield(L, -2, "__index");
    a.pushcfunction(L, drawing_newindex, "__newindex");
    a.setfield(L, -2, "__newindex");
    a.setmetatable(L, -2);
    return 1;
}

int drawing_clear(lua_State*) {
    std::lock_guard lock(g_mtx);
    g_objects.clear();
    recount_locked();
    return 0;
}

uint8_t to8(float v) {
    if (v < 0) v = 0;
    if (v > 1) v = 1;
    return (uint8_t)(v * 255.f + 0.5f);
}

} // namespace

void set_draw_sink(std::function<void(std::string)> sink) {
    g_sink = std::move(sink);
}

void register_drawing(lua_State* L) {
    auto& a = LuaApi::instance();
    a.pushcfunction(L, drawing_remove, "__vt_draw_remove");
    a.setglobal(L, "__vt_draw_remove");

    a.newtable(L);
    a.pushcfunction(L, drawing_new, "new");
    a.setfield(L, -2, "new");
    a.pushcfunction(L, drawing_clear, "clear");
    a.setfield(L, -2, "clear");
    a.newtable(L);
    a.pushnumber(L, 0); a.setfield(L, -2, "UI");
    a.pushnumber(L, 1); a.setfield(L, -2, "System");
    a.pushnumber(L, 2); a.setfield(L, -2, "Plex");
    a.pushnumber(L, 3); a.setfield(L, -2, "Monospace");
    a.setfield(L, -2, "Fonts");
    a.setglobal(L, "Drawing");

    a.pushcfunction(L, drawing_clear, "cleardrawcache");
    a.setglobal(L, "cleardrawcache");
}

bool drawing_live() {
    return g_nobj.load(std::memory_order_relaxed) > 0;
}

void render_drawings() {
    if (!g_sink)
        return;
    if (!drawing_live()) {
        if (g_sent_empty.exchange(true, std::memory_order_relaxed))
            return;
        g_sink(pack_draws({}));
        return;
    }
    g_sent_empty.store(false, std::memory_order_relaxed);
    std::vector<DrawItem> snap;
    {
        std::lock_guard lock(g_mtx);
        snap.reserve(g_objects.size());
        for (auto& kv : g_objects) {
            auto& o = kv.second;
            if (!o.visible)
                continue;
            DrawItem it;
            it.p.kind = (uint8_t)o.type;
            it.p.flags = DF_VIS;
            if (o.filled) it.p.flags = (uint8_t)(it.p.flags | DF_FILL);
            if (o.outline) it.p.flags = (uint8_t)(it.p.flags | DF_OUT);
            it.p.r = to8(o.color.r); it.p.g = to8(o.color.g);
            it.p.b = to8(o.color.b); it.p.a = to8(o.color.a);
            it.p.or_ = to8(o.ocol.r); it.p.og = to8(o.ocol.g);
            it.p.ob = to8(o.ocol.b); it.p.oa = to8(o.ocol.a);
            it.p.thick = o.thickness;
            it.p.size = o.size;
            it.p.rad = o.radius > 0 ? o.radius : o.size;
            it.p.x1 = o.x1; it.p.y1 = o.y1;
            it.p.x2 = o.x2; it.p.y2 = o.y2;
            it.p.x3 = o.x3; it.p.y3 = o.y3;
            it.p.x4 = o.x4; it.p.y4 = o.y4;
            it.text = o.text;
            snap.push_back(std::move(it));
        }
    }
    g_sink(pack_draws(snap));
}

} // namespace vt::libs
