#include "lua/libs/Input.h"

#include <Windows.h>

namespace vt::libs {
namespace {

void send_mouse(DWORD flags) {
    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.dwFlags = flags;
    SendInput(1, &in, sizeof(INPUT));
}

void send_key(WORD vk, bool up) {
    INPUT in{};
    in.type = INPUT_KEYBOARD;
    in.ki.wVk = vk;
    in.ki.dwFlags = up ? KEYEVENTF_KEYUP : 0;
    SendInput(1, &in, sizeof(INPUT));
}

int l_mouse1click(lua_State*) {
    send_mouse(MOUSEEVENTF_LEFTDOWN);
    send_mouse(MOUSEEVENTF_LEFTUP);
    return 0;
}
int l_mouse1press(lua_State*) { send_mouse(MOUSEEVENTF_LEFTDOWN); return 0; }
int l_mouse1release(lua_State*) { send_mouse(MOUSEEVENTF_LEFTUP); return 0; }
int l_mouse2click(lua_State*) {
    send_mouse(MOUSEEVENTF_RIGHTDOWN);
    send_mouse(MOUSEEVENTF_RIGHTUP);
    return 0;
}
int l_mouse2press(lua_State*) { send_mouse(MOUSEEVENTF_RIGHTDOWN); return 0; }
int l_mouse2release(lua_State*) { send_mouse(MOUSEEVENTF_RIGHTUP); return 0; }

HWND game_hwnd() {
    struct Ctx { HWND h = nullptr; DWORD pid = GetCurrentProcessId(); };
    Ctx ctx;
    EnumWindows([](HWND w, LPARAM lp) -> BOOL {
        auto* c = (Ctx*)lp;
        DWORD pid = 0;
        GetWindowThreadProcessId(w, &pid);
        if (pid != c->pid || !IsWindowVisible(w))
            return TRUE;
        if (GetWindow(w, GW_OWNER))
            return TRUE;
        RECT rc{};
        GetClientRect(w, &rc);
        if (rc.right < 200 || rc.bottom < 200)
            return TRUE;
        c->h = w;
        return FALSE;
    }, (LPARAM)&ctx);
    return ctx.h;
}

int l_mousemoveabs(lua_State* L) {
    auto& a = LuaApi::instance();
    POINT p{(int)a.tonumber(L, 1), (int)a.tonumber(L, 2)};
    if (HWND w = game_hwnd())
        ClientToScreen(w, &p);
    SetCursorPos(p.x, p.y);
    return 0;
}

int l_getmousepos(lua_State* L) {
    auto& a = LuaApi::instance();
    POINT p{};
    GetCursorPos(&p);
    if (HWND w = game_hwnd())
        ScreenToClient(w, &p);
    a.pushnumber(L, (lua_Number)p.x);
    a.pushnumber(L, (lua_Number)p.y);
    return 2;
}

int l_mousemoverel(lua_State* L) {
    auto& a = LuaApi::instance();
    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.dwFlags = MOUSEEVENTF_MOVE;
    in.mi.dx = (LONG)a.tonumber(L, 1);
    in.mi.dy = (LONG)a.tonumber(L, 2);
    SendInput(1, &in, sizeof(INPUT));
    return 0;
}

int l_keypress(lua_State* L) {
    auto& a = LuaApi::instance();
    const WORD vk = (WORD)a.tonumber(L, 1);
    send_key(vk, false);
    send_key(vk, true);
    return 0;
}
int l_keypress_hold(lua_State* L) {
    auto& a = LuaApi::instance();
    send_key((WORD)a.tonumber(L, 1), false);
    return 0;
}
int l_keyrelease(lua_State* L) {
    auto& a = LuaApi::instance();
    send_key((WORD)a.tonumber(L, 1), true);
    return 0;
}

int l_isrbxactive(lua_State* L) {
    auto& a = LuaApi::instance();
    HWND fg = GetForegroundWindow();
    DWORD pid = 0;
    GetWindowThreadProcessId(fg, &pid);
    a.pushboolean(L, pid == GetCurrentProcessId() ? 1 : 0);
    return 1;
}

} // namespace

void register_input(lua_State* L) {
    auto& a = LuaApi::instance();
    struct { const char* n; lua_CFunction f; } fns[] = {
        {"mouse1click", l_mouse1click},
        {"mouse1press", l_mouse1press},
        {"mouse1down", l_mouse1press},
        {"mouse1up", l_mouse1release},
        {"mouse1release", l_mouse1release},
        {"mouse2click", l_mouse2click},
        {"mouse2press", l_mouse2press},
        {"mouse2down", l_mouse2press},
        {"mouse2up", l_mouse2release},
        {"mouse2release", l_mouse2release},
        {"mousemoveabs", l_mousemoveabs},
        {"mousemoverel", l_mousemoverel},
        {"getmouseposition", l_getmousepos},
        {"getmousepos", l_getmousepos},
        {"keypress", l_keypress},
        {"keyclick", l_keypress},
        {"keypress_hold", l_keypress_hold},
        {"keyrelease", l_keyrelease},
        {"isrbxactive", l_isrbxactive},
        {"isgameactive", l_isrbxactive},
    };
    for (auto& f : fns) {
        a.pushcfunction(L, f.f, f.n);
        a.setglobal(L, f.n);
    }
}

} // namespace vt::libs
