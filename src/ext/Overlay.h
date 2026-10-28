#pragma once

#include "ext/World.h"
#include "shared/DrawSnap.h"

#include <Windows.h>
#include <cstdint>
#include <climits>
#include <mutex>
#include <string>
#include <vector>

namespace vt::ext {

// Own-process overlay. Nothing is mapped into Roblox.
class Overlay {
public:
    static Overlay& instance();

    bool start(DWORD pid, uintptr_t image_base, size_t image_size, HWND game);
    void stop();
    bool running() const { return wnd_ != nullptr; }
    void set_game(HWND game) { game_ = game; }
    void set_host(HWND host) { host_ = host; }
    void set_esp(bool on) { esp_ = on; }
    bool esp() const { return esp_; }
    WorldStats stats() const { return world_.stats(); }
    uintptr_t script_job() { return world_.find_script_job(); }
    uintptr_t data_model() const { return world_.cached_data_model(); }
    void set_lua_draw(std::string blob);

    // In-game status chip (bottom-right of Roblox): shows VoidTrace,
    // the attach state, and the hooked username when known.
    void set_status(bool attached, std::string user, std::string backend) {
        std::lock_guard lock(status_mtx_);
        status_attached_ = attached;
        status_user_ = std::move(user);
        status_backend_ = std::move(backend);
    }

private:
    static LRESULT CALLBACK wndproc(HWND, UINT, WPARAM, LPARAM);
    void tick();
    void present(int w, int h);

    HWND    wnd_ = nullptr;
    HWND    game_ = nullptr;
    HWND    host_ = nullptr;
    World   world_;
    HFONT   font_ = nullptr;
    HDC     memdc_ = nullptr;
    HBITMAP dib_ = nullptr;
    HGDIOBJ oldbmp_ = nullptr;
    void*   bits_ = nullptr;
    int     dib_w_ = 0, dib_h_ = 0;
    bool    on_ = false;
    bool    shown_ = false;
    bool    esp_ = true;
    int     last_x_ = INT_MIN, last_y_ = 0, last_w_ = 0, last_h_ = 0;
    int     dirty_x0_ = 0, dirty_y0_ = 0, dirty_x1_ = 0, dirty_y1_ = 0;
    bool    dirty_any_ = false;
    DWORD   last_poll_ = 0;
    DWORD   attach_pid_ = 0;
    int     last_ents_ = 0;
    int     ent_sw_ = 0, ent_sh_ = 0;
    std::vector<Entity> ents_;
    std::mutex lua_mtx_;
    std::vector<DrawItem> lua_draw_;

    // Status chip state — drawn bottom-right of Roblox window.
    std::mutex status_mtx_;
    bool        status_attached_ = false;
    std::string status_user_;
    std::string status_backend_;
};

} // namespace vt::ext
