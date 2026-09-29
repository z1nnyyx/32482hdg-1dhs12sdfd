#pragma once

#include "ext/Memory.h"

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace vt::ext {

struct Vec2 { float x = 0, y = 0; };
struct Vec3 { float x = 0, y = 0, z = 0; };

struct Entity {
    uintptr_t player = 0;
    uintptr_t character = 0;
    std::string name;
    Vec3 pos{};
    float health = 0, max_health = 0;
    bool local = false;
    bool has_pos = false;
};

struct WorldStats {
    bool    attached = false;
    bool    datamodel = false;
    bool    visual = false;
    bool    players_svc = false;
    int     entities = 0;
    wchar_t note[64]{};
};

class World {
public:
    bool attach(DWORD pid, uintptr_t image_base, size_t image_size = 0);
    void detach();
    bool ok() const { return mem_.ok() && base_; }

    bool poll(std::vector<Entity>& out, int* screen_w, int* screen_h);
    bool world_to_screen(const Vec3& w, Vec2& s) const;
    WorldStats stats() const { return stats_; }
    uintptr_t find_script_job() const;
    DWORD find_lua_tid(uintptr_t lua_pcall, uintptr_t luau_load) const;
    uintptr_t find_lua_state(uintptr_t job) const;
    bool execute_script(const std::string& source, std::wstring* err);
    void set_fallback_size(float w, float h) { if (w > 64 && h > 64) { width_ = w; height_ = h; } }

private:
    std::string class_name(uintptr_t inst) const;
    std::string inst_name(uintptr_t inst) const;
    void children_of(uintptr_t inst, std::vector<uintptr_t>& out) const;
    uintptr_t find_child_class(uintptr_t inst, const char* cls) const;
    uintptr_t find_child_name(uintptr_t inst, const char* name) const;
    bool part_pos(uintptr_t part, Vec3& out) const;
    bool looks_dm(uintptr_t dm) const;
    bool looks_place(uintptr_t dm) const;
    int  place_score(uintptr_t dm) const;
    bool looks_instance(uintptr_t p) const;
    uintptr_t find_service(uintptr_t dm, const char* name) const;
    uintptr_t discover_datamodel();
    uintptr_t resolve_datamodel();
    uintptr_t resolve_from_scheduler();
    uintptr_t resolve_visual();
    uintptr_t resolve_players(uintptr_t dm);

    struct Tracked {
        Entity    e;
        uintptr_t part = 0;
        uintptr_t hum = 0;
    };

    Memory     mem_;
    uintptr_t  base_ = 0;
    size_t     size_ = 0;
    bool       dm_scan_done_ = false;
    float      view_[16]{};
    float      width_ = 1920, height_ = 1080;
    WorldStats stats_{};
    uintptr_t  cached_dm_ = 0;
    uintptr_t  cached_ve_ = 0;
    uintptr_t  cached_players_ = 0;
    DWORD      last_dm_check_ = 0;
    DWORD      last_tree_ = 0;
    std::vector<Tracked> tracked_;
};

} // namespace vt::ext
