#pragma once

#include "lua/LuaApi.h"

#include <cstdint>
#include <string>
#include <vector>

namespace vt {

struct ScriptJob {
    uintptr_t job = 0;
    uintptr_t script_context = 0;
    lua_State* state = nullptr;
    std::string name;
};

// Walks Roblox TaskScheduler jobs looking for WaitingHybridScriptsJob /
// LuauJob / ScriptContext. Offsets live in OffsetTable and change weekly.
class Scheduler {
public:
    static uintptr_t task_scheduler();
    static std::vector<ScriptJob> jobs();
    static ScriptJob acquire_job();
    static lua_State* acquire_state();
    static lua_State* state_from(uintptr_t job);
    // Higher is safer to vtable-hook. 0 = skip.
    static int hook_rank(const std::string& name);
};

} // namespace vt
