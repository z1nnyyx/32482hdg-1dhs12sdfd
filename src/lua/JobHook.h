#pragma once

#include <atomic>
#include <cstdint>
#include <Windows.h>

namespace vt {

// Set to true by pulse() the first time seh_pump runs successfully — signals
// the render-thread tick to send an ExtHookUnpatch message to the exe.
inline std::atomic<bool> g_pump_ran{false};

// Diagnostic: incremented on every pulse() invocation (across all threads).
// Read+logged by the render tick to determine if our ExtHook stub is firing.
extern std::atomic<uint32_t> g_pulse_hits;

// PeekMessage is pipe-only. Pump on the script job thread: CFG vtable
// gadget if the host found one, else PAGE_GUARD Rip-redirect (never APC).
class JobHook {
public:
    static void arm(uintptr_t job);
    static void install_game_hooks();   // install game-IAT hooks eagerly (no job needed)
    static void set_lua_tid(DWORD tid);
    static void set_lua_state(uintptr_t L);
    static void tick();
    static void pulse();
    static void kick(uintptr_t hint);   // force one pump from any thread (render-thread bootstrap)
    static void remove();
    static bool armed();
    static bool probing();
};

} // namespace vt
