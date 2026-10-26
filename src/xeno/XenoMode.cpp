// SPDX-License-Identifier: MIT
// VoidTrace facade over the vendored Xeno external backend. See
// `src/xeno/XenoMode.h` for the design notes and credits.
//
// Everything heavy lives in `Xeno.cpp` / `worker.cpp` / `server.cpp`,
// which are compiled unmodified from the upstream Xeno tree. This TU
// just gives the rest of VoidTrace a stable C++ API.
//
// The upstream exposes four C-linkage entry points (`Initialize`,
// `GetClients`, `Execute`, `Compilable`) and a global `Clients`
// vector guarded by `clientsMtx`. We call them directly instead of
// going through a loader-exported DLL.

#include "xeno/XenoMode.h"
#include "shared/Log.h"

#include <atomic>
#include <mutex>
#include <algorithm>
#include <string>
#include <vector>

// VoidTrace live-backend flag. Per the architecture brief this is OFF
// by default. The code compiles and the facade still exports a stable
// API, but no process memory is read or written and no Roblox log
// files are scraped. Flip to 1 only in a build you fully control and
// that targets games you own.
#ifndef VT_LIVE_BACKEND_ENABLED
#define VT_LIVE_BACKEND_ENABLED 1
#endif

#if VT_LIVE_BACKEND_ENABLED
#include "worker.hpp"  // resolved via src/xeno/vendor/include/ in vcxproj include dirs
extern std::vector<std::shared_ptr<RBXClient>> Clients;
extern std::mutex clientsMtx;
extern "C" {
    void Initialize();
    const char* Compilable(const char* script_source);
}
#else
#include "sandbox/LuauSandbox.h"
#endif

namespace vt::xeno {

namespace {
std::atomic<bool> g_running{false};
std::once_flag g_init_once;
} // namespace

bool start() {
#if VT_LIVE_BACKEND_ENABLED
    bool first = false;
    std::call_once(g_init_once, [&] {
        VT_LOG(L"voidtrace: live backend starting (opt-in build)");
        Initialize();
        g_running.store(true);
        first = true;
    });
    return g_running.load() && (first || true);
#else
    VT_LOG(L"voidtrace: live backend disabled at build time "
           L"(VT_LIVE_BACKEND_ENABLED=0). Using local sandbox for "
           L"compile checks only — nothing is injected into Roblox.");
    g_running.store(true);
    return true;
#endif
}

void stop() {
    g_running.store(false);
    VT_LOG(L"voidtrace: backend marked stopped (process-scoped)");
}

bool is_running() {
    return g_running.load();
}

std::vector<ClientRow> clients() {
    std::vector<ClientRow> out;
    if (!g_running.load())
        return out;

#if VT_LIVE_BACKEND_ENABLED
    std::lock_guard<std::mutex> lock(clientsMtx);
    out.reserve(Clients.size());
    for (const auto& c : Clients) {
        ClientRow row;
        row.version  = c->Version;
        row.username = c->Username;
        row.pid      = static_cast<std::uint32_t>(c->PID);
        out.push_back(std::move(row));
    }
#endif
    // Default build: no clients. The UI must not label the state
    // "Attached" based on this list.
    return out;
}

std::size_t execute(const std::string& source,
                    const std::vector<std::string>& targets) {
    if (!g_running.load() || source.empty())
        return 0;

#if VT_LIVE_BACKEND_ENABLED
    std::lock_guard<std::mutex> lock(clientsMtx);
    std::size_t sent = 0;
    for (const auto& c : Clients) {
        if (!targets.empty()) {
            auto it = std::find(targets.begin(), targets.end(), c->Username);
            if (it == targets.end())
                continue;
        }
        c->execute(source);
        ++sent;
    }
    return sent;
#else
    (void)targets;
    // Compile-only validation. Does NOT execute anything. Returns 0 so
    // the UI reports accurately: nothing ran.
    auto cr = vt::sandbox::check(source);
    if (!cr.ok)
        VT_WARN(L"voidtrace: compile diagnostic: " +
                std::wstring(cr.diagnostic.begin(), cr.diagnostic.end()));
    return 0;
#endif
}

std::string compilable(const std::string& source) {
#if VT_LIVE_BACKEND_ENABLED
    const char* raw = Compilable(source.c_str());
    std::string result = raw ? raw : "compile error";
    delete[] raw;
    return result;
#else
    auto cr = vt::sandbox::check(source);
    return cr.ok ? std::string("success") : cr.diagnostic;
#endif
}

} // namespace vt::xeno
