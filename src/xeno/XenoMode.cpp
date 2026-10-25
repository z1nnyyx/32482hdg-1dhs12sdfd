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
#include "xeno/vendor/worker.hpp"
#include "shared/Log.h"

#include <atomic>
#include <mutex>
#include <algorithm>

// Pulled in from the upstream Xeno TUs so we can broadcast without a
// per-client user list — identical semantics to tyronetheqt/Xeno's
// server.cpp `/execute` handler.
extern std::vector<std::shared_ptr<RBXClient>> Clients;
extern std::mutex clientsMtx;

extern "C" {
    void Initialize();
    ClientInfo* GetClients();
    const char* Compilable(const char* script_source);
}

namespace vt::xeno {

namespace {
std::atomic<bool> g_running{false};
std::once_flag g_init_once;
} // namespace

bool start() {
    bool first = false;
    std::call_once(g_init_once, [&] {
        VT_LOG(L"xeno: starting external execution backend");
        Initialize();              // spawns the Roblox-tracker + bridge
        g_running.store(true);
        first = true;
    });
    return g_running.load() && (first || true);
}

void stop() {
    // The upstream `init()` thread is detached and the httplib server
    // blocks indefinitely; stopping it cleanly requires reaching into
    // internals the upstream did not expose. For VoidTrace's lifetime
    // model (process-scoped) we flip the flag; sockets and handles are
    // reclaimed when the exe exits.
    g_running.store(false);
    VT_LOG(L"xeno: external backend marked stopped (process-scoped)");
}

bool is_running() {
    return g_running.load();
}

std::vector<ClientRow> clients() {
    std::vector<ClientRow> out;
    if (!g_running.load())
        return out;

    std::lock_guard<std::mutex> lock(clientsMtx);
    out.reserve(Clients.size());
    for (const auto& c : Clients) {
        ClientRow row;
        row.version  = c->Version;
        row.username = c->Username;
        row.pid      = static_cast<std::uint32_t>(c->PID);
        out.push_back(std::move(row));
    }
    return out;
}

std::size_t execute(const std::string& source,
                    const std::vector<std::string>& targets) {
    if (!g_running.load() || source.empty())
        return 0;

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
}

std::string compilable(const std::string& source) {
    const char* raw = Compilable(source.c_str());
    std::string result = raw ? raw : "compile error";
    // Upstream `new[]`s the buffer in `Xeno.cpp::Compilable` — mirror its
    // ownership so we don't leak between syntax-check clicks.
    delete[] raw;
    return result;
}

} // namespace vt::xeno
