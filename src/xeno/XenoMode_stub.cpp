// SPDX-License-Identifier: MIT
// VoidTrace facade — compile-friendly stub.
//
// Provides every symbol App.cpp references from vt::xeno:: without
// pulling in the heavy external backend (which would need vcpkg
// openssl + zstd + xxhash + httplib). The full backend lives at
// XenoMode.cpp and the vendored Xeno sources; wire those into the
// vcxproj + vcpkg manifest when you want the live Roblox driver.
//
// With this stub linked, the host still runs end-to-end. The internal
// manual-map DLL backend is unchanged. The xeno path simply reports
// "nothing attached" and compile-checks source only.

#include "xeno/XenoMode.h"
#include "sandbox/LuauSandbox.h"
#include "shared/Log.h"

#include <atomic>

namespace vt::xeno {

static std::atomic<bool> g_running{false};

bool start() {
    g_running.store(true);
    VT_LOG(L"voidtrace: facade online (stub backend; internal manual-map still active)");
    return true;
}

void stop() {
    g_running.store(false);
}

bool is_running() {
    return g_running.load();
}

std::vector<ClientRow> clients() {
    // Stub never tracks any clients — the internal backend handles
    // attach via its own path. Returning empty keeps App.cpp from
    // short-circuiting to a non-existent external attach.
    return {};
}

std::size_t execute(const std::string& source,
                    const std::vector<std::string>& /*targets*/) {
    if (source.empty())
        return 0;
    // Compile-check only. Returns 0 so the UI reports "nothing
    // dispatched" and falls through to the internal backend.
    auto cr = vt::sandbox::check(source);
    if (!cr.ok)
        VT_WARN(L"voidtrace stub: compile diagnostic: " +
                std::wstring(cr.diagnostic.begin(), cr.diagnostic.end()));
    return 0;
}

std::string compilable(const std::string& source) {
    auto cr = vt::sandbox::check(source);
    return cr.ok ? std::string("success") : cr.diagnostic;
}

} // namespace vt::xeno
