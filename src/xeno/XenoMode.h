// SPDX-License-Identifier: MIT
// VoidTrace — external execution backend ported from Xeno by tyronetheqt
// Original method credit: Incognito-Roblox/Incognito.
//
// This header exposes a clean VoidTrace-facing surface over the vendored
// Xeno core (`src/xeno/vendor/`) and the ported glue (`Xeno.cpp`,
// `worker.cpp`, `server.cpp`). Nothing injects a DLL — this backend
// drives Roblox entirely with cross-process memory writes against
// `RobloxPlayerBeta.exe`, matching the Xeno design:
//
//   1. Scan `%LOCALAPPDATA%\Roblox\logs\*.log` for the RenderView pointer
//      printed by `SurfaceController[_:1]::initialize view(0x...)`.
//   2. Walk the Instance tree via hardcoded offsets (`offsets::*`) to
//      reach `CoreGui.RobloxGui.Modules.Common.Url` and, in-game,
//      `StarterPlayer.StarterPlayerScripts.PlayerModule.ControlModule.VRNavigation`.
//   3. Compile a bootstrap `client.lua` to Luau bytecode with the bundled
//      compiler, XOR-obfuscate the opcode stream (op *= 227), prefix an
//      `RSB1` header, zstd-compress, re-XOR the whole blob with a
//      `xxh32(..., 42)`-keyed stream.
//   4. `VirtualAllocEx` a page in the Roblox process, write the blob,
//      then rewrite the target `ModuleScript`'s `Bytecode` / `BytecodeSize`
//      fields so Roblox's own loader picks it up on next invocation.
//   5. The bootstrap client.lua creates `RobloxReplicatedStorage.Xeno`
//      and polls a localhost HTTP server (`setup_connection`) for scripts.
//
// VoidTrace calls `vt::xeno::start()` once at app launch when the user
// toggles **External Mode**; `execute()` pushes a script to every
// attached client. The internal manual-map/LoadLibrary path stays intact
// — the two backends coexist and the UI picks between them per attach.
//
// See `src/xeno/LICENSE.Xeno` for the upstream MIT notice.

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace vt::xeno {

struct ClientRow {
    std::string version;   // Roblox Versions folder name
    std::string username;  // LocalPlayer.Name
    std::uint32_t pid{};   // RobloxPlayerBeta.exe PID
};

// Starts the background client-tracker and the httplib bridge. Idempotent;
// the second call is a no-op. Returns true if the external mode is live.
bool start();

// Stops the tracker thread, closes the bridge, releases per-client handles.
void stop();

// Snapshot of currently-attached clients. Safe to call from any thread.
std::vector<ClientRow> clients();

// Queue a Luau script against every PID whose username is in `targets`.
// Pass an empty vector to broadcast to all attached clients.
// Returns the number of clients the script was dispatched to.
std::size_t execute(const std::string& source,
                    const std::vector<std::string>& targets = {});

// Validates a Luau source string against the bundled compiler. Returns
// "success" on OK, otherwise the compile diagnostic. Useful for the
// editor's syntax-check button.
std::string compilable(const std::string& source);

// True when start() succeeded and the tracker is running.
bool is_running();

} // namespace vt::xeno
