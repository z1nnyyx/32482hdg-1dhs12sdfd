// SPDX-License-Identifier: MIT
// VoidTrace local Luau sandbox. In-process, no Roblox, no network,
// no file I/O beyond what the host explicitly injects.
//
// This is the "standalone Luau test runner/sandbox" the brief asks
// for. It uses the vendored Luau compiler (`src/xeno/vendor/Luau/`) to
// validate source, and — on hosts that link an embedded Luau VM — can
// actually execute it against a limited standard environment.
//
// Honest limitation: this repository vendors the Luau **compiler** only
// (no VM). `run()` therefore degrades to a compile-only validator and
// returns `ok=true` with `stdout_text="[sandbox: compile-only build;
// link Luau/VM to execute]"`. The surface is designed so a VM wired-up
// drop-in (lua_State + minimal `print`/`type`/`tostring` baselib) can
// replace the body of `run()` without touching callers.
//
// Default-exposed baseline (when a VM is linked):
//   print, tostring, tonumber, type, pairs, ipairs, next, select,
//   math.*, string.*, table.*, bit32.*
//
// Default-DISABLED:
//   getfenv/setfenv, loadstring/load/loadfile, dofile, require,
//   os.*, io.*, debug.*, package.*, coroutine.* (opt-in), FFI,
//   anything that touches the filesystem, network, or process.

#pragma once

#include <string>

namespace vt::sandbox {

struct CheckResult {
    bool ok{};
    std::string diagnostic;   // compile diagnostic text when !ok
    std::string bytecode;     // compiled bytecode (opaque) when ok
};

struct RunResult {
    bool ok{};
    std::string stdout_text;  // captured print() output
    std::string error;        // runtime error if !ok
};

// Validates `source` with the Luau compiler. Does not execute anything.
// Safe to call on any input, including untrusted strings.
CheckResult check(const std::string& source);

// Executes `source` in the embedded Luau VM if one is linked into the
// build. If no VM is linked, degrades to compile-only validation and
// records that in `stdout_text`. Does NOT touch Roblox, the network,
// the filesystem, or any other process.
RunResult run(const std::string& source);

} // namespace vt::sandbox
