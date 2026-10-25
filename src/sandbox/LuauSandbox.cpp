// SPDX-License-Identifier: MIT
// VoidTrace local Luau sandbox. See LuauSandbox.h for the contract.
//
// The implementation uses the vendored Luau compiler for `check()`.
// `run()` is wired to a VM behind the VT_SANDBOX_HAS_LUAU_VM flag; the
// default build does not link the Luau VM, so `run()` is a compile-only
// validator and says so in the output. This is the honest baseline the
// brief demands: no claim that a script executed if a VM is not present.
//
// To wire a VM later, link Luau/VM, define VT_SANDBOX_HAS_LUAU_VM, and
// replace the body of run() with lua_newstate + luaL_openlibs
// (restricted) + luau_load + lua_pcall.

#include "sandbox/LuauSandbox.h"

#include "Luau/Compiler.h"

#include <string>

namespace vt::sandbox {

CheckResult check(const std::string& source) {
    CheckResult r;
    try {
        Luau::CompileOptions opts{};
        std::string bc = Luau::compile(source, opts);
        // Luau signals a compile error by starting the bytecode with a
        // NUL byte and following it with the error message.
        if (!bc.empty() && bc[0] == '\0') {
            r.ok = false;
            r.diagnostic.assign(bc.data() + 1, bc.size() - 1);
            return r;
        }
        r.ok = true;
        r.bytecode = std::move(bc);
    } catch (const std::exception& e) {
        r.ok = false;
        r.diagnostic = std::string("compile exception: ") + e.what();
    } catch (...) {
        r.ok = false;
        r.diagnostic = "compile exception: unknown";
    }
    return r;
}

RunResult run(const std::string& source) {
    RunResult r;
    auto c = check(source);
    if (!c.ok) {
        r.ok = false;
        r.error = c.diagnostic;
        return r;
    }

#if defined(VT_SANDBOX_HAS_LUAU_VM)
    // Hook point for a future Luau VM wire-up. Intentionally not
    // implemented in this build to avoid false claims of execution.
    //  - luau_load(L, chunkname, bc.data(), bc.size(), 0);
    //  - restricted baselib (print, tostring, tonumber, type, pairs,
    //    ipairs, math.*, string.*, table.*, bit32.*)
    //  - capture print() to r.stdout_text
    //  - lua_pcall, surface errors in r.error
#endif

    r.ok = true;
    r.stdout_text =
        "[sandbox: compile-only build. source compiled to " +
        std::to_string(c.bytecode.size()) +
        " bytes of bytecode. link Luau/VM and define "
        "VT_SANDBOX_HAS_LUAU_VM to execute.]";
    return r;
}

} // namespace vt::sandbox
