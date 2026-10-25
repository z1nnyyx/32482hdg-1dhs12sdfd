// SPDX-License-Identifier: MIT
// VoidTrace mock-backend + sandbox smoke test. Minimal zero-dep harness
// that walks every state-machine branch the architecture brief requires
// evidence for. Build on any C++20 host — Linux, macOS, or MSVC. There
// is no Roblox dependency, no network, no filesystem write.
//
// Example build (Linux clang/gcc):
//   g++ -std=c++20 -I src -I src/xeno/vendor/include \
//       src/mock/MockBackend.cpp \
//       src/sandbox/LuauSandbox.cpp \
//       src/xeno/vendor/Luau/*.cpp \
//       tests/test_mock_and_sandbox.cpp -o tests/mock_smoke -lpthread
//   ./tests/mock_smoke
//
// Prints one PASS/FAIL line per case and exits non-zero on any failure.

#include "mock/MockBackend.h"
#include "sandbox/LuauSandbox.h"

#include <chrono>
#include <future>
#include <iostream>
#include <string>

using namespace std::chrono_literals;
using vt::mock::Scenario;
using vt::mock::BackendState;

static int g_fail = 0;
#define EXPECT(cond, msg)                                                 \
    do {                                                                  \
        if (!(cond)) {                                                    \
            ++g_fail;                                                     \
            std::cout << "  FAIL " << __LINE__ << " : " << msg << "\n";   \
        } else {                                                          \
            std::cout << "  pass " << __LINE__ << " : " << msg << "\n";   \
        }                                                                 \
    } while (0)

static void banner(const char* name) {
    std::cout << "\n[case] " << name << "\n";
}

static vt::mock::ExecResult wait_for(std::future<vt::mock::ExecResult>& f) {
    return f.get();
}

int main() {
    // 1. Sandbox compile — happy path
    banner("sandbox::check: valid Luau");
    {
        auto r = vt::sandbox::check("local x = 1 + 1 return x");
        EXPECT(r.ok, "valid source compiles");
        EXPECT(!r.bytecode.empty(), "bytecode present");
    }

    // 2. Sandbox compile — syntax error
    banner("sandbox::check: syntax error");
    {
        auto r = vt::sandbox::check("local x = ");
        EXPECT(!r.ok, "syntax error reported");
        EXPECT(!r.diagnostic.empty(), "diagnostic text present");
    }

    // 3. Sandbox run — compile-only build advertises itself
    banner("sandbox::run: compile-only build is honest about it");
    {
        auto r = vt::sandbox::run("print('hi')");
        EXPECT(r.ok, "run reports ok on valid source (compile pass)");
        EXPECT(r.stdout_text.find("compile-only") != std::string::npos,
               "stdout_text advertises compile-only build");
    }

    // 4. Mock: NoTarget scenario never promotes to BackendReady
    banner("mock: NoTarget stays in BackendStarting");
    {
        vt::mock::MockBackend b(Scenario::NoTarget);
        EXPECT(b.start(), "start returns true");
        std::this_thread::sleep_for(200ms);
        EXPECT(b.clients().empty(), "no clients populated");
        EXPECT(b.state() != BackendState::BackendReady,
               "state is NOT BackendReady");
    }

    // 5. Mock: TargetNotReady detects but handshake stays false
    banner("mock: TargetNotReady — target detected, handshake=false");
    {
        vt::mock::MockBackend b(Scenario::TargetNotReady);
        b.start();
        std::this_thread::sleep_for(300ms);
        auto rows = b.clients();
        EXPECT(rows.size() == 1, "exactly one row");
        EXPECT(!rows.front().handshake_complete,
               "handshake flag is false — UI must not label 'Attached'");
    }

    // 6. Mock: BackendReady happy path
    banner("mock: BackendReady — exec acks with request id");
    {
        vt::mock::MockBackend b(Scenario::BackendReady);
        b.start();
        std::this_thread::sleep_for(300ms);
        EXPECT(b.state() == BackendState::BackendReady, "state ready");
        auto f = b.execute("print(1+1)");
        auto r = wait_for(f);
        EXPECT(r.compile_ok, "compile ok");
        EXPECT(r.runtime_ok, "runtime ok");
        EXPECT(r.request_id == b.last_request_id(), "rid matches");
    }

    // 7. Mock: CompileError
    banner("mock: CompileError");
    {
        vt::mock::MockBackend b(Scenario::CompileError);
        b.start();
        std::this_thread::sleep_for(200ms);
        auto r = b.execute("return 1").get();
        EXPECT(!r.compile_ok, "compile_ok false");
        EXPECT(!r.error.empty(), "diagnostic present");
    }

    // 8. Mock: RuntimeError
    banner("mock: RuntimeError");
    {
        vt::mock::MockBackend b(Scenario::RuntimeError);
        b.start();
        std::this_thread::sleep_for(200ms);
        auto r = b.execute("return 1").get();
        EXPECT(r.compile_ok, "compile ok");
        EXPECT(!r.runtime_ok, "runtime_ok false");
        EXPECT(!r.error.empty(), "runtime error reported");
    }

    // 9. Mock: Timeout
    banner("mock: Timeout — no ack within timeout");
    {
        vt::mock::MockBackend b(Scenario::Timeout);
        b.start();
        std::this_thread::sleep_for(200ms);
        auto r = b.execute("return 1").get();
        EXPECT(r.timed_out, "timed_out set");
        EXPECT(!r.runtime_ok, "runtime_ok false");
    }

    // 10. Mock: MultipleTargets
    banner("mock: MultipleTargets");
    {
        vt::mock::MockBackend b(Scenario::MultipleTargets);
        b.start();
        std::this_thread::sleep_for(300ms);
        EXPECT(b.clients().size() == 3, "3 clients tracked");
        auto r = b.execute("return 1").get();
        EXPECT(r.actor.find("AltOne") != std::string::npos,
               "actor lists broadcast targets");
    }

    // 11. Mock: BridgeUnavailable
    banner("mock: BridgeUnavailable");
    {
        vt::mock::MockBackend b(Scenario::BridgeUnavailable);
        EXPECT(!b.start(), "start returns false");
        EXPECT(b.state() == BackendState::Failed, "state Failed");
    }

    // 12. Mock: ShutdownDuringTask
    banner("mock: ShutdownDuringTask — stop() interrupts in-flight exec");
    {
        auto b = std::make_unique<vt::mock::MockBackend>(
            Scenario::ShutdownDuringTask);
        b->start();
        std::this_thread::sleep_for(200ms);
        auto f = b->execute("return 1");
        std::this_thread::sleep_for(100ms);
        b->stop();
        auto r = f.get();
        EXPECT(r.timed_out, "timed_out set after shutdown");
    }

    std::cout << "\n";
    if (g_fail) {
        std::cout << g_fail << " failure(s)\n";
        return 1;
    }
    std::cout << "all cases pass\n";
    return 0;
}
