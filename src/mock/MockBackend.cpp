// SPDX-License-Identifier: MIT
// VoidTrace mock backend implementation. See MockBackend.h for the
// contract. Everything in here runs in-process and touches nothing
// outside the TU's own threads and buffers.

#include "mock/MockBackend.h"
#include "sandbox/LuauSandbox.h"

#include <chrono>
#include <condition_variable>

namespace vt::mock {

using namespace std::chrono_literals;

MockBackend::MockBackend(Scenario s) : scenario_(s) {}
MockBackend::~MockBackend() { stop(); }

bool MockBackend::start() {
    if (running_.exchange(true))
        return state_.load() != BackendState::Failed;

    state_.store(BackendState::BackendStarting);

    if (scenario_ == Scenario::BridgeUnavailable) {
        state_.store(BackendState::Failed);
        running_.store(false);
        return false;
    }

    tracker_ = std::jthread([this](std::stop_token st) { tracker_loop(st); });
    return true;
}

void MockBackend::stop() {
    if (!running_.exchange(false))
        return;
    state_.store(BackendState::ShuttingDown);
    if (tracker_.joinable()) {
        tracker_.request_stop();
        tracker_.join();
    }
    state_.store(BackendState::Idle);
}

void MockBackend::tracker_loop(std::stop_token st) {
    // Simulate the time it takes a real tracker to notice a client.
    for (int i = 0; i < 2 && !st.stop_requested(); ++i)
        std::this_thread::sleep_for(50ms);
    if (st.stop_requested()) return;

    switch (scenario_) {
        case Scenario::NoTarget:
            // Never populate clients_. Stay in BackendStarting.
            while (!st.stop_requested())
                std::this_thread::sleep_for(100ms);
            return;

        case Scenario::TargetNotReady: {
            std::lock_guard<std::mutex> lock(clients_mtx_);
            clients_.push_back({"version-mock", "Guest123", 1234, /*handshake=*/false});
            state_.store(BackendState::TargetDetected);
            break;
        }

        case Scenario::MultipleTargets: {
            std::lock_guard<std::mutex> lock(clients_mtx_);
            clients_.push_back({"version-mock", "AltOne",  1001, true});
            clients_.push_back({"version-mock", "AltTwo",  1002, true});
            clients_.push_back({"version-mock", "AltThree",1003, true});
            state_.store(BackendState::BackendReady);
            break;
        }

        default: {
            std::lock_guard<std::mutex> lock(clients_mtx_);
            clients_.push_back({"version-mock", "DevUser", 4242, true});
            state_.store(BackendState::BackendReady);
            break;
        }
    }

    while (!st.stop_requested())
        std::this_thread::sleep_for(100ms);
}

std::vector<ClientRow> MockBackend::clients() const {
    std::lock_guard<std::mutex> lock(clients_mtx_);
    return clients_;
}

std::future<ExecResult> MockBackend::execute(const std::string& source) {
    const std::uint64_t rid = ++last_rid_;
    return std::async(std::launch::async, [this, rid, source] {
        return simulate_exec(rid, source);
    });
}

ExecResult MockBackend::simulate_exec(std::uint64_t rid, const std::string& source) {
    ExecResult r;
    r.request_id = rid;

    // Shared compile step for every scenario — brutally honest: either
    // the source compiles or it does not. We use the real sandbox so
    // the same compiler the UI shows diagnostics for runs the test.
    auto compile = vt::sandbox::check(source);
    r.compile_ok = compile.ok;
    if (!compile.ok) {
        r.error = compile.diagnostic;
        return r;
    }

    switch (scenario_) {
        case Scenario::CompileError:
            // Force a compile failure even if the real source would pass,
            // to let the UI exercise this branch deterministically.
            r.compile_ok = false;
            r.error = "mock: forced compile diagnostic";
            return r;

        case Scenario::RuntimeError:
            r.runtime_ok = false;
            r.error = "mock: runtime exception at line 1";
            r.actor = "DevUser";
            return r;

        case Scenario::Timeout:
            std::this_thread::sleep_for(1500ms);
            r.timed_out = true;
            r.error = "mock: no acknowledgement within timeout";
            return r;

        case Scenario::ClientExitMidRequest:
            std::this_thread::sleep_for(300ms);
            r.timed_out = true;
            r.error = "mock: client exited during request";
            return r;

        case Scenario::ShutdownDuringTask:
            while (running_.load())
                std::this_thread::sleep_for(50ms);
            r.timed_out = true;
            r.error = "mock: backend shut down during task";
            return r;

        case Scenario::MultipleTargets: {
            r.runtime_ok = true;
            r.actor = "AltOne,AltTwo,AltThree";
            r.output = "[mock] broadcast to 3 clients: `" + source.substr(0, 40) + "`";
            return r;
        }

        case Scenario::SuccessWithOutput: {
            auto run = vt::sandbox::run(source);
            r.runtime_ok = run.ok;
            r.output = run.stdout_text;
            r.error = run.error;
            r.actor = "DevUser";
            return r;
        }

        case Scenario::NoTarget:
        case Scenario::TargetNotReady:
            r.timed_out = true;
            r.error = "mock: no ready client to receive request";
            return r;

        case Scenario::BridgeUnavailable:
            r.error = "mock: bridge never bound";
            return r;

        case Scenario::BackendReady:
        default: {
            auto run = vt::sandbox::run(source);
            r.runtime_ok = run.ok;
            r.output = run.stdout_text;
            r.error = run.error;
            r.actor = "DevUser";
            return r;
        }
    }
}

const char* to_string(BackendState s) {
    switch (s) {
        case BackendState::Idle:            return "Idle";
        case BackendState::BackendStarting: return "BackendStarting";
        case BackendState::TargetDetected:  return "TargetDetected";
        case BackendState::BackendReady:    return "BackendReady";
        case BackendState::Failed:          return "Failed";
        case BackendState::ShuttingDown:    return "ShuttingDown";
    }
    return "?";
}

const char* to_string(Scenario s) {
    switch (s) {
        case Scenario::NoTarget:              return "NoTarget";
        case Scenario::TargetNotReady:        return "TargetNotReady";
        case Scenario::BackendReady:          return "BackendReady";
        case Scenario::SuccessWithOutput:     return "SuccessWithOutput";
        case Scenario::CompileError:          return "CompileError";
        case Scenario::RuntimeError:          return "RuntimeError";
        case Scenario::Timeout:               return "Timeout";
        case Scenario::MultipleTargets:       return "MultipleTargets";
        case Scenario::ClientExitMidRequest:  return "ClientExitMidRequest";
        case Scenario::BridgeUnavailable:     return "BridgeUnavailable";
        case Scenario::ShutdownDuringTask:    return "ShutdownDuringTask";
    }
    return "?";
}

} // namespace vt::mock
