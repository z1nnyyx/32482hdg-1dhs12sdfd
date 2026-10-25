// SPDX-License-Identifier: MIT
// VoidTrace mock backend — safe, in-process stand-in for the live
// Roblox-facing execution path. The brief requires that UI logic,
// state transitions, and error reporting can be exercised without
// touching another process. This mock exists for that purpose.
//
// Design notes:
//   - No OpenProcess, no RPM/WPM, no sockets, no file writes outside
//     the per-request transcript in memory.
//   - A background "tracker" tick runs on a std::jthread; stop_token
//     ends it on destruction.
//   - execute(source, request_id) returns a future<Result> that the UI
//     awaits/polls — no "fire and forget" marked as executed.
//   - Scenarios are selectable at runtime so tests can walk every
//     branch of the state machine the brief enumerates.

#pragma once

#include <atomic>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>

namespace vt::mock {

enum class Scenario {
    NoTarget,              // tracker never sees a client
    TargetNotReady,        // tracker sees a PID but handshake never completes
    BackendReady,          // happy path: handshake, exec acks
    SuccessWithOutput,     // exec acks and emits a stdout line
    CompileError,          // compile() returns a diagnostic
    RuntimeError,          // exec acks with a runtime exception
    Timeout,               // exec never acks
    MultipleTargets,       // tracker sees N clients
    ClientExitMidRequest,  // ack never arrives because the client dropped
    BridgeUnavailable,     // bridge never binds its port
    ShutdownDuringTask,    // destructor interrupts an in-flight exec
};

struct ExecResult {
    std::uint64_t request_id{};
    bool compile_ok{};
    bool runtime_ok{};
    std::string output;       // stdout the sandbox emitted
    std::string error;        // compile diagnostic or runtime message
    std::string actor;        // which simulated client ack'd (empty on error)
    bool timed_out{};
};

struct ClientRow {
    std::string version;
    std::string username;
    std::uint32_t pid{};
    bool handshake_complete{};
};

enum class BackendState {
    Idle,
    BackendStarting,
    TargetDetected,
    BackendReady,
    Failed,
    ShuttingDown,
};

class MockBackend {
public:
    explicit MockBackend(Scenario s);
    ~MockBackend();

    MockBackend(const MockBackend&) = delete;
    MockBackend& operator=(const MockBackend&) = delete;

    // Starts the simulated tracker and bridge. Returns true if the
    // scenario permits startup (BridgeUnavailable returns false and
    // sets state=Failed).
    bool start();
    void stop();

    BackendState state() const { return state_.load(); }
    std::vector<ClientRow> clients() const;

    // Submits a script. Non-blocking. The returned future resolves when
    // the mock either acks, errors, or hits the per-scenario timeout.
    std::future<ExecResult> execute(const std::string& source);

    // Current monotonically-increasing request id (last issued).
    std::uint64_t last_request_id() const { return last_rid_.load(); }

private:
    void tracker_loop(std::stop_token st);
    ExecResult simulate_exec(std::uint64_t rid, const std::string& source);

    Scenario scenario_;
    std::atomic<BackendState> state_{BackendState::Idle};
    std::atomic<std::uint64_t> last_rid_{0};

    mutable std::mutex clients_mtx_;
    std::vector<ClientRow> clients_;

    std::jthread tracker_;
    std::atomic<bool> running_{false};
};

const char* to_string(BackendState s);
const char* to_string(Scenario s);

} // namespace vt::mock
