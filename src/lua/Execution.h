#pragma once

#include "lua/LuaApi.h"

#include <string>
#include <mutex>
#include <deque>
#include <atomic>
#include <functional>
#include <vector>

namespace vt {

struct ExecResult {
    bool ok = false;
    std::string error;
};

class Execution {
public:
    static Execution& instance();

    void set_state(lua_State* L);
    lua_State* state() const { return L_; }
    bool ready() const { return L_ != nullptr && LuaApi::instance().ready(); }

    // True only while pump() is draining a chunk on the job thread.
    static bool on_script_thread();

    using Sink = std::function<void(const ExecResult&)>;
    void set_sink(Sink s) { sink_ = std::move(s); }

    // Thread-safe queue. Drained only from the script-job / proven Lua thread.
    void enqueue(std::string source, std::string chunkname);
    void pump();
    bool pending() const;

    void queue_teleport(std::string source);
    void drain_teleports();

    ExecResult run_now(const std::string& source, const std::string& chunkname);

private:
    struct Job {
        std::string source;
        std::string chunkname;
    };

    lua_State* L_ = nullptr;
    mutable std::mutex mtx_;
    std::deque<Job> queue_;
    std::vector<std::string> teleports_;
    std::atomic<bool> pumping_{false};
    std::atomic<size_t> queued_{0};
    Sink sink_;
};

} // namespace vt
