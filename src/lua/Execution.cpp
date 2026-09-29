#include "lua/Execution.h"
#include "lua/Offsets.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <Windows.h>

namespace vt {
namespace {

thread_local int g_script_depth = 0;

struct ExecGuard {
    ExecGuard() { ++g_script_depth; }
    ~ExecGuard() { --g_script_depth; }
};

struct SehExec {
    lua_State* L;
    lua_State* thread;
    const char* chunkname;
    const char* data;
    size_t size;
    int load_status;
    int pcall_status;
    char err[512];
};

int seh_run(SehExec* s) {
    s->load_status = 1;
    s->pcall_status = 1;
    s->err[0] = 0;
    __try {
        auto& api = LuaApi::instance();
        api.setidentity(s->L, 8);
        const int saved_top = api.gettop(s->L);
        lua_State* thread = api.newthread(s->L);
        if (!thread || !api.plausible_state(thread))
            thread = s->L;
        s->thread = thread;
        api.setidentity(thread, 8);

        s->load_status = api.load(thread, s->chunkname, s->data, s->size, 0);
        if (s->load_status != 0) {
            const char* msg = api.tostring(thread, -1);
            if (msg)
                strncpy_s(s->err, msg, _TRUNCATE);
            api.settop(s->L, saved_top);
            return 0;
        }
        s->pcall_status = api.pcall(thread, 0, LUA_MULTRET, 0);
        if (s->pcall_status != 0) {
            const char* msg = api.tostring(thread, -1);
            if (msg)
                strncpy_s(s->err, msg, _TRUNCATE);
            api.settop(s->L, saved_top);
            return 0;
        }
        api.settop(s->L, saved_top);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        strncpy_s(s->err, "execution AV — offsets or calling convention mismatch for this build", _TRUNCATE);
        return -1;
    }
}

} // namespace

Execution& Execution::instance() {
    static Execution g;
    return g;
}

bool Execution::on_script_thread() {
    return g_script_depth > 0;
}

void Execution::set_state(lua_State* L) {
    L_ = L;
}

void Execution::enqueue(std::string source, std::string chunkname) {
    std::lock_guard lock(mtx_);
    queue_.push_back(Job{std::move(source), std::move(chunkname)});
    queued_.store(queue_.size(), std::memory_order_relaxed);
}

bool Execution::pending() const {
    return queued_.load(std::memory_order_relaxed) != 0;
}

void Execution::queue_teleport(std::string source) {
    if (source.empty())
        return;
    std::lock_guard lock(mtx_);
    teleports_.push_back(std::move(source));
}

void Execution::drain_teleports() {
    std::vector<std::string> batch;
    {
        std::lock_guard lock(mtx_);
        batch.swap(teleports_);
    }
    for (auto& s : batch)
        enqueue(std::move(s), "=teleport");
}

void Execution::pump() {
    if (pumping_.exchange(true))
        return;
    for (;;) {
        Job job;
        {
            std::lock_guard lock(mtx_);
            if (queue_.empty()) {
                queued_.store(0, std::memory_order_relaxed);
                break;
            }
            job = std::move(queue_.front());
            queue_.pop_front();
            queued_.store(queue_.size(), std::memory_order_relaxed);
        }
        auto r = run_now(job.source, job.chunkname);
        if (!r.ok)
            VT_ERR(utf8_to_wide(r.error));
        if (sink_)
            sink_(r);
    }
    pumping_ = false;
}

ExecResult Execution::run_now(const std::string& source, const std::string& chunkname) {
    ExecResult r;
    if (!L_) {
        r.error = "no lua_State — attach after you are in a game, then update offsets";
        return r;
    }
    auto& api = LuaApi::instance();
    if (!api.ready()) {
        r.error = "Lua C API not bound — fill luau_load / lua_pcall in offsets.json";
        return r;
    }

    ExecGuard guard;
    SehExec s{};
    s.L = L_;
    s.chunkname = chunkname.c_str();
    s.data = source.data();
    s.size = source.size();
    const int rc = seh_run(&s);
    if (rc == 1) {
        r.ok = true;
        return r;
    }
    if (s.err[0])
        r.error = s.err;
    else if (s.load_status != 0)
        r.error = "luau_load failed (" + std::to_string(s.load_status) + ")";
    else
        r.error = "lua_pcall failed (" + std::to_string(s.pcall_status) + ")";
    return r;
}

} // namespace vt
