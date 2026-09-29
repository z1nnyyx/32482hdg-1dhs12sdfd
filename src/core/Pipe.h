#pragma once

#include "shared/Protocol.h"

#include <Windows.h>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <string>
#include <vector>

namespace vt {

// Host side: creates the named pipe, accepts one client (the injected module).
class PipeServer {
public:
    using Handler = std::function<void(const Message&)>;

    bool start(const std::wstring& name, Handler on_msg);
    void stop();
    bool send(const Message& m);
    bool connected() const { return connected_.load(); }

private:
    void accept_loop();
    void read_loop();
    void write_loop();

    std::wstring name_;
    Handler handler_;
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    std::thread thr_;
    std::thread wr_thr_;
    std::atomic<bool> run_{false};
    std::atomic<bool> connected_{false};
    std::mutex wr_mtx_;
    std::mutex out_mtx_;
    std::condition_variable out_cv_;
    std::deque<std::vector<uint8_t>> outq_;
};

// Module side: connects to the host pipe.
class PipeClient {
public:
    using Handler = std::function<void(const Message&)>;

    bool connect(const std::wstring& name, Handler on_msg, int timeout_ms = 8000);
    // One CreateFile attempt, no worker thread. Call poll() on the game thread.
    bool attach_poll(const std::wstring& name, Handler on_msg);
    void poll();
    void stop();
    bool send(const Message& m);
    bool connected() const { return connected_.load(); }

private:
    void read_loop();
    bool drain_available();

    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    Handler handler_;
    std::thread thr_;
    std::vector<uint8_t> acc_;
    std::atomic<bool> run_{false};
    std::atomic<bool> connected_{false};
    std::atomic<bool> poll_mode_{false};
    std::mutex wr_mtx_;
};

} // namespace vt
