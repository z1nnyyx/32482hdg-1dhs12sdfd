#include "core/Pipe.h"
#include "shared/Log.h"

#include <sddl.h>
#include <vector>
#include <condition_variable>
#include <chrono>

#pragma comment(lib, "advapi32.lib")

namespace vt {
namespace {

bool write_all(HANDLE h, const void* data, size_t n, std::mutex& mtx) {
    std::lock_guard lock(mtx);
    const auto* p = (const uint8_t*)data;
    size_t left = n;
    while (left) {
        DWORD wrote = 0;
        if (!WriteFile(h, p, (DWORD)left, &wrote, nullptr) || wrote == 0) {
            const DWORD e = GetLastError();
            if (e == ERROR_NO_DATA) {
                Sleep(1);
                continue;
            }
            return false;
        }
        p += wrote;
        left -= wrote;
    }
    return true;
}

bool pump_reads(HANDLE h, std::atomic<bool>& run, const std::function<void(const Message&)>& handler) {
    std::vector<uint8_t> acc;
    uint8_t chunk[4096];
    while (run.load()) {
        DWORD got = 0;
        if (!ReadFile(h, chunk, sizeof(chunk), &got, nullptr)) {
            const DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED || err == ERROR_NO_DATA)
                return false;
            if (err == ERROR_MORE_DATA) {
                acc.insert(acc.end(), chunk, chunk + got);
                continue;
            }
            return false;
        }
        if (got == 0)
            return false;
        acc.insert(acc.end(), chunk, chunk + got);
        size_t consumed = 0;
        Message msg;
        while (try_unpack(acc.data(), acc.size(), msg, consumed)) {
            if (handler)
                handler(msg);
            acc.erase(acc.begin(), acc.begin() + (ptrdiff_t)consumed);
        }
        if (acc.size() > kMaxPayload + 16)
            return false;
    }
    return true;
}

} // namespace

bool PipeServer::start(const std::wstring& name, Handler on_msg) {
    stop();
    name_ = name;
    handler_ = std::move(on_msg);
    run_ = true;
    wr_thr_ = std::thread([this] { write_loop(); });
    thr_ = std::thread([this] { accept_loop(); });
    return true;
}

void PipeServer::stop() {
    run_ = false;
    connected_ = false;
    out_cv_.notify_all();
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CancelIoEx(pipe_, nullptr);
        DisconnectNamedPipe(pipe_);
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
    if (wr_thr_.joinable())
        wr_thr_.join();
    if (thr_.joinable())
        thr_.join();
}

bool PipeServer::send(const Message& m) {
    if (!run_.load() || !connected_.load())
        return false;
    auto buf = pack(m);
    {
        std::lock_guard lock(out_mtx_);
        if (outq_.size() > 256)
            outq_.pop_front();
        outq_.push_back(std::move(buf));
    }
    out_cv_.notify_one();
    return true;
}

void PipeServer::write_loop() {
    while (run_.load()) {
        std::vector<uint8_t> buf;
        {
            std::unique_lock lock(out_mtx_);
            out_cv_.wait_for(lock, std::chrono::milliseconds(50), [&] {
                return !outq_.empty() || !run_.load();
            });
            if (!run_.load())
                break;
            if (outq_.empty())
                continue;
            buf = std::move(outq_.front());
            outq_.pop_front();
        }
        if (connected_.load() && pipe_ != INVALID_HANDLE_VALUE)
            write_all(pipe_, buf.data(), buf.size(), wr_mtx_);
    }
}

void PipeServer::accept_loop() {
    // Allow the Roblox AppContainer (and same-user clients) to connect.
    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;GA;;;WD)(A;;GA;;;AC)(A;;GA;;;S-1-15-2-1)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)",
        SDDL_REVISION_1, &sd, nullptr);
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    while (run_) {
        HANDLE h = CreateNamedPipeW(
            name_.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 1 << 16, 1 << 16, 0, sd ? &sa : nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            Sleep(200);
            continue;
        }
        pipe_ = h;
        const BOOL ok = ConnectNamedPipe(h, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!ok || !run_) {
            CloseHandle(h);
            pipe_ = INVALID_HANDLE_VALUE;
            continue;
        }
        connected_ = true;
        VT_LOG(L"Module connected on named pipe");
        read_loop();
        connected_ = false;
        if (pipe_ != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(pipe_);
            CloseHandle(pipe_);
            pipe_ = INVALID_HANDLE_VALUE;
        }
        VT_WARN(L"Module disconnected");
    }
    if (sd)
        LocalFree(sd);
}

void PipeServer::read_loop() {
    pump_reads(pipe_, run_, handler_);
}

bool PipeClient::connect(const std::wstring& name, Handler on_msg, int timeout_ms) {
    stop();
    handler_ = std::move(on_msg);
    const DWORD start = GetTickCount();
    HANDLE h = INVALID_HANDLE_VALUE;
    while (GetTickCount() - start < (DWORD)timeout_ms) {
        h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                        OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE)
            break;
        if (GetLastError() == ERROR_PIPE_BUSY)
            WaitNamedPipeW(name.c_str(), 500);
        else
            Sleep(50);
    }
    if (h == INVALID_HANDLE_VALUE)
        return false;

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
    pipe_ = h;
    run_ = true;
    connected_ = true;
    poll_mode_ = false;
    thr_ = std::thread([this] { read_loop(); });
    return true;
}

bool PipeClient::attach_poll(const std::wstring& name, Handler on_msg) {
    if (connected_ && pipe_ != INVALID_HANDLE_VALUE)
        return true;
    handler_ = std::move(on_msg);
    HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
    pipe_ = h;
    run_ = true;
    connected_ = true;
    poll_mode_ = true;
    return true;
}

bool PipeClient::drain_available() {
    if (pipe_ == INVALID_HANDLE_VALUE || !handler_)
        return connected_;
    DWORD avail = 0;
    if (!PeekNamedPipe(pipe_, nullptr, 0, nullptr, &avail, nullptr)) {
        const DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
            connected_ = false;
            return false;
        }
        return true;
    }
    if (!avail)
        return true;
    uint8_t chunk[4096];
    const DWORD want = avail > sizeof(chunk) ? (DWORD)sizeof(chunk) : avail;
    DWORD got = 0;
    if (!ReadFile(pipe_, chunk, want, &got, nullptr) || got == 0)
        return true;
    acc_.insert(acc_.end(), chunk, chunk + got);
    size_t consumed = 0;
    Message msg;
    while (try_unpack(acc_.data(), acc_.size(), msg, consumed)) {
        handler_(msg);
        acc_.erase(acc_.begin(), acc_.begin() + (ptrdiff_t)consumed);
        consumed = 0;
    }
    if (acc_.size() > kMaxPayload + 16)
        acc_.clear();
    return true;
}

void PipeClient::poll() {
    if (!poll_mode_ || !connected_)
        return;
    for (int i = 0; i < 64; ++i) {
        DWORD avail = 0;
        if (!PeekNamedPipe(pipe_, nullptr, 0, nullptr, &avail, nullptr) || !avail)
            break;
        if (!drain_available())
            break;
    }
}

void PipeClient::stop() {
    run_ = false;
    connected_ = false;
    if (pipe_ != INVALID_HANDLE_VALUE) {
        CancelIoEx(pipe_, nullptr);
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
    }
    if (thr_.joinable())
        thr_.join();
}

bool PipeClient::send(const Message& m) {
    if (!connected_ || pipe_ == INVALID_HANDLE_VALUE)
        return false;
    auto buf = pack(m);
    return write_all(pipe_, buf.data(), buf.size(), wr_mtx_);
}

void PipeClient::read_loop() {
    pump_reads(pipe_, run_, handler_);
    connected_ = false;
}

} // namespace vt
