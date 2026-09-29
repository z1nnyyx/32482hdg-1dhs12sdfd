#include "shared/Log.h"

#include <Windows.h>

namespace vt {

namespace {
thread_local bool tls_silent = false;
}

Logger& Logger::instance() {
    static Logger g;
    return g;
}

void Logger::set_sink(std::function<void(const LogLine&)> sink) {
    std::lock_guard lock(mtx_);
    sink_ = std::move(sink);
}

void Logger::set_thread_silent(bool on) {
    tls_silent = on;
}

void Logger::drain_silent() {
    std::vector<LogLine> to_flush;
    std::function<void(const LogLine&)> sink;
    {
        std::lock_guard lock(mtx_);
        if (silent_buf_.empty()) return;
        to_flush.swap(silent_buf_);
        sink = sink_;
    }
    if (sink) {
        for (auto& l : to_flush) sink(l);
    }
}

void Logger::write(LogLevel level, const std::wstring& text) {
    LogLine line{level, text};
    std::function<void(const LogLine&)> sink;
    const bool silent = tls_silent;
    {
        std::lock_guard lock(mtx_);
        history_.push_back(line);
        if (history_.size() > 500)
            history_.erase(history_.begin(), history_.begin() + 100);
        if (silent) {
            // Queue for later flush from a safe (non-Lua) thread — do NOT
            // touch the sink here (pipe write could block Roblox).
            silent_buf_.push_back(line);
            // Cap the buffer to prevent runaway growth.
            if (silent_buf_.size() > 512)
                silent_buf_.erase(silent_buf_.begin(), silent_buf_.begin() + 128);
            return;
        }
        sink = sink_;
    }
    if (sink)
        sink(line);
}

void Logger::info(const std::wstring& text)  { write(LogLevel::Info, text); }
void Logger::warn(const std::wstring& text)  { write(LogLevel::Warn, text); }
void Logger::error(const std::wstring& text) { write(LogLevel::Error, text); }

std::vector<LogLine> Logger::snapshot() const {
    std::lock_guard lock(mtx_);
    return history_;
}

} // namespace vt
