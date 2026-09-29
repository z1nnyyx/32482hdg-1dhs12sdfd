#pragma once

#include <string>
#include <functional>
#include <mutex>
#include <vector>
#include <cstdint>

namespace vt {

enum class LogLevel : uint8_t { Trace, Info, Warn, Error };

struct LogLine {
    LogLevel level;
    std::wstring text;
};

class Logger {
public:
    static Logger& instance();

    void set_sink(std::function<void(const LogLine&)> sink);
    void write(LogLevel level, const std::wstring& text);
    void info(const std::wstring& text);
    void warn(const std::wstring& text);
    void error(const std::wstring& text);

    std::vector<LogLine> snapshot() const;

    // Silent context: when set on a thread, VT_LOG appends to an in-memory
    // ring buffer instead of calling the pipe sink. Prevents blocking Roblox's
    // Lua thread on a slow pipe write. Flushed by drain_silent() from the
    // render tick.
    void set_thread_silent(bool on);
    void drain_silent();   // called by render tick — writes buffered lines to sink

private:
    mutable std::mutex mtx_;
    std::function<void(const LogLine&)> sink_;
    std::vector<LogLine> history_;
    std::vector<LogLine> silent_buf_;
};

} // namespace vt

#define VT_LOG(msg)  ::vt::Logger::instance().info(msg)
#define VT_WARN(msg) ::vt::Logger::instance().warn(msg)
#define VT_ERR(msg)  ::vt::Logger::instance().error(msg)
