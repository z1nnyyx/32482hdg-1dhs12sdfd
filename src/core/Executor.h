// SPDX-License-Identifier: MIT
// VoidTrace native executor — replaces the Xeno backend entirely.
// Clean single-class design: attach, bootstrap, execute. No HTTP server,
// no log-scrape, no background init thread.

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>
#include <memory>

#include <Windows.h>

// Forward-declare Luau encoder; definition lives in Executor.cpp
namespace Luau { class BytecodeEncoder; }

namespace vt {

// Runtime-overridable Instance layout offsets. Defaults target
// version-765338e04cf54fde; VoidTrace's World scanner calls
// apply_discovered() with the real values for the running build.
namespace inst_offsets {
    constexpr std::uint64_t This = 0x8;

    inline std::uint64_t& Name_mut()     { static std::uint64_t v = 0x78; return v; }
    inline std::uint64_t& Children_mut() { static std::uint64_t v = 0x80; return v; }
    inline std::uint64_t& Parent_mut()   { static std::uint64_t v = 0x50; return v; }

    inline std::uint64_t Name()     { return Name_mut(); }
    inline std::uint64_t Children() { return Children_mut(); }
    inline std::uint64_t Parent()   { return Parent_mut(); }

    constexpr std::uint64_t ClassDescriptor       = 0x18;
    constexpr std::uint64_t ClassName              = 0x8;

    constexpr std::uint64_t ModuleScriptEmbedded   = 0x158;
    constexpr std::uint64_t IsCoreScript            = 0x6E0;
    constexpr std::uint64_t ModuleFlags             = IsCoreScript - 0x4;
    constexpr std::uint64_t LocalScriptEmbedded     = 0x1B0;

    constexpr std::uint64_t Bytecode     = 0x10;
    constexpr std::uint64_t BytecodeSize = 0x20;

    constexpr std::uint64_t LocalPlayer  = 0x128;
    constexpr std::uint64_t ObjectValue  = 0xD8;

    void apply_discovered(std::uint64_t name, std::uint64_t children, std::uint64_t parent);
}

// Lightweight Instance wrapper — reads from a remote process handle.
class Instance {
public:
    Instance(std::uintptr_t address, HANDLE handle);

    std::uintptr_t self() const { return addr_; }

    std::string name() const;
    std::string class_name() const;
    std::uintptr_t parent_address() const;

    std::vector<std::uintptr_t> children_addresses() const;
    std::unique_ptr<Instance> find_child(std::string_view name) const;
    std::uintptr_t find_child_address(std::string_view name) const;
    std::unique_ptr<Instance> find_child_of_class(std::string_view cls) const;
    std::uintptr_t find_child_of_class_address(std::string_view cls) const;
    std::uintptr_t wait_for_child_address(std::string_view name, int timeout_sec = 30) const;

    bool set_bytecode(const std::string& compressed, bool revert = false) const;
    void unlock_module() const;

private:
    std::uintptr_t addr_;
    HANDLE hproc_;
};

struct ClientRow {
    std::string version;
    std::string username;
    std::uint32_t pid = 0;
};

// Main executor — singleton. Owns a single Roblox client connection.
class Executor {
public:
    static Executor& instance();

    // Attach to a Roblox process whose DataModel address is already known
    // (discovered by VoidTrace's World scanner / OffsetSync).
    bool attach(std::uint32_t pid, std::uintptr_t data_model);

    // Detach from the current client.
    void detach();

    // Is a client attached and alive?
    bool is_attached() const;

    // List attached clients (0 or 1 in the current design).
    std::vector<ClientRow> clients() const;

    // Execute a Luau script on the attached client.
    // Returns number of clients it was sent to (0 or 1).
    std::size_t execute(const std::string& source);

    // Check if a script compiles. Returns "success" or the diagnostic.
    std::string compilable(const std::string& source);

    // Accessors
    std::string username() const;
    std::uint32_t pid() const;

private:
    Executor() = default;

    void do_bootstrap();

    mutable std::mutex mtx_;
    HANDLE hproc_ = nullptr;
    std::uint32_t pid_ = 0;
    std::uintptr_t data_model_ = 0;
    std::string username_ = "N/A";
    std::string version_;
    std::string guid_;
    bool bootstrapped_ = false;
};

// Memory primitives
template<typename T> T read_mem(std::uintptr_t addr, HANDLE h);
template<typename T> bool write_mem(std::uintptr_t addr, const T& val, HANDLE h);
std::string read_roblox_string(std::uintptr_t addr, HANDLE h);

// Bytecode pipeline
std::string compile_luau(const std::string& source);
std::string compress_bytecode(std::string_view bytecode);

} // namespace vt
