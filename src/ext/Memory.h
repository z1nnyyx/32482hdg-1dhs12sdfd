#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace vt::ext {

class Memory {
public:
    bool open(DWORD pid);
    void close();
    bool ok() const { return h_ != nullptr; }
    HANDLE handle() const { return h_; }

    bool read(uintptr_t addr, void* out, size_t n) const;
    bool write(uintptr_t addr, const void* in, size_t n) const;

    template <typename T>
    bool write_t(uintptr_t addr, const T& v) const {
        return write(addr, &v, sizeof(T));
    }

    template <typename T>
    T read(uintptr_t addr) const {
        T v{};
        read(addr, &v, sizeof(T));
        return v;
    }

    uintptr_t read_ptr(uintptr_t addr) const { return read<uintptr_t>(addr); }
    bool looks(uintptr_t p) const { return p > 0x10000 && p < 0x00007FFFFFFFFFFFULL; }

    std::string rstring(uintptr_t addr) const;
    std::string rstring_ptr(uintptr_t addr) const;

private:
    HANDLE h_ = nullptr;
};

} // namespace vt::ext
