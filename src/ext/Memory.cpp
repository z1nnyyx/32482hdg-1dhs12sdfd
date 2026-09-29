#include "ext/Memory.h"

#include <cstring>

namespace vt::ext {
namespace {
using NtRead_t = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
NtRead_t nt_read() {
    static NtRead_t fn = nullptr;
    static bool once = false;
    if (!once) {
        once = true;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        fn = ntdll ? (NtRead_t)GetProcAddress(ntdll, "NtReadVirtualMemory") : nullptr;
    }
    return fn;
}
} // namespace

bool Memory::open(DWORD pid) {
    close();
    h_ = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                     PROCESS_QUERY_INFORMATION, FALSE, pid);
    return h_ != nullptr;
}

void Memory::close() {
    if (h_) {
        CloseHandle(h_);
        h_ = nullptr;
    }
}

bool Memory::write(uintptr_t addr, const void* in, size_t n) const {
    if (!h_ || !addr || !in || !n)
        return false;
    using NtW = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    static NtW fn = nullptr;
    static bool once = false;
    if (!once) {
        once = true;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        fn = ntdll ? (NtW)GetProcAddress(ntdll, "NtWriteVirtualMemory") : nullptr;
    }
    SIZE_T got = 0;
    if (fn && fn(h_, (PVOID)addr, (PVOID)in, n, &got) >= 0 && got == n)
        return true;
    got = 0;
    return WriteProcessMemory(h_, (LPVOID)addr, in, n, &got) && got == n;
}

bool Memory::read(uintptr_t addr, void* out, size_t n) const {
    if (!h_ || !addr || !out || !n)
        return false;
    SIZE_T got = 0;
    if (auto nt = nt_read()) {
        if (nt(h_, (PVOID)addr, out, n, &got) >= 0 && got == n)
            return true;
    }
    got = 0;
    return ReadProcessMemory(h_, (LPCVOID)addr, out, n, &got) && got == n;
}

std::string Memory::rstring(uintptr_t addr) const {
    if (!looks(addr))
        return {};
    // MSVC std::string
    const uintptr_t p0  = read_ptr(addr);
    const size_t    sz  = read<size_t>(addr + 0x10);
    const size_t    cap = read<size_t>(addr + 0x18);
    if (sz == 0 || sz > 128 || cap > 4096)
        return {};
    std::string s(sz, '\0');
    const uintptr_t src = cap < 16 ? addr : p0;
    if (!read(src, s.data(), sz))
        return {};
    for (char c : s)
        if ((unsigned char)c < 32 || (unsigned char)c > 126)
            return {};
    return s;
}

std::string Memory::rstring_ptr(uintptr_t addr) const {
    if (!looks(addr))
        return {};
    char buf[96]{};
    if (!read(addr, buf, sizeof(buf) - 1))
        return {};
    buf[sizeof(buf) - 1] = 0;
    const size_t n = strnlen(buf, sizeof(buf) - 1);
    if (n == 0)
        return {};
    for (size_t i = 0; i < n; ++i)
        if ((unsigned char)buf[i] < 32 || (unsigned char)buf[i] > 126)
            return {};
    return std::string(buf, n);
}

} // namespace vt::ext
