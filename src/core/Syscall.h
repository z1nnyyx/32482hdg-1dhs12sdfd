#pragma once

#include <Windows.h>
#include <winternl.h>
#include <cstdint>

#ifndef _NTSTATUS_DEFINED
#define _NTSTATUS_DEFINED
typedef LONG NTSTATUS;
#endif

// Direct-syscall layer.
// Bypasses all usermode (ntdll) hooks by invoking the kernel gate directly.
// Each stub is the canonical 11-byte sequence:
//   mov r10, rcx  | mov eax, SSN  | syscall  | ret
// written into a private RWX page so no writable+executable section exists
// inside ntdll and no inline hook can intercept the call.
//
// SSN resolution uses Hell's Gate (read from clean stub) with
// Halo's Gate fallback (infer from sorted clean neighbours).
//
// Call Syscalls::get().init() once before any injection attempt.

namespace vt {

class Syscalls {
public:
    static Syscalls& get();

    bool init();
    bool ready() const { return ready_; }

    // -- typed function pointers (set after init) ----------------------------
    using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE Process, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

    using NtFreeVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE Process, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

    using NtWriteVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE Process, PVOID BaseAddress, PVOID Buffer,
        ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

    using NtReadVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE Process, PVOID BaseAddress, PVOID Buffer,
        ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);

    using NtProtectVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE Process, PVOID* BaseAddress, PSIZE_T RegionSize,
        ULONG NewProtect, PULONG OldProtect);

    using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
        PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes, HANDLE ProcessHandle,
        PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
        SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
        PVOID AttributeList);

    using NtFlushInstructionCache_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, PVOID BaseAddress, ULONG Length);

    using NtSetInformationVirtualMemory_t = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle, ULONG VmInformationClass,
        ULONG_PTR NumberOfEntries, PVOID VirtualAddresses,
        PVOID VmInformation, ULONG VmInformationLength);

    using NtQueueApcThreadEx2_t = NTSTATUS(NTAPI*)(
        HANDLE ThreadHandle, HANDLE ReserveHandle, ULONG ApcFlags,
        PVOID ApcRoutine, PVOID SystemArgument1,
        PVOID SystemArgument2, PVOID SystemArgument3);

    NtAllocateVirtualMemory_t  AllocVirtualMemory   = nullptr;
    NtFreeVirtualMemory_t      FreeVirtualMemory     = nullptr;
    NtWriteVirtualMemory_t     WriteVirtualMemory    = nullptr;
    NtReadVirtualMemory_t      ReadVirtualMemory     = nullptr;
    NtProtectVirtualMemory_t   ProtectVirtualMemory  = nullptr;
    NtCreateThreadEx_t         CreateThreadEx        = nullptr;
    NtFlushInstructionCache_t  FlushInstructionCache = nullptr;
    NtSetInformationVirtualMemory_t SetInformationVirtualMemory = nullptr;
    NtQueueApcThreadEx2_t      QueueApcThreadEx2     = nullptr;

private:
    static uint32_t resolve_ssn(HMODULE ntdll, const char* name);
    bool  make_stub(HMODULE ntdll, const char* name, void*& out);

    void*  page_       = nullptr;
    size_t page_used_  = 0;
    bool   ready_      = false;
};

// Convenience wrappers that mirror the Win32 API surface ManualMap uses.
// Fall back to Win32 if the syscall layer hasn't been initialised.

inline BOOL SC_VirtualAllocEx(HANDLE proc, LPVOID addr, SIZE_T sz,
                               DWORD type, DWORD prot, LPVOID* out) {
    auto& sc = Syscalls::get();
    if (sc.ready()) {
        PVOID base = addr;
        SIZE_T size = sz;
        NTSTATUS s = sc.AllocVirtualMemory(proc, &base, 0, &size, type, prot);
        if (s >= 0 && out) *out = base;
        return s >= 0;
    }
    LPVOID r = VirtualAllocEx(proc, addr, sz, type, prot);
    if (out) *out = r;
    return r != nullptr;
}

inline BOOL SC_WriteProcessMemory(HANDLE proc, LPVOID dest,
                                   const void* src, SIZE_T n, SIZE_T* written) {
    auto& sc = Syscalls::get();
    if (sc.ready()) {
        ULONG w = 0;
        NTSTATUS s = sc.WriteVirtualMemory(proc, dest, const_cast<PVOID>(src), (ULONG)n, &w);
        if (written) *written = w;
        return s >= 0;
    }
    SIZE_T w2 = 0;
    BOOL r = WriteProcessMemory(proc, dest, src, n, &w2);
    if (written) *written = w2;
    return r;
}

inline BOOL SC_ReadProcessMemory(HANDLE proc, LPCVOID src,
                                  void* dest, SIZE_T n, SIZE_T* read_out) {
    auto& sc = Syscalls::get();
    if (sc.ready()) {
        ULONG r = 0;
        NTSTATUS s = sc.ReadVirtualMemory(proc, const_cast<PVOID>(src), dest, (ULONG)n, &r);
        if (read_out) *read_out = r;
        return s >= 0;
    }
    SIZE_T r2 = 0;
    BOOL res = ReadProcessMemory(proc, src, dest, n, &r2);
    if (read_out) *read_out = r2;
    return res;
}

inline BOOL SC_VirtualProtectEx(HANDLE proc, LPVOID addr, SIZE_T sz,
                                 DWORD prot, PDWORD old_prot) {
    auto& sc = Syscalls::get();
    if (sc.ready()) {
        PVOID base = addr;
        SIZE_T size = sz;
        ULONG old = 0;
        NTSTATUS s = sc.ProtectVirtualMemory(proc, &base, &size, prot, &old);
        if (old_prot) *old_prot = old;
        return s >= 0;
    }
    return VirtualProtectEx(proc, addr, sz, prot, old_prot);
}

} // namespace vt
