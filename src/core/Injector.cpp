#include "core/Injector.h"
#include "core/ManualMap.h"
#include "exe/Payload.h"
#include "shared/Utils.h"
#include "shared/Log.h"

#include <TlHelp32.h>

#ifndef NTSTATUS
using NTSTATUS = LONG;
#endif
#ifndef NTAPI
#define NTAPI __stdcall
#endif

namespace vt {

namespace {

// Queue LoadLibraryW as an APC to every alertable Roblox thread.
// Callback = kernel32!LoadLibraryW (CFG-valid, whitelisted).
// No new thread created → no PsSetCreateThreadNotifyRoutine notification.
// APC fires the next time the target thread enters an alertable wait.
// Returns true if DllMain beacon is signalled within 5 s.
bool try_apc_loadlib(HANDLE process, void* remote_path, DWORD pid) {
    using NtQueueApcThread_t    = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, PVOID);
    using NtQueueApcThreadEx_t  = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID);
    using NtQueueApcThreadEx2_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, ULONG, PVOID, PVOID, PVOID, PVOID);
    constexpr ULONG kSpecialApc = 0x1;

    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQueueApc    = (NtQueueApcThread_t)   GetProcAddress(ntdll, "NtQueueApcThread");
    auto NtQueueApcEx  = (NtQueueApcThreadEx_t) GetProcAddress(ntdll, "NtQueueApcThreadEx");
    auto NtQueueApcEx2 = (NtQueueApcThreadEx2_t)GetProcAddress(ntdll, "NtQueueApcThreadEx2");
    if (!NtQueueApc) { VT_WARN(L"NtQueueApcThread not resolved"); return false; }

    auto k32  = GetModuleHandleW(L"kernel32.dll");
    auto load = GetProcAddress(k32, "LoadLibraryW");
    if (!load) { VT_WARN(L"LoadLibraryW not resolved"); return false; }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { VT_WARN(L"LoadLib-APC: snapshot failed"); return false; }

    int queued_special = 0, queued_regular = 0;
    int considered = 0;
    THREADENTRY32 te{sizeof(te)};
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (++considered > 4) break; // never spray every thread
            HANDLE ht = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!ht) continue;

            NTSTATUS ns = 0xC0000001;
            const wchar_t* method = L"?";

            if (NtQueueApcEx2) {
                ns = NtQueueApcEx2(ht, nullptr, kSpecialApc, (void*)load, remote_path, nullptr, nullptr);
                method = L"Ex2-special";
            } else if (NtQueueApcEx) {
                ns = NtQueueApcEx(ht, (HANDLE)1, (void*)load, remote_path, nullptr, nullptr);
                method = L"Ex-special";
            }

            if (ns < 0) {
                ns = NtQueueApc(ht, (void*)load, remote_path, nullptr, nullptr);
                method = L"regular";
            }

            wchar_t nb[20]; swprintf_s(nb, L"0x%08X", (unsigned)ns);
            VT_LOG(L"LoadLib-APC[" + std::wstring(method) + L"] tid=" +
                   std::to_wstring(te.th32ThreadID) + L" ns=" + nb);
            if (ns >= 0) {
                if (method[0] == L'r') ++queued_regular; else ++queued_special;
            }
            CloseHandle(ht);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    const int total = queued_special + queued_regular;
    if (!total) { VT_WARN(L"LoadLib-APC: no threads accepted"); return false; }

    const DWORD wait_ms = queued_special > 0 ? 2000 : 5000;
    VT_LOG(L"LoadLib-APC: special=" + std::to_wstring(queued_special) +
           L" regular=" + std::to_wstring(queued_regular) +
           L" — waiting " + std::to_wstring(wait_ms) + L" ms for DllMain beacon");

    HANDLE beacon = OpenEventW(SYNCHRONIZE, FALSE, L"VT_Diag_DllMain");
    bool ran = false;
    if (beacon) {
        ran = (WaitForSingleObject(beacon, wait_ms) == WAIT_OBJECT_0);
        CloseHandle(beacon);
    }
    if (!ran) { VT_WARN(L"LoadLib-APC: DllMain beacon not signalled in " + std::to_wstring(wait_ms) + L" ms"); return false; }
    VT_LOG(L"LoadLib-APC: DllMain confirmed");
    return true;
}

} // namespace

bool Injector::already_present(DWORD pid, const wchar_t* module_name) {
    return find_module(pid, module_name).has_value();
}

InjectResult Injector::inject(HANDLE process, const std::filesystem::path& dll, InjectMethod method) {
    if (!process) {
        return {false, L"invalid process handle", 0};
    }
    if (!file_exists(dll)) {
        return {false, L"DLL not found: " + dll.wstring(), 0};
    }

    if (method == InjectMethod::ManualMap) {
        VT_LOG(L"Manual-mapping " + dll.filename().wstring());
        auto mapped = ManualMapper::map(process, dll);
        if (!mapped.ok)
            return {false, mapped.error, 0};
        return {true, {}, mapped.base};
    }
    return load_library(process, dll);
}

InjectResult Injector::inject_embedded(HANDLE process, InjectMethod method) {
    if (!process)
        return {false, L"invalid process handle", 0};

    if (method == InjectMethod::ManualMap) {
        // Map from the packed image only. Do not LoadLibrary-APC first:
        // spraying Special User APCs at LoadLibraryW is what put Roblox into
        // STATUS_PROCESS_IS_TERMINATING (0xC000010A) before DllMain could run.
        auto bytes = Payload::module_bytes();
        if (bytes.empty())
            return {false, L"exe has no packed module — rebuild Release | x64", 0};
        auto mapped = ManualMapper::map_buffer(process, bytes.data(), bytes.size());
        if (mapped.ok)
            return {true, {}, mapped.base, mapped.iat_slot, mapped.iat_stub, mapped.iat_orig, mapped.wait_hooked};
        return {false, mapped.error.empty() ? L"ManualMap failed" : mapped.error, 0};
    }

    const auto dll = Payload::unpack_hidden_module();
    if (dll.empty() || !file_exists(dll))
        return {false, L"could not stage hidden module", 0};
    return load_library(process, dll);
}

InjectResult Injector::load_library(HANDLE process, const std::filesystem::path& dll) {
    const std::wstring path = std::filesystem::absolute(dll).wstring();
    const size_t bytes = (path.size() + 1) * sizeof(wchar_t);

    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
        return {false, L"VirtualAllocEx: " + last_error_text(), 0};

    if (!WriteProcessMemory(process, remote, path.c_str(), bytes, nullptr)) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return {false, L"WriteProcessMemory: " + last_error_text(), 0};
    }

    // Prefer APC delivery over CreateRemoteThread:
    //   - No new thread → no PsSetCreateThreadNotifyRoutine notification
    //   - LoadLibraryW is CFG-valid and fully whitelisted
    //   - APC executes on an EXISTING Roblox thread (normal-looking call stack)
    DWORD pid = GetProcessId(process);
    if (pid && try_apc_loadlib(process, remote, pid)) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return {true, {}, 1};  // module base unknown via APC path; pipe connects separately
    }

    // APC path did not confirm DllMain — try NtCreateThreadEx+HideFromDebugger
    // with LoadLibraryW as start.  LoadLibraryW is CFG-valid (kernel32 export)
    // so RtlUserThreadStart will not kill the thread.  HideFromDebugger reduces
    // the thread's visibility to debugger-based detection.
    VT_WARN(L"APC-LoadLib failed — trying NtCreateThreadEx+LoadLibraryW");
    {
        using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
            PHANDLE, ACCESS_MASK, PVOID, HANDLE,
            PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
        constexpr ULONG kHideFromDebugger = 0x4;
        auto ntdll = GetModuleHandleW(L"ntdll.dll");
        auto NtCTEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");
        auto k32    = GetModuleHandleW(L"kernel32.dll");
        auto load   = GetProcAddress(k32, "LoadLibraryW");
        if (NtCTEx && load) {
            HANDLE th = nullptr;
            NTSTATUS ns = NtCTEx(&th, THREAD_ALL_ACCESS, nullptr, process,
                                  load, remote, kHideFromDebugger, 0, 0, 0, nullptr);
            wchar_t nb[20]; swprintf_s(nb, L"0x%08X", (unsigned)ns);
            if (ns >= 0 && th) {
                VT_LOG(std::wstring(L"NtCreateThreadEx+LoadLibraryW ns=") + nb + L" — waiting 5000 ms for DllMain beacon");
                WaitForSingleObject(th, 5000);
                DWORD code = 0;
                GetExitCodeThread(th, &code);
                CloseHandle(th);
                wchar_t cb[20]; swprintf_s(cb, L"0x%08X", code);
                VT_LOG(std::wstring(L"NtCreateThreadEx+LoadLibraryW thread exited code=") + cb);
                // NTSTATUS error pattern: 0xC0000xxx — Hyperion killed the thread.
                // Valid x64 HMODULE low-32 bits are never in that range.
                const bool ntstatus_fail = ((code & 0xF0000000) == 0xC0000000);
                // Check the DllMain beacon — the only reliable success indicator.
                HANDLE beacon = OpenEventW(SYNCHRONIZE, FALSE, L"VT_Diag_DllMain");
                bool ran = false;
                if (beacon) { ran = (WaitForSingleObject(beacon, 50) == WAIT_OBJECT_0); CloseHandle(beacon); }
                if (ran) {
                    VT_LOG(L"LoadLibrary(NtCTEx): DllMain beacon confirmed");
                    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
                    return {true, {}, (uintptr_t)code};
                }
                if (ntstatus_fail)
                    VT_WARN(std::wstring(L"NtCreateThreadEx+LoadLibraryW: Hyperion killed thread (code=") + cb + L")");
                else
                    VT_WARN(std::wstring(L"NtCreateThreadEx+LoadLibraryW: DllMain beacon not set (code=") + cb + L")");
            } else {
                VT_WARN(std::wstring(L"NtCreateThreadEx+LoadLibraryW failed ns=") + nb);
            }
        }
    }

    // Last resort: bare CreateRemoteThread — fully visible, but a definitive test.
    VT_WARN(L"Falling back to CreateRemoteThread+LoadLibraryW");
    {
        auto k32 = GetModuleHandleW(L"kernel32.dll");
        auto load = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
        HANDLE th = CreateRemoteThread(process, nullptr, 0, load, remote, 0, nullptr);
        if (!th) {
            VirtualFreeEx(process, remote, 0, MEM_RELEASE);
            return {false, L"CreateRemoteThread: " + last_error_text(), 0};
        }
        WaitForSingleObject(th, 10000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        CloseHandle(th);
        // Use DllMain beacon as the real success indicator — exit code alone is
        // ambiguous in x64 (GetExitCodeThread returns low 32 bits only).
        HANDLE beacon2 = OpenEventW(SYNCHRONIZE, FALSE, L"VT_Diag_DllMain");
        bool ran2 = false;
        if (beacon2) { ran2 = (WaitForSingleObject(beacon2, 50) == WAIT_OBJECT_0); CloseHandle(beacon2); }
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        if (ran2) {
            VT_LOG(L"LoadLibrary(CRT): DllMain beacon confirmed");
            return {true, {}, (uintptr_t)code};
        }
        wchar_t cb2[20]; swprintf_s(cb2, L"0x%08X", code);
        return {false, std::wstring(L"LoadLibraryW: DllMain not reached (code=") + cb2 + L", Hyperion blocked)", 0};
    }
}

} // namespace vt
