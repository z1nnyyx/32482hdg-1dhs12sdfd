#pragma once

#include <Windows.h>
#include <string>
#include <cstdint>

// Thread hijacking injector.
// Redirects an existing Roblox thread's execution to the entry stub instead
// of creating a new thread via NtCreateThreadEx.
//
// This eliminates the PsSetCreateThreadNotifyRoutine signal that fires when
// any new thread is created in a monitored process — one of Hyperion's
// primary injection detection vectors.
//
// Flow:
//   1. Enumerate Roblox threads, pick a sleepy worker thread.
//   2. SuspendThread, GetThreadContext — save full CONTEXT.
//   3. Write a tiny "spin" trampoline just below RSP.
//   4. Redirect RIP → stub, RSP → our area, RCX → param.
//   5. ResumeThread — stub runs inside the victim thread.
//   6. Poll until DLL signals connect or timeout expires.
//   7. SuspendThread, SetThreadContext (restore), ResumeThread.

namespace vt {

struct HijackResult {
    bool         ok     = false;
    std::wstring error;
};

class ThreadHijacker {
public:
    // Execute start_addr(param) inside an existing Roblox thread.
    // connect_event: set by the DLL's pipe connect path; we wait for it
    //                before restoring the victim thread.
    // timeout_ms:    hard cap in case connect never fires.
    static HijackResult run(HANDLE  process,
                            DWORD   pid,
                            LPVOID  start_addr,
                            LPVOID  param,
                            HANDLE  connect_event = nullptr,
                            DWORD   timeout_ms    = 12000,
                            DWORD   target_tid    = 0);

    static DWORD   pick_victim(DWORD pid);

private:
    static bool    is_hyperion_thread(HANDLE thread, HANDLE process);
};

} // namespace vt
