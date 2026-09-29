#include "core/ThreadHijack.h"
#include "core/Syscall.h"
#include "shared/Log.h"

#include <TlHelp32.h>
#include <vector>

namespace vt {
namespace {

// Remote page layout used during the hijack window:
//   +0x00  2 bytes  jmp $ (EB FE) — thread spins here after stub returns
//   +0x08  8 bytes  return-address slot — set to +0x00 so stub ret lands on jmp $
// (the rest is guard / alignment)
constexpr SIZE_T kTrampolinePageSize = 0x1000;

// Pick a target return address that is readable and writable but will
// simply spin the victim thread harmlessly until we restore its context.
// We embed the "jmp $" in remote memory so there is no risk of landing
// on an access-violating null page.
bool write_trampoline(HANDLE process, uintptr_t page) {
    // EB FE = jmp -2 (infinite loop — spins in place without touching memory)
    const uint8_t code[] = {0xEB, 0xFE, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    SIZE_T written = 0;
    return SC_WriteProcessMemory(process, (void*)page, code, sizeof(code), &written)
        && written == sizeof(code);
}

} // namespace

DWORD ThreadHijacker::pick_victim(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    // Collect all candidate TIDs.
    std::vector<DWORD> tids;
    THREADENTRY32 te{sizeof(te)};
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                tids.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (tids.empty())
        return 0;

    // The main thread typically has the smallest TID.
    DWORD main_tid = tids[0];
    for (DWORD t : tids)
        if (t < main_tid) main_tid = t;

    // Prefer a thread that's currently waiting (SuspendCount == 0 and alertable).
    // We fall back to any non-main thread if we can't determine sleep state.
    for (DWORD tid : tids) {
        if (tid == main_tid)
            continue;
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                              THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!h)
            continue;
        // Briefly suspend to read the context — if suspend count was 0 the thread
        // was running/waiting, which is what we want (threads with SuspendCount > 0
        // already have their context modified by someone else).
        DWORD prev = SuspendThread(h);
        ResumeThread(h);
        CloseHandle(h);
        // prev == 0 means thread was active (not already suspended).
        if (prev == 0)
            return tid;
    }

    // Last resort: take the first non-main thread.
    for (DWORD tid : tids)
        if (tid != main_tid)
            return tid;

    return 0;
}

bool ThreadHijacker::is_hyperion_thread(HANDLE /*thread*/, HANDLE /*process*/) {
    // Full heuristic: compare thread start address against known Hyperion module
    // ranges. For now we just avoid the main thread (done in pick_victim).
    return false;
}

HijackResult ThreadHijacker::run(HANDLE  process,
                                 DWORD   pid,
                                 LPVOID  start_addr,
                                 LPVOID  param,
                                 HANDLE  connect_event,
                                 DWORD   timeout_ms,
                                 DWORD   target_tid)
{
    HijackResult r;

    const DWORD tid = target_tid ? target_tid : pick_victim(pid);
    if (!tid) {
        r.error = L"no suitable victim thread found in target";
        return r;
    }

    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE, tid);
    if (!hThread) {
        r.error = L"OpenThread failed on victim";
        return r;
    }

    // Allocate remote trampoline page — only used as the spin target (jmp $).
    // RSP is NOT pointed here; the thread's own existing stack is used instead.
    void* raw_page = nullptr;
    if (!SC_VirtualAllocEx(process, nullptr, kTrampolinePageSize,
                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, &raw_page) || !raw_page) {
        CloseHandle(hThread);
        r.error = L"failed to allocate trampoline page";
        return r;
    }
    const uintptr_t page = (uintptr_t)raw_page;

    // Write the jmp-$ trampoline at the start of the page.
    if (!write_trampoline(process, page)) {
        VirtualFreeEx(process, raw_page, 0, MEM_RELEASE);
        CloseHandle(hThread);
        r.error = L"failed to write jmp$ trampoline";
        return r;
    }

    DWORD old_prot = 0;
    SC_VirtualProtectEx(process, raw_page, kTrampolinePageSize, PAGE_EXECUTE_READ, &old_prot);

    // Suspend the victim and save its full context.
    if (SuspendThread(hThread) == (DWORD)-1) {
        VirtualFreeEx(process, raw_page, 0, MEM_RELEASE);
        CloseHandle(hThread);
        r.error = L"SuspendThread failed";
        return r;
    }

    CONTEXT saved{};
    saved.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &saved)) {
        ResumeThread(hThread);
        VirtualFreeEx(process, raw_page, 0, MEM_RELEASE);
        CloseHandle(hThread);
        r.error = L"GetThreadContext failed";
        return r;
    }

    // Use the victim thread's existing stack — write the return address one
    // slot below its current RSP.  This keeps the stack in fully-committed
    // memory and guarantees 16-byte alignment inside the injection stub.
    //
    //   Before stub:  RSP = saved.Rsp - 8   (ret_addr = page = jmp$ is at [RSP])
    //   Stub: sub rsp,28h → RSP - 48 (0 mod 16, correct before CALL)
    //   CALL DllMain  → RSP - 56 (8 mod 16, correct at callee entry)
    //   After DllMain returns + add rsp,28h → RSP = saved.Rsp - 8
    //   RET → pops page, thread spins on jmp$, we then restore saved context.
    const uintptr_t ret_addr  = page;              // ret → jmp $
    const uintptr_t rsp_entry = saved.Rsp - 8;    // one slot below thread's current RSP

    SIZE_T dummy = 0;
    if (!SC_WriteProcessMemory(process, (void*)rsp_entry, &ret_addr, sizeof(ret_addr), &dummy)) {
        ResumeThread(hThread);
        VirtualFreeEx(process, raw_page, 0, MEM_RELEASE);
        CloseHandle(hThread);
        r.error = L"failed to write return address onto thread stack";
        return r;
    }

    // Build redirected context:
    //   RIP = start_addr (our injection stub in Roblox's address space)
    //   RSP = rsp_entry  ([rsp_entry] = ret_addr = jmp $)
    //   RCX = param      (first argument to the stub)
    CONTEXT hijacked = saved;
    hijacked.Rip = (DWORD64)start_addr;
    hijacked.Rsp = (DWORD64)rsp_entry;
    hijacked.Rcx = (DWORD64)param;
    hijacked.EFlags &= ~0x100UL; // clear TF (single-step trap)

    if (!SetThreadContext(hThread, &hijacked)) {
        ResumeThread(hThread);
        VirtualFreeEx(process, raw_page, 0, MEM_RELEASE);
        CloseHandle(hThread);
        r.error = L"SetThreadContext failed";
        return r;
    }

    ResumeThread(hThread);

    // Wait for the DLL to bootstrap and return from DllMain.
    // DllMain queues its work via a worker thread and returns quickly.
    if (connect_event) {
        WaitForSingleObject(connect_event, timeout_ms < 2500 ? timeout_ms : 2500);
    } else {
        Sleep(2500);
    }

    // Restore the victim thread to its original context.
    SuspendThread(hThread);
    SetThreadContext(hThread, &saved);
    ResumeThread(hThread);

    // Free the trampoline page.
    VirtualFreeEx(process, raw_page, 0, MEM_RELEASE);
    CloseHandle(hThread);

    r.ok = true;
    return r;
}

} // namespace vt
