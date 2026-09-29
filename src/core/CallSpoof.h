#pragma once

// Call stack spoofing for NT syscall wrappers.
//
// When an NT function executes its `syscall` instruction, the kernel can
// optionally inspect the user-mode call stack.  Without spoofing, [RSP+0]
// points into our mapped region (or our EXE), which is a recognisable pattern.
//
// This module builds a tiny per-function "spoofer stub" that, when called
// in place of the real NT function, overwrites [RSP] with an ntdll gadget
// address BEFORE the syscall fires, then restores execution correctly after:
//
//   Caller → spoofer stub → sets [RSP]=gadget, [RSP+8]=real_ret → jmp NT stub
//   NT stub executes `syscall` — kernel sees [RSP] = ntdll address ✓
//   NT stub `ret` → gadget (C3 in ntdll) → real_ret → back in caller ✓
//
// This works for leaf NT syscall stubs because they never call subfunctions
// and therefore never write to their shadow space ([RSP+8] is safe).
//
// Usage:
//   CallSpoof cs;
//   cs.init();     // finds gadget, allocates page
//   auto fn = cs.make<NtCreateSection_t>(direct_syscall_stub_ptr);
//   fn(args...);   // called exactly like the real NT function

#include <Windows.h>
#include <cstdint>
#include <cstring>

namespace vt {

class CallSpoof {
public:
    static CallSpoof& get();

    // Locate ntdll ret gadget + allocate stub page.  Non-fatal if init fails —
    // make<> falls back to an unspoofed direct call.
    bool init();
    bool ready() const { return m_page != nullptr && m_gadget != 0; }

    // Build a spoofed wrapper for target_fn.  Each call to make<> carves
    // 48 bytes from the shared executable page.
    // Returns target_fn directly if not ready (unspoofed fallback).
    template<typename FnT>
    FnT make(void* target_fn) {
        if (!ready())
            return reinterpret_cast<FnT>(target_fn);
        void* stub = alloc_stub(target_fn);
        return stub ? reinterpret_cast<FnT>(stub) : reinterpret_cast<FnT>(target_fn);
    }

private:
    CallSpoof() = default;
    ~CallSpoof();

    void*    m_page    = nullptr;
    size_t   m_used    = 0;
    uintptr_t m_gadget = 0;

    static constexpr size_t kStubSize  = 48;
    static constexpr size_t kPageSize  = 4096;

    void*     alloc_stub(void* target_fn);
    uintptr_t find_gadget(HMODULE ntdll);

    // Spoofer stub template (position-independent, 48 bytes):
    //
    //  +0  48 8B 04 24              mov rax, [rsp]         save real ret addr
    //  +4  4C 8B 15 15 00 00 00     mov r10, [rip+0x15]    load gadget addr (r10=scratch)
    //  +11 4C 89 14 24              mov [rsp], r10          overwrite ret with gadget
    //  +15 48 89 44 24 08           mov [rsp+8], rax        shadow0 = real ret
    //  +20 FF 25 0E 00 00 00        jmp qword [rip+0x0E]   jump to NT stub
    //  +26 (6 bytes padding: 0x90)
    //  +32 qword  gadget_ptr        filled at build time
    //  +40 qword  target_ptr        filled at build time
    //
    // r10 is used instead of rdx so no argument register is corrupted.
    // When NT stub rets: RSP+8 → gadget → rets to real_ret_addr.  ✓
    static const uint8_t kTemplate[48];
};

} // namespace vt
