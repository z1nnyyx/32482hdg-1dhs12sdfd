#include "core/CallSpoof.h"
#include "shared/Log.h"

#include <Windows.h>

namespace vt {

// Position-independent 48-byte stub (see CallSpoof.h for layout comments).
// Offsets +32 and +40 are qwords filled at build time with gadget and target.
const uint8_t CallSpoof::kTemplate[48] = {
    // +0  mov rax, [rsp]
    0x48, 0x8B, 0x04, 0x24,
    // +4  mov r10, [rip+0x15]   (points to gadget_ptr at +32)
    //     r10 is volatile/scratch — does NOT corrupt any argument register
    0x4C, 0x8B, 0x15, 0x15, 0x00, 0x00, 0x00,
    // +11 mov [rsp], r10        (overwrite return addr with gadget)
    0x4C, 0x89, 0x14, 0x24,
    // +15 mov [rsp+8], rax      (shadow0 = real return address)
    0x48, 0x89, 0x44, 0x24, 0x08,
    // +20 jmp qword [rip+0x0E]  (points to stub_ptr at +40)
    0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00,
    // +26 padding (6 nops)
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    // +32 gadget_ptr  (8 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // +40 target_ptr  (8 bytes)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

CallSpoof& CallSpoof::get() {
    static CallSpoof s;
    return s;
}

CallSpoof::~CallSpoof() {
    if (m_page)
        VirtualFree(m_page, 0, MEM_RELEASE);
}

uintptr_t CallSpoof::find_gadget(HMODULE ntdll) {
    if (!ntdll)
        return 0;
    auto* base = (const uint8_t*)ntdll;
    auto* dos  = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    auto* nt  = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;
        const uint8_t* p = base + sec->VirtualAddress;
        const size_t   n = sec->Misc.VirtualSize;
        // Find `ret` (C3) that follows a multi-byte instruction epilogue
        // (add rsp, N is common: 48 83 C4 XX C3).  This looks like a
        // legitimate function return rather than a padding ret.
        for (size_t j = 4; j < n; ++j) {
            if (p[j] == 0xC3 &&
                p[j-4] == 0x48 && p[j-3] == 0x83 && p[j-2] == 0xC4)
                return (uintptr_t)(p + j);
        }
        // Fallback: any standalone ret.
        for (size_t j = 0; j < n; ++j) {
            if (p[j] == 0xC3)
                return (uintptr_t)(p + j);
        }
    }
    return 0;
}

bool CallSpoof::init() {
    if (ready())
        return true;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    m_gadget = find_gadget(ntdll);
    if (!m_gadget) {
        VT_WARN(L"CallSpoof: no ret gadget found in ntdll");
        return false;
    }

    // One 4KB page holds 4096/48 = 85 stubs — more than enough.
    m_page = VirtualAlloc(nullptr, kPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m_page) {
        VT_WARN(L"CallSpoof: failed to allocate stub page");
        return false;
    }
    m_used = 0;

    VT_LOG(L"CallSpoof: ready — gadget at ntdll+" + [&]{
        wchar_t b[32];
        swprintf_s(b, L"%llX", (ULONGLONG)(m_gadget - (uintptr_t)ntdll));
        return std::wstring(b);
    }());
    return true;
}

void* CallSpoof::alloc_stub(void* target_fn) {
    if (m_used + kStubSize > kPageSize)
        return nullptr;

    // Re-open the page for writing (may already be RX from a prior stub).
    DWORD old = 0;
    VirtualProtect(m_page, kPageSize, PAGE_READWRITE, &old);

    auto* slot = (uint8_t*)m_page + m_used;
    std::memcpy(slot, kTemplate, kStubSize);

    // Patch gadget pointer at +32 and target pointer at +40.
    auto* gadget_slot  = (uintptr_t*)(slot + 32);
    auto* target_slot  = (uintptr_t*)(slot + 40);
    *gadget_slot = m_gadget;
    *target_slot = (uintptr_t)target_fn;

    m_used += kStubSize;

    // Make the whole page RX now that the stub is written.
    // alloc_stub re-opens RW at the top on the next call.
    VirtualProtect(m_page, kPageSize, PAGE_EXECUTE_READ, &old);

    return slot;
}

} // namespace vt
