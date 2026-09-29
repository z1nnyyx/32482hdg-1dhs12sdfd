#pragma once

// Runtime import resolution by FNV-1a hash.
// Use this instead of GetProcAddress for any function the DLL looks up at
// runtime — it leaves no plaintext strings in the IAT or code section.
//
// Usage:
//   auto fn = import_hash::resolve<MyFnType>(import_hash::hash("FunctionName"));

#include <Windows.h>
#include <intrin.h>
#include <cstdint>

namespace vt::import_hash {

// Compile-time FNV-1a hash of an ASCII string.
constexpr uint32_t hash(const char* s) noexcept {
    uint32_t h = 2166136261u;
    while (*s)
        h = (h ^ (uint8_t)*s++) * 16777619u;
    return h;
}

namespace detail {

// Walk the export table of a loaded module and return the VA of the export
// whose name hashes to target_hash.  Returns nullptr on failure.
inline void* find_export(HMODULE mod, uint32_t target_hash) {
    if (!mod)
        return nullptr;
    auto* base = (const uint8_t*)mod;
    auto* dos  = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;
    auto* nt   = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;
    const auto& edir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!edir.Size)
        return nullptr;
    auto* exp = (const IMAGE_EXPORT_DIRECTORY*)(base + edir.VirtualAddress);
    auto* names   = (const DWORD*)(base + exp->AddressOfNames);
    auto* funcs   = (const DWORD*)(base + exp->AddressOfFunctions);
    auto* ords    = (const WORD* )(base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = (const char*)(base + names[i]);
        if (hash(name) == target_hash)
            return (void*)(base + funcs[ords[i]]);
    }
    return nullptr;
}

// Resolve a module by name (already loaded — walks PEB loader list).
inline HMODULE get_module(uint32_t name_hash) {
    // Walk PEB InLoadOrderModuleList.
    auto* peb = (const uint8_t*)__readgsqword(0x60);
    auto* ldr = *(const uint8_t**)(peb + 0x18);
    auto* head = ldr + 0x10;  // InLoadOrderModuleList.Flink
    auto* cur  = *(const uint8_t**)head;
    while (cur != head) {
        // LDR_DATA_TABLE_ENTRY: +0x58 = DllBase, +0x48 = BaseDllName (UNICODE_STRING)
        auto* dll_base = *(void**)(cur + 0x30);
        auto* name_len = (const USHORT*)(cur + 0x58);
        auto* name_buf = *(const wchar_t**)(cur + 0x60);
        if (dll_base && name_buf && *name_len > 0) {
            // Hash the lowercase module name.
            uint32_t h = 2166136261u;
            for (USHORT j = 0; j < *name_len / sizeof(wchar_t); ++j) {
                wchar_t c = name_buf[j];
                if (c >= L'A' && c <= L'Z') c += 32;
                h = (h ^ (uint8_t)c) * 16777619u;
                h = (h ^ (uint8_t)(c >> 8)) * 16777619u;
            }
            if (h == name_hash)
                return (HMODULE)dll_base;
        }
        cur = *(const uint8_t**)cur; // Flink
    }
    return nullptr;
}

} // namespace detail

// Compile-time module name hash (lowercase).
constexpr uint32_t module_hash(const char* s) noexcept {
    uint32_t h = 2166136261u;
    while (*s) {
        char c = *s++;
        if (c >= 'A' && c <= 'Z') c += 32;
        h = (h ^ (uint8_t)c) * 16777619u;
    }
    return h;
}

// Resolve a function by module hash + function name hash.
// Returns nullptr if not found.
template<typename FnT = void*>
FnT resolve(uint32_t mod_hash, uint32_t fn_hash) {
    HMODULE mod = detail::get_module(mod_hash);
    return reinterpret_cast<FnT>(detail::find_export(mod, fn_hash));
}

// Pre-computed hashes for common targets.
// Usage: import_hash::resolve<FnType>(Mod::ntdll, Fn::NtSetInformationThread)
namespace Mod {
    constexpr uint32_t ntdll    = module_hash("ntdll.dll");
    constexpr uint32_t kernel32 = module_hash("kernel32.dll");
    constexpr uint32_t kernbase = module_hash("kernelbase.dll");
}
namespace Fn {
    constexpr uint32_t NtSetInformationThread = hash("NtSetInformationThread");
    constexpr uint32_t RtlQueueWorkItem       = hash("RtlQueueWorkItem");
    constexpr uint32_t NtDelayExecution       = hash("NtDelayExecution");
    constexpr uint32_t NtCreateThreadEx       = hash("NtCreateThreadEx");
    constexpr uint32_t LdrLoadDll             = hash("LdrLoadDll");
    constexpr uint32_t VirtualAlloc           = hash("VirtualAlloc");
}

} // namespace vt::import_hash
