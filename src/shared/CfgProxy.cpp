#include "shared/CfgProxy.h"
#include "shared/Log.h"
#include "shared/Utils.h"

#include <Windows.h>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#ifndef IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK 0xF0000000u
#define IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT 28
#endif

namespace vt {
namespace {

bool seh_read(uintptr_t addr, void* out, size_t n) {
    __try {
        memcpy(out, (const void*)addr, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}



bool gadget_usable(const CfgGadget& g) {
    if (!g.va || g.disp <= 0 || (g.disp & 7))
        return false;
    // Any 8-aligned disp that fits on the clone page. Old 0x100+ window
    // produced hits=0 — COM thunks are jmp [rax+8]/+0x10/+0x18.
    if (g.disp >= 8 && g.disp <= 0x3F8)
        return true;
    return false;
}

// Decode a CFG-shaped indirect jump at `b`.
CfgGadget decode_jmp(uintptr_t va, const uint8_t* b, size_t n) {
    CfgGadget g{};
    if (n < 3)
        return g;
    g.va = va;
    // Prefer vtable-shaped: mov rax,[rcx]; then jmp [rax+disp] / jmp rax
    if (n >= 6 && b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x01) {
        g.reload_rcx = true;
        g.via_rax = true;
        const uint8_t* p = b + 3;
        size_t left = n - 3;
        if (left >= 3 && p[0] == 0xFF && p[1] == 0x60) { g.disp = (int8_t)p[2]; return g; }
        if (left >= 6 && p[0] == 0xFF && p[1] == 0xA0) { g.disp = *(int32_t*)(p + 2); return g; }
        if (left >= 2 && p[0] == 0xFF && p[1] == 0x20) { g.disp = 0; return g; }
        if (left >= 6 && p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x40 && left >= 6 &&
            p[4] == 0xFF && p[5] == 0xE0) {
            g.disp = (int8_t)p[3]; return g;
        }
        if (left >= 9 && p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x80 &&
            p[7] == 0xFF && p[8] == 0xE0) {
            g.disp = *(int32_t*)(p + 3); return g;
        }
        if (left >= 4 && p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x00 &&
            p[3] == 0xFF && left >= 5 && p[4] == 0xE0) {
            g.disp = 0; return g;
        }
        g.va = 0;
        return g;
    }
    if (b[0] == 0xFF && b[1] == 0x60) { g.via_rax = true;  g.disp = (int8_t)b[2]; return g; }
    if (n >= 6 && b[0] == 0xFF && b[1] == 0xA0) { g.via_rax = true;  g.disp = *(int32_t*)(b + 2); return g; }
    if (b[0] == 0xFF && b[1] == 0x61) { g.via_rax = false; g.disp = (int8_t)b[2]; return g; }
    if (n >= 6 && b[0] == 0xFF && b[1] == 0xA1) { g.via_rax = false; g.disp = *(int32_t*)(b + 2); return g; }
    if (n >= 4 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x60) { g.via_rax = true;  g.disp = (int8_t)b[3]; return g; }
    if (n >= 7 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0xA0) { g.via_rax = true;  g.disp = *(int32_t*)(b + 3); return g; }
    if (n >= 4 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x61) { g.via_rax = false; g.disp = (int8_t)b[3]; return g; }
    if (n >= 7 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0xA1) { g.via_rax = false; g.disp = *(int32_t*)(b + 3); return g; }
    if (n >= 6 && b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x40 && b[4] == 0xFF && b[5] == 0xE0) {
        g.via_rax = true; g.disp = (int8_t)b[3]; return g;
    }
    if (n >= 6 && b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x41 && b[4] == 0xFF && b[5] == 0xE0) {
        g.via_rax = false; g.disp = (int8_t)b[3]; return g;
    }
    if (n >= 9 && b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x80 && b[7] == 0xFF && b[8] == 0xE0) {
        g.via_rax = true; g.disp = *(int32_t*)(b + 3); return g;
    }
    if (n >= 9 && b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x81 && b[7] == 0xFF && b[8] == 0xE0) {
        g.via_rax = false; g.disp = *(int32_t*)(b + 3); return g;
    }
    g.va = 0;
    return g;
}

size_t skip_one(const uint8_t* p, size_t left) {
    if (left < 1) return 0;
    if (p[0] == 0x90) return 1;
    if (left >= 2 && p[0] == 0x66 && p[1] == 0x90) return 2;
    if (left >= 3 && p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x00) return 3;
    if (p[0] >= 0x50 && p[0] <= 0x57) return 1;
    if (left >= 2 && p[0] == 0x41 && p[1] >= 0x50 && p[1] <= 0x57) return 2;
    if (left >= 2 && (p[0] & 0xF0) == 0x40 && p[1] >= 0x50 && p[1] <= 0x57) return 2;
    if (left >= 4 && p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return 4;
    if (left >= 7 && p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return 7;
    if (left >= 5 && (p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x89 && p[3] == 0x24) return 5;
    if (left >= 3 && p[0] == 0x48 && p[1] == 0x8B && p[2] == 0x01) return 3;
    if (left >= 3 && p[0] == 0x48 && p[1] == 0x85 && p[2] == 0xC0) return 3;
    if (left >= 3 && p[0] == 0x48 && p[1] == 0x3B && p[2] == 0xC1) return 3;
    if (left >= 3 && p[0] == 0x48 && p[1] == 0x85 && p[2] == 0xC9) return 3;
    if (left >= 3 && p[0] == 0x45 && p[1] == 0x33 && p[2] == 0xC0) return 3;
    if (left >= 6 && p[0] == 0x41 && p[1] == 0xB8) return 6;
    if (left >= 6 && p[0] == 0x41 && p[1] == 0xB9) return 6;
    if (left >= 2 && p[0] == 0x74) return 2;
    if (left >= 6 && p[0] == 0x0F && p[1] == 0x84) return 6;
    return 0;
}

int find_ind_jmp(const uint8_t* b, size_t n) {
    for (size_t i = 0; i + 2 < n; ) {
        if (b[i] == 0xE8 || b[i] == 0xE9) { i += 5; continue; } // rel32 — FF 60 in disp is not a gadget
        if (b[i] == 0xFF) {
            if (b[i + 1] == 0x60 || b[i + 1] == 0x61 || b[i + 1] == 0x20)
                return (int)i;
            if (i + 5 < n && (b[i + 1] == 0xA0 || b[i + 1] == 0xA1))
                return (int)i;
        }
        ++i;
    }
    return -1;
}

CfgGadget parse_bytes(uintptr_t va, const uint8_t* b, size_t n) {
    CfgGadget direct = decode_jmp(va, b, n);
    if (gadget_usable(direct))
        return direct;
    const int jo = find_ind_jmp(b, n);
    if (jo > 0) {
        size_t i = 0;
        while (i < (size_t)jo) {
            const size_t k = skip_one(b + i, n - i);
            if (!k)
                break;
            i += k;
        }
        if (i == (size_t)jo) {
            CfgGadget g = decode_jmp(va, b + (size_t)jo, n - (size_t)jo);
            if (gadget_usable(g) || (g.va && g.disp >= 8 && (g.disp & 7) == 0 && g.disp <= 0x3F8)) {
                g.va = va;
                for (size_t p = 0; p + 2 < i; ++p)
                    if (b[p] == 0x48 && b[p + 1] == 0x8B && b[p + 2] == 0x01)
                        g.reload_rcx = true;
                if (gadget_usable(g))
                    return g;
            }
        }
    }
    size_t skip = 0;
    for (int step = 0; step < 14; ++step) {
        const size_t k = skip_one(b + skip, n - skip);
        if (!k) break;
        skip += k;
    }
    if (!skip || skip >= n)
        return {};
    CfgGadget g = decode_jmp(va, b + skip, n - skip);
    if (!g.va)
        return {};
    if (n >= 3 && b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x01)
        g.reload_rcx = true;
    g.va = va;
    return g;
}

CfgGadget parse_bytes(uintptr_t va) {
    uint8_t b[24]{};
    if (!seh_read(va, b, sizeof(b)))
        return {};
    return parse_bytes(va, b, sizeof(b));
}

int score_of(const CfgGadget& x) {
    int s = 0;
    if (x.reload_rcx) s += 2000;
    if (x.via_rax)    s += 1000;
    if (x.disp >= 0x40) s += 400;
    s += x.disp;
    return s;
}

uintptr_t g_mov_rcx[8]{};
int       g_mov_rcx_n = 0;
int       g_near_jmp = 0;
struct NearJmp { uintptr_t va; int off; uint8_t b[16]; };
NearJmp   g_nears[8]{};
int       g_near_n = 0;

void consider_bytes(CfgGadget& best, uintptr_t va, const uint8_t* b, size_t n, int& hits, int* kind) {
    const int jo = find_ind_jmp(b, n);
    if (jo >= 0) {
        ++g_near_jmp;
        if (g_near_n < 8) {
            g_nears[g_near_n].va = va;
            g_nears[g_near_n].off = jo;
            memcpy(g_nears[g_near_n].b, b, 16);
            ++g_near_n;
        }
    }
    if (n >= 4 && kind) {
        if (b[0] == 0xFF && b[1] == 0x60) ++kind[0];
        if (b[0] == 0xFF && b[1] == 0x61) ++kind[1];
        if (b[0] == 0x48 && b[1] == 0x8B && b[2] == 0x01) {
            ++kind[2];
            if (g_mov_rcx_n < 8)
                g_mov_rcx[g_mov_rcx_n++] = va;
        }
        if (b[0] == 0xFF && b[1] == 0xE1) ++kind[3];
    }
    CfgGadget g = parse_bytes(va, b, n);
    if (!gadget_usable(g))
        return;
    ++hits;
    if (!best.va || score_of(g) > score_of(best))
        best = g;
}

void consider(CfgGadget& best, uintptr_t va, int& hits, int* kind) {
    uint8_t b[32]{};
    if (!seh_read(va, b, sizeof(b)))
        return;
    consider_bytes(best, va, b, sizeof(b), hits, kind);
}

struct CfTable {
    uint8_t*  base = nullptr;
    uintptr_t table = 0;
    size_t    count = 0;
    DWORD     stride = 4;
};

bool seh_load_cf_table(HMODULE hm, CfTable* out) {
    __try {
        auto* base = (uint8_t*)hm;
        auto* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;
        auto* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;
        const auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (!dir.VirtualAddress || dir.Size < 0x94)
            return false;
        auto* lc = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(base + dir.VirtualAddress);
        if (lc->Size < 0x94 || !lc->GuardCFFunctionTable || !lc->GuardCFFunctionCount)
            return false;
        const DWORD extra = (lc->GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>
                            IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
        out->base = base;
        out->stride = 4 + extra;
        out->count = (size_t)lc->GuardCFFunctionCount;
        out->table = (uintptr_t)lc->GuardCFFunctionTable;
        return out->table && out->count;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}



void walk_guard_cf(HMODULE hm, const wchar_t* name, CfgGadget& best, int& hits, int* kind) {
    CfTable t{};
    if (!seh_load_cf_table(hm, &t))
        return;
    const int before = hits;
    VT_LOG(L"CFG table " + std::wstring(name) + L" count=" +
           std::to_wstring((unsigned long long)t.count));
    for (size_t i = 0; i < t.count && i < 250000; ++i) {
        uint32_t rva = 0;
        if (!seh_read(t.table + i * t.stride, &rva, 4) || !rva)
            continue;
        consider(best, (uintptr_t)t.base + rva, hits, kind);
    }
    if (hits != before)
        VT_LOG(L"CFG " + std::wstring(name) + L" usable gadgets +" +
               std::to_wstring(hits - before));
}

uintptr_t file_rva_off(const uint8_t* raw, size_t n, const IMAGE_NT_HEADERS64* nt, uint64_t rva) {
    auto* sec = IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS64*>(nt));
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        const uint32_t va = sec->VirtualAddress;
        const uint32_t sz = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (rva >= va && rva < va + sz) {
            const uint64_t off = (uint64_t)sec->PointerToRawData + (rva - va);
            if (off < n)
                return (uintptr_t)off;
            return 0;
        }
    }
    return 0;
}

void walk_guard_cf_file(const uint8_t* raw, size_t n, uintptr_t live_base,
                        const wchar_t* name, CfgGadget& best, int& hits, int* kind) {
    if (!raw || n < 0x200)
        return;
    auto* dos = (const IMAGE_DOS_HEADER*)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return;
    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > n)
        return;
    auto* nt = (const IMAGE_NT_HEADERS64*)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return;
    const auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!dir.VirtualAddress || dir.Size < 0x94)
        return;
    const uintptr_t lc_off = file_rva_off(raw, n, nt, dir.VirtualAddress);
    if (!lc_off || lc_off + 0x94 > n)
        return;
    auto* lc = (const IMAGE_LOAD_CONFIG_DIRECTORY64*)(raw + lc_off);
    if (lc->Size < 0x94 || !lc->GuardCFFunctionTable || !lc->GuardCFFunctionCount)
        return;
    uint64_t table_va = (uint64_t)lc->GuardCFFunctionTable;
    uint64_t table_rva = table_va;
    if (table_va >= nt->OptionalHeader.ImageBase)
        table_rva = table_va - nt->OptionalHeader.ImageBase;
    const DWORD extra = (lc->GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>
                        IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
    const DWORD stride = 4 + extra;
    const size_t count = (size_t)lc->GuardCFFunctionCount;
    const uintptr_t tbl_off = file_rva_off(raw, n, nt, table_rva);
    if (!tbl_off)
        return;
    const int before = hits;
    VT_LOG(L"CFG file " + std::wstring(name) + L" count=" +
           std::to_wstring((unsigned long long)count));
    for (size_t i = 0; i < count && i < 250000; ++i) {
        const uintptr_t eoff = tbl_off + i * stride;
        if (eoff + 4 > n)
            break;
        uint32_t rva = 0;
        memcpy(&rva, raw + eoff, 4);
        if (!rva)
            continue;
        const uintptr_t foff = file_rva_off(raw, n, nt, rva);
        if (!foff || foff + 32 > n)
            continue;
        uint8_t b[32]{};
        memcpy(b, raw + foff, sizeof(b));
        consider_bytes(best, live_base + rva, b, sizeof(b), hits, kind);
    }
    if (hits != before)
        VT_LOG(L"CFG file " + std::wstring(name) + L" usable gadgets +" +
               std::to_wstring(hits - before));
}

void log_best(const CfgGadget& best, int hits) {
    if (best.va) {
        std::wstring how = best.reload_rcx
            ? L" mov rax,[rcx]; jmp[rax+"
            : (best.via_rax ? L" jmp[rax+" : L" jmp[rcx+");
        VT_LOG(L"CFG gadget " + format_hex(best.va) + how +
               format_hex((uintptr_t)best.disp) + L"]  cf-table=yes hits=" +
               std::to_wstring(hits));
    } else
        VT_WARN(L"CFG gadget: none in CF tables (hits=" +
                std::to_wstring(hits) + L")");
}

CfgGadget g_cached{};
bool      g_scanned_local = false;

} // namespace

CfgGadget scan_cfg_gadget() {
    if (g_scanned_local)
        return g_cached;
    g_scanned_local = true;

    // System images only for the local pass — same VA in every process this boot.
    const wchar_t* mods[] = {
        L"ntdll.dll", L"KERNELBASE.dll", L"KERNEL32.dll", L"USER32.dll",
        L"combase.dll", L"ole32.dll", L"oleaut32.dll", L"rpcrt4.dll",
        L"SHCORE.dll", L"clbcatq.dll", L"WinTypes.dll", L"OLEACC.dll",
        L"PROPSYS.dll", L"urlmon.dll", L"iertutil.dll",
        L"dxgi.dll", L"d3d11.dll", L"d2d1.dll", L"dcomp.dll", L"DWrite.dll",
        L"windowscodecs.dll", L"CoreMessaging.dll", L"twinapi.appcore.dll",
        L"advapi32.dll", L"sechost.dll", L"shell32.dll", L"shlwapi.dll",
        L"ucrtbase.dll", L"msvcrt.dll", L"crypt32.dll",
        nullptr
    };
    CfgGadget best{};
    int hits = 0;
    int kind[4]{};
    g_mov_rcx_n = 0;
    g_near_jmp = 0;
    g_near_n = 0;
    for (int i = 0; mods[i]; ++i) {
        HMODULE hm = GetModuleHandleW(mods[i]);
        if (!hm)
            hm = LoadLibraryExW(mods[i], nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!hm)
            continue;
        walk_guard_cf(hm, mods[i], best, hits, kind);
        if (best.va && best.reload_rcx && best.disp >= 0x40)
            break;
    }
    VT_LOG(L"CFG prologues jmp[rax+]= " + std::to_wstring(kind[0]) +
           L" jmp[rcx+]= " + std::to_wstring(kind[1]) +
           L" mov[rcx]= " + std::to_wstring(kind[2]) +
           L" jmp rcx= " + std::to_wstring(kind[3]) +
           L" near-jmp-in-32b= " + std::to_wstring(g_near_jmp));
    for (int i = 0; i < g_mov_rcx_n; ++i) {
        uint8_t b[16]{};
        seh_read(g_mov_rcx[i], b, 16);
        wchar_t hex[48]{};
        size_t n = 0;
        for (int k = 0; k < 12 && n + 4 < 48; ++k)
            n += (size_t)swprintf_s(hex + n, 48 - n, L"%02X ", b[k]);
        VT_LOG(L"mov[rcx] " + format_hex(g_mov_rcx[i]) + L"  " + hex);
    }
    for (int i = 0; i < g_near_n; ++i) {
        wchar_t hex[48]{};
        size_t n = 0;
        for (int k = 0; k < 12 && n + 4 < 48; ++k)
            n += (size_t)swprintf_s(hex + n, 48 - n, L"%02X ", g_nears[i].b[k]);
        VT_LOG(L"near-jmp off=" + std::to_wstring(g_nears[i].off) + L" " +
               format_hex(g_nears[i].va) + L"  " + hex);
    }
    g_cached = best;
    log_best(best, hits);
    return g_cached;
}

CfgGadget scan_cfg_gadget_remote(HANDLE process, DWORD pid) {
    (void)process;
    scan_cfg_gadget();
    if (!pid)
        return g_cached;

    // Read Roblox's PE from disk — do not RPM 170k .text prologues (that is
    // what Hyperion used to delayed-kill after map). Live VA = module base + RVA.
    CfgGadget best = g_cached;
    int hits = best.va ? 1 : 0;
    int kind[4]{};
    const wchar_t* names[] = {
        L"RobloxPlayerBeta.exe", L"RobloxPlayerBeta.dll", nullptr
    };
    for (int i = 0; names[i]; ++i) {
        auto m = find_module(pid, names[i]);
        if (!m || !m->base || m->path.empty())
            continue;
        std::ifstream f(m->path, std::ios::binary);
        if (!f)
            continue;
        f.seekg(0, std::ios::end);
        const std::streamoff sz = f.tellg();
        if (sz < 0x400 || sz > 256 * 1024 * 1024)
            continue;
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> raw((size_t)sz);
        if (!f.read((char*)raw.data(), sz))
            continue;
        walk_guard_cf_file(raw.data(), raw.size(), m->base, names[i], best, hits, kind);
    }
    if (best.va && (!g_cached.va || score_of(best) > score_of(g_cached))) {
        g_cached = best;
        VT_LOG(L"CFG using target-image gadget");
        log_best(best, hits);
    } else if (!g_cached.va) {
        VT_WARN(L"CFG gadget: none — holding attach, no vtable/APC/GUARD");
    }
    return g_cached;
}

} // namespace vt
