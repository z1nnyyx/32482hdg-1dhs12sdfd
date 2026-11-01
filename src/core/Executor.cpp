// SPDX-License-Identifier: MIT
// VoidTrace native executor implementation. Ported from Xeno's worker.cpp
// with all dead code (GetRV, HTTP server, init loop, GetProcessIDsByName)
// removed. Single clean attach→bootstrap→execute pipeline.

#include "Executor.h"
#include "shared/Config.h"
#include "shared/Log.h"

#include <windows.h>
#include <objbase.h>
#include <psapi.h>
#include <iostream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <filesystem>

#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include <xxhash.h>
#include <zstd.h>

#include "Luau/Compiler.h"
#include "Luau/BytecodeBuilder.h"
#include "Luau/BytecodeUtils.h"

#include "utils/ntdll.h"
#include "utils/resource.h"

namespace vt {

// -----------------------------------------------------------------------
// Memory primitives
// -----------------------------------------------------------------------

template<typename T>
T read_mem(std::uintptr_t address, HANDLE handle) {
    T value{};
    MEMORY_BASIC_INFORMATION bi{};
    VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &bi, sizeof(bi));
    NtReadVirtualMemory(handle, reinterpret_cast<LPCVOID>(address),
                        &value, sizeof(T), nullptr);
    PVOID baddr = bi.AllocationBase;
    SIZE_T size = bi.RegionSize;
    NtUnlockVirtualMemory(handle, &baddr, &size, 1);
    return value;
}

template std::uintptr_t read_mem<std::uintptr_t>(std::uintptr_t, HANDLE);
template std::uint64_t  read_mem<std::uint64_t>(std::uintptr_t, HANDLE);
template std::uint32_t  read_mem<std::uint32_t>(std::uintptr_t, HANDLE);
template std::uint8_t   read_mem<std::uint8_t>(std::uintptr_t, HANDLE);
template DWORD          read_mem<DWORD>(std::uintptr_t, HANDLE);

template<typename T>
bool write_mem(std::uintptr_t address, const T& value, HANDLE handle) {
    MEMORY_BASIC_INFORMATION bi{};
    VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &bi, sizeof(bi));

    DWORD old_protect = 0;
    VirtualProtectEx(handle, reinterpret_cast<LPVOID>(address),
                     sizeof(T), PAGE_READWRITE, &old_protect);

    SIZE_T written = 0;
    NTSTATUS status = NtWriteVirtualMemory(
        handle, reinterpret_cast<LPVOID>(address),
        (PVOID)&value, sizeof(T), &written);

    DWORD dummy = 0;
    VirtualProtectEx(handle, reinterpret_cast<LPVOID>(address),
                     sizeof(T), old_protect, &dummy);

    PVOID baddr = bi.AllocationBase;
    SIZE_T sz = bi.RegionSize;
    NtUnlockVirtualMemory(handle, &baddr, &sz, 1);
    return status == 0 && written == sizeof(T);
}

template bool write_mem<std::uintptr_t>(std::uintptr_t, const std::uintptr_t&, HANDLE);
template bool write_mem<std::uint64_t>(std::uintptr_t, const std::uint64_t&, HANDLE);
template bool write_mem<std::uint32_t>(std::uintptr_t, const std::uint32_t&, HANDLE);

std::string read_roblox_string(std::uintptr_t address, HANDLE handle) {
    std::uint64_t len = read_mem<std::uint64_t>(address + 0x10, handle);
    if (len > 15000 || len <= 0)
        return "";
    if (len > 15)
        address = read_mem<std::uintptr_t>(address, handle);

    std::string buf;
    buf.resize(len);

    MEMORY_BASIC_INFORMATION bi{};
    VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &bi, sizeof(bi));
    NtReadVirtualMemory(handle, reinterpret_cast<LPCVOID>(address),
                        buf.data(), (ULONG)len, nullptr);
    PVOID baddr = bi.AllocationBase;
    SIZE_T sz = bi.RegionSize;
    NtUnlockVirtualMemory(handle, &baddr, &sz, 1);
    return buf;
}

// -----------------------------------------------------------------------
// inst_offsets
// -----------------------------------------------------------------------

namespace inst_offsets {
void apply_discovered(std::uint64_t name, std::uint64_t children, std::uint64_t parent) {
    if (name)     Name_mut()     = name;
    if (children) Children_mut() = children;
    if (parent)   Parent_mut()   = parent;
    std::cout << "[voidtrace] offsets::apply_discovered  Name=0x"
              << std::hex << Name() << " Children=0x" << Children()
              << " Parent=0x" << Parent() << std::dec << "\n";
}
} // namespace inst_offsets

// -----------------------------------------------------------------------
// Instance
// -----------------------------------------------------------------------

Instance::Instance(std::uintptr_t address, HANDLE handle)
    : addr_(address), hproc_(handle) {}

std::string Instance::name() const {
    return read_roblox_string(
        read_mem<std::uintptr_t>(addr_ + inst_offsets::Name(), hproc_), hproc_);
}

std::string Instance::class_name() const {
    auto desc = read_mem<std::uintptr_t>(addr_ + inst_offsets::ClassDescriptor, hproc_);
    auto cn_ptr = read_mem<std::uintptr_t>(desc + inst_offsets::ClassName, hproc_);
    return read_roblox_string(cn_ptr, hproc_);
}

std::uintptr_t Instance::parent_address() const {
    return read_mem<std::uintptr_t>(addr_ + inst_offsets::Parent(), hproc_);
}

std::vector<std::uintptr_t> Instance::children_addresses() const {
    std::uintptr_t childrenPtr = read_mem<std::uintptr_t>(
        addr_ + inst_offsets::Children(), hproc_);
    if (childrenPtr == 0) return {};

    std::uintptr_t start = read_mem<std::uintptr_t>(childrenPtr, hproc_);
    std::uintptr_t end   = read_mem<std::uintptr_t>(childrenPtr + 0x8, hproc_) + 1;
    if (end <= start || start == 0) return {};
    if ((end - start) > 0x2000) return {};

    auto try_stride = [&](std::uintptr_t stride) {
        std::vector<std::uintptr_t> out;
        for (std::uintptr_t a = start; a < end; a += stride) {
            std::uintptr_t p = read_mem<std::uintptr_t>(a, hproc_);
            if (p != 0 && p > 0x10000 && p < 0x00007FFFFFFFFFFFULL)
                out.push_back(p);
        }
        return out;
    };
    auto c16 = try_stride(0x10);
    auto c8  = try_stride(0x8);
    return (c8.size() > c16.size()) ? c8 : c16;
}

std::unique_ptr<Instance> Instance::find_child(std::string_view name) const {
    auto addr = find_child_address(name);
    if (addr) return std::make_unique<Instance>(addr, hproc_);
    return nullptr;
}

std::uintptr_t Instance::find_child_address(std::string_view name) const {
    for (auto addr : children_addresses()) {
        auto n = read_roblox_string(
            read_mem<std::uintptr_t>(addr + inst_offsets::Name(), hproc_), hproc_);
        if (n == name) return addr;
    }
    return 0;
}

std::unique_ptr<Instance> Instance::find_child_of_class(std::string_view cls) const {
    auto addr = find_child_of_class_address(cls);
    if (addr) return std::make_unique<Instance>(addr, hproc_);
    return nullptr;
}

std::uintptr_t Instance::find_child_of_class_address(std::string_view cls) const {
    for (auto addr : children_addresses()) {
        auto desc = read_mem<std::uintptr_t>(addr + inst_offsets::ClassDescriptor, hproc_);
        auto cn_ptr = read_mem<std::uintptr_t>(desc + inst_offsets::ClassName, hproc_);
        if (read_roblox_string(cn_ptr, hproc_) == cls) return addr;
    }
    return 0;
}

std::uintptr_t Instance::wait_for_child_address(std::string_view name, int timeout_sec) const {
    auto existing = find_child_address(name);
    if (existing) return existing;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    while (std::chrono::steady_clock::now() < deadline) {
        auto a = find_child_address(name);
        if (a) return a;
        Sleep(100);
    }
    return 0;
}

bool Instance::set_bytecode(const std::string& compressed, bool revert) const {
    auto cn = class_name();
    if (cn != "LocalScript" && cn != "ModuleScript")
        return false;

    std::uintptr_t embOff = (cn == "LocalScript")
        ? inst_offsets::LocalScriptEmbedded
        : inst_offsets::ModuleScriptEmbedded;
    std::uintptr_t embPtr = read_mem<std::uintptr_t>(addr_ + embOff, hproc_);

    if (revert) {
        std::uintptr_t origBC = read_mem<std::uintptr_t>(embPtr + inst_offsets::Bytecode, hproc_);
        std::uint64_t origSz  = read_mem<std::uint64_t>(embPtr + inst_offsets::BytecodeSize, hproc_);
        auto h = hproc_;
        std::thread([embPtr, origBC, origSz, h]() {
            Sleep(850);
            write_mem<std::uintptr_t>(embPtr + inst_offsets::Bytecode, origBC, h);
            write_mem<std::uint64_t>(embPtr + inst_offsets::BytecodeSize, origSz, h);
        }).detach();
    }

    LPVOID alloc = VirtualAllocEx(hproc_, nullptr, compressed.size(),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) return false;

    DWORD oldProt = 0, d = 0;
    VirtualProtectEx(hproc_, alloc, compressed.size(), PAGE_READWRITE, &oldProt);
    NtWriteVirtualMemory(hproc_, alloc, (PVOID)compressed.c_str(),
                         (ULONG)compressed.size(), nullptr);

    return VirtualProtectEx(hproc_, alloc, compressed.size(), oldProt, &d)
        && write_mem<std::uintptr_t>(embPtr + inst_offsets::Bytecode,
                                     reinterpret_cast<std::uintptr_t>(alloc), hproc_)
        && write_mem<std::uint64_t>(embPtr + inst_offsets::BytecodeSize,
                                    compressed.size(), hproc_);
}

void Instance::unlock_module() const {
    if (class_name() == "ModuleScript") {
        write_mem<std::uintptr_t>(addr_ + inst_offsets::ModuleFlags, 0x100000000, hproc_);
        write_mem<std::uintptr_t>(addr_ + inst_offsets::IsCoreScript, 0x1, hproc_);
    }
}

// -----------------------------------------------------------------------
// Bytecode pipeline
// -----------------------------------------------------------------------

namespace {

class BytecodeEncoderImpl : public Luau::BytecodeEncoder {
    void encode(uint32_t* data, size_t count) override {
        for (size_t i = 0; i < count;) {
            auto& opcode = *reinterpret_cast<uint8_t*>(data + i);
            i += Luau::getOpLength(LuauOpcode(opcode));
            opcode *= 227;
        }
    }
};

BytecodeEncoderImpl g_encoder;

} // namespace

std::string compress_bytecode(std::string_view bytecode) {
    const auto data_size = bytecode.size();
    const auto max_size = ZSTD_compressBound(data_size);
    std::vector<char> buffer(max_size + 8);

    strcpy_s(&buffer[0], buffer.capacity(), "RSB1");
    memcpy_s(&buffer[4], buffer.capacity(), &data_size, sizeof(data_size));

    const auto comp_size = ZSTD_compress(&buffer[8], max_size,
                                          bytecode.data(), data_size,
                                          ZSTD_maxCLevel());
    if (ZSTD_isError(comp_size))
        return "";

    const auto size = comp_size + 8;
    const auto key = XXH32(buffer.data(), size, 42u);
    const auto bytes = reinterpret_cast<const uint8_t*>(&key);

    for (size_t i = 0; i < size; ++i)
        buffer[i] ^= bytes[i % 4] + static_cast<uint8_t>(i * 41u);

    return std::string(buffer.data(), size);
}

std::string compile_luau(const std::string& source) {
    const std::string bytecode = Luau::compile(source, {}, {}, &g_encoder);
    if (!bytecode.empty() && bytecode[0] == '\0') {
        std::string diag = bytecode;
        diag.erase(std::remove(diag.begin(), diag.end(), '\0'), diag.end());
        std::cerr << "[voidtrace] bytecode compile failed: " << diag << "\n";
    }
    return compress_bytecode(bytecode);
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

static HMODULE get_self_module() {
    HMODULE h = nullptr;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                      (LPCTSTR)get_self_module, &h);
    return h;
}

static std::filesystem::path get_handle_path(HANDLE h) {
    char buf[MAX_PATH]{};
    DWORD sz = sizeof(buf);
    if (QueryFullProcessImageNameA(h, 0, buf, &sz))
        return std::filesystem::path(buf);
    return {};
}

static std::string generate_guid() {
    GUID guid;
    if (CoCreateGuid(&guid) != S_OK)
        return "00000000-0000-0000-0000-000000000000";

    char str[39];
    snprintf(str, sizeof(str), "%08lX-%04X-%04X-%04X-%012llX",
             guid.Data1, guid.Data2, guid.Data3,
             (guid.Data4[0] << 8) | guid.Data4[1],
             ((static_cast<unsigned long long>(guid.Data4[2]) << 40) |
              (static_cast<unsigned long long>(guid.Data4[3]) << 32) |
              (static_cast<unsigned long long>(guid.Data4[4]) << 24) |
              (static_cast<unsigned long long>(guid.Data4[5]) << 16) |
              (static_cast<unsigned long long>(guid.Data4[6]) << 8)  |
               static_cast<unsigned long long>(guid.Data4[7])));
    return std::string(str);
}

static void replace_str(std::string& s, std::string_view from, std::string_view to) {
    auto pos = s.find(from);
    if (pos != std::string::npos)
        s.replace(pos, from.length(), to);
}

static HWND hwnd_from_pid(DWORD pid) {
    struct Ctx { DWORD pid; HWND result; };
    Ctx ctx{pid, nullptr};
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lp);
        DWORD wp = 0;
        GetWindowThreadProcessId(hwnd, &wp);
        if (wp == c->pid && IsWindowVisible(hwnd)) {
            c->result = hwnd;
            return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));
    return ctx.result;
}

// -----------------------------------------------------------------------
// Executor
// -----------------------------------------------------------------------

Executor& Executor::instance() {
    static Executor s;
    return s;
}

bool Executor::attach(std::uint32_t pid, std::uintptr_t data_model) {
    std::lock_guard<std::mutex> lock(mtx_);

    if (hproc_ && pid_ == pid && data_model_ == data_model && bootstrapped_) {
        VT_LOG(L"voidtrace: already attached to pid=" + std::to_wstring(pid));
        return true;
    }

    // Close any previous handle
    if (hproc_) { CloseHandle(hproc_); hproc_ = nullptr; }

    hproc_ = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
    if (!hproc_) {
        VT_WARN(L"voidtrace: OpenProcess failed err=" +
                std::to_wstring(GetLastError()));
        return false;
    }

    pid_ = pid;
    data_model_ = data_model;
    guid_ = generate_guid();

    auto dir = get_handle_path(hproc_).parent_path();
    version_ = dir.filename().string();

    VT_LOG(L"voidtrace: attached pid=" + std::to_wstring(pid) +
           L" DM=0x" + std::to_wstring(data_model) +
           L" ver=" + std::wstring(version_.begin(), version_.end()));

    // Bridge discovered offsets from Config into inst_offsets
    {
        const auto& ot = Config::instance().get().offsets;
        inst_offsets::apply_discovered(ot.name_off, ot.child_off, 0);
    }

    bootstrapped_ = false;
    do_bootstrap();
    return bootstrapped_;
}

void Executor::detach() {
    std::lock_guard<std::mutex> lock(mtx_);
    if (hproc_) { CloseHandle(hproc_); hproc_ = nullptr; }
    pid_ = 0;
    data_model_ = 0;
    username_ = "N/A";
    version_.clear();
    guid_.clear();
    bootstrapped_ = false;
    VT_LOG(L"voidtrace: detached");
}

bool Executor::is_attached() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!hproc_ || !bootstrapped_) return false;
    DWORD ec = 0;
    if (GetExitCodeProcess(hproc_, &ec))
        return ec == STILL_ACTIVE;
    return false;
}

std::vector<ClientRow> Executor::clients() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!hproc_ || !bootstrapped_) return {};
    DWORD ec = 0;
    if (!GetExitCodeProcess(hproc_, &ec) || ec != STILL_ACTIVE) return {};
    return {{ version_, username_, pid_ }};
}

std::string Executor::username() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return username_;
}

std::uint32_t Executor::pid() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return pid_;
}

std::size_t Executor::execute(const std::string& source) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!hproc_ || !bootstrapped_ || source.empty()) return 0;

    Instance dm(data_model_, hproc_);
    auto rrs = dm.find_child_of_class("RobloxReplicatedStorage");
    if (!rrs) {
        VT_WARN(L"voidtrace: execute: RobloxReplicatedStorage not found");
        return 0;
    }
    auto vtFolder = rrs->find_child("VoidTrace");
    if (!vtFolder) {
        VT_WARN(L"voidtrace: execute: VoidTrace folder not found — bootstrap may not have run");
        return 0;
    }
    auto scripts = vtFolder->find_child("Scripts");
    if (!scripts) {
        VT_WARN(L"voidtrace: execute: VoidTrace/Scripts not found");
        return 0;
    }
    auto mod = scripts->find_child_of_class("ModuleScript");
    if (!mod) {
        VT_WARN(L"voidtrace: execute: no ModuleScript in VoidTrace/Scripts");
        return 0;
    }

    std::string wrapped =
        "return {['v o i d t r a c e']=function(...)do local function s(i, v)"
        "getfenv(debug.info(0, 'f'))[i] = v;getfenv(debug.info(1, 'f'))[i] = v;"
        "end;for i,v in pairs(getfenv(debug.info(1,'f')))do s(i, v)end;"
        "setmetatable(getgenv(),{__newindex=function(t,i,v)rawset(t,i,v)s(i,v)end})end;"
        + source + "\nend}";

    mod->set_bytecode(compile_luau(wrapped), true);
    mod->unlock_module();
    return 1;
}

std::string Executor::compilable(const std::string& source) {
    BytecodeEncoderImpl enc;
    std::string bc = Luau::compile(source, {}, {}, &enc);
    if (!bc.empty() && bc[0] == '\0') {
        bc.erase(std::remove(bc.begin(), bc.end(), '\0'), bc.end());
        return bc;
    }
    return "success";
}

// -----------------------------------------------------------------------
// Bootstrap hijack — writes client.lua into Url + VRNavigation
// -----------------------------------------------------------------------

void Executor::do_bootstrap() {
    if (data_model_ == 0 || !hproc_) return;

    Instance dm(data_model_, hproc_);

    // Diagnostic: dump DM children
    {
        auto ch = dm.children_addresses();
        std::cout << "[voidtrace] bootstrap: DataModel children count=" << ch.size() << "\n";
        int n = 0;
        for (auto addr : ch) {
            if (++n > 12) break;
            std::string nm, cn;
            try { nm = read_roblox_string(read_mem<std::uintptr_t>(addr + inst_offsets::Name(), hproc_), hproc_); } catch (...) {}
            try {
                cn = read_roblox_string(
                    read_mem<std::uintptr_t>(
                        read_mem<std::uintptr_t>(addr + inst_offsets::ClassDescriptor, hproc_)
                        + inst_offsets::ClassName, hproc_), hproc_);
            } catch (...) {}
            std::cout << "  child[" << n << "] addr=0x" << std::hex << addr << std::dec
                      << " name=\"" << nm << "\" class=\"" << cn << "\"\n";
        }
        if (ch.empty()) {
            VT_WARN(L"voidtrace: DataModel has 0 children — offsets likely wrong");
            return;
        }
    }

    // Find Players → LocalPlayer → Username
    auto playersAddr = dm.find_child_of_class_address("Players");
    if (!playersAddr) {
        VT_WARN(L"voidtrace: bootstrap: Players service not found");
        return;
    }
    auto lpAddr = read_mem<std::uintptr_t>(playersAddr + inst_offsets::LocalPlayer, hproc_);
    for (int i = 0; lpAddr == 0 && i < 200; ++i) {
        lpAddr = read_mem<std::uintptr_t>(playersAddr + inst_offsets::LocalPlayer, hproc_);
        Sleep(25);
    }
    if (lpAddr) {
        Instance lp(lpAddr, hproc_);
        username_ = lp.name();
        for (int i = 0; username_ == "Player" && i < 200; ++i) {
            username_ = lp.name();
            Sleep(25);
        }
    }
    if (username_.empty() || username_ == "N/A")
        username_ = "Unknown";

    VT_LOG(L"voidtrace: bootstrap: Username=" +
           std::wstring(username_.begin(), username_.end()));

    // CoreGui → RobloxGui → Modules → InGameMenu/Network → Url
    auto coreGui = dm.find_child("CoreGui");
    if (!coreGui) { VT_WARN(L"bootstrap: CoreGui not found"); return; }
    auto robloxGui = coreGui->find_child("RobloxGui");
    if (!robloxGui) { VT_WARN(L"bootstrap: RobloxGui not found"); return; }
    auto modules = robloxGui->find_child("Modules");
    if (!modules) { VT_WARN(L"bootstrap: Modules not found"); return; }

    std::unique_ptr<Instance> patchScript;
    {
        auto igm = modules->find_child("InGameMenu");
        if (igm) {
            auto net = igm->find_child("Network");
            if (net) patchScript = net->find_child("Url");
        }
        if (!patchScript) {
            auto common = modules->find_child("Common");
            if (common) patchScript = common->find_child("Url");
        }
    }
    if (!patchScript) {
        VT_WARN(L"bootstrap: PatchScript 'Url' not found");
        return;
    }

    // Load client.lua from embedded resource
    std::string clientScript;
    {
        HMODULE mod = get_self_module();
        if (!mod) { VT_WARN(L"bootstrap: GetModuleHandle failed"); return; }
        HRSRC res = FindResource(mod, MAKEINTRESOURCE(SCRIPT), MAKEINTRESOURCE(LUAFILE));
        if (!res) { VT_WARN(L"bootstrap: client.lua resource not found"); return; }
        HGLOBAL data = LoadResource(mod, res);
        if (!data) { VT_WARN(L"bootstrap: LoadResource failed"); return; }
        DWORD sz = SizeofResource(mod, res);
        char* raw = static_cast<char*>(LockResource(data));
        clientScript.assign(raw, sz);
    }

    replace_str(clientScript, "%XENO_UNIQUE_ID%", guid_);
    replace_str(clientScript, "%XENO_VERSION%", "1.2.0-voidtrace");

    const std::string patchSrc =
        "--!native\n--!optimize 1\n--!nonstrict\n"
        "local a={}local b=game:GetService(\"ContentProvider\")"
        "local function c(d)local e,f=d:find(\"%.\")local g=d:sub(f+1)"
        "if g:sub(-1)~=\"/\"then g=g..\"/\"end;return g end;"
        "local d=b.BaseUrl;local g=c(d)"
        "local h=string.format(\"https://games.%s\",g)"
        "local i=string.format(\"https://apis.rcs.%s\",g)"
        "local j=string.format(\"https://apis.%s\",g)"
        "local k=string.format(\"https://accountsettings.%s\",g)"
        "local l=string.format(\"https://gameinternationalization.%s\",g)"
        "local m=string.format(\"https://locale.%s\",g)"
        "local n=string.format(\"https://users.%s\",g)"
        "local o={GAME_URL=h,RCS_URL=i,APIS_URL=j,ACCOUNT_SETTINGS_URL=k,"
        "GAME_INTERNATIONALIZATION_URL=l,LOCALE_URL=m,ROLES_URL=n}"
        "setmetatable(a,{__newindex=function(p,q,r)end,"
        "__index=function(p,r)return o[r]end})return a";

    // LuaApp (home page) — just patch Url
    if (dm.name() == "LuaApp") {
        patchScript->set_bytecode(
            compile_luau("coroutine.wrap(function(...)" + clientScript +
                         "\nend)();" + patchSrc));
        bootstrapped_ = true;
        return;
    }

    auto rrs = dm.find_child_of_class("RobloxReplicatedStorage");
    if (!rrs) { VT_WARN(L"bootstrap: RobloxReplicatedStorage not found"); return; }

    // Already bootstrapped?
    if (rrs->find_child("VoidTrace")) {
        patchScript->set_bytecode(
            compile_luau("coroutine.wrap(function(...)" + clientScript +
                         "\nend)();" + patchSrc));
        bootstrapped_ = true;
        VT_LOG(L"voidtrace: bootstrap: VoidTrace folder already exists — re-patched Url");
        return;
    }

    // Find PlayerListManager for the spoof trick
    std::unique_ptr<Instance> plm;
    {
        auto pl = modules->find_child("PlayerList");
        if (!pl) { VT_WARN(L"bootstrap: PlayerList not found"); return; }
        plm = pl->find_child("PlayerListManager");
    }
    if (!plm) { VT_WARN(L"bootstrap: PlayerListManager not found"); return; }

    // Wait for DropDownFullscreenFrame (game loaded)
    if (!robloxGui->find_child("DropDownFullscreenFrame")) {
        std::cout << "Waiting for " << username_ << " to join the game\n";
        robloxGui->wait_for_child_address("DropDownFullscreenFrame");
        if (dm.name() == "App") {
            patchScript->set_bytecode(
                compile_luau("coroutine.wrap(function(...)" + clientScript +
                             "\nend)();" + patchSrc));
            bootstrapped_ = true;
            return;
        }
        std::cout << "Joined, waiting 2.5s for " << username_ << " to load\n";
        Sleep(2500);
    }

    // Find VRNavigation
    std::unique_ptr<Instance> vrNav;
    {
        auto sp = dm.find_child_of_class("StarterPlayer");
        if (!sp) { VT_WARN(L"bootstrap: StarterPlayer not found"); return; }
        auto sps = sp->find_child("StarterPlayerScripts");
        if (!sps) { VT_WARN(L"bootstrap: StarterPlayerScripts not found"); return; }
        auto pm = sps->find_child("PlayerModule");
        if (!pm) { VT_WARN(L"bootstrap: PlayerModule not found"); return; }
        auto cm = pm->find_child("ControlModule");
        if (!cm) { VT_WARN(L"bootstrap: ControlModule not found"); return; }
        vrNav = cm->find_child("VRNavigation");
    }
    if (!vrNav) {
        VT_WARN(L"bootstrap: VRNavigation not found (already attached?)");
        return;
    }

    // Write bytecode into VRNavigation + Url
    vrNav->unlock_module();
    write_mem<std::uintptr_t>(plm->self() + inst_offsets::This,
                              vrNav->self(), hproc_);

    vrNav->set_bytecode(
        compile_luau("script.Parent=nil;coroutine.wrap(function(...)"
                     + clientScript +
                     "\nend)();while wait(9e9) do wait(9e9);end"),
        true);
    patchScript->set_bytecode(
        compile_luau("coroutine.wrap(function(...)" + clientScript +
                     "\nend)();" + patchSrc));

    // Press ESC to trigger the in-game menu (loads corescript)
    HWND hwnd = hwnd_from_pid(pid_);
    if (hwnd) {
        HWND prev = GetForegroundWindow();
        for (int i = 0; GetForegroundWindow() != hwnd && i < 100; ++i) {
            SetForegroundWindow(hwnd);
            Sleep(5);
        }
        keybd_event(VK_ESCAPE, MapVirtualKey(VK_ESCAPE, 0),
                    KEYEVENTF_SCANCODE, 0);
        keybd_event(VK_ESCAPE, MapVirtualKey(VK_ESCAPE, 0),
                    KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP, 0);
        Sleep(100);
        if (prev) SetForegroundWindow(prev);
        Sleep(800);
    }

    // Restore PlayerListManager spoof
    write_mem<std::uintptr_t>(plm->self() + inst_offsets::This,
                              plm->self(), hproc_);

    // Retry username if still unknown
    if (username_ == "Unknown") {
        auto pa = dm.find_child_of_class_address("Players");
        if (pa) {
            auto lpa = read_mem<std::uintptr_t>(pa + inst_offsets::LocalPlayer, hproc_);
            if (lpa) {
                Instance lp(lpa, hproc_);
                auto n = lp.name();
                if (!n.empty()) username_ = n;
            }
        }
    }

    bootstrapped_ = true;
    VT_LOG(L"voidtrace: bootstrap COMPLETE — VoidTrace folder should appear in RRS");
}

} // namespace vt
